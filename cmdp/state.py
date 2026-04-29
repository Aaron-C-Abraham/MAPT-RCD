import numpy as np
from dataclasses import dataclass, field
from typing import Optional, List
from TIB_and_PCF.TIB.TIB_structures import DeviceTier, CircuitBreakerStatus


@dataclass
class CMDPState:
    """
    State representation for the constrained MDP.

    Captures all information needed for the DRL policy to select actions.
    Can be flattened to a 20-dimensional numeric vector for neural network input
    via the to_vector() method.

    Each field group maps to a subset of the state vector dimensions.
    The dataclass form is human-readable; the vector form is machine-consumable.
    """

    # ── Target profile ─────────────────────────────────────────────────────────
    # device_tier: Classifies the device's robustness (1=ROBUST .. 5=UNKNOWN).
    # Determines how aggressively the policy may probe — CRITICAL devices get
    # near-zero aggression, ROBUST devices allow full-speed scanning.
    device_tier: DeviceTier = DeviceTier.UNKNOWN

    # known_services_count: Number of services already identified via banners.
    # Higher values mean we already have substantial info, reducing the marginal
    # value of additional probing (diminishing returns).
    known_services_count: int = 0

    # open_ports_count: Number of open ports discovered so far.
    # Normalized by /100 in the vector because typical devices have 0-100 open ports.
    open_ports_count: int = 0

    # os_hypothesis: Best-guess OS string from nmap or banner analysis.
    # Used by the heuristic policy for tool selection (not in the numeric vector).
    os_hypothesis: str = ""

    # os_confidence: Confidence in the OS hypothesis, range [0.0, 1.0].
    # Already normalized; fed directly into the state vector.
    # High confidence means further OS detection probes have low marginal value.
    os_confidence: float = 0.0

    # is_industrial: True if the device exposes known industrial/OT ports
    # (Modbus/502, S7/102, EtherNet/IP/44818, etc.).
    # Triggers more conservative probing behavior to avoid disrupting physical processes.
    is_industrial: bool = False

    # ── TIB budget ─────────────────────────────────────────────────────────────
    # budget_total: Maximum budget points allocated by the TIB for this device.
    # Used as a denominator for normalization; zero means no budget limit.
    budget_total: float = 0.0

    # budget_remaining_pct: Percentage of budget still available (0-100).
    # Normalized to [0, 1] in the vector by dividing by 100.
    # The policy must plan actions so this does not reach zero prematurely.
    budget_remaining_pct: float = 100.0

    # current_rate_limit_pct: Current packet rate as a percentage of the configured
    # maximum packets-per-second.  When the TIB throttles due to stress, this drops
    # below 100, signaling the policy to slow down or switch to passive probes.
    current_rate_limit_pct: float = 100.0

    # ── Impact signals ─────────────────────────────────────────────────────────
    # rtt_ratio: current RTT / baseline RTT.  A ratio of 1.0 means no degradation.
    # Values > 1.5 indicate the target is becoming sluggish under probe load.
    # Clamped to [0, 10] and normalized by /10 in the vector.
    rtt_ratio: float = 1.0              # current / baseline

    # consecutive_timeouts: How many probes in a row received no response.
    # High values suggest the target may be overloaded or has crashed.
    # Normalized by /10 (clamped) in the vector.
    consecutive_timeouts: int = 0

    # stress_events: Cumulative count of stress indicators observed
    # (e.g., RTT spikes, connection resets, service restarts).
    # Each event increases the constraint cost and may trigger rate reduction.
    stress_events: int = 0

    # circuit_breaker_status: Current state of the TIB circuit breaker.
    # ACTIVE = normal operation; PAUSED = temporarily halted; TRIPPED = emergency stop;
    # EXHAUSTED = budget fully consumed.  Encoded as a one-hot triple in the vector
    # (dims 10-12) to give the neural network a clear categorical signal.
    circuit_breaker_status: CircuitBreakerStatus = CircuitBreakerStatus.ACTIVE

    # ── Safety mode ────────────────────────────────────────────────────────────
    # is_ot_environment: True if the engagement is in an OT/ICS network.
    # OT mode globally reduces aggression (70% multiplier in heuristic policy)
    # because disrupting physical processes can cause real-world harm.
    is_ot_environment: bool = False

    # safety_officer_active: True if a human safety officer is supervising.
    # When active, exploitation-class probes are blocked on non-ROBUST devices
    # as a hard constraint (see constraints.py).
    safety_officer_active: bool = False

    # ── PTG progress ───────────────────────────────────────────────────────────
    # ptg_nodes_total: Total number of nodes in the Penetration Testing Graph.
    # Used as denominator for the progress ratio (dim 15).
    ptg_nodes_total: int = 0

    # ptg_nodes_completed: How many PTG nodes have been executed and validated.
    # Progress = completed / total; the completeness bonus in the reward function
    # incentivizes the policy to advance through the PTG.
    ptg_nodes_completed: int = 0

    # ptg_nodes_remaining: How many PTG nodes are still PENDING or READY.
    # Helps the policy estimate how much work (and budget) is left.
    ptg_nodes_remaining: int = 0

    # ptg_estimated_remaining_cost: Estimated budget cost to complete all remaining
    # PTG nodes.  Normalized by budget_total in the vector so the policy can judge
    # whether the remaining budget is sufficient to finish the scan.
    ptg_estimated_remaining_cost: float = 0.0

    # ── Fleet context ──────────────────────────────────────────────────────────
    # cluster_id: Identifier for the device's cluster in fleet mode.
    # Not included in the numeric vector (categorical string), but used by the
    # heuristic policy to decide whether to skip non-representative devices.
    cluster_id: Optional[str] = None

    # cluster_size: Number of devices in this cluster.
    # Normalized by /50 (clamped) in the vector.  Larger clusters benefit more
    # from fleet propagation (probe one, apply findings to all).
    cluster_size: int = 0

    # cluster_probed_count: How many devices in the cluster have already been probed.
    # The ratio probed/size tells the policy how much fleet coverage already exists.
    cluster_probed_count: int = 0

    # is_representative: True if this device is the chosen representative for its
    # cluster.  Non-representative devices should mostly be skipped; findings from
    # the representative are propagated to them.
    is_representative: bool = True

    def to_vector(self) -> np.ndarray:
        """
        Flatten state to a 20-dimensional numeric vector for DRL policy input.

        Every dimension is normalized to approximately [0, 1] because:
        1. Neural networks train faster with uniformly scaled inputs (avoids
           large-magnitude features dominating the gradient).
        2. Normalization makes the learned weights interpretable across dimensions.
        3. Clamping (via min(..., 1.0)) prevents outlier values from destabilizing
           the forward pass.
        """
        # Cache the circuit breaker status enum to avoid repeated attribute access.
        breaker = self.circuit_breaker_status

        vec = np.array([
            # [0] Device tier: enum value (1-5) scaled to [0.2, 1.0].
            #     ROBUST=1 -> 0.2, UNKNOWN=5 -> 1.0.  This ordering lets the network
            #     learn that higher values correspond to less-known/more-cautious tiers.
            self.device_tier.value / 5.0,

            # [1] Known services: capped at 20 to normalize.  Most IoT devices
            #     expose fewer than 20 services; values above 20 are equally "many".
            min(self.known_services_count / 20.0, 1.0),

            # [2] Open ports: capped at 100.  Typical IoT devices have 1-30 open ports;
            #     100 is an upper-bound ceiling for normalization.
            min(self.open_ports_count / 100.0, 1.0),

            # [3] OS confidence: already in [0, 1], no transformation needed.
            self.os_confidence,

            # [4] Industrial flag: binary 0 or 1.
            float(self.is_industrial),

            # [5] Budget remaining: convert from percentage (0-100) to fraction (0-1).
            self.budget_remaining_pct / 100.0,

            # [6] Rate limit: convert from percentage (0-100) to fraction (0-1).
            #     Low values signal that the TIB has already throttled us.
            self.current_rate_limit_pct / 100.0,

            # [7] RTT ratio: clamped to [0, 10] then normalized by /10.
            #     A value of 1.0 means no degradation; >0.15 (ratio >1.5) signals stress.
            min(self.rtt_ratio / 10.0, 1.0),

            # [8] Consecutive timeouts: capped at 10.  More than 10 timeouts in a row
            #     is equally alarming; the clamp prevents outlier domination.
            min(self.consecutive_timeouts / 10.0, 1.0),

            # [9] Stress events: capped at 10, same rationale as timeouts.
            min(self.stress_events / 10.0, 1.0),

            # [10-12] Circuit breaker status: one-hot encoding over three states.
            #     One-hot is preferred over a single ordinal because the states are
            #     categorical (ACTIVE/PAUSED/TRIPPED), not ordered.
            #     Note: EXHAUSTED maps to all-zeros here since it is handled
            #     as a hard constraint in constraints.py and the policy never sees it.
            float(breaker == CircuitBreakerStatus.ACTIVE),   # [10]
            float(breaker == CircuitBreakerStatus.PAUSED),   # [11]
            float(breaker == CircuitBreakerStatus.TRIPPED),  # [12]

            # [13] OT environment flag: binary.
            float(self.is_ot_environment),

            # [14] Safety officer flag: binary.
            float(self.safety_officer_active),

            # [15] PTG progress: fraction of nodes completed.
            #     max(total, 1) prevents division by zero when no PTG is loaded.
            (self.ptg_nodes_completed / max(self.ptg_nodes_total, 1)),

            # [16] PTG remaining cost ratio: estimated remaining cost as a fraction
            #     of total budget.  Values > 1.0 mean the remaining work exceeds
            #     the total budget (the policy should prioritize cheap nodes).
            #     Returns 0.0 if budget_total is 0 (no budget limit).
            (self.ptg_estimated_remaining_cost /
             max(self.budget_total, 1.0) if self.budget_total > 0 else 0.0),

            # [17] Cluster size: capped at 50 devices for normalization.
            #     Fleet clusters rarely exceed 50 identical devices.
            min(self.cluster_size / 50.0, 1.0),

            # [18] Cluster probed ratio: fraction of cluster already probed.
            #     max(size, 1) prevents division by zero for non-clustered devices.
            (self.cluster_probed_count / max(self.cluster_size, 1)),

            # [19] Is representative: binary.  If False, the heuristic policy will
            #     heavily discount non-passive probes to avoid redundant work.
            float(self.is_representative),
        ], dtype=np.float32)  # float32 matches the neural network weight dtype.

        return vec

    @staticmethod
    def from_tib_and_ptg(tib, graph=None, context=None) -> "CMDPState":
        """
        Construct a CMDPState from live system objects.

        This factory method bridges the gap between the TIB/PTG runtime objects
        and the CMDP's abstract state representation.  It pulls data from:
          - tib: a TIBManager instance (device tier, signals, budget, rate, impact metrics)
          - graph: an optional PTG graph (progress, remaining cost)
          - context: an optional engagement context (OT mode, safety officer, fleet info)

        Args:
            tib: The TIBManager for the target device.
            graph: The Penetration Testing Graph (if available).
            context: The engagement-level context (OT mode, fleet clusters, etc.).

        Returns:
            A fully populated CMDPState ready for policy evaluation.
        """
        # Import the set of known industrial/OT port numbers (502, 102, 44818, etc.)
        # to determine if this device is an industrial system.
        from TIB_and_PCF.TIB.device_classifier import INDUSTRIAL_PORTS

        state = CMDPState()

        # ── Target profile ────────────────────────────────────────────────
        # Copy the device tier classification from TIB.  The tier was determined
        # by the TIB classifier based on banners, ports, and behavioral signals.
        state.device_tier = tib.tier

        # Count services identified by banner grabbing.
        state.known_services_count = len(tib.signals.banners)

        # Count open ports discovered so far.
        state.open_ports_count = len(tib.signals.open_ports)

        # Store the best OS guess from nmap or banner analysis (may be None/empty).
        state.os_hypothesis = tib.signals.nmap_os_guess or ""

        # Check if any open port is in the known industrial port set.
        # This flag triggers conservative behavior in both heuristic and DRL policies
        # because disrupting OT devices can have physical-world consequences.
        state.is_industrial = any(p in INDUSTRIAL_PORTS for p in tib.signals.open_ports)

        # ── Budget ────────────────────────────────────────────────────────
        # Total budget from the TIB configuration (max points for this device).
        state.budget_total = tib.config.max_budget_points

        if tib.config.max_budget_points > 0:
            # Compute remaining budget as a percentage.
            # max(0, ...) ensures we never report negative remaining budget.
            state.budget_remaining_pct = max(0, (
                (tib.config.max_budget_points - tib.state.budget_spent)
                / tib.config.max_budget_points * 100
            ))
        else:
            # No budget limit configured — report 100% remaining (unconstrained).
            state.budget_remaining_pct = 100.0

        # Current rate limit as a percentage of the maximum configured rate.
        # When the TIB throttles (due to stress), current_rate_limit drops,
        # signaling the policy to use slower probe rates.
        state.current_rate_limit_pct = (
            tib.state.current_rate_limit / max(tib.config.max_packets_per_second, 1) * 100
        )

        # ── Impact signals ────────────────────────────────────────────────
        # RTT ratio: current round-trip time divided by the baseline.
        # Only computed when both baseline and current measurements exist.
        # A ratio > 1.0 indicates the target is responding more slowly than normal.
        if tib.state.baseline_rtt_ms and tib.state.current_rtt_ms:
            state.rtt_ratio = tib.state.current_rtt_ms / tib.state.baseline_rtt_ms

        # Consecutive timeouts: number of probes in a row with no response.
        state.consecutive_timeouts = tib.state.consecutive_timeouts

        # Stress events: cumulative count of stress indicators.
        state.stress_events = tib.state.stress_events

        # Circuit breaker status: ACTIVE, PAUSED, TRIPPED, or EXHAUSTED.
        state.circuit_breaker_status = tib.state.circuit_breaker_status

        # ── PTG progress ──────────────────────────────────────────────────
        if graph:
            from ptg.models import PTGNodeStatus

            # Retrieve all nodes in the Penetration Testing Graph.
            all_nodes = graph.get_all_nodes()
            state.ptg_nodes_total = len(all_nodes)

            # Count completed nodes (COMPLETED or VALIDATED status).
            # VALIDATED means the finding has been confirmed; both count as "done".
            state.ptg_nodes_completed = len([
                n for n in all_nodes
                if n.status in (PTGNodeStatus.COMPLETED, PTGNodeStatus.VALIDATED)
            ])

            # Count remaining nodes (PENDING or READY status).
            # PENDING = waiting for prerequisites; READY = can be executed now.
            state.ptg_nodes_remaining = len([
                n for n in all_nodes
                if n.status in (PTGNodeStatus.PENDING, PTGNodeStatus.READY)
            ])

            # Estimated budget cost to complete all remaining nodes.
            # Used by the policy to judge if the remaining budget is sufficient.
            state.ptg_estimated_remaining_cost = graph.estimate_remaining_cost()

        # ── Engagement context ────────────────────────────────────────────
        if context:
            # OT mode flag: set at the engagement level, affects all devices.
            state.is_ot_environment = context.ot_mode

            # Safety officer: when active, hard constraints block exploitation
            # on non-ROBUST devices (see constraints.py).
            state.safety_officer_active = context.safety_officer_active

            # Fleet cluster info: look up this device's cluster membership.
            # If the device belongs to a cluster, record whether it is the
            # representative (the one we probe in detail) or a member (skipped).
            cluster_info = context.fleet_clusters.get(tib.device_ip, {})
            if cluster_info:
                state.cluster_id = cluster_info.get("cluster_id")
                # A device is the representative if its IP matches the cluster's
                # designated representative_ip.
                state.is_representative = (
                    cluster_info.get("representative_ip") == tib.device_ip
                )

        return state

    @property
    def state_dim(self) -> int:
        """Return the dimensionality of the state vector (always 20).

        This constant must match the input layer size of the DRL policy network.
        """
        return 20
