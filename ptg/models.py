from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Callable


class PTGNodeStatus(Enum):
    """
    Lifecycle status of a PTG node. Each node transitions through these
    states as the pentest engine executes the graph.

    State machine:
      PENDING -> READY -> RUNNING -> COMPLETED -> VALIDATED
                                  -> FAILED
                                  -> FALLBACK (primary abandoned, fallback activated)
      PENDING -> SKIPPED (pruned due to budget)
      PENDING -> BLOCKED (dependency failed with no fallback)

    Terminal states: COMPLETED, VALIDATED, SKIPPED, FAILED, FALLBACK, BLOCKED
    These states allow dependent nodes to proceed (or be blocked).
    """
    PENDING = "pending"       # Node is waiting for its dependencies to complete
    READY = "ready"           # All dependencies met; node is eligible for execution
    RUNNING = "running"       # Node is currently being executed by the pentest engine
    COMPLETED = "completed"   # Execution finished successfully, awaiting validation
    VALIDATED = "validated"   # Findings confirmed by validation oracle(s)
    SKIPPED = "skipped"       # Node was pruned (budget insufficient or not needed)
    FAILED = "failed"         # Execution encountered an error
    FALLBACK = "fallback"     # Node was abandoned in favor of its fallback alternative
    BLOCKED = "blocked"       # Cannot execute because a dependency failed irreversibly


class RiskTier(Enum):
    """
    Risk tier for PTG actions.

    The risk tier determines which actions are allowed for a given device
    fragility level. Higher tiers require more robust targets. A fragile
    PLC would only allow TIER_0 and TIER_1 actions, while a robust Linux
    server might allow up to TIER_3.

    The tier also influences stop condition thresholds: higher-risk actions
    on sensitive devices get tighter budget and RTT limits.
    """
    TIER_0 = 0   # Passive — zero impact on target (e.g., listening for mDNS broadcasts)
    TIER_1 = 1   # Gentle — minimal probing, single lightweight packets (e.g., ARP, ICMP echo)
    TIER_2 = 2   # Standard — normal active probing like port scans, banner grabs
    TIER_3 = 3   # Aggressive — requires preflight/approval (e.g., exploitation, fuzzing)


@dataclass
class ValidationOracle:
    """
    Validation recipe for confirming a finding without unnecessary disruption.

    After a PTG node completes, its findings need verification. Validation
    oracles define HOW to verify, ordered by disruptiveness: passive checks
    are tried first (e.g., "does the result contain a MAC address?"), then
    cross-references (e.g., "does the OS match the banner?"), and only if
    needed, active re-probes (e.g., "ping the host again to confirm").

    This ordering minimizes additional impact on the target device while
    still ensuring findings are reliable.

    Attributes:
        name: Short identifier for this oracle (e.g., "mac_present")
        description: Human-readable explanation of what is being validated
        oracle_type: Category of validation — one of:
            "passive"          — check existing data, no new packets sent
            "active_recheck"   — send additional probes to re-verify
            "cross_reference"  — compare results from different tools/phases
        disruptiveness: Float from 0.0 (passive) to 1.0 (very disruptive),
                        used to order oracles from least to most impactful
        budget_cost: Budget points consumed by this validation step (only
                     non-zero for active rechecks that send real traffic)
        probe_types: For active rechecks, which probe types to use (e.g.,
                     ["icmp_echo", "tcp_syn"]) — maps to IC-ToolSpec probes
    """
    name: str
    description: str
    oracle_type: str               # "passive", "active_recheck", "cross_reference"
    disruptiveness: float = 0.0    # 0.0 = passive, 1.0 = very disruptive
    budget_cost: float = 0.0       # Budget points this validation step consumes
    probe_types: List[str] = field(default_factory=list)  # Probe types for active rechecks

    @staticmethod
    def passive_check(name: str, description: str = "") -> "ValidationOracle":
        """
        Factory for a passive validation oracle. Passive checks examine
        existing data without sending any traffic to the target. They have
        zero disruptiveness and zero budget cost.

        Example: checking if a discovery result contains a MAC address.
        """
        return ValidationOracle(name=name, description=description,
                                oracle_type="passive", disruptiveness=0.0)

    @staticmethod
    def active_recheck(name: str, budget_cost: float,
                       probe_types: List[str]) -> "ValidationOracle":
        """
        Factory for an active recheck validation oracle. Active rechecks
        send additional packets to the target to re-verify a finding. They
        consume budget points and have moderate disruptiveness (0.5).

        These are only used when passive checks and cross-references are
        insufficient to confirm a finding with adequate confidence.

        Args:
            name: Oracle identifier
            budget_cost: Budget points consumed by the recheck probes
            probe_types: List of probe type strings (e.g., ["icmp_echo"])
                         that map to IC-ToolSpec tool categories
        """
        return ValidationOracle(name=name, description=f"Active re-probe: {name}",
                                oracle_type="active_recheck", disruptiveness=0.5,
                                budget_cost=budget_cost, probe_types=probe_types)

    @staticmethod
    def cross_reference(name: str) -> "ValidationOracle":
        """
        Factory for a cross-reference validation oracle. Cross-references
        compare results from different tools or phases to check consistency.
        They have low disruptiveness (0.1) since they only examine existing
        data from multiple sources, sending no new traffic.

        Example: verifying that the OS detected by TCP fingerprinting matches
        the OS suggested by banner strings.
        """
        return ValidationOracle(name=name, description=f"Cross-reference: {name}",
                                oracle_type="cross_reference", disruptiveness=0.1)


@dataclass
class StopCondition:
    """
    Condition that triggers early termination of a PTG node or subtree.

    Stop conditions are safety guardrails that protect the target device.
    Each node can have multiple stop conditions; if ANY condition fires,
    execution of that node (and potentially its subtree) is halted.

    The four check types map to different runtime signals:
      - "budget":  Fires when remaining budget drops below a percentage
                   threshold. Prevents over-spending on a single target.
      - "rtt":     Fires when round-trip time exceeds a multiplier of the
                   baseline RTT. An RTT spike often indicates the target
                   device is becoming overloaded or degraded.
      - "timeout": Fires after N consecutive timeouts, suggesting the target
                   may be unresponsive or crashing.
      - "breaker": Fires when the circuit breaker trips (detected by the
                   TIB-PCF layer). This is the ultimate safety mechanism.
      - "custom":  Reserved for user-defined conditions via callback.

    Fragile/critical devices get much tighter thresholds than robust ones.

    Attributes:
        name: Short identifier (e.g., "budget_50pct", "rtt_1.5x")
        description: Human-readable explanation of the condition
        threshold: Numeric threshold for triggering (meaning depends on check_type)
        check_type: One of "budget", "rtt", "timeout", "breaker", "custom"
    """
    name: str
    description: str
    threshold: float = 0.0
    check_type: str = "budget"   # "budget", "rtt", "timeout", "breaker", "custom"

    @staticmethod
    def budget_threshold(pct: float) -> "StopCondition":
        """
        Factory for a budget-based stop condition. Triggers when the
        remaining budget percentage falls below the given threshold.

        For example, budget_threshold(50.0) means "stop this node if
        less than 50% of the total budget remains." Critical devices use
        high thresholds (50%) to preserve budget, while robust devices
        use low thresholds (5%) to allow more thorough testing.

        Args:
            pct: Budget percentage threshold (0-100). Execution stops
                 when remaining_budget_pct < pct.
        """
        return StopCondition(
            name=f"budget_{pct:.0f}pct",
            description=f"Stop if budget below {pct}%",
            threshold=pct,
            check_type="budget",
        )

    @staticmethod
    def rtt_spike(multiplier: float) -> "StopCondition":
        """
        Factory for an RTT-based stop condition. Triggers when the current
        round-trip time exceeds a multiplier of the baseline RTT.

        A sudden RTT increase is a strong signal that the target device is
        becoming overloaded. For critical devices, even a 1.5x spike triggers
        a stop; for robust devices, a 5x spike is tolerated.

        Args:
            multiplier: RTT multiplier threshold. Execution stops when
                        current_rtt > baseline_rtt * multiplier.
        """
        return StopCondition(
            name=f"rtt_{multiplier:.1f}x",
            description=f"Stop if RTT exceeds {multiplier}x baseline",
            threshold=multiplier,
            check_type="rtt",
        )

    @staticmethod
    def consecutive_timeouts(count: int) -> "StopCondition":
        """
        Factory for a timeout-based stop condition. Triggers after N
        consecutive timeouts from the target device.

        Consecutive timeouts suggest the device may be unresponsive, crashed,
        or has entered a degraded state. Critical devices stop after just 1
        timeout; robust devices tolerate up to 10.

        Args:
            count: Number of consecutive timeouts before triggering.
                   Stored as float internally for uniform threshold comparison.
        """
        return StopCondition(
            name=f"timeout_{count}",
            description=f"Stop after {count} consecutive timeouts",
            threshold=float(count),
            check_type="timeout",
        )

    @staticmethod
    def breaker_trip() -> "StopCondition":
        """
        Factory for a circuit-breaker stop condition. Triggers when the
        TIB-PCF circuit breaker trips for this target.

        The circuit breaker is the top-level safety mechanism in the TIB
        framework. When it trips (due to cumulative impact exceeding safe
        thresholds), ALL active testing on the target must cease immediately.
        This stop condition is added to every node by default.
        """
        return StopCondition(
            name="breaker_trip",
            description="Stop if circuit breaker trips",
            check_type="breaker",
        )


@dataclass
class PTGNode:
    """
    Single node in the TIB-aware Penetration Task Graph.

    Each node represents one specific penetration testing action to be
    executed against a target device. The node carries all the metadata
    needed for the runtime engine to decide whether, when, and how to
    execute the action safely.

    Paper equation (2):
      v = <pre(v), G(v), icost(v), risk(v), oracle(v), stop(v), fb(v)>

    Mapping to this dataclass:
      pre(v)    -> dependencies      (list of node_ids that must complete first)
      G(v)      -> safe_mode + tool_id (bounded grammar from IC-ToolSpec)
      icost(v)  -> estimated_budget_cost / actual_budget_cost
      risk(v)   -> risk_tier         (TIER_0 through TIER_3)
      oracle(v) -> validation_oracles (ordered list, passive-first)
      stop(v)   -> stop_conditions   (budget, RTT, timeout, breaker checks)
      fb(v)     -> fallback_node_id  (pointer to a cheaper/safer alternative)
    """
    # ── Identity ────────────────────────────────────────────────────────────
    node_id: str                # Unique identifier (e.g., "p1-a3f8c012")
    name: str                   # Human-readable name (e.g., "ARP Discovery")
    tool_id: str                # IC-ToolSpec registry key identifying which tool to run
    safe_mode: str              # Which SafeMode configuration to use for this tool
    target_ip: str = ""         # Target IP address (set by PTGGraph.add_node)
    phase: str = ""             # Pentest phase this node belongs to (e.g., "HOST_DISCOVERY")

    # ── Impact cost (from IC-ToolSpec) ──────────────────────────────────────
    # estimated_budget_cost: predicted cost in budget points, set at graph build time
    #   based on the tool's SafeMode configuration. Used for pruning decisions.
    estimated_budget_cost: float = 0.0
    # actual_budget_cost: real cost recorded after execution completes.
    #   May differ from estimate due to varying target responses.
    actual_budget_cost: float = 0.0

    # ── Risk tier ───────────────────────────────────────────────────────────
    # Determines whether this action is allowed for the target's fragility level.
    # The builder only creates nodes with risk tiers the target can tolerate.
    risk_tier: RiskTier = RiskTier.TIER_1

    # ── Graph structure (DAG edges) ─────────────────────────────────────────
    # dependencies: node_ids of prerequisite nodes. ALL must be in a terminal
    #   state (COMPLETED, VALIDATED, SKIPPED, or FALLBACK) before this node
    #   can transition from PENDING to READY.
    dependencies: List[str] = field(default_factory=list)
    # fallback_node_id: pointer to an alternative node that is cheaper or
    #   less aggressive. Activated when this node cannot execute (budget
    #   exceeded, failed, etc.). The fallback node is promoted to READY.
    fallback_node_id: Optional[str] = None
    # children: node_ids of nodes that depend on this one. Maintained
    #   automatically by PTGGraph.add_node() — the inverse of dependencies.
    children: List[str] = field(default_factory=list)

    # ── Validation ──────────────────────────────────────────────────────────
    # Ordered list of validation oracles for confirming findings.
    # Oracles are tried in order: passive checks first, then cross-references,
    # then active rechecks. This minimizes additional impact on the target.
    validation_oracles: List[ValidationOracle] = field(default_factory=list)

    # ── Stop conditions ─────────────────────────────────────────────────────
    # List of conditions that trigger early termination of this node.
    # Checked by the runtime engine before and during execution.
    stop_conditions: List[StopCondition] = field(default_factory=list)

    # ── Status and results ──────────────────────────────────────────────────
    status: PTGNodeStatus = PTGNodeStatus.PENDING  # Current lifecycle state
    priority: float = 0.0       # Scheduling priority; higher = execute sooner.
                                # Used by get_ready_nodes() to order execution
                                # and by prune_by_budget() to decide what to cut.
    result: Optional[Dict] = None   # Execution output (tool-specific dict)
    error: str = ""                 # Error message if status is FAILED or SKIPPED
    pcf_node_id: str = ""           # Cross-reference to the TIB-PCF circuit breaker node

    def to_dict(self) -> dict:
        """
        Serialize this node to a plain dictionary for JSON export, logging,
        or API responses. Only includes the most important fields — omits
        validation_oracles, stop_conditions, and result to keep output concise.

        Returns:
            Dictionary representation of the node's key attributes.
        """
        return {
            "node_id": self.node_id,
            "name": self.name,
            "tool_id": self.tool_id,
            "safe_mode": self.safe_mode,
            "target_ip": self.target_ip,
            "phase": self.phase,
            "estimated_budget_cost": self.estimated_budget_cost,
            "actual_budget_cost": self.actual_budget_cost,
            "risk_tier": self.risk_tier.value,      # Serialize enum as integer (0-3)
            "dependencies": self.dependencies,
            "fallback_node_id": self.fallback_node_id,
            "status": self.status.value,            # Serialize enum as string
            "priority": self.priority,
            "error": self.error,
        }
