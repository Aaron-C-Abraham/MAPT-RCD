"""
agents/impact_monitor_agent.py — Impact Monitor Agent.

PURPOSE:
    The Impact Monitor Agent is the SEVENTH agent in the 9-step pipeline
    (Step 7). It runs AFTER the ToolOrchestrator has executed all PTG nodes
    and performs a post-execution health check across all devices.

    It monitors four types of impact signals:
      1. Circuit breaker trips — a device's safety fuse has blown.
      2. Budget exhaustion    — a device's probing budget is fully spent.
      3. RTT stress           — a device is responding much slower than baseline.
      4. Budget warnings      — budget usage is above 80%.

    When it detects critical conditions, it can:
      - Send ALERTS to the ToolOrchestrator and Planner (informational).
      - Send VETOES to the ToolOrchestrator (blocks further actions).
      - Send ALERTS to the Coordinator (subnet-wide stress).

INTER-AGENT COMMUNICATION:
    Receives:
        ToolOrchestratorAgent ──STATUS──> ImpactMonitorAgent
          (execution complete — trigger monitoring sweep)

    Sends:
        ImpactMonitorAgent ──ALERT──> ToolOrchestratorAgent
          (breaker_tripped, budget_exhausted, rtt_stress)
        ImpactMonitorAgent ──ALERT──> PlannerAgent
          (budget_warning — so planner can adjust future PTGs)
        ImpactMonitorAgent ──VETO───> ToolOrchestratorAgent
          (block CRITICAL devices under stress)
        ImpactMonitorAgent ──ALERT──> Coordinator
          (subnet-wide correlated stress)

VETO MECHANISM:
    The Impact Monitor is one of only TWO agents that can send vetoes
    (the other is SafetyOfficer). It vetoes actions on CRITICAL-tier
    devices that have stress events AND whose circuit breaker hasn't
    already tripped. This catches the case where a device is showing
    stress signals but hasn't yet hit the circuit breaker threshold.

Watches RTT trends, circuit breaker events, and stress signals
across all devices. Can veto actions via the message bus.
Subsumes cross-device stress correlation.

Paper reference: Section VI-B item 5
"""

import time
import logging
from agents.base import BaseAgent, AgentRole, AgentResult, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class ImpactMonitorAgent(BaseAgent):
    """
    Agent responsible for monitoring device health and enforcing impact limits.

    Scans all devices for stress indicators (RTT spikes, circuit breaker
    trips, budget exhaustion) and issues alerts or vetoes to protect
    devices from further harm.
    """

    def __init__(self, context: SessionContext):
        # Register with the IMPACT_MONITOR role for message bus addressing
        super().__init__(AgentRole.IMPACT_MONITOR, context)

    def execute(self) -> AgentResult:
        """
        Monitor all devices for impact signals and issue alerts/vetoes.

        FLOW:
            For each device:
              1. Check circuit breaker status → alert if TRIPPED or EXHAUSTED.
              2. Check RTT ratio vs. baseline → alert if above pause multiplier.
              3. Check budget usage → warn planner if above 80%.
              4. Veto CRITICAL devices under stress (pre-emptive protection).
            Then check for subnet-level correlated stress across /24 ranges.

        Returns:
            AgentResult with alerts_sent and vetoes_sent counts.
        """
        from TIB_and_PCF.TIB.TIB_structures import CircuitBreakerStatus, DeviceTier
        from TIB_and_PCF.PCF import NodeType, EvidenceApproach

        alerts_sent = 0   # Counter for informational alerts dispatched
        vetoes_sent = 0   # Counter for blocking vetoes dispatched

        # ── Per-device health checks ─────────────────────────────────────────
        for ip, tib in self.context.devices.items():
            status = tib.state.circuit_breaker_status

            # ── Check 1: Circuit breaker TRIPPED ─────────────────────────────
            # A tripped breaker means the device exhibited dangerous stress
            # levels (e.g., too many consecutive timeouts). Alert the
            # ToolOrchestrator so it knows not to probe this device further.
            if status == CircuitBreakerStatus.TRIPPED:
                self.send_alert(
                    AgentRole.TOOL_ORCHESTRATOR,
                    "breaker_tripped",
                    {"device_ip": ip, "reason": tib.state.trip_reason},
                )
                alerts_sent += 1

                # Record the breaker trip in the PCF DAG as a SESSION_EVENT
                # so it appears in the evidence chain and engagement ledger.
                self.context.pcf_dag.add_node(
                    node_type=NodeType.SESSION_EVENT,
                    phase="IMPACT_MONITOR",
                    payload={"event": "breaker_tripped", "ip": ip,
                             "reason": tib.state.trip_reason},
                    parent_ids=[tib.pcf_device_root_id],
                    evidence_approaches=EvidenceApproach.INFERRED,  # We inferred stress, didn't probe
                    device_ip=ip,
                )

            # ── Check 2: Budget EXHAUSTED ────────────────────────────────────
            # The device's probing budget is fully spent. This is less severe
            # than a breaker trip (the device isn't necessarily stressed), but
            # no more actions can be taken on it.
            elif status == CircuitBreakerStatus.EXHAUSTED:
                self.send_alert(
                    AgentRole.TOOL_ORCHESTRATOR,
                    "budget_exhausted",
                    {"device_ip": ip, "spent": tib.state.budget_spent},
                )
                alerts_sent += 1

            # ── Check 3: RTT stress ──────────────────────────────────────────
            # Compare the device's current RTT to its baseline. If the ratio
            # exceeds the configured pause multiplier, the device is responding
            # significantly slower than normal — likely due to our probing or
            # general overload.
            if (tib.state.baseline_rtt_ms and tib.state.current_rtt_ms):
                ratio = tib.state.current_rtt_ms / tib.state.baseline_rtt_ms
                # rtt_pause_multiplier is configured per-tier (e.g., 3.0x for
                # STANDARD, 2.0x for FRAGILE, 1.5x for CRITICAL)
                if ratio > tib.config.rtt_pause_multiplier:
                    self.send_alert(
                        AgentRole.TOOL_ORCHESTRATOR,
                        "rtt_stress",
                        {"device_ip": ip, "rtt_ratio": ratio,
                         "baseline": tib.state.baseline_rtt_ms,
                         "current": tib.state.current_rtt_ms},
                    )
                    alerts_sent += 1

            # ── Check 4: Budget warnings (>80% used) ────────────────────────
            # Alert the Planner so it can potentially adjust future PTGs or
            # deprioritize this device in subsequent rounds.
            if tib.config.max_budget_points > 0:
                pct_used = (tib.state.budget_spent /
                            tib.config.max_budget_points * 100)
                if pct_used > 80:
                    self.send_alert(
                        AgentRole.PLANNER,
                        "budget_warning",
                        {"device_ip": ip, "pct_used": round(pct_used, 1)},
                    )
                    alerts_sent += 1

            # ── Check 5: Veto CRITICAL devices under stress ─────────────────
            # This is the pre-emptive safety mechanism: if a CRITICAL-tier
            # device (e.g., a PLC or SCADA controller) has ANY stress events
            # and its circuit breaker hasn't already tripped (which would
            # already block actions), issue a VETO to prevent further probing.
            # This is MORE conservative than the circuit breaker alone.
            if (tib.tier == DeviceTier.CRITICAL
                    and tib.state.stress_events > 0
                    and status != CircuitBreakerStatus.TRIPPED):
                self.send_veto(
                    AgentRole.TOOL_ORCHESTRATOR,
                    f"CRITICAL device {ip} under stress — blocking further actions",
                )
                vetoes_sent += 1
                self.context.vetoed_actions += 1  # Increment session metric

        # ── Subnet-level correlated stress ───────────────────────────────────
        # Check if multiple devices on the same /24 subnet are stressed,
        # which might indicate we are overloading a shared network resource
        # (switch, gateway, firewall). Alert the Coordinator if so.
        subnet_stress = self._check_subnet_stress()
        if subnet_stress:
            for subnet, ips in subnet_stress.items():
                self.send_alert(
                    AgentRole.COORDINATOR,
                    "subnet_stress",
                    {"subnet": subnet, "affected_ips": ips},
                )
                alerts_sent += 1

        return AgentResult(
            success=True,
            data={"alerts": alerts_sent, "vetoes": vetoes_sent},
        )

    def _check_subnet_stress(self) -> dict:
        """
        Detect correlated stress across /24 subnets.

        Groups all devices by their /24 subnet prefix, counts how many
        have stress_events > 0, and returns only subnets where 3 or more
        devices are stressed — indicating a likely network-wide issue
        rather than an isolated device problem.

        Returns:
            Dict mapping subnet CIDR strings to lists of stressed IPs.
            Only subnets with >= 3 stressed devices are included.
        """
        subnet_stress = dict()
        for ip, tib in self.context.devices.items():
            # Skip devices with zero stress events — they're healthy
            if tib.state.stress_events == 0:
                continue
            # Extract the /24 subnet prefix from the IP
            parts = ip.split(".")
            if len(parts) != 4:
                continue  # Not a valid IPv4 address — skip
            subnet = ".".join(parts[:3]) + ".0/24"
            # Group stressed IPs by subnet
            if subnet not in subnet_stress:
                subnet_stress[subnet] = []
            subnet_stress[subnet].append(ip)

        # Only report subnets with 3+ stressed devices — a single stressed
        # device is likely a local issue, not a network-wide problem.
        return {
            s: ips for s, ips in subnet_stress.items()
            if len(ips) >= 3
        }
