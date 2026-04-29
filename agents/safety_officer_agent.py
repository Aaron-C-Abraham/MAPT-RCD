"""
agents/safety_officer_agent.py — Safety Officer Agent (OT Mode).

PURPOSE:
    The Safety Officer Agent is the FIFTH agent in the 9-step pipeline
    (Step 5), but it ONLY runs when OT (Operational Technology) devices
    are detected (context.safety_officer_active == True).

    It is the GATEKEEPER for all actions on sensitive devices. Before the
    ToolOrchestrator executes any PTG nodes, the Safety Officer reviews
    every pending node and either APPROVES or VETOES it based on a strict
    set of safety rules.

SAFETY GATING RULES:
    1. CRITICAL devices + Tier 3 actions → ALWAYS VETOED.
       Tier 3 actions (e.g., aggressive exploitation) are never allowed on
       CRITICAL-tier devices (PLCs, SCADA controllers, etc.) because they
       could cause physical damage or process disruption.

    2. CRITICAL devices + Tier 2 actions → REQUIRES PREFLIGHT CHECK.
       Tier 2 actions (e.g., service probing, moderate scanning) on CRITICAL
       devices must pass a preflight validation:
         - Circuit breaker is ACTIVE (not stressed)
         - Budget has >30% remaining
         - No more than 2 stress events
         - RTT ratio is within 80% of the pause threshold

    3. FRAGILE devices + Exploitation → VETOED for Tier 2+.
       Exploitation actions on FRAGILE devices are blocked if they are
       risk tier 2 or higher.

    4. Industrial protocol probes (Modbus, S7) → VETOED if device is stressed.
       Even on non-CRITICAL devices, industrial protocol probes are blocked
       if the device is showing stress signals.

VETO MECHANISM:
    When the Safety Officer vetoes an action, it:
      1. Marks the PTG node as SKIPPED with a safety reason.
      2. Sends a VETO message to the ToolOrchestrator.
      3. Increments context.vetoed_actions.
    The ToolOrchestrator checks for vetoes before executing each device.

INTER-AGENT COMMUNICATION:
    Receives:
        TargetProfilingAgent ──ALERT──> SafetyOfficerAgent
          (OT devices detected — activates this agent)

    Sends:
        SafetyOfficerAgent ──VETO──> ToolOrchestratorAgent
          (blocks unsafe actions on CRITICAL devices)

    Also records a SAFETY_REVIEW session event in the PCF DAG.

Special agent for OT/industrial environments. Has veto power over
any tool invocation on CRITICAL-tier devices. Enforces risk tier
gating and preflight requirements.

Paper reference: Section V-B (Safety Baseline for OT), Section VI-B item 7
"""

import logging
from agents.base import BaseAgent, AgentRole, AgentResult, AgentMessage, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class SafetyOfficerAgent(BaseAgent):
    """
    Agent responsible for OT safety enforcement.

    Reviews all pending PTG nodes across all devices and vetoes any action
    that violates the safety gating rules for CRITICAL and FRAGILE devices.
    Also enforces industrial protocol safety and generates a compliance report.
    """

    def __init__(self, context: SessionContext):
        # Register with the SAFETY_OFFICER role for message bus addressing
        super().__init__(AgentRole.SAFETY_OFFICER, context)
        # Track vetoed actions for the compliance report
        self._vetoed_actions = []
        # Track approved actions for the compliance report
        self._approved_actions = []

    def execute(self) -> AgentResult:
        """
        Review all pending actions for OT safety compliance.
        Enforce risk tier gating. Veto unsafe actions.

        FLOW:
            For each device with a PTG:
              For each PENDING or READY node:
                1. CRITICAL + Tier 3 → veto and skip.
                2. CRITICAL + Tier 2 → run preflight; skip if fail.
                3. FRAGILE + Exploitation + Tier 2+ → veto and skip.
                4. Industrial probes on stressed devices → veto and skip.
                5. Everything else → approve.
            Record the safety review summary in the PCF DAG.

        Returns:
            AgentResult with vetoes, approvals, and preflight_blocks counts.
        """
        from TIB_and_PCF.TIB.TIB_structures import DeviceTier
        from ptg.models import RiskTier, PTGNodeStatus
        from TIB_and_PCF.PCF import NodeType, EvidenceApproach

        vetoes = 0            # Counter for vetoed actions
        approvals = 0         # Counter for approved actions
        preflight_blocks = 0  # Counter for Tier 2 actions blocked by preflight

        # ── Review all devices and their PTG nodes ───────────────────────────
        for ip, tib in self.context.devices.items():
            graph = self.context.get_ptg(ip)
            if not graph:
                continue  # No PTG for this device — nothing to review

            # Iterate over ALL nodes in the PTG (not just ready ones) so we
            # can pre-emptively block nodes before they become ready.
            for node in graph.get_all_nodes():
                # Only review nodes that haven't been executed yet
                if node.status not in (PTGNodeStatus.PENDING, PTGNodeStatus.READY):
                    continue

                # ── Safety gate: CRITICAL devices ────────────────────────────
                if tib.tier == DeviceTier.CRITICAL:

                    # RULE 1: Block ALL Tier 3 (high-risk) actions on CRITICAL
                    # devices. Tier 3 includes aggressive exploitation,
                    # brute-force attacks, and destructive scans that could
                    # crash an industrial controller.
                    if node.risk_tier == RiskTier.TIER_3:
                        graph.mark_skipped(
                            node.node_id,
                            "Safety Officer: Tier 3 action blocked on CRITICAL device"
                        )
                        # Send a VETO message to ToolOrchestrator
                        self.send_veto(
                            AgentRole.TOOL_ORCHESTRATOR,
                            f"Blocked Tier 3 action '{node.name}' on CRITICAL device {ip}",
                        )
                        vetoes += 1
                        # Record for the compliance report
                        self._vetoed_actions.append({
                            "ip": ip, "node": node.name,
                            "reason": "CRITICAL + Tier 3"
                        })
                        self.context.vetoed_actions += 1
                        continue  # Move to the next node

                    # RULE 2: Tier 2 (moderate-risk) actions on CRITICAL devices
                    # require a preflight safety check before they are allowed.
                    if node.risk_tier == RiskTier.TIER_2:
                        preflight_ok = self._preflight_check(ip, tib, node)
                        if not preflight_ok:
                            # Preflight failed — skip this node (but don't send
                            # a VETO message since this is a softer block)
                            graph.mark_skipped(
                                node.node_id,
                                "Safety Officer: Preflight check failed"
                            )
                            preflight_blocks += 1
                            continue

                # ── Safety gate: FRAGILE devices with exploitation ───────────
                # RULE 3: Block exploitation on FRAGILE devices if the risk
                # tier is 2 or higher. FRAGILE devices can handle basic
                # scanning but not aggressive exploitation.
                if (tib.tier == DeviceTier.FRAGILE
                        and node.phase == "EXPLOITATION"):
                    if node.risk_tier.value >= RiskTier.TIER_2.value:
                        graph.mark_skipped(
                            node.node_id,
                            "Safety Officer: Exploitation blocked on FRAGILE device"
                        )
                        vetoes += 1
                        self.context.vetoed_actions += 1
                        continue

                # ── Safety gate: Industrial protocol probes ──────────────────
                # RULE 4: Block Modbus/S7 industrial protocol probes on any
                # device that is currently showing stress signals. Even on
                # non-CRITICAL devices, industrial protocols can cause process
                # disruption if the device is already struggling.
                if node.tool_id in ("modbus_identify", "s7_identify"):
                    if tib.state.stress_events > 0:
                        graph.mark_skipped(
                            node.node_id,
                            "Safety Officer: Industrial probe blocked — device under stress"
                        )
                        vetoes += 1
                        self.context.vetoed_actions += 1
                        continue

                # ── Action approved ──────────────────────────────────────────
                # If none of the safety gates triggered, the action is approved.
                approvals += 1
                self._approved_actions.append({"ip": ip, "node": node.name})

        # ── Record safety review in PCF DAG ──────────────────────────────────
        # Create a SESSION_EVENT node summarizing the safety review. This
        # provides evidence that safety checks were performed and what the
        # outcomes were.
        self.context.pcf_dag.add_node(
            node_type=NodeType.SESSION_EVENT,
            phase="SAFETY_REVIEW",
            payload={
                "vetoes": vetoes,
                "approvals": approvals,
                "preflight_blocks": preflight_blocks,
                "ot_mode": self.context.ot_mode,
            },
            parent_ids=[self.context.session_root_id],  # Hangs off session root
            evidence_approaches=EvidenceApproach.INFERRED,  # Safety review is an inference
        )

        return AgentResult(
            success=True,
            data={
                "vetoes": vetoes,
                "approvals": approvals,
                "preflight_blocks": preflight_blocks,
            },
        )

    def _preflight_check(self, ip: str, tib, node) -> bool:
        """
        Preflight validation for Tier 2+ actions on CRITICAL devices.

        This is a multi-criteria safety check that verifies the device is
        in a healthy enough state to tolerate a moderate-risk action.

        Checks (ALL must pass):
        1. Circuit breaker is ACTIVE (not stressed, tripped, or exhausted).
        2. Budget has >30% remaining (enough headroom for the action).
        3. No more than 2 stress events (limited stress history).
        4. RTT ratio is within 80% of the configured pause threshold
           (device is responding within acceptable latency).

        Args:
            ip   — Device IP address (for logging).
            tib  — The device's TIBManager.
            node — The PTG node being checked (unused but available for
                    future per-node preflight logic).

        Returns:
            True if all checks pass, False if any check fails.
        """
        from TIB_and_PCF.TIB.TIB_structures import CircuitBreakerStatus

        # CHECK 1: Circuit breaker must be in ACTIVE state.
        # PAUSED, TRIPPED, or EXHAUSTED all indicate the device is not healthy.
        if tib.state.circuit_breaker_status != CircuitBreakerStatus.ACTIVE:
            self.logger.warning(
                f"[{ip}] Preflight FAIL: breaker {tib.state.circuit_breaker_status.value}"
            )
            return False

        # CHECK 2: Budget must have >30% remaining.
        # Running a Tier 2 action with little budget left risks exhaustion
        # mid-probe, which could leave the device in an inconsistent state.
        if tib.config.max_budget_points > 0:
            pct_remaining = (
                (tib.config.max_budget_points - tib.state.budget_spent)
                / tib.config.max_budget_points * 100
            )
            if pct_remaining < 30:
                self.logger.warning(
                    f"[{ip}] Preflight FAIL: only {pct_remaining:.0f}% budget remaining"
                )
                return False

        # CHECK 3: No more than 2 stress events.
        # A device with 3+ stress events has a pattern of instability
        # and should not be subjected to more moderate-risk actions.
        if tib.state.stress_events > 2:
            self.logger.warning(
                f"[{ip}] Preflight FAIL: {tib.state.stress_events} stress events"
            )
            return False

        # CHECK 4: RTT must be within 80% of the pause threshold.
        # If the device's RTT is already close to the pause threshold,
        # a Tier 2 action could push it over the edge.
        if tib.state.baseline_rtt_ms and tib.state.current_rtt_ms:
            ratio = tib.state.current_rtt_ms / tib.state.baseline_rtt_ms
            # Multiply by 0.8 to give a 20% safety margin below the threshold
            if ratio > tib.config.rtt_pause_multiplier * 0.8:
                self.logger.warning(
                    f"[{ip}] Preflight FAIL: RTT ratio {ratio:.2f}"
                )
                return False

        # All checks passed — the device is healthy enough for this action
        return True

    def get_compliance_report(self) -> dict:
        """
        Generate a safety compliance report.

        Summarizes the Safety Officer's actions during the session:
          - How many actions were vetoed vs. approved.
          - Details of each vetoed action (IP, node name, reason).
          - Whether OT mode was active.
          - Compliance rate (approved / total * 100).

        This report is included in the final session results by the
        Coordinator and can be used for audit/regulatory compliance.

        Returns:
            Dict with total_vetoed, total_approved, vetoed_actions list,
            ot_mode flag, and compliance_rate percentage.
        """
        return {
            "total_vetoed": len(self._vetoed_actions),
            "total_approved": len(self._approved_actions),
            "vetoed_actions": self._vetoed_actions,
            "ot_mode": self.context.ot_mode,
            # Compliance rate: what fraction of reviewed actions were approved.
            # Uses max(…, 1) to avoid division by zero when no actions exist.
            "compliance_rate": (
                len(self._approved_actions) /
                max(len(self._approved_actions) + len(self._vetoed_actions), 1)
                * 100
            ),
        }
