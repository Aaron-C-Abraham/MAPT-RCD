"""
agents/target_profiling_agent.py — Target Profiling Agent (Phases 2-3).

PURPOSE:
    The Target Profiling Agent is the SECOND agent in the 9-step pipeline.
    It takes the raw device list from the DiscoveryAgent and performs:

      Phase 2 (Fingerprinting):
        Collects detailed signals from each device — TCP/IP stack behavior,
        banner grabbing, TTL analysis, TCP window sizes, etc. These signals
        populate the TIB's signal store.

      Phase 3 (TIB Assignment):
        Runs the TIB classifier on each device's signals to assign a tier:
          STANDARD  — General-purpose IT devices (full probing allowed).
          FRAGILE   — Devices sensitive to aggressive scanning.
          CRITICAL  — OT/industrial devices requiring maximum protection.
          UNKNOWN   — Insufficient data for classification.

INTER-AGENT COMMUNICATION:
    Receives:
        DiscoveryAgent ──RESULT──> TargetProfilingAgent
          (signals that devices are registered and ready for profiling)

    Sends:
        TargetProfilingAgent ──ALERT──>  SafetyOfficerAgent
          (when CRITICAL-tier OT devices are detected — activates OT mode)
        TargetProfilingAgent ──RESULT──> PlannerAgent
          (tier summary so the planner can build appropriate PTGs)
        TargetProfilingAgent ──RESULT──> FleetReasonerAgent
          (device count so fleet can attempt clustering)

OT DETECTION:
    If any device is classified as CRITICAL, this agent enables OT mode
    (context.ot_mode = True) and activates the SafetyOfficer
    (context.safety_officer_active = True). This is the trigger that makes
    the SafetyOfficer run at Step 5 of the pipeline.

"""

import logging
from agents.base import BaseAgent, AgentRole, AgentResult, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class TargetProfilingAgent(BaseAgent):
    """
    Agent responsible for fingerprinting and TIB tier assignment (Phases 2-3).

    After this agent runs, every device in the session has:
      - A populated signal store (open ports, banners, TTL, OS guesses, etc.)
      - A tier classification (STANDARD, FRAGILE, CRITICAL, or UNKNOWN)
      - Appropriate rate limits and budget constraints set by the TIB config
    """

    def __init__(self, context: SessionContext):
        # Register with the TARGET_PROFILING role for message bus addressing
        super().__init__(AgentRole.TARGET_PROFILING, context)

    def execute(self) -> AgentResult:
        """
        Run Phase 2 (fingerprinting) and Phase 3 (TIB assignment).

        FLOW:
            1. Retrieve all registered TIBs from the session context.
            2. Transition each device to FINGERPRINTING phase.
            3. Run the FingerprintingPhase module to collect signals.
            4. Transition each device to TIB_ASSIGNMENT phase.
            5. Run the TIBAssignmentPhase module to classify tiers.
            6. If CRITICAL devices found → enable OT mode + Safety Officer.
            7. Notify PlannerAgent and FleetReasonerAgent with tier summary.

        Returns:
            AgentResult with profiled count, tier summary, and any errors.
        """
        from TIB_and_PCF.TIB.TIB_structures import PentestPhase
        from Discovery.fingerprinting import FingerprintingPhase
        from Discovery.TIB_assignment import TIBAssignentPhase

        # Get all registered devices — these were created by DiscoveryAgent
        all_tibs = self.context.all_tibs()
        if not all_tibs:
            # Cannot proceed without devices — early exit with failure
            return AgentResult(success=False, errors=["No devices to profile"])

        errors = []

        # ── Phase 2: Fingerprinting ──────────────────────────────────────────
        # Collect detailed signals from each device: banner grabbing, TCP/IP
        # stack fingerprinting, TTL measurement, etc. These signals are stored
        # in each TIB's signal store and will feed the classifier in Phase 3.
        self.logger.info(f"Phase 2: Fingerprinting {len(all_tibs)} devices")
        try:
            # Advance all devices to the FINGERPRINTING phase in their state machine
            for tib in all_tibs:
                tib.transition_phase(PentestPhase.FINGERPRINTING)

            # Run the fingerprinting module. It operates on all TIBs in parallel
            # (up to max_threads), enriching each TIB's signals with probe data.
            phase2 = FingerprintingPhase(
                pcf_dag=self.context.pcf_dag,
                max_threads=self.context.max_threads,
            )
            phase2._progress_cb = self.context.progress_cb
            phase2.run(all_tibs)
        except Exception as e:
            errors.append(f"Phase 2 error: {e}")

        # ── Phase 3: TIB assignment ──────────────────────────────────────────
        # Run the classifier on each device's signals to determine its tier:
        #   STANDARD  — normal IT devices, full scanning allowed
        #   FRAGILE   — sensitive devices, reduced scanning intensity
        #   CRITICAL  — OT/industrial, maximum protection, safety gating
        #   UNKNOWN   — not enough data to classify
        self.logger.info("Phase 3: TIB assignment")
        try:
            # Advance all devices to the TIB_ASSIGNMENT phase
            for tib in all_tibs:
                tib.transition_phase(PentestPhase.TIB_ASSIGNMENT)

            # Run the classifier — this sets tib.tier for each device and
            # adjusts rate limits and budget constraints based on tier.
            phase3 = TIBAssignentPhase(pcf_dag=self.context.pcf_dag)
            phase3.run(all_tibs)
        except Exception as e:
            errors.append(f"Phase 3 error: {e}")

        # ── OT detection: activate Safety Officer if CRITICAL devices exist ──
        # CRITICAL tier indicates industrial/OT devices (e.g., PLCs, SCADA
        # controllers) that could cause physical damage if probed aggressively.
        from TIB_and_PCF.TIB.TIB_structures import DeviceTier
        critical_count = len(self.context.tibs_by_tier(DeviceTier.CRITICAL))
        if critical_count > 0:
            # Enable OT mode — this flag affects safety constraints globally
            self.context.ot_mode = True
            # Activate the Safety Officer — the Coordinator will run it at Step 5
            self.context.safety_officer_active = True
            # Send an ALERT to the Safety Officer so it knows about the OT devices
            self.send_message(
                AgentRole.SAFETY_OFFICER, MessageType.ALERT,
                {"alert_type": "ot_devices_detected",
                 "critical_count": critical_count},
            )

        # ── Notify downstream agents ────────────────────────────────────────
        # Build a tier summary dict: {"STANDARD": 5, "FRAGILE": 2, "CRITICAL": 1, ...}
        tier_summary = {
            tier.name: len(self.context.tibs_by_tier(tier))
            for tier in DeviceTier
        }

        # Notify PlannerAgent — it needs the tier summary to decide how
        # aggressive each device's PTG should be.
        self.send_message(
            AgentRole.PLANNER, MessageType.RESULT,
            {"phase": "profiling", "tier_summary": tier_summary,
             "device_count": len(all_tibs)},
        )

        # Notify FleetReasonerAgent — it needs to know how many devices
        # exist so it can attempt fleet clustering.
        self.send_message(
            AgentRole.FLEET_REASONER, MessageType.RESULT,
            {"phase": "profiling", "device_count": len(all_tibs)},
        )

        return AgentResult(
            success=True,
            data={"profiled": len(all_tibs), "tier_summary": tier_summary},
            errors=errors,
        )
