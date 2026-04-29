import logging
from agents.base import BaseAgent, AgentRole, AgentResult, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class TargetProfilingAgent(BaseAgent):
    """
    Agent responsible for fingerprinting and TIB tier assignment
    """

    def __init__(self, context: SessionContext):
        super().__init__(AgentRole.TARGET_PROFILING, context)

    def execute(self) -> AgentResult:
        from TIB_and_PCF.TIB.TIB_structures import PentestPhase
        from Discovery.fingerprinting import FingerprintingPhase
        from Discovery.TIB_assignment import TIBAssignentPhase

        # Get all registered devices — these were created by DiscoveryAgent
        all_tibs = self.context.all_tibs()
        if not all_tibs:
            # Cannot proceed without devices — early exit with failure
            return AgentResult(success=False, errors=["No devices to profile"])

        errors = []

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

        # Phase 3: TIB assignment
        # Run the classifier on each device's signals to determine its tier:
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

        #OT detection: activate Safety Officer if CRITICAL devices exist 
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
