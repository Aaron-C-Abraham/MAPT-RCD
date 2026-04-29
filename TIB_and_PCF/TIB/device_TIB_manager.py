import time
import logging
from dataclasses import dataclass,field
from typing import Optional,Callable
from TIB_and_PCF.TIB.TIB_structures import (
    DeviceTier,PentestPhase,TIBConfig,CircuitBreakerStatus,
    TIBState,ExploitIntensity,TIER_TIB_DEFAULTS
)
from TIB_and_PCF.TIB.circuit_breaker import CircuitBreaker,TIBViolation
from TIB_and_PCF.TIB.device_classifier import DeviceClassifier,DeviceSignals,ClassificationResult
from TIB_and_PCF.PCF import PCFDAG,NodeType,EvidenceApproach

logger=logging.getLogger(__name__)

@dataclass
class TIBEvent:
    """
    Single event in the TIB event log. Records tier changes, phase
    transitions, exploit approvals/blocks, and reclassification triggers.
    """
    timestamp:float
    event_type:str
    phase:PentestPhase
    message:str
    details:dict=field(default_factory=dict)

    def __str__(self):
        ts=time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] [{self.event_type}] {self.message}"
    
class TIBManager:
    """
    Manages the full TIB lifecycle for a single device: classification,
    tier assignment, phase transitions, signal-driven reclassification,
    circuit breaker integration, and PCF DAG evidence recording.
    """
    def __init__(
        self,
        device_ip:str,
        device_mac:str,
        tib_overrides:Optional[TIBConfig]=None,
        session_retier_callback:Optional[Callable]=None,
        pcf_dag: Optional[PCFDAG]=None,
        pcf_device_root_id:str="",
    ):
        self.device_ip=device_ip
        self.device_mac=device_mac
        self.tib_overrides=tib_overrides

        self.session_retier_callback=session_retier_callback
        self.pcf_dag:Optional[PCFDAG]=pcf_dag
        self.pcf_device_root_id:str=pcf_device_root_id
        self.pcf_signal_node_ids:list=[]
        self.pcf_tib_node_id:str=""
        self.signals=DeviceSignals(ip=device_ip,mac=device_mac)
        self.signals.register_callback(self.on_signals_changed)
        self.tier=DeviceTier.UNKNOWN
        self.config=TIER_TIB_DEFAULTS[DeviceTier.UNKNOWN]
        self.state=TIBState()
        self.breaker=CircuitBreaker(device_ip,self.config,self.state)

        self.classification_history:list[ClassificationResult]=[]
        self.event_log:list[TIBEvent]=[]
        self.classifier=DeviceClassifier()
        self.current_phase=PentestPhase.PASSIVE_LISTENING
        self.reclassifying=False

        self.log_event(
            "TIB_CREATED",
            f"Device {device_ip} ({device_mac}) registered",
            {"initial_tier":"UNKNOWN"}
        )
    def on_signals_changed(self,field_name:str,new_value)->None:
        """
        Callback invoked when any signal update function is called.
        Records the signal change in the PCF DAG and triggers automatic
        reclassification (unless in an active scanning phase where mid-scan
        tier changes would be disruptive).
        """
        if self.reclassifying:
            return
        from TIB_and_PCF.TIB.TIB_structures import PentestPhase
        no_reclass_phases = (PentestPhase.PORT_SCAN, PentestPhase.SERVICE_PROBE,
                             PentestPhase.OS_IDENTIFICATION, PentestPhase.EXPLOITATION)
        if self.current_phase in no_reclass_phases:
            return
        
        if field_name=='icmp_rtt_samples':
            for rtt in new_value:
                self.breaker.record_rtt(rtt)
            return
        
        if self.pcf_dag and self.pcf_device_root_id:
            evidence_source=(
                EvidenceApproach.PASSIVE if field_name in ("mdns_services","dhcp_fingerprint","netbios_present")
                else EvidenceApproach.ACTIVE
            )
            node_id=self.pcf_dag.add_node(
                node_type=NodeType.PROBE,
                phase=self.current_phase.name,
                payload = {"field":field_name,"value":str(new_value)[:200]},
                parent_ids=[self.pcf_device_root_id],
                evidence_approaches=evidence_source,
                device_ip=self.device_ip,
            )
            self.pcf_signal_node_ids.append(node_id)
        self.log_event(
            "AUTO_RECLASSIFY_TRIGGERED",
            f"Signal '{field_name}' updated — triggering automatic reclassification",
            {"field":field_name,"value_preview":str(new_value)[:100]},
        )
        self.reclassify(trigger_reason=f"Signal '{field_name}' updated automatically")

    def classify_and_assign(self)->ClassificationResult:
        """
        Run the classifier on current signals and assign the initial TIB tier.
        Updates config, rebuilds the circuit breaker, and logs the assignment.
        """
        result=self.classifier.classify(self.signals)
        old_tier=self.tier
        self.apply_tier(result.tier,result)
        self.log_event(
            "TIER_ASSIGNED",
            f"Tier: {old_tier.name} -> {result.tier.name} "
            f"(score={result.score:.1f}, confidence={result.confidence:.0%})",
            {"old_tier": old_tier.name, "new_tier": result.tier.name,
             "score": result.score, "confidence": result.confidence,
             "reasons": result.reasons},
        )
        return result
    def reclassify(self,trigger_reason:str="")->Optional[ClassificationResult]:
        """
        Re-run classification to check if the tier has changed. If the tier
        becomes more fragile mid-session (during active scanning), trips the
        circuit breaker to halt further probing on this device.
        """
        if self.reclassifying:
            return None
        self.reclassifying=True
        try:
            result=self.classifier.classify(self.signals)
            old_tier=self.tier
            if result.tier==old_tier:
                self.log_event(
                    "RECLASSIFY_NO_CHANGE",
                    f"Reclassification ({trigger_reason}) — tier unchanged ({old_tier.name})",
                )
                return 
            self.apply_tier(result.tier,result)
            became_more_fragile=result.tier.value>old_tier.value
            self.log_event(
                "RETIER",
                f"RETIER ({trigger_reason}): {old_tier.name} -> {result.tier.name} "
                f"({'MORE fragile' if became_more_fragile else 'less fragile'})",
                {"trigger": trigger_reason, "old": old_tier.name,
                 "new": result.tier.name, "more_fragile": became_more_fragile,
                 "reasons": result.reasons},
            )
            if self.session_retier_callback:
                self.session_retier_callback(self.device_ip,old_tier,result.tier)
            if became_more_fragile and self.current_phase.value>=PentestPhase.PORT_SCAN.value:
                logger.warning(
                    f"[{self.device_ip}] Re-tiered {old_tier.name}->{result.tier.name} "
                    f"mid-session. Tripping breaker. Trigger: {trigger_reason}"
                )
                self.breaker.state.circuit_breaker_status=CircuitBreakerStatus.TRIPPED
                self.breaker.state.trip_reason=(
                    f"[{self.device_ip}] Re-tiered {old_tier.name}->{result.tier.name} "
                    f"mid-session. Tripping breaker. Trigger: {trigger_reason}"
                )
                return result
        finally:
            self.reclassifying=False
        

    def transition_phase(self,new_phase:PentestPhase)->None:
        """
        Transition the device to the next pentest phase and log the event.
        """
        old_phase=self.current_phase
        self.current_phase=new_phase
        self.state.current_phase=new_phase
        self.state.phase_history.append({"phase": new_phase.name, "timestamp": time.time()})
        self.log_event("PHASE_TRANSITION", f"{old_phase.name} -> {new_phase.name}")

    def attempt_exploit(self,exploit_name:str,intensity:ExploitIntensity)->bool:
        try:
            self.breaker.request_exploit_permission(exploit_name,intensity)
            self.log_event("EXPLOIT_APPROVED", f"'{exploit_name}'")
            return True
        except TIBViolation as e:
            self.log_event("EXPLOIT_BLOCKED", f"'{exploit_name}' blocked: {e}")
            return False
    def get_summary(self)->dict:
        """
        Generate a comprehensive summary dict for this device's TIB.
        """
        rtt_stats = self.breaker.get_rtt_stats()
        budget_stats = self.breaker.get_budget_stats()  
        return {
            "ip": self.device_ip,
            "mac": self.device_mac,
            "vendor": self.signals.oui_vendor,
            "hostname": self.signals.reverse_dns,
            "device_name": self.signals.mdns_device_name or self.signals.reverse_dns or "",
            "device_type": self.signals.device_type or "",
            "current_tier": self.tier.name,
            "current_phase": self.current_phase.name,
            "circuit_breaker": self.state.circuit_breaker_status.value,
            "trip_reason": self.state.trip_reason,
            "budget": budget_stats,                          
            "live_rate_limit": self.state.current_rate_limit,
            "config_rate_max": self.config.max_packets_per_second,
            "findings": {
                "open_ports": list(self.signals.open_ports) or self.state.open_ports_found,
                "os_hint": getattr(self.signals, 'nmap_os_guess', '') or "Unknown",
                "vulnerabilities": getattr(self.state, 'vuln_findings', []),
                "banners": dict(self.signals.banners),
            },
            "rtt_stats": rtt_stats,
            "stress_events": self.state.stress_events,
            "classification_history": [
                {"tier": r.tier.name, "score": r.score,
                 "confidence": r.confidence, "reasons": r.reasons}
                for r in self.classification_history
            ],
            "event_log": [str(e) for e in self.event_log],
        }
    # Private helpers
    def apply_tier(self,tier:DeviceTier,result:ClassificationResult)->None:
        """
        Apply a new tier: update config to tier defaults, rebuild the circuit
        breaker with the new config while preserving the existing runtime state.
        """
        self.tier=tier
        self.config=self.tib_overrides or TIER_TIB_DEFAULTS[tier]
        self.breaker=CircuitBreaker(self.device_ip,self.config,self.state)
        self.classification_history.append(result)
    def log_event(self,event_type:str,message:str,details:dict=None):
        event = TIBEvent(
            timestamp=time.time(),
            event_type=event_type,
            phase=self.current_phase,
            message=message,
            details=details or {},
        )
        self.event_log.append(event)
        logger.info(f"[{self.device_ip}] {event}")
        
    
    
