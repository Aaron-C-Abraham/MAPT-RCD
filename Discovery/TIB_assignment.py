import logging
from typing import List
from TIB_and_PCF.PCF import PCFDAG,NodeType,EvidenceApproach
from TIB_and_PCF.TIB.TIB_structures import DeviceTier
from TIB_and_PCF.TIB.device_TIB_manager import TIBManager
from TIB_and_PCF.TIB.device_classifier import CRITICAL_OT_PORTS

logger=logging.getLogger(__name__)

MIN_CONFINDENCE_THRESHOLD=0.2 

class TIBAssignentPhase:
    """
    Assigns TIB tiers and budget constraints to all devices after fingerprinting.
    Records tier assignments and any overrides in the PCF DAG.
    """
    def __init__(self,pcf_dag:PCFDAG):
        self.pcf_dag=pcf_dag
    def run(self,tib_managers:List[TIBManager])->None:
        """
        Classify every device and assign its TIB tier, then log a summary.
        """
        logger.info(f"Assigning TIBs to {len(tib_managers)} devices")
        for tib in tib_managers:
            self.assign_one(tib)
        counts={tier:0 for tier in DeviceTier}
        for tib in tib_managers:
            counts[tib.tier]+=1
        logger.info(f"Assignment summary - "+" | ".join(f"{t.name}:{counts[t]}" for t in DeviceTier if counts[t]>0))
    def assign_one(self,tib:TIBManager)->None:
        ip=tib.device_ip
        result=tib.classify_and_assign()
        if result.confidence<MIN_CONFINDENCE_THRESHOLD:
            logger.warning(
                f"[TIB Assignment] {ip} — low confidence ({result.confidence:.0%}), "
                f"forcing UNKNOWN tier. Collect more signals before scanning."
            )
            tib.apply_tier(DeviceTier.UNKNOWN,result)
            self.pcf_dag.add_node(
                node_type=NodeType.TIER_ID,
                phase="TIB_ASSIGNMENT",
                payload={
                    "ip":ip,
                    "event":"low_confidence_override",
                    "original_tier":result.tier.name,   
                    "forced_tier":"UNKNOWN",            
                    "confidence":result.confidence,
                    "reason":"Fewer than 2 reliable signals collected",
                },
                parent_ids=tib.pcf_signal_node_ids or [tib.pcf_device_root_id],
                evidence_approaches=EvidenceApproach.INFERRED,
                device_ip=ip
            )
        else:
            tib.pcf_tib_node_id = self.pcf_dag.add_node(
                node_type =NodeType.TIER_ID,
                phase="TIB_ASSIGNMENT",
                payload={
                    "ip":ip,
                    "tier":result.tier.name,          
                    "score":round(result.score, 2),   
                    "confidence":round(result.confidence, 2),  
                    "reasons":result.reasons,            
                    "overrides":result.override_signals,   
                    "budget":tib.config.max_budget_points,       
                    "max_rate":tib.config.max_packets_per_second,  
                },
                parent_ids=tib.pcf_signal_node_ids or [tib.pcf_device_root_id],
                evidence_approaches=EvidenceApproach.INFERRED,
                device_ip=ip,
            )
            self.industrial_port_safety_check(tib)
            logger.info(
            f"[TIB Assignment] {ip:16} → {tib.tier.name:8} "
            f"score={result.score:+.1f} "
            f"conf={result.confidence:.0%} "
            f"budget={tib.config.max_budget_points:.0f}pts "
            f"rate={tib.config.max_packets_per_second}pps"
        )
    def industrial_port_safety_check(self,tib:TIBManager)->None:
        """Force CRITICAL tier if the device has any true OT/SCADA ports open."""
        if tib.tier==DeviceTier.CRITICAL:
            return   

        for port in tib.signals.open_ports:
            if port in CRITICAL_OT_PORTS:
                logger.warning(
                    f"[TIB Assignment] SAFETY CHECK: {tib.device_ip} has OT port "
                    f"{port} ({CRITICAL_OT_PORTS[port]}) but tier={tib.tier.name}. "
                    f"Forcing CRITICAL."
                )
                tib.signals.update_open_ports(tib.signals.open_ports)
                self.pcf_dag.add_node(
                    node_type=NodeType.TIER_ID,
                    phase="TIB_ASSIGNMENT",
                    payload={
                        "ip":tib.device_ip,
                        "event":"industrial_port_safety_override",
                        "port":port,
                        "protocol":CRITICAL_OT_PORTS[port],
                        "forced_tier":"CRITICAL",
                    },
                    parent_ids=[tib.pcf_device_root_id],
                    evidence_approaches=EvidenceApproach.INFERRED,
                    device_ip=tib.device_ip,
                )
                break
