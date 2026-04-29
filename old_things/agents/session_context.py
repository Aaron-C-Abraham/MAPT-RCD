import time
import logging
from typing import Dict, List, Optional
from TIB_and_PCF.TIB.TIB_structures import DeviceTier, CircuitBreakerStatus
from TIB_and_PCF.PCF import PCFDAG,NodeType, EvidenceApproach                
from TIB_and_PCF.TIB.device_TIB_manager import TIBManager      
from TIB_and_PCF.TIB.device_classifier import OUIDatabase       
from IC_ToolSpec.registry import ToolSpecRegistry    
from ptg.graph import PTGGraph                     

logger = logging.getLogger(__name__)


class SessionContext:
    """
    Shared context for a PT engagement session.
    """

    def __init__(
        self,
        networks: List[str],              
        oui_db: Optional[OUIDatabase] = None,  
        passive_only: bool = False,       
        max_threads: int = 10,             
        output_dir: str = "",              
        exploit_all: bool = False,         
    ):
        self.networks = networks           
        self.oui_db = oui_db              
        self.passive_only = passive_only 
        self.max_threads = max_threads     
        self.output_dir = output_dir       
        self.exploit_all = exploit_all     
        self.start_time = time.time()   
        self.progress_cb = None            

        self.pcf_dag = PCFDAG()
        self.tool_registry = ToolSpecRegistry()
        from agents.base import MessageBus
        self.message_bus = MessageBus()
        self.devices: Dict[str, TIBManager] = {}
        self.ptg_graphs: Dict[str, PTGGraph] = {}
        self.fleet_clusters: Dict[str, dict] = {}

        self.session_root_id = self.pcf_dag.add_node(
            node_type=NodeType.SESSION,       
            phase="INIT",                     
            payload={
                "networks": networks,         
                "start_time": time.strftime("%Y-%m-%dT%H:%M:%S"), 
                "passive_only": passive_only,
            },
            evidence_approaches=EvidenceApproach.PASSIVE,
        )

        self.safety_officer_active = False
        self.ot_mode = False
        self.total_findings = 0       
        self.validated_findings = 0   
        self.instability_events = 0   
        self.vetoed_actions = 0       

    def progress(self, msg: str) -> None:
        """Emit a progress message if a callback is registered."""
        if self.progress_cb:
            self.progress_cb(msg)

    def register_device(self, ip: str, mac: str = "",
                        vendor: str = "Unknown",
                        discovery_method: str = "active",
                        pcf_parent_id: str = "") -> TIBManager:
        """
        Register a discovered device and create its TIBManager
        """
        if ip in self.devices:
            return self.devices[ip]
        parent_ids = [pcf_parent_id] if pcf_parent_id else [self.session_root_id]
        device_root_id = self.pcf_dag.add_node(
            node_type=NodeType.DISCOVERY,
            phase="HOST_DISCOVERY",
            payload={"ip": ip, "mac": mac, "vendor": vendor,
                     "method": discovery_method},
            parent_ids=parent_ids,
            evidence_approaches=EvidenceApproach.ACTIVE, 
            device_ip=ip,
        )

        tib = TIBManager(
            device_ip=ip,
            device_mac=mac,
            session_retier_callback=self._on_device_retier,  # Cross-device stress hook
            pcf_dag=self.pcf_dag,
            pcf_device_root_id=device_root_id,  
        )
        tib.signals.oui_vendor = vendor
        self.devices[ip] = tib
        logger.info(f"[SessionContext] Registered device {ip} ({mac}) vendor={vendor}")
        return tib

    def get_device(self, ip: str) -> Optional[TIBManager]:
        """Look up a device's TIBManager by IP. Returns None if not registered."""
        return self.devices.get(ip)

    def all_tibs(self) -> List[TIBManager]:
        """Return a list of all registered TIBManagers (all devices)."""
        return list(self.devices.values())

    def tibs_by_tier(self, tier: DeviceTier) -> List[TIBManager]:
        """
        Filter devices by their current tier classification.
        """
        return [t for t in self.devices.values() if t.tier == tier]
    def set_ptg(self, ip: str, graph: PTGGraph) -> None:
        """Store a Per-Target Graph (PTG) for a device. Called by PlannerAgent."""
        self.ptg_graphs[ip] = graph

    def get_ptg(self, ip: str) -> Optional[PTGGraph]:
        """Retrieve the PTG for a device. Returns None if no PTG was built."""
        return self.ptg_graphs.get(ip)

    _STRESS_THRESHOLD = 3     
    _STRESS_WINDOW_SEC = 60.0  
    _last_backoff_time = 0.0   

    def _on_device_retier(self, device_ip: str,old_tier: DeviceTier, new_tier: DeviceTier) -> None:
        """
        Cross-device stress correlation callback.
        """
        # Only care about tier upgrades (more restrictive = higher stress)
        if new_tier.value <= old_tier.value:
            return

        now = time.time()
        # Cooldown: don't trigger another backoff within 30 seconds
        if now - self._last_backoff_time < 30.0:
            return

        # Extract the /24 subnet prefix from the IP address
        parts = device_ip.split(".")
        if len(parts) != 4:
            return  # Not a valid IPv4 address — skip
        subnet = ".".join(parts[:3])  

        # Count how many devices on this subnet have experienced stress
        stressed = [
            ip for ip, tib in self.devices.items()
            if ip.startswith(subnet + ".") and tib.state.stress_events > 0
        ]

        # If enough devices are stressed, trigger subnet-wide rate reduction
        if len(stressed) >= self._STRESS_THRESHOLD:
            self.instability_events += 1  # Increment session-level metric
            logger.warning(
                f"[SessionContext] Subnet {subnet}.0/24 correlated stress: "
                f"{len(stressed)} devices"
            )
            # Iterate all devices on this subnet and reduce their rate limits
            for ip, tib in self.devices.items():
                if not ip.startswith(subnet + "."):
                    continue  # Skip devices on other subnets
                if tib.state.circuit_breaker_status != CircuitBreakerStatus.ACTIVE:
                    continue
                old_rate = tib.state.current_rate_limit
                # Floor: never go below 10% of the configured maximum rate
                min_rate = tib.config.max_packets_per_second * 0.10
                # Halve the current rate, but respect the floor
                tib.state.current_rate_limit = max(min_rate, old_rate * 0.5)
            # Record the time so we respect the 30-second cooldown
            self._last_backoff_time = now

    def get_session_metrics(self) -> dict:
        return {
            "duration_sec": round(time.time() - self.start_time, 1),
            "device_count": len(self.devices),
            "tier_summary": {
                tier.name: len(self.tibs_by_tier(tier))
                for tier in DeviceTier 
            },
            "total_findings": self.total_findings,
            "validated_findings": self.validated_findings,
            "instability_events": self.instability_events,
            "vetoed_actions": self.vetoed_actions,
            "ptg_graphs": len(self.ptg_graphs),
            "fleet_clusters": len(self.fleet_clusters),
            "pcf_nodes": self.pcf_dag.summary()["total_nodes"],
        }
