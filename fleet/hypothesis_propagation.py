import logging
from dataclasses import dataclass
from typing import List, Optional

from TIB_and_PCF.TIB.device_TIB_manager import TIBManager

logger = logging.getLogger(__name__)


@dataclass
class PropagatedHypothesis:
    field_name: str
    value: object
    confidence: float
    source_ip: str
    description: str
    requires_confirmation: bool = True


class HypothesisPropagator:
    """
    Propagates findings from a representative device to cluster members
    """
    HIGH_CONFIDENCE_FIELDS = {
        "oui_vendor": 0.95,
        "tier": 0.90,
        "os_guess": 0.80,
        "dhcp_fingerprint": 0.85,
    }
    MEDIUM_CONFIDENCE_FIELDS = {
        "open_ports": 0.60,
        "banners": 0.50,
        "snmp_sysdescr": 0.70,
        "tcp_window_size": 0.75,
        "tcp_options": 0.75,
        "mdns_services": 0.65,
    }

    def propagate(self, source_tib: TIBManager,target_tib: TIBManager,cluster=None) -> List[PropagatedHypothesis]:
        """
        Generate hypotheses to propagate from source to target device.
        """
        hypotheses = []
        for field, base_conf in self.HIGH_CONFIDENCE_FIELDS.items():
            hyp = self._try_propagate(source_tib, target_tib, field,
                                      base_conf, requires_confirmation=False)
            if hyp:
                hypotheses.append(hyp)
        for field, base_conf in self.MEDIUM_CONFIDENCE_FIELDS.items():
            hyp = self._try_propagate(source_tib, target_tib, field,
                                      base_conf, requires_confirmation=True)
            if hyp:
                hypotheses.append(hyp)

        # Cluster-confidence scaling 
        # If the cluster object is available, scale each hypothesis's confidence by the cluster's internal similarity score.
        if cluster and hasattr(cluster, "confidence"):
            for hyp in hypotheses:
                hyp.confidence *= cluster.confidence

        logger.info(
            f"[FleetPropagation] {source_tib.device_ip} -> {target_tib.device_ip}: "
            f"{len(hypotheses)} hypotheses"
        )
        return hypotheses

    def _try_propagate(self, source: TIBManager, target: TIBManager,field: str, base_confidence: float,requires_confirmation: bool) -> Optional[PropagatedHypothesis]:
        """
        Try to propagate a single field from source to target.
        """
        source_val = self._get_field(source, field)
        target_val = self._get_field(target, field)
        if source_val is None or source_val == "" or source_val == []:
            return None
        if target_val is not None and target_val != "" and target_val != []:
            return None
        return PropagatedHypothesis(
            field_name=field,
            value=source_val,
            confidence=base_confidence,
            source_ip=source.device_ip,
            description=f"Propagated {field}={str(source_val)[:80]} from cluster representative",
            requires_confirmation=requires_confirmation,
        )

    def _get_field(self, tib: TIBManager, field: str) -> object:
        """
        Get a field value from a TIBManager.
        """
        if field == "tier":
            return tib.tier.name
        elif field == "os_guess":
            return tib.signals.nmap_os_guess
        elif field == "oui_vendor":
            return tib.signals.oui_vendor if tib.signals.oui_vendor != "Unknown" else None
        elif field == "open_ports":
            return tib.signals.open_ports or None
        elif field == "banners":
            return tib.signals.banners or None
        elif field == "snmp_sysdescr":
            return tib.signals.snmp_sysdescr or None
        elif field == "tcp_window_size":
            return tib.signals.tcp_window_size
        elif field == "tcp_options":
            return tib.signals.tcp_options or None
        elif field == "mdns_services":
            return tib.signals.mdns_services or None
        elif field == "dhcp_fingerprint":
            return tib.signals.dhcp_fingerprint or None
        return None

    def apply_hypothesis(self, target_tib: TIBManager, hyp: PropagatedHypothesis) -> None:
        """
        Apply a propagated hypothesis to a target device.
        """
        field = hyp.field_name
        if field == "oui_vendor" and isinstance(hyp.value, str):
            target_tib.signals.update_oui_vendor(hyp.value)
        elif field == "open_ports" and isinstance(hyp.value, (list, tuple)):
            target_tib.signals.update_open_ports(list(hyp.value))
        elif field == "banners" and isinstance(hyp.value, dict):
            target_tib.signals.update_banners(hyp.value)
        elif field == "snmp_sysdescr" and isinstance(hyp.value, str):
            target_tib.signals.update_snmp_sysdescr(hyp.value)
        elif field == "tcp_window_size" and isinstance(hyp.value, int):
            target_tib.signals.update_tcp_window_size(hyp.value)
        elif field == "tcp_options" and isinstance(hyp.value, (list, tuple)):
            target_tib.signals.update_tcp_options(list(hyp.value))
        elif field == "mdns_services" and isinstance(hyp.value, (list, tuple)):
            target_tib.signals.update_mdns_services(list(hyp.value))
        elif field == "dhcp_fingerprint" and isinstance(hyp.value, str):
            target_tib.signals.update_dhcp_fingerprint(hyp.value)
        elif field == "os_guess" and isinstance(hyp.value, str):
            target_tib.signals.update_nmap_os_guess(hyp.value)

        logger.debug(
            f"[FleetPropagation] Applied {field}={str(hyp.value)[:50]} "
            f"to {target_tib.device_ip}"
        )

    #Confirmation of a propagated hypothesis                             
    def confirm_hypothesis(self, hyp: PropagatedHypothesis, target_tib: TIBManager) -> bool:
        """
        Confirm a propagated hypothesis with minimal probing.
        """
        actual = self._get_field(target_tib, hyp.field_name)
        if actual is None:
            return False
        if hyp.field_name == "open_ports":
            if isinstance(actual, (list, tuple)) and isinstance(hyp.value, (list, tuple)):
                actual_set = set(actual)
                hyp_set = set(hyp.value)
                if hyp_set and actual_set:
                    overlap = len(actual_set & hyp_set) / len(hyp_set)
                    return overlap >= 0.7
            return False
        return str(actual) == str(hyp.value)
