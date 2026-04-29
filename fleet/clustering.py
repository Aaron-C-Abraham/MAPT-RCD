import uuid
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from TIB_and_PCF.TIB.device_TIB_manager import TIBManager
from utils.constants import FLEET_SIMILARITY_THRESHOLD, FLEET_MIN_CLUSTER_SIZE

logger = logging.getLogger(__name__)


@dataclass
class DeviceCluster:
    cluster_id: str
    member_ips: List[str]
    shared_signals: Dict[str, str]
    representative_ip: str = ""
    confidence: float = 0.0
    hypothesis: str = ""
    def to_dict(self) -> dict:
        """Serialize the cluster to a plain dictionary for JSON export or logging."""
        return {
            "cluster_id": self.cluster_id,
            "member_ips": self.member_ips,
            "shared_signals": self.shared_signals,
            "representative_ip": self.representative_ip,
            "confidence": self.confidence,
            "hypothesis": self.hypothesis,
        }


class FleetClusterer:
    """
    Clusters devices into families based on shared fingerprints.
    """

    def __init__(self, similarity_threshold: float = FLEET_SIMILARITY_THRESHOLD,
                 min_cluster_size: int = FLEET_MIN_CLUSTER_SIZE):
        self.similarity_threshold = similarity_threshold
        self.min_cluster_size = min_cluster_size

    def cluster(self, tibs: List[TIBManager]) -> List[DeviceCluster]:
        """
        Cluster devices into families.
        """
        if len(tibs) < self.min_cluster_size:
            return []

        # Step 1: Feature extraction 
        features = {tib.device_ip: self._extract_features(tib) for tib in tibs}

        # Collect the list of IPs (used later for iteration order).
        ips = list(features.keys())
        n = len(ips)

        # Step 2: Initialize agglomerative clustering 
        cluster_map = {ip: [ip] for ip in ips}

        # Step 3: Iterative merging loop 
        while len(cluster_map) > 1:
            best_sim = 0.0
            best_pair = None
            cluster_ids = list(cluster_map.keys())
            for i in range(len(cluster_ids)):
                for j in range(i + 1, len(cluster_ids)):
                    sim = self._cluster_similarity(
                        cluster_map[cluster_ids[i]],
                        cluster_map[cluster_ids[j]],
                        features,
                    )
                    # Keep track of the most similar pair found so far.
                    if sim > best_sim:
                        best_sim = sim
                        best_pair = (cluster_ids[i], cluster_ids[j])
            if best_sim < self.similarity_threshold or best_pair is None:
                break
            id_a, id_b = best_pair
            merged = cluster_map[id_a] + cluster_map[id_b]
            del cluster_map[id_a]
            del cluster_map[id_b]
            cluster_map[merged[0]] = merged

        # Step 4: Build DeviceCluster objects
        tib_map = {tib.device_ip: tib for tib in tibs}
        clusters = []

        for members in cluster_map.values():
            if len(members) < self.min_cluster_size:
                continue
            shared = self._find_shared_signals(
                [features[ip] for ip in members]
            )

            # Step 5: Select representative device 
            # The representative is the member with the most non-empty signal
            # values.
            rep_ip = max(
                members,
                key=lambda ip: sum(
                    1 for v in features[ip].values() if v is not None and v != ""
                ),
            )
            hypothesis = self._generate_hypothesis(shared, tib_map.get(rep_ip))
            cluster = DeviceCluster(
                cluster_id=f"cluster-{uuid.uuid4().hex[:8]}",
                member_ips=members,
                shared_signals=shared,
                representative_ip=rep_ip,
                confidence=self._cluster_confidence(members, features),
                hypothesis=hypothesis,
            )
            clusters.append(cluster)

        logger.info(
            f"[FleetClusterer] {len(tibs)} devices -> {len(clusters)} clusters"
        )
        return clusters

    def _extract_features(self, tib: TIBManager) -> dict:
        """Extract comparable features from a device's signals.
        """
        s = tib.signals
        return {
            "vendor": s.oui_vendor,
            "tier": tib.tier.name,
            "ttl": s.ttl+s.hops_for_ttl,
            "tcp_window": s.tcp_window_size,
            "tcp_options": tuple(sorted(s.tcp_options)) if s.tcp_options else None,
            "open_ports": tuple(sorted(s.open_ports)) if s.open_ports else None,
            "snmp_sysdescr": s.snmp_sysdescr[:50] if s.snmp_sysdescr else "",
            "mdns_services": tuple(sorted(s.mdns_services)) if s.mdns_services else None,
            "os_guess": s.nmap_os_guess,
            "dhcp_fingerprint": s.dhcp_fingerprint,
        }

    def similarity_score(self, a: dict, b: dict) -> float:
        """
        Compute similarity between two feature vectors.
        """
        # Per-feature weights — higher weight means the feature contributes
        # more to the overall similarity score.
        weights = {
            "vendor": 3.0,
            "tier": 2.0,
            "ttl": 1.0,
            "tcp_window": 2.0,
            "tcp_options": 2.0,
            "open_ports": 4.0,
            "snmp_sysdescr": 3.0,
            "mdns_services": 2.0,
            "os_guess": 3.0,
            "dhcp_fingerprint": 1.0,
        }

        total_weight = 0.0   
        match_weight = 0.0   

        for key, weight in weights.items():
            val_a = a.get(key)
            val_b = b.get(key)
            if (val_a is None or val_a == "") and (val_b is None or val_b == ""):
                continue
            total_weight += weight
            if val_a is None or val_b is None or val_a == "" or val_b == "":
                continue 
            if key == "open_ports" and val_a and val_b:
                # Jaccard similarity for port sets:
                # J(A,B) = |A intersection B| / |A union B|
                set_a = set(val_a) if isinstance(val_a, (list, tuple)) else set()
                set_b = set(val_b) if isinstance(val_b, (list, tuple)) else set()
                if set_a or set_b:
                    jaccard = len(set_a & set_b) / len(set_a | set_b)
                    match_weight += weight * jaccard
            elif key == "vendor":
                if val_a.lower() == val_b.lower():
                    match_weight += weight
                elif val_a.lower().split()[0] == val_b.lower().split()[0]:
                    match_weight += weight * 0.5
            elif key == "tcp_window":
                if val_a and val_b:
                    ratio = min(val_a, val_b) / max(val_a, val_b, 1)
                    match_weight += weight * ratio
            else:
                if val_a == val_b:
                    match_weight += weight
        if total_weight == 0:
            return 0.0
        return match_weight / total_weight

    def _cluster_similarity(self, members_a: List[str],members_b: List[str],features: Dict[str, dict]) -> float:
        """
        Average-link similarity between two clusters.
        """
        total_sim = 0.0
        count = 0
        for ip_a in members_a:
            for ip_b in members_b:
                total_sim += self.similarity_score(features[ip_a], features[ip_b])
                count += 1
        return total_sim / max(count, 1)

    def _find_shared_signals(self, feature_list: List[dict]) -> dict:
        """
        Find signals common to ALL members of a cluster.
        """
        if not feature_list:
            return {}

        shared = {}
        first = feature_list[0]
        for key, val in first.items():
            if val is None or val == "":
                continue
            if all(f.get(key) == val for f in feature_list[1:]):
                shared[key] = str(val)
        return shared

    def _cluster_confidence(self, members: List[str],
                            features: Dict[str, dict]) -> float:
        """
        Compute cluster confidence based on internal similarity.
        """
        if len(members) < 2:
            return 0.0
        total_sim = 0.0
        count = 0
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                total_sim += self.similarity_score(
                    features[members[i]], features[members[j]]
                )
                count += 1
        return total_sim / max(count, 1)

    def _generate_hypothesis(self, shared: dict, rep_tib: Optional[TIBManager]) -> str:

        parts = []
        if shared.get("vendor"):
            parts.append(f"Vendor: {shared['vendor']}")
        if shared.get("os_guess"):
            parts.append(f"OS: {shared['os_guess']}")
        if shared.get("tier"):
            parts.append(f"Tier: {shared['tier']}")
        if shared.get("open_ports"):
            parts.append(f"Ports: {shared['open_ports']}")

        if parts:
            return "All members share: " + ", ".join(parts)
        return "Cluster of similar devices"
