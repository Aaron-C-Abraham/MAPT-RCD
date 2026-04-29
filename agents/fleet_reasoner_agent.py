"""
agents/fleet_reasoner_agent.py — Fleet Reasoner Agent.

PURPOSE:
    The Fleet Reasoner Agent is the THIRD agent in the 9-step pipeline
    (Step 3). It optimizes probing across large device populations by:

      1. CLUSTERING: Groups devices into "fleet families" based on shared
         signals (same vendor, same open ports, same OS, similar TTL, etc.).
         Each cluster has a "representative" device that will be fully probed.

      2. HYPOTHESIS PROPAGATION: After the representative device is fully
         probed, its findings (vulnerabilities, OS details, service versions)
         are PROPAGATED to all other members of the same cluster. This avoids
         redundant probing of identical devices.

    Example: If a network has 50 identical Siemens PLCs, only the
    representative PLC is fully scanned. The other 49 receive the same
    findings via hypothesis propagation, reducing probing by ~98%.

INTER-AGENT COMMUNICATION:
    Receives:
        TargetProfilingAgent ──RESULT──> FleetReasonerAgent
          (device count — signals that profiling is complete and clustering
           can begin)

    Sends:
        FleetReasonerAgent ──RESULT──> PlannerAgent
          (cluster count and propagated hypotheses — so the planner can
           build minimal PTGs for non-representative devices)

FLEET OPTIMIZATION IMPACT:
    The Planner checks context.fleet_clusters when building PTGs. If a
    device is a non-representative cluster member, its PTG is pruned:
    exploitation and deep port scan nodes are skipped. This is the
    primary mechanism for probe reduction in fleet environments.

PCF EVIDENCE:
    Propagated hypotheses are recorded in the PCF DAG as FLEET_INFERENCE
    nodes with EvidenceApproach.INFERRED, making it clear that these findings
    were derived from another device's probing (not directly observed).

Clusters devices into families, propagates hypotheses, minimizes
per-device probing by identifying representative devices.

Paper reference: Section VI-B item 9
"""

import logging
from agents.base import BaseAgent, AgentRole, AgentResult, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class FleetReasonerAgent(BaseAgent):
    """
    Agent responsible for fleet-level reasoning: clustering similar devices
    and propagating hypotheses from representative devices to cluster members.

    This agent runs TWICE in the pipeline:
      - Step 3 (pre-execution): Clusters devices and stores cluster info
        so the Planner can build pruned PTGs for non-representatives.
      - Post-execution (after Step 9): Propagates findings from the
        representative's full scan to all cluster members.
    """

    def __init__(self, context: SessionContext):
        # Register with the FLEET_REASONER role for message bus addressing
        super().__init__(AgentRole.FLEET_REASONER, context)

    def execute(self) -> AgentResult:
        """
        Cluster devices and propagate hypotheses.
        Uses the fleet module for clustering and propagation.

        FLOW:
            1. Get all TIBs — need at least 2 devices for clustering.
            2. Run the FleetClusterer to group similar devices.
            3. Store cluster data in context.fleet_clusters (used by Planner).
            4. Propagate findings from representative to cluster members.
            5. Record propagated hypotheses in the PCF DAG.
            6. Notify the PlannerAgent with cluster count and propagation stats.

        Returns:
            AgentResult with cluster count, propagated hypotheses, and
            estimated probing reduction percentage.
        """
        from fleet.clustering import FleetClusterer
        from fleet.hypothesis_propagation import HypothesisPropagator

        tibs = self.context.all_tibs()
        # Clustering requires at least 2 devices — can't form clusters
        # with a single device.
        if len(tibs) < 2:
            return AgentResult(success=True, data={"clusters": 0})

        errors = []

        # ── Step 1: Cluster devices ──────────────────────────────────────────
        # The FleetClusterer groups devices based on shared signals:
        #   - Same OUI vendor (MAC prefix)
        #   - Similar open port sets
        #   - Same TTL value (indicates same OS family)
        #   - Similar banner/service fingerprints
        # Each cluster has a representative_ip (the device that will be
        # fully probed) and member_ips (all devices in the cluster).
        try:
            clusterer = FleetClusterer()
            clusters = clusterer.cluster(tibs)

            for cluster in clusters:
                # Store the full cluster info keyed by cluster_id.
                # This is used by the Coordinator for metrics and reporting.
                self.context.fleet_clusters[cluster.cluster_id] = {
                    "cluster_id": cluster.cluster_id,
                    "member_ips": cluster.member_ips,
                    "representative_ip": cluster.representative_ip,
                    "shared_signals": cluster.shared_signals,
                    "confidence": cluster.confidence,
                    "hypothesis": cluster.hypothesis,
                }

                # Also store a per-IP lookup so that the PlannerAgent can
                # quickly check whether a device is a non-representative
                # cluster member (and thus should get a pruned PTG).
                for ip in cluster.member_ips:
                    if ip != cluster.representative_ip:
                        self.context.fleet_clusters[ip] = {
                            "cluster_id": cluster.cluster_id,
                            "representative_ip": cluster.representative_ip,
                        }

        except Exception as e:
            errors.append(f"Clustering error: {e}")
            return AgentResult(success=False, errors=errors)

        # ── Step 2: Propagate hypotheses ─────────────────────────────────────
        # After the representative device has been fully probed (in a later
        # pipeline step), propagate its findings to all other cluster members.
        # On the first run (Step 3), the representative hasn't been probed yet,
        # so propagation produces few or no results. On the post-execution run,
        # the representative has full results, and propagation is effective.
        propagated = 0
        try:
            propagator = HypothesisPropagator()
            for cluster in clusters:
                # Skip clusters without a representative (shouldn't happen
                # but guard defensively)
                if not cluster.representative_ip:
                    continue
                # Get the representative device's TIBManager
                rep_tib = self.context.get_device(cluster.representative_ip)
                if not rep_tib:
                    continue

                # Iterate over all non-representative members
                for ip in cluster.member_ips:
                    if ip == cluster.representative_ip:
                        continue  # Skip the representative itself
                    target_tib = self.context.get_device(ip)
                    if not target_tib:
                        continue

                    # Generate hypotheses by comparing the representative's
                    # signals/findings with the target's current state
                    hypotheses = propagator.propagate(rep_tib, target_tib, cluster)
                    for hyp in hypotheses:
                        # Apply the hypothesis to the target device's TIB
                        # (e.g., set os_guess, add service banners, etc.)
                        propagator.apply_hypothesis(target_tib, hyp)
                        propagated += 1

                        # Record the propagated hypothesis in the PCF DAG.
                        # The oracle level is INFERRED because this finding
                        # was NOT directly observed on the target device —
                        # it was inferred from the representative's data.
                        from TIB_and_PCF.PCF import NodeType, EvidenceApproach
                        self.context.pcf_dag.add_node(
                            node_type=NodeType.PROBE,
                            phase="FLEET_INFERENCE",
                            payload={
                                "hypothesis": hyp.description,
                                "source_ip": cluster.representative_ip,
                                "confidence": hyp.confidence,
                                "field": hyp.field_name,
                                # Truncate value to 200 chars to avoid DAG bloat
                                "value": str(hyp.value)[:200],
                            },
                            # Two parents: the representative's root (source of
                            # the hypothesis) and the target's root (receiver).
                            # This creates a cross-device link in the evidence chain.
                            parent_ids=[rep_tib.pcf_device_root_id,
                                        target_tib.pcf_device_root_id],
                            evidence_approaches=EvidenceApproach.INFERRED,
                            device_ip=ip,
                        )

        except Exception as e:
            errors.append(f"Propagation error: {e}")

        # ── Notify PlannerAgent ──────────────────────────────────────────────
        # Tell the planner how many clusters were formed and how many
        # hypotheses were propagated. The planner uses cluster data (stored
        # in context.fleet_clusters) to prune PTGs for non-representatives.
        self.send_message(
            AgentRole.PLANNER, MessageType.RESULT,
            {"phase": "fleet_reasoning",
             "clusters": len(clusters),
             "propagated_hypotheses": propagated},
        )

        return AgentResult(
            success=True,
            data={
                "clusters": len(clusters),
                "propagated": propagated,
                "probing_reduction_pct": self._estimate_probing_reduction(clusters),
            },
            errors=errors,
        )

    def _estimate_probing_reduction(self, clusters) -> float:
        """
        Estimate the probing reduction percentage from fleet inference.

        Calculates what fraction of devices do NOT need full probing because
        they are non-representative members of a cluster. For example, if
        there are 10 devices and 8 are non-representatives, the reduction
        is 80%.

        Args:
            clusters — List of cluster objects from FleetClusterer.

        Returns:
            Probing reduction percentage (0.0 to 100.0).
        """
        total_devices = len(self.context.devices)
        if total_devices == 0:
            return 0.0

        # Count non-representative devices across all multi-member clusters.
        # A cluster with N members has N-1 non-representatives (only the
        # representative needs full probing).
        non_reps = sum(
            len(c.member_ips) - 1  # Subtract 1 for the representative
            for c in clusters
            if len(c.member_ips) > 1  # Skip singleton clusters
        )

        # Return as a percentage of total devices
        return round(non_reps / total_devices * 100, 1)
