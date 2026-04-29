import json
import logging
import hashlib
from agents.base import BaseAgent, AgentRole, AgentResult, AgentMessage, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class EvidenceAgent(BaseAgent):
    """
    Agent responsible for evidence recording, proof bundle construction,
    and engagement ledger management.
    """

    def __init__(self, context: SessionContext):
        super().__init__(AgentRole.EVIDENCE, context)
        self._proof_bundles = []

    def execute(self) -> AgentResult:
        """
        Process evidence messages and construct proof bundles.
        """
        messages = self.context.message_bus.receive(self.role)
        nodes_recorded = 0  
        bundles_created = 0

        for msg in messages:
            if msg.message_type == MessageType.RESULT:
                try:
                    self._record_evidence(msg.payload)
                    nodes_recorded += 1
                except Exception as e:
                    self.logger.error(f"Evidence recording error: {e}")
        bundles_created = self._build_proof_bundles()
        try:
            if self.context.output_dir:
                import os
                checkpoint_path = os.path.join(self.context.output_dir, "pcf_evidence.json.checkpoint")
                self.context.pcf_dag.save(checkpoint_path)
        except Exception as e:
            self.logger.error(f"PCF checkpoint error: {e}")

        return AgentResult(
            success=True,
            data={
                "nodes_recorded": nodes_recorded,
                "bundles_created": bundles_created,
                "total_pcf_nodes": self.context.pcf_dag.summary()["total_nodes"],
            },
        )

    def _record_evidence(self, payload: dict) -> None:
        """
        Record a tool execution result in the PCF DAG.
        """
        from TIB_and_PCF.PCF import NodeType, EvidenceApproach

        device_ip = payload.get("device_ip", "")
        tool_id = payload.get("tool_id", "")
        result = payload.get("result", {})
        node_id = payload.get("node_id", "")

        # Build the parent chain
        tib = self.context.get_device(device_ip)
        parent_ids = []
        if tib:
            parent_ids = [tib.pcf_device_root_id]  # Link to device's evidence root
        if node_id:
            parent_ids.append(node_id)  # Link to the PTG node that generated this

        # Add the evidence node to the PCF DAG
        self.context.pcf_dag.add_node(
            node_type=NodeType.PROBE,
            phase="EVIDENCE_RECORDING",
            payload={
                "tool_id": tool_id,
                "result_summary": str(result)[:500],
                "findings_count": len(result.get("findings", [])),
                "budget_cost": result.get("budget_cost", 0.0),
            },
            parent_ids=parent_ids,
            evidence_approaches=EvidenceApproach.ACTIVE,  
            device_ip=device_ip,
        )

    def _build_proof_bundles(self) -> int:
        """
        Build Proof-Carrying Finding (PCF) bundles.
        """

        bundles_created = 0
        for device_ip, tib in self.context.devices.items():
            device_nodes = self.context.pcf_dag.get_device_nodes(device_ip)

            for node_dict in device_nodes:
                if node_dict.get("node_type") != "probe":
                    continue

                payload = node_dict.get("payload", {})
                if not payload.get("findings_count", 0):
                    continue
                evidence_chain = self.context.pcf_dag.get_path(
                    node_dict["node_id"]
                )
                bundle = {
                    "finding_node_id": node_dict["node_id"],
                    "device_ip": device_ip,
                    "device_tier": tib.tier.name,  
                    "evidence_chain": [
                        {
                            "node_id": n["node_id"],
                            "node_type": n["node_type"],
                            "phase": n["phase"],
                            "timestamp": n["timestamp"],
                            "data_hash": n["data_hash"],      
                            "oracle_level": n["oracle_level"],  
                        }
                        for n in evidence_chain
                    ],
                    "chain_length": len(evidence_chain),
                }
                bundle_hash = hashlib.sha256(
                    json.dumps(bundle, sort_keys=True, default=str).encode()
                ).hexdigest()
                bundle["bundle_hash"] = bundle_hash

                # Store the completed bundle
                self._proof_bundles.append(bundle)
                bundles_created += 1

        return bundles_created

    def get_proof_bundles(self) -> list:
        """Return all proof bundles constructed during this session."""
        return self._proof_bundles

    def verify_all_bundles(self) -> dict:
        """
        Verify integrity of all proof bundles.
        """
        valid_count = 0
        invalid_count = 0

        for bundle in self._proof_bundles:
            # Create a copy and remove the stored hash for recomputation
            bundle_copy = dict(bundle)
            stored_hash = bundle_copy.pop("bundle_hash", "")
            # Recompute the hash from the remaining fields
            expected = hashlib.sha256(
                json.dumps(bundle_copy, sort_keys=True, default=str).encode()
            ).hexdigest()
            # Compare recomputed hash with stored hash
            if expected == stored_hash:
                valid_count += 1
            else:
                invalid_count += 1 

        return {
            "total_bundles": len(self._proof_bundles),
            "valid": valid_count,
            "invalid": invalid_count,
        }

    def export_engagement_ledger(self, path: str) -> None:
        """
        Export the complete engagement ledger with all proof bundles.
        """
        # Verify the PCF DAG's hash chain integrity
        dag_valid, dag_errors = self.context.pcf_dag.integrity_verification()
        # Verify all proof bundles' self-sealing hashes
        bundle_status = self.verify_all_bundles()

        # Assemble the complete ledger
        ledger = {
            "session_root_id": self.context.session_root_id,
            "pcf_dag_integrity": {"valid": dag_valid, "errors": len(dag_errors)},
            "proof_bundles": self._proof_bundles,
            "bundle_integrity": bundle_status,
            "session_metrics": self.context.get_session_metrics(),
        }
        # Write to disk as formatted JSON
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ledger, f, indent=2, default=str)

        self.logger.info(f"Engagement ledger exported to {path}")
