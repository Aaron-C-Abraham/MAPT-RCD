"""
agents/evidence_agent.py — Evidence Agent.

PURPOSE:
    The Evidence Agent is the NINTH and FINAL agent in the 9-step pipeline
    (Step 9). It is responsible for managing the Proof-Carrying Findings
    (PCF) DAG — the cryptographic evidence chain that makes every finding
    in a TRUCE-PT engagement tamper-evident and auditable.

    Specifically, it:
      1. Processes RESULT messages from the ToolOrchestrator, recording each
         tool execution and its output in the PCF DAG.
      2. Builds "proof bundles" — self-contained evidence packages that bind
         a finding to its complete evidence chain and a cryptographic hash.
      3. Checkpoints the PCF DAG to disk for crash recovery.
      4. Provides verification and export functions for the engagement ledger.

PROOF BUNDLES:
    A proof bundle is the core deliverable of the PCF system. For each
    finding (e.g., "port 22 is open", "device runs Linux 5.x"), it contains:

      - finding_node_id  : The PCF node that recorded the finding.
      - device_ip        : Which device the finding pertains to.
      - device_tier      : The device's classification at the time.
      - evidence_chain   : All ancestor nodes in the PCF DAG, from the
                           session root down to the finding. Each entry
                           includes the node_id, type, phase, timestamp,
                           data_hash, and oracle level.
      - chain_length     : Number of nodes in the evidence chain.
      - bundle_hash      : SHA-256 hash of the entire bundle (self-sealing).

    The bundle_hash allows anyone to verify that the bundle has not been
    tampered with by recomputing it from the bundle contents.

INTER-AGENT COMMUNICATION:
    Receives:
        ToolOrchestratorAgent ──RESULT──> EvidenceAgent
          (per-action results: device_ip, node_id, tool_id, result data)

    Does not send messages to other agents (terminal consumer).

Manages the PCF DAG. Ensures every tool invocation and result is
properly recorded with cryptographic provenance. Handles persistence
and integrity verification. Constructs proof bundles per finding.

Paper reference: Section VI-B item 8, Section XI (PCF)
"""

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

    This is a terminal consumer — it receives messages but does not send
    any to other agents. It is the last agent in the pipeline, ensuring
    that all evidence is properly recorded and verifiable.
    """

    def __init__(self, context: SessionContext):
        # Register with the EVIDENCE role for message bus addressing
        super().__init__(AgentRole.EVIDENCE, context)
        # Accumulates proof bundles across the session. Each bundle is a
        # self-contained evidence package for one finding.
        self._proof_bundles = []

    def execute(self) -> AgentResult:
        """
        Process evidence messages and construct proof bundles.

        FLOW:
            1. Consume all pending RESULT messages from the message bus.
            2. For each message, record the tool execution in the PCF DAG.
            3. Build proof bundles for all validated findings.
            4. Checkpoint the PCF DAG to disk for crash recovery.

        Returns:
            AgentResult with nodes_recorded, bundles_created, and total PCF node count.
        """
        # Consume all pending messages addressed to this agent
        messages = self.context.message_bus.receive(self.role)
        nodes_recorded = 0   # Count of evidence nodes added to the PCF DAG
        bundles_created = 0  # Count of proof bundles constructed

        # ── Record each tool execution result ────────────────────────────────
        for msg in messages:
            # Only process RESULT messages (sent by ToolOrchestrator)
            if msg.message_type == MessageType.RESULT:
                try:
                    self._record_evidence(msg.payload)
                    nodes_recorded += 1
                except Exception as e:
                    self.logger.error(f"Evidence recording error: {e}")

        # ── Build proof bundles ──────────────────────────────────────────────
        # Iterate over the PCF DAG to find findings and construct self-sealing
        # evidence packages for each one.
        bundles_created = self._build_proof_bundles()

        # ── Checkpoint the PCF DAG ───────────────────────────────────────────
        # Save a checkpoint to disk so that if the process crashes, we can
        # recover the evidence chain up to this point.
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

        Creates a PROBE node in the evidence chain with the tool_id, a
        truncated result summary (max 500 chars to avoid bloating the DAG),
        findings count, and budget cost.

        The node's parents are:
          - The device's PCF root node (always).
          - The PTG node_id (if available), linking the evidence to the
            specific attack plan step that generated it.

        Args:
            payload — Dict with keys: device_ip, tool_id, result, node_id.
        """
        from TIB_and_PCF.PCF import NodeType, EvidenceApproach

        device_ip = payload.get("device_ip", "")
        tool_id = payload.get("tool_id", "")
        result = payload.get("result", {})
        node_id = payload.get("node_id", "")

        # Build the parent chain: always include the device root, and
        # optionally include the PTG node_id for cross-referencing.
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
                # Truncate result to 500 chars to avoid bloating the DAG
                # while still capturing enough for debugging
                "result_summary": str(result)[:500],
                "findings_count": len(result.get("findings", [])),
                "budget_cost": result.get("budget_cost", 0.0),
            },
            parent_ids=parent_ids,
            evidence_approaches=EvidenceApproach.ACTIVE,  # Tool execution is an active observation
            device_ip=device_ip,
        )

    def _build_proof_bundles(self) -> int:
        """
        Build Proof-Carrying Finding (PCF) bundles.

        A proof bundle binds a finding to:
        1. The evidence chain (all ancestor nodes in PCF DAG) — provides
           the full provenance from session start to finding.
        2. Validation oracle results (recorded as child nodes in the DAG).
        3. A cryptographic hash of the bundle (SHA-256) — makes the bundle
           self-sealing and tamper-detectable.

        The method scans all PCF nodes for each device, identifies nodes
        with findings (findings_count > 0), traces their evidence chain
        back to the root, and packages everything into a bundle.

        Returns:
            Number of new bundles created in this invocation.
        """
        from TIB_and_PCF.PCF import NodeType

        bundles_created = 0

        # ── Scan all devices for findings ────────────────────────────────────
        for device_ip, tib in self.context.devices.items():
            # Get all PCF nodes associated with this device
            device_nodes = self.context.pcf_dag.get_device_nodes(device_ip)

            for node_dict in device_nodes:
                # Only process PROBE nodes (not SESSION_EVENT, DISCOVERY, etc.)
                if node_dict.get("node_type") != "probe":
                    continue

                payload = node_dict.get("payload", {})
                # Skip nodes that didn't produce any findings
                if not payload.get("findings_count", 0):
                    continue

                # ── Trace the evidence chain ─────────────────────────────────
                # Get the path from the session root to this finding node.
                # This is the complete provenance chain proving HOW the
                # finding was discovered.
                evidence_chain = self.context.pcf_dag.get_path(
                    node_dict["node_id"]
                )

                # ── Construct the proof bundle ───────────────────────────────
                bundle = {
                    "finding_node_id": node_dict["node_id"],
                    "device_ip": device_ip,
                    "device_tier": tib.tier.name,  # Tier at bundle creation time
                    # Extract key fields from each evidence chain node
                    "evidence_chain": [
                        {
                            "node_id": n["node_id"],
                            "node_type": n["node_type"],
                            "phase": n["phase"],
                            "timestamp": n["timestamp"],
                            "data_hash": n["data_hash"],       # Per-node content hash
                            "oracle_level": n["oracle_level"],  # PASSIVE/ACTIVE/INFERRED
                        }
                        for n in evidence_chain
                    ],
                    "chain_length": len(evidence_chain),
                }

                # ── Compute self-sealing hash ────────────────────────────────
                # SHA-256 hash of the entire bundle (with sorted keys for
                # deterministic serialization). This hash makes the bundle
                # tamper-evident: if any field is modified, the hash won't match.
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

        For each bundle, re-computes the SHA-256 hash from the bundle's
        contents (excluding the stored bundle_hash) and checks if it
        matches the stored hash. A mismatch indicates tampering.

        Returns:
            Dict with: total_bundles, valid (count), invalid (count).
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
                invalid_count += 1  # Tampering or corruption detected

        return {
            "total_bundles": len(self._proof_bundles),
            "valid": valid_count,
            "invalid": invalid_count,
        }

    def export_engagement_ledger(self, path: str) -> None:
        """
        Export the complete engagement ledger with all proof bundles.

        The engagement ledger is the master document for the entire
        TRUCE-PT session. It contains:
          - session_root_id    : Root of the PCF DAG.
          - pcf_dag_integrity  : Whether the DAG's hash chain is valid.
          - proof_bundles      : All proof bundles (one per finding).
          - bundle_integrity   : Verification status of all bundles.
          - session_metrics    : High-level session metrics.

        This file serves as the primary audit artifact — it can be
        provided to assessors, regulators, or clients as evidence that
        the engagement was conducted safely and that all findings have
        cryptographic provenance.

        Args:
            path — File path where the JSON ledger will be written.
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
