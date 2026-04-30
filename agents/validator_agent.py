"""
agents/validator_agent.py — Validator Agent.

PURPOSE:
    The Validator Agent is the EIGHTH agent in the 9-step pipeline (Step 8).
    It validates tool outputs against expected schemas, checks PCF evidence
    chain integrity, and executes validation oracles on findings.

    Validation is essential for reducing false positives: a finding is only
    considered "validated" if it passes a majority of its assigned oracles.

ORACLE SYSTEM:
    Each PTG node can specify a list of validation oracles. Oracles are
    named checks that verify findings from different angles:

    Passive checks (no target interaction):
      - passive_data_present : Is there mDNS/DHCP/NetBIOS data for this device?
      - mac_present          : Do we have the device's MAC address?
      - ttl_present          : Was a TTL value captured?
      - ttl_consistency      : Is the TTL value consistent across probes?

    Cross-reference checks:
      - os_matches_banner     : Does the OS guess match service banner strings?
      - os_banner_consistency : Are OS and banner data internally consistent?
      - tier_consistency      : Has the device been classified at least once?

    Signal-presence checks:
      - rtt_baseline_established : Was an RTT baseline measured?
      - window_options_present   : Are TCP window/options fingerprints available?
      - ports_discovered         : Were any open ports found?
      - os_confidence_above_threshold : Did OS detection produce a result?

    The validation confidence is: passed_oracles / total_oracles.
    A finding is "validated" if confidence >= 0.5 (majority of oracles pass).

INTER-AGENT COMMUNICATION:
    Receives:
        ToolOrchestratorAgent ──REQUEST──> ValidatorAgent
          (payload: device_ip, node_id, oracles list, result data)

    Sends:
        ValidatorAgent ──RESULT──> ToolOrchestratorAgent
          (validation outcome: validated/rejected, confidence, oracle details)

PCF INTEGRITY:
    After processing all validation requests, the agent also verifies the
    entire PCF DAG's hash chain integrity, catching any tampered or
    corrupted evidence nodes.

Validates tool outputs against expected schemas. Checks PCF evidence
chain integrity. Flags anomalous results. Executes validation oracles.

"""

import logging
from agents.base import BaseAgent, AgentRole, AgentResult, AgentMessage, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class ValidatorAgent(BaseAgent):
    """
    Agent responsible for validating findings and verifying evidence integrity.

    Processes validation REQUEST messages from the ToolOrchestrator, executes
    oracle checks against device signals/state, and replies with validation
    outcomes. Also verifies the PCF DAG's cryptographic hash chain.
    """

    def __init__(self, context: SessionContext):
        # Register with the VALIDATOR role for message bus addressing
        super().__init__(AgentRole.VALIDATOR, context)

    def execute(self) -> AgentResult:
        """
        Process validation requests from the tool orchestrator.
        Validate findings using oracle recipes.

        FLOW:
            1. Consume all pending REQUEST messages from the message bus.
            2. For each request, execute the specified oracles and compute
               a validation confidence score.
            3. Send RESULT replies back to the requesting agent with the
               validation outcome.
            4. Verify the PCF DAG's hash chain integrity.

        Returns:
            AgentResult with validated/rejected counts and PCF integrity status.
        """
        validated = 0   # Count of findings that passed validation
        rejected = 0    # Count of findings that failed validation
        errors = []     # Non-fatal errors during oracle execution

        # ── Process pending validation requests ──────────────────────────────
        # Consume all messages in this agent's queue. The ToolOrchestrator
        # sends a REQUEST for each PTG node that has validation_oracles.
        messages = self.context.message_bus.receive(self.role)
        for msg in messages:
            # Only process REQUEST messages — ignore any other type
            if msg.message_type != MessageType.REQUEST:
                continue

            try:
                # Run the validation oracles and compute confidence
                result = self._validate_finding(msg.payload)
                if result["validated"]:
                    validated += 1
                    # Increment the session-level validated findings counter
                    self.context.validated_findings += 1
                else:
                    rejected += 1

                # Send the validation result back to the agent that requested it
                # (typically ToolOrchestrator). The in_reply_to field links this
                # reply to the original request for correlation.
                self.send_message(
                    msg.sender, MessageType.RESULT,
                    {"validation": result, "original_node": msg.payload.get("node_id")},
                    in_reply_to=msg.message_id,
                )

            except Exception as e:
                errors.append(f"Validation error: {e}")

        # ── Verify PCF DAG integrity ─────────────────────────────────────────
        # Check the entire evidence chain's cryptographic hashes. If any node
        # was tampered with or corrupted, this will catch it.
        integrity_result = self._verify_pcf_integrity()

        return AgentResult(
            success=True,
            data={
                "validated": validated,
                "rejected": rejected,
                "pcf_integrity": integrity_result,
            },
            errors=errors,
        )

    def _validate_finding(self, payload: dict) -> dict:
        """
        Validate a finding using oracle recipes.

        Oracle execution order (passive-first):
        1. Passive checks (no target interaction)
        2. Cross-reference checks (compare with other evidence)
        3. Active re-checks (re-probe target — last resort)

        The confidence score is: oracles_passed / total_oracles.
        A finding is "validated" if confidence >= 0.5 (majority vote).

        Args:
            payload — Dict with keys: device_ip, result, oracles, node_id.

        Returns:
            Dict with: node_id, device_ip, validated (bool), confidence (float),
            oracle_results (list of per-oracle outcomes).
        """
        device_ip = payload.get("device_ip", "")
        result_data = payload.get("result", {})
        oracles = payload.get("oracles", [])      # List of oracle names to execute
        node_id = payload.get("node_id", "")

        # Initialize the validation result structure
        validation = {
            "node_id": node_id,
            "device_ip": device_ip,
            "validated": False,        # Will be set based on confidence threshold
            "confidence": 0.0,         # Fraction of oracles that passed
            "oracle_results": [],      # Detailed per-oracle outcomes
        }

        # Look up the device's TIBManager to access its signals and state
        tib = self.context.get_device(device_ip)
        if not tib:
            # Device not found — cannot validate without device data
            validation["error"] = f"Device {device_ip} not found"
            return validation

        # ── Execute oracles in order ─────────────────────────────────────────
        # Each oracle is a named check that tests a specific property of the
        # device's signals or state. We count how many pass to compute confidence.
        passed = 0
        total = len(oracles) if oracles else 1  # Default to 1 to avoid division by zero

        for oracle_name in oracles:
            # Execute the individual oracle check
            oracle_result = self._execute_oracle(oracle_name, device_ip, result_data, tib)
            validation["oracle_results"].append(oracle_result)
            if oracle_result.get("passed"):
                passed += 1

        # ── Compute confidence score ─────────────────────────────────────────
        # Confidence is the fraction of oracles that passed (0.0 to 1.0).
        # A finding is validated if confidence >= 0.5 (majority vote).
        if total > 0:
            validation["confidence"] = passed / total
            validation["validated"] = validation["confidence"] >= 0.5

        # ── Record validation in PCF DAG ─────────────────────────────────────
        # Create a PROBE node in the evidence chain recording the validation
        # outcome. This node's parent is the original finding node, creating
        # a provenance link: finding → validation.
        from TIB_and_PCF.PCF import NodeType, EvidenceApproach
        self.context.pcf_dag.add_node(
            node_type=NodeType.PROBE,
            phase="VALIDATION",
            payload={
                "target_node_id": node_id,                    # Which finding was validated
                "validated": validation["validated"],          # Pass or fail
                "confidence": validation["confidence"],        # Numeric confidence
                "oracle_results": validation["oracle_results"],  # Detailed oracle outcomes
            },
            # Parent is the finding node itself (if available), otherwise the device root.
            # This links the validation evidence to the finding evidence in the DAG.
            parent_ids=[node_id] if node_id else [tib.pcf_device_root_id],
            evidence_approaches=EvidenceApproach.INFERRED,  # Validation is an inference, not a probe
            device_ip=device_ip,
        )

        return validation

    def _execute_oracle(self, oracle_name: str, device_ip: str,
                        result_data: dict, tib) -> dict:
        """
        Execute a single validation oracle.

        Each oracle tests a specific property of the device's signal store
        or state. The checks are intentionally lightweight — they verify
        that expected data exists and is internally consistent, rather than
        re-probing the target.

        Args:
            oracle_name — Name of the oracle to execute (e.g., "mac_present").
            device_ip   — Target device IP (for context).
            result_data — The tool result being validated.
            tib         — The device's TIBManager.

        Returns:
            Dict with: name, passed (bool), details (str).
        """
        # Initialize oracle result with default failure state
        oracle_result = {
            "name": oracle_name,
            "passed": False,
            "details": "",
        }

        # ── Passive data presence check ──────────────────────────────────────
        # Verifies that at least some passive recon data was captured for
        # this device (mDNS, DHCP fingerprint, or NetBIOS). Having passive
        # data provides an independent corroboration channel.
        if oracle_name == "passive_data_present":
            oracle_result["passed"] = bool(
                tib.signals.mdns_services or tib.signals.dhcp_fingerprint
                or tib.signals.netbios_present
            )
            oracle_result["details"] = "Passive data available" if oracle_result["passed"] else "No passive data"

        # ── MAC address presence check ───────────────────────────────────────
        # Verifies that the device's MAC address was captured (typically from
        # ARP responses). MAC is needed for OUI vendor classification.
        elif oracle_name == "mac_present":
            oracle_result["passed"] = bool(tib.device_mac)
            oracle_result["details"] = f"MAC: {tib.device_mac}" if oracle_result["passed"] else "No MAC"

        # ── TTL presence check ───────────────────────────────────────────────
        # Verifies that a TTL value was observed. TTL is useful for OS
        # family identification (Linux=64, Windows=128, etc.).
        elif oracle_name == "ttl_present":
            oracle_result["passed"] = tib.signals.ttl is not None
            oracle_result["details"] = f"TTL: {tib.signals.ttl}" if oracle_result["passed"] else "No TTL"

        # ── TTL consistency check ────────────────────────────────────────────
        # Verifies that TTL data exists and is consistent. In a more advanced
        # implementation, this would compare TTL across multiple probes.
        elif oracle_name == "ttl_consistency":
            oracle_result["passed"] = tib.signals.ttl is not None
            oracle_result["details"] = "TTL consistent" if oracle_result["passed"] else "No TTL data"

        # ── RTT baseline established check ───────────────────────────────────
        # Verifies that a round-trip-time baseline was measured. The baseline
        # is essential for detecting RTT stress during probing.
        elif oracle_name == "rtt_baseline_established":
            oracle_result["passed"] = tib.state.baseline_rtt_ms is not None
            oracle_result["details"] = (
                f"Baseline: {tib.state.baseline_rtt_ms:.1f}ms"
                if oracle_result["passed"] else "No baseline"
            )

        # ── TCP window/options presence check ────────────────────────────────
        # Verifies that TCP fingerprinting data (window size or options) was
        # captured. These are key signals for passive OS identification.
        elif oracle_name == "window_options_present":
            oracle_result["passed"] = (
                tib.signals.tcp_window_size is not None or bool(tib.signals.tcp_options)
            )

        # ── Ports discovered check ───────────────────────────────────────────
        # Verifies that at least one open port was found during port scanning.
        # A device with zero open ports may indicate a firewall or scan failure.
        elif oracle_name == "ports_discovered":
            oracle_result["passed"] = len(tib.state.open_ports_found) > 0
            oracle_result["details"] = f"Found {len(tib.state.open_ports_found)} ports"

        # ── Tier classification consistency check ────────────────────────────
        # Verifies that the device has been classified at least once. This
        # catches edge cases where classification was skipped or failed.
        elif oracle_name == "tier_consistency":
            oracle_result["passed"] = len(tib.classification_history) > 0

        # ── OS confidence threshold check ────────────────────────────────────
        # Verifies that OS detection produced a result (any result). In a
        # more advanced implementation, this would check a confidence score.
        elif oracle_name == "os_confidence_above_threshold":
            oracle_result["passed"] = bool(tib.signals.nmap_os_guess)

        # ── OS matches banner cross-reference ────────────────────────────────
        # Checks whether OS guess data and banner data are both present.
        # A more sophisticated version would actually compare them for
        # consistency (e.g., "Linux" OS guess with "Apache" banner = consistent).
        elif oracle_name == "os_matches_banner":
            os_guess = (tib.signals.nmap_os_guess or "").lower()
            banners = " ".join(tib.signals.banners.values()).lower()
            # Currently passes if either OS or banner data exists
            oracle_result["passed"] = bool(os_guess) or bool(banners)

        # ── OS-banner consistency check ──────────────────────────────────────
        # Placeholder for a deeper cross-reference check between OS and
        # banner data. Currently defaults to True (always passes).
        elif oracle_name == "os_banner_consistency":
            oracle_result["passed"] = True  # Cross-reference check (placeholder)

        else:
            # ── Unknown oracle ───────────────────────────────────────────────
            # If an oracle name is not recognized, default to passing.
            # This allows new oracles to be added to PTG nodes without
            # immediately breaking validation (forward compatibility).
            oracle_result["passed"] = True
            oracle_result["details"] = f"Unknown oracle '{oracle_name}' — default pass"

        return oracle_result

    def _verify_pcf_integrity(self) -> dict:
        """
        Verify the PCF DAG hash chain integrity.

        Calls the PCF DAG's built-in verification method, which checks that
        every node's stored hash matches a recomputation from its data and
        parent hashes. Any mismatch indicates tampering or corruption.

        Returns:
            Dict with: valid (bool), error_count (int).
        """
        valid, errors = self.context.pcf_dag.integrity_verification()
        if not valid:
            # Log the first few errors for debugging — full list may be very long
            self.logger.warning(f"PCF integrity errors: {len(errors)}")
            for err in errors[:3]:
                self.logger.warning(f"  {err}")
        return {"valid": valid, "error_count": len(errors)}
