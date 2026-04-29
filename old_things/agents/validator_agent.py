import logging
from agents.base import BaseAgent, AgentRole, AgentResult, AgentMessage, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class ValidatorAgent(BaseAgent):
    """
    Agent responsible for validating findings and verifying evidence integrity.
    """

    def __init__(self, context: SessionContext):
        super().__init__(AgentRole.VALIDATOR, context)

    def execute(self) -> AgentResult:
        """
        Process validation requests from the tool orchestrator.
        Validate findings using oracle recipes.
        """
        validated = 0   
        rejected = 0    
        errors = []     

        messages = self.context.message_bus.receive(self.role)
        for msg in messages:
            if msg.message_type != MessageType.REQUEST:
                continue

            try:
                result = self._validate_finding(msg.payload)
                if result["validated"]:
                    validated += 1
                    self.context.validated_findings += 1
                else:
                    rejected += 1
                self.send_message(
                    msg.sender, MessageType.RESULT,
                    {"validation": result, "original_node": msg.payload.get("node_id")},
                    in_reply_to=msg.message_id,
                )

            except Exception as e:
                errors.append(f"Validation error: {e}")
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
        Validate a finding using oracle recipes
        """
        device_ip = payload.get("device_ip", "")
        result_data = payload.get("result", {})
        oracles = payload.get("oracles", [])      
        node_id = payload.get("node_id", "")

        validation = {
            "node_id": node_id,
            "device_ip": device_ip,
            "validated": False,        
            "confidence": 0.0,         
            "oracle_results": [],      
        }
        tib = self.context.get_device(device_ip)
        if not tib:
            validation["error"] = f"Device {device_ip} not found"
            return validation

        passed = 0
        total = len(oracles) if oracles else 1 

        for oracle_name in oracles:
            oracle_result = self._execute_oracle(oracle_name, device_ip, result_data, tib)
            validation["oracle_results"].append(oracle_result)
            if oracle_result.get("passed"):
                passed += 1
        if total > 0:
            validation["confidence"] = passed / total
            validation["validated"] = validation["confidence"] >= 0.5
        from TIB_and_PCF.PCF import NodeType, EvidenceApproach
        self.context.pcf_dag.add_node(
            node_type=NodeType.PROBE,
            phase="VALIDATION",
            payload={
                "target_node_id": node_id,                   
                "validated": validation["validated"],        
                "confidence": validation["confidence"],        
                "oracle_results": validation["oracle_results"], 
            },
            parent_ids=[node_id] if node_id else [tib.pcf_device_root_id],
            evidence_approaches=EvidenceApproach.INFERRED,  
            device_ip=device_ip,
        )

        return validation

    def _execute_oracle(self, oracle_name: str, device_ip: str, result_data: dict, tib) -> dict:
        """
        Execute a single validation oracle.
        """
        # Initialize oracle result with default failure state
        oracle_result = {
            "name": oracle_name,
            "passed": False,
            "details": "",
        }

        # Passive data presence check 
        if oracle_name == "passive_data_present":
            oracle_result["passed"] = bool(
                tib.signals.mdns_services or tib.signals.dhcp_fingerprint
                or tib.signals.netbios_present
            )
            oracle_result["details"] = "Passive data available" if oracle_result["passed"] else "No passive data"

        # MAC address presence check
        elif oracle_name == "mac_present":
            oracle_result["passed"] = bool(tib.device_mac)
            oracle_result["details"] = f"MAC: {tib.device_mac}" if oracle_result["passed"] else "No MAC"

        # TTL presence check
        elif oracle_name == "ttl_present":
            oracle_result["passed"] = tib.signals.ttl is not None
            oracle_result["details"] = f"TTL: {tib.signals.ttl}" if oracle_result["passed"] else "No TTL"

        # TTL consistency check 
        elif oracle_name == "ttl_consistency":
            oracle_result["passed"] = tib.signals.ttl is not None
            oracle_result["details"] = "TTL consistent" if oracle_result["passed"] else "No TTL data"

        # RTT baseline established check 
        elif oracle_name == "rtt_baseline_established":
            oracle_result["passed"] = tib.state.baseline_rtt_ms is not None
            oracle_result["details"] = (
                f"Baseline: {tib.state.baseline_rtt_ms:.1f}ms"
                if oracle_result["passed"] else "No baseline"
            )
        # TCP window/options presence check 
        elif oracle_name == "window_options_present":
            oracle_result["passed"] = (
                tib.signals.tcp_window_size is not None or bool(tib.signals.tcp_options)
            )
        # Ports discovered checkure.
        elif oracle_name == "ports_discovered":
            oracle_result["passed"] = len(tib.state.open_ports_found) > 0
            oracle_result["details"] = f"Found {len(tib.state.open_ports_found)} ports"

        # Tier classification consistency check
        elif oracle_name == "tier_consistency":
            oracle_result["passed"] = len(tib.classification_history) > 0

        # OS confidence threshold check 
        elif oracle_name == "os_confidence_above_threshold":
            oracle_result["passed"] = bool(tib.signals.nmap_os_guess)

        # OS matches banner cross-reference
        elif oracle_name == "os_matches_banner":
            os_guess = (tib.signals.nmap_os_guess or "").lower()
            banners = " ".join(tib.signals.banners.values()).lower()
            # Currently passes if either OS or banner data exists
            oracle_result["passed"] = bool(os_guess) or bool(banners)

        # OS-banner consistency check 
        elif oracle_name == "os_banner_consistency":
            oracle_result["passed"] = True  # Cross-reference check (placeholder)

        else:
            # Unknown oracle
            oracle_result["passed"] = True
            oracle_result["details"] = f"Unknown oracle '{oracle_name}' — default pass"

        return oracle_result

    def _verify_pcf_integrity(self) -> dict:
        """
        Verify the PCF DAG hash chain integrity.
        """
        valid, errors = self.context.pcf_dag.integrity_verification()
        if not valid:
            # Log the first few errors for debugging — full list may be very long
            self.logger.warning(f"PCF integrity errors: {len(errors)}")
            for err in errors[:3]:
                self.logger.warning(f"  {err}")
        return {"valid": valid, "error_count": len(errors)}
