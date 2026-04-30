"""
agents/tool_orchestrator_agent.py — Tool Orchestrator Agent.

PURPOSE:
    The Tool Orchestrator Agent is the SIXTH agent in the 9-step pipeline
    (Step 6). It is the ENGINE that actually executes scanning and probing
    actions by walking each device's PTG and invoking the appropriate phase
    modules (port scan, service probe, OS ID, exploitation).

    For each device, it:
      1. Checks for safety vetoes from SafetyOfficer / ImpactMonitor.
      2. Iterates over ready PTG nodes in priority order.
      3. Checks stop conditions (budget, RTT, timeouts, circuit breaker).
      4. Executes each node by delegating to the appropriate phase module.
      5. Records results in the PCF DAG and notifies Evidence + Validator.

INTER-AGENT COMMUNICATION:
    Receives:
        PlannerAgent    ──RESULT--> ToolOrchestratorAgent  (PTGs ready)
        SafetyOfficer   ──VETO───> ToolOrchestratorAgent   (block unsafe actions)
        ImpactMonitor   ──VETO───> ToolOrchestratorAgent   (block stressed devices)
        ImpactMonitor   ──ALERT──> ToolOrchestratorAgent   (breaker/RTT/budget alerts)
        ValidatorAgent  ──RESULT──> ToolOrchestratorAgent  (validation outcomes)

    Sends:
        ToolOrchestratorAgent ──RESULT──>  EvidenceAgent   (per-action results)
        ToolOrchestratorAgent ──REQUEST──> ValidatorAgent   (validation needed)
        ToolOrchestratorAgent ──STATUS──>  ImpactMonitor    (execution complete)

VETO CHECKING:
    Before executing any actions on a device, the orchestrator peeks its
    message queue for VETO messages targeting that device's IP. If a veto
    is found, ALL actions on that device are skipped. This is how the
    SafetyOfficer and ImpactMonitor enforce safety constraints.

CMDP POLICY:
    Optionally accepts a CMDP/DRL policy for intelligent action selection.
    When no policy is set, nodes are executed in the PTG's natural priority
    order (heuristic).

Executes PTG nodes by invoking tools via IC-ToolSpec contracts.
Manages parallelism. Reports results back to the planner.
Integrates with CMDP policy for action selection.

"""

import time
import logging
from typing import Optional
from agents.base import BaseAgent, AgentRole, AgentResult, AgentMessage, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class ToolOrchestratorAgent(BaseAgent):
    """
    Agent responsible for executing PTG nodes across all devices.

    This is the most complex agent — it bridges the planning layer (PTGs)
    with the execution layer (phase modules), while respecting safety
    constraints (vetoes), resource constraints (budgets, rate limits), and
    evidence requirements (PCF recording).
    """

    def __init__(self, context: SessionContext):
        # Register with the TOOL_ORCHESTRATOR role
        super().__init__(AgentRole.TOOL_ORCHESTRATOR, context)
        # Optional CMDP/DRL policy for intelligent action selection.
        # When None, nodes are executed in natural PTG priority order.
        self._cmdp_policy = None

    def set_cmdp_policy(self, policy) -> None:
        """
        Optionally set a CMDP policy for action selection.

        The CMDP (Constrained Markov Decision Process) policy selects which
        PTG node to execute next based on expected information gain vs. risk.
        If not set, the orchestrator falls back to the PTG's built-in
        priority ordering (heuristic approach).
        """
        self._cmdp_policy = policy

    def execute(self) -> AgentResult:
        """
        Execute PTG nodes across all devices using IC-ToolSpec contracts.
        Uses CMDP policy for action selection when available.

        FLOW:
            For each device with a PTG:
              1. Check for VETO messages — skip the entire device if vetoed.
              2. Loop: get ready nodes from PTG → check stop conditions →
                 execute node → record results → notify Evidence + Validator.
              3. Handle exceptions: TIBExhausted (budget gone), TIBViolation
                 (circuit breaker), general errors.
            After all devices: notify ImpactMonitor that execution is complete.

        Returns:
            AgentResult with total actions, findings count, and errors.
        """
        from TIB_and_PCF.TIB.TIB_structures import PentestPhase
        # from TIB_and_PCF.PCF import NodeType, EvidenceApproach
        # TIBViolation: raised when an action violates a TIB constraint (rate, etc.)
        # TIBExhausted: raised when the device's budget is fully spent
        from TIB_and_PCF.TIB.circuit_breaker import TIBViolation, TIBExhausted
        # from ptg.models import PTGNodeStatus

        total_actions = 0    # Count of successfully executed PTG nodes
        total_findings = 0   # Count of findings discovered across all devices
        errors = []          # Non-fatal error descriptions

        def _p(msg):
            self.context.progress(f"           {msg}")

        device_list = list(self.context.devices.items())
        device_total = len(device_list)

        # ── Execute phases 4-7 using PTG ─────────────────────────────────────
        _p(f"PTG execution: {device_total} devices to process...")
        for dev_idx, (ip, tib) in enumerate(device_list, 1):
            graph = self.context.get_ptg(ip)
            if not graph:
                continue

            # ── Veto check ───────────────────────────────────────────────────
            # Before executing any actions on this device, check if the
            # SafetyOfficer or ImpactMonitor has vetoed it. We use peek()
            # (non-destructive read) so the veto messages remain in the queue
            # for potential re-checking by other logic.
            if self.context.safety_officer_active:
                vetoes = [
                    m for m in self.context.message_bus.peek(self.role)
                    if m.message_type == MessageType.VETO
                    and m.payload.get("device_ip") == ip  # Veto targets this device
                ]
                if vetoes:
                    _p(f"[{dev_idx}/{device_total}] {ip} — VETOED by safety officer")
                    self.context.vetoed_actions += 1
                    continue

            # ── Execute ready nodes in priority order ────────────────────────
            # The PTG is a DAG with dependencies. get_ready_nodes() returns
            # nodes whose dependencies are all satisfied and that haven't been
            # executed, skipped, or failed yet.
            total_nodes = len(graph.get_all_nodes())
            nodes_done = 0
            _p(f"[{dev_idx}/{device_total}] {ip} ({tib.tier.name}) — {total_nodes} PTG nodes")
            while not graph.is_complete():
                ready_nodes = graph.get_ready_nodes()
                if not ready_nodes:
                    break

                for node in ready_nodes:
                    # ── Check stop conditions ────────────────────────────────
                    # Stop conditions are per-node safety checks:
                    #   - Budget remaining percentage
                    #   - RTT ratio (current vs. baseline — detects device stress)
                    #   - Consecutive timeouts (device may be unresponsive)
                    #   - Circuit breaker status (TRIPPED = device is stressed)

                    # Calculate remaining budget as a percentage (100% = untouched)
                    budget_pct = 100.0
                    if tib.config.max_budget_points > 0:
                        budget_pct = (
                            (tib.config.max_budget_points - tib.state.budget_spent)
                            / tib.config.max_budget_points * 100
                        )

                    # Calculate RTT ratio: how much slower is the device compared
                    # to its baseline? A ratio > 1.0 means the device is slower
                    # than normal, possibly due to our probing.
                    rtt_ratio = 1.0
                    if tib.state.baseline_rtt_ms and tib.state.current_rtt_ms:
                        rtt_ratio = tib.state.current_rtt_ms / tib.state.baseline_rtt_ms

                    # Check all stop conditions against the node's thresholds
                    triggered = graph.check_stop_conditions(
                        node, budget_pct, rtt_ratio,
                        tib.state.consecutive_timeouts,
                        tib.state.circuit_breaker_status,
                    )
                    if triggered:
                        fb = graph.activate_fallback(node.node_id)
                        if not fb:
                            graph.mark_skipped(
                                node.node_id,
                                f"Stop condition: {triggered.name}"
                            )
                            _p(f"  {ip} SKIPPED: {node.phase}/{node.name} — {triggered.name}")
                        continue

                    # ── Execute the node ─────────────────────────────────────
                    # Mark the node as RUNNING in the PTG (prevents re-execution)
                    graph.mark_running(node.node_id)

                    try:
                        # Delegate to _execute_ptg_node which maps the node's
                        # phase/tool_id to the appropriate scanning module
                        result = self._execute_ptg_node(ip, tib, node)

                        # Mark the node as COMPLETED in the PTG with its result
                        # and actual budget cost (may differ from estimated cost)
                        graph.mark_completed(
                            node.node_id,
                            result=result,
                            actual_cost=result.get("budget_cost", 0.0),
                        )
                        total_actions += 1
                        nodes_done += 1
                        n_findings = len(result.get("findings", []))

                        if result.get("findings"):
                            total_findings += len(result["findings"])
                            self.context.total_findings += len(result["findings"])

                        _p(f"  {ip} node {nodes_done}/{total_nodes}: "
                           f"{node.phase}/{node.name} — "
                           f"{n_findings} findings, cost={result.get('budget_cost', 0):.0f}")

                        # ── Notify Evidence Agent ────────────────────────────
                        # Send every action result to the Evidence Agent so it
                        # can record it in the PCF DAG and build proof bundles.
                        self.send_message(
                            AgentRole.EVIDENCE, MessageType.RESULT,
                            {"device_ip": ip, "node_id": node.node_id,
                             "tool_id": node.tool_id, "result": result},
                        )

                        # ── Notify Validator ─────────────────────────────────
                        # If this PTG node has validation oracles defined, send
                        # a REQUEST to the ValidatorAgent to validate the findings.
                        # Oracles check things like "does the OS guess match the
                        # banner?" or "is the TTL consistent?"
                        if node.validation_oracles:
                            self.send_message(
                                AgentRole.VALIDATOR, MessageType.REQUEST,
                                {"device_ip": ip, "node_id": node.node_id,
                                 "oracles": [o.name for o in node.validation_oracles],
                                 "result": result},
                            )

                    except TIBExhausted:
                        # Budget is fully spent — no more actions allowed on
                        # this device. Skip the current node and break out of
                        # the inner loop to move to the next device.
                        graph.mark_skipped(node.node_id, "Budget exhausted")
                        break
                    except TIBViolation as e:
                        # A TIB constraint was violated (e.g., rate limit exceeded).
                        # Try a fallback node; if none exists, mark as failed.
                        fb = graph.activate_fallback(node.node_id)
                        if not fb:
                            graph.mark_failed(node.node_id, str(e))
                    except Exception as e:
                        # Unexpected error — mark the node as failed and log it
                        graph.mark_failed(node.node_id, str(e))
                        errors.append(f"[{ip}] {node.name}: {e}")

        # ── Post-PTG: service probes + OS identification on all devices ─────
        from Discovery.service_probe import ServiceProbePhase
        from Discovery.os_identifier import OSIdentificationPhase
        _p(f"Post-PTG: service probes + OS identification on {device_total} devices...")
        for dev_idx, (ip, tib) in enumerate(device_list, 1):
            ports_count = len(tib.signals.open_ports)
            # Service probes only on devices with open ports
            if tib.signals.open_ports:
                _p(f"  [{dev_idx}/{device_total}] {ip} — service probe ({ports_count} ports)...")
                try:
                    tib.transition_phase(PentestPhase.SERVICE_PROBE)
                except ValueError:
                    pass
                svc = ServiceProbePhase(pcf_dag=self.context.pcf_dag, max_threads=3)
                svc.run([tib])
                vuln_findings = getattr(tib.state, 'vuln_findings', [])
                if vuln_findings:
                    total_findings += len(vuln_findings)
                    self.context.total_findings += len(vuln_findings)
                    _p(f"    {ip} — {len(vuln_findings)} vulnerabilities found")
                total_actions += 1

            # OS identification runs on ALL devices
            _p(f"  [{dev_idx}/{device_total}] {ip} — OS identification...")
            try:
                tib.transition_phase(PentestPhase.OS_IDENTIFICATION)
            except ValueError:
                pass
            os_phase = OSIdentificationPhase(pcf_dag=self.context.pcf_dag)
            os_phase.run([tib])
            total_actions += 1
            os_result = tib.signals.nmap_os_guess or "Unknown"
            dtype = tib.signals.device_type or ""
            _p(f"    {ip} → OS={os_result}  type={dtype}")

        # ── Post-PTG exploitation: run on ALL devices with open ports ────────
        # The PTG exploitation may have been skipped due to fleet pruning,
        # budget, or tier restrictions. This ensures every device with services
        # gets CVE database matching, real credential testing, and active config weakness verification.
        #
        # When --exploit-all is active, CRITICAL devices are included (dry_run
        # mode) and every device gets a budget top-up to guarantee exploitation
        # can proceed even if earlier phases consumed the budget.
        from exploitation.safe_exploit_runner import SafeExploitRunner
        from TIB_and_PCF.TIB.TIB_structures import DeviceTier

        exploit_all = self.context.exploit_all
        if exploit_all:
            _p(f"Post-PTG exploitation: --exploit-all active, targeting ALL {device_total} devices...")
        else:
            _p(f"Post-PTG exploitation: checking all devices...")

        # Minimum budget reserved for exploitation when --exploit-all is set.
        # This guarantees at least 3 safe-mode exploit attempts per device.
        _EXPLOIT_BUDGET_FLOOR = 50.0

        for dev_idx, (ip, tib) in enumerate(device_list, 1):
            # ── Tier gate (skippable with --exploit-all) ────────────────────
            if tib.tier == DeviceTier.CRITICAL and not exploit_all:
                _p(f"  [{dev_idx}/{device_total}] {ip} — CRITICAL tier, exploitation skipped")
                continue
            if not tib.signals.open_ports and not tib.signals.banners:
                continue  # No services discovered — nothing to exploit

            # ── Budget top-up for --exploit-all ─────────────────────────────
            # If earlier phases consumed the budget, inject enough headroom
            # so exploitation isn't starved by prior scanning costs.
            if exploit_all:
                remaining = tib.config.max_budget_points - tib.state.budget_spent
                if remaining < _EXPLOIT_BUDGET_FLOOR:
                    top_up = _EXPLOIT_BUDGET_FLOOR - remaining
                    tib.config.max_budget_points += top_up
                    _p(f"    {ip} budget topped up by {top_up:.0f} pts for exploitation")

            # ── Select exploitation mode based on tier ──────────────────────
            if tib.tier == DeviceTier.CRITICAL:
                mode = "dry_run"       # Simulate only — never send packets to CRITICAL
            elif tib.tier == DeviceTier.FRAGILE:
                mode = "safe"          # Low-impact exploits only
            elif tib.tier in (DeviceTier.MODERATE, DeviceTier.UNKNOWN):
                mode = "safe"          # Safe mode for moderate/unknown
            else:
                mode = "moderate"      # ROBUST gets moderate exploitation

            _p(f"  [{dev_idx}/{device_total}] {ip} — exploitation ({mode} mode, "
               f"tier={tib.tier.name})...")
            try:
                runner = SafeExploitRunner(self.context.pcf_dag)
                exploit_results = runner.run_for_device(tib, mode)
                if exploit_results:
                    if not hasattr(tib.state, 'vuln_findings'):
                        tib.state.vuln_findings = []
                    for er in exploit_results:
                        success = er.get("success", False)
                        eid = er.get("exploit_id", "?")
                        _p(f"    {ip} exploit: {eid} — {'SUCCESS' if success else 'no match'}")
                        if success or er.get("dry_run"):
                            total_findings += 1
                            self.context.total_findings += 1
                            tib.state.vuln_findings.append({
                                "type": "exploit",
                                "exploit_id": eid,
                                "severity": er.get("evidence", {}).get("severity", "HIGH") if success else "INFO",
                                "detail": f"Exploit: {eid} — {str(er.get('evidence', {}))[:120]}",
                                "confidence": er.get("confidence", 0),
                                "success": success,
                            })
                    total_actions += 1
            except Exception as e:
                _p(f"    {ip} exploitation error: {e}")

        _p(f"Post-PTG complete: {total_actions} actions, {total_findings} findings")

        # ── Notify Impact Monitor ────────────────────────────────────────────
        # Send a STATUS message indicating that all PTG execution is complete.
        # The ImpactMonitor runs at Step 7 and uses this as a cue.
        self.send_message(
            AgentRole.IMPACT_MONITOR, MessageType.STATUS,
            {"phase": "execution_complete",
             "total_actions": total_actions},
        )

        return AgentResult(
            success=True,
            data={"actions": total_actions, "findings": total_findings},
            errors=errors,
            actions_taken=total_actions,
        )

    def _execute_ptg_node(self, ip: str, tib, node) -> dict:
        """
        Execute a single PTG node by invoking the appropriate phase code.

        This method is the DISPATCH TABLE that maps a PTG node's phase and
        tool_id to actual scanning functions. Each phase module (port scan,
        service probe, OS ID, exploitation) is invoked through its respective
        Python class.

        Args:
            ip   — Target device IP address.
            tib  — The device's TIBManager (for state, signals, circuit breaker).
            node — The PTG node to execute (has phase, tool_id, safe_mode, etc.).

        Returns:
            Dict with keys: tool_id, safe_mode, budget_cost, findings, duration_ms.
        """
        from TIB_and_PCF.TIB.TIB_structures import PentestPhase
        from TIB_and_PCF.PCF import NodeType, EvidenceApproach

        # Initialize the result dict with defaults
        result = {"tool_id": node.tool_id, "safe_mode": node.safe_mode,
                  "budget_cost": 0.0, "findings": []}
        start_time = time.time()  # Track execution duration

        # Determine which phase module to invoke based on the node's phase string
        phase = node.phase

        if phase == "PORT_SCAN":
            # Phase 4: Port scanning — discovers open TCP/UDP ports.
            # Transition the TIB's phase state machine (may already be in
            # this phase, hence the try/except for ValueError).
            try:
                tib.transition_phase(PentestPhase.PORT_SCAN)
            except ValueError:
                pass  # Already in this phase — safe to ignore
            from Discovery.port_scan import PortScanPhase
            phase4 = PortScanPhase(
                pcf_dag=self.context.pcf_dag,
                # Limit thread count to 3 per device to avoid overwhelming
                # the target or causing network congestion
                max_threads=min(self.context.max_threads, 3),
            )
            phase4.run([tib])  # Run port scan on this single device
            # Collect findings: each open port is a finding
            result["findings"] = [{"type": "open_port", "port": p}
                                  for p in tib.signals.open_ports]

            # If port scan found new ports, run service probe + OS ID immediately
            # so vulnerability checks see the discovered ports
            if tib.signals.open_ports:
                try:
                    tib.transition_phase(PentestPhase.SERVICE_PROBE)
                except ValueError:
                    pass
                from Discovery.service_probe import ServiceProbePhase
                svc = ServiceProbePhase(pcf_dag=self.context.pcf_dag, max_threads=3)
                svc.run([tib])
                result["findings"].extend([{"type": "service", "port": p, "banner": b}
                                           for p, b in tib.signals.banners.items()])
                vuln_findings = getattr(tib.state, 'vuln_findings', [])
                if vuln_findings:
                    result["findings"].extend(vuln_findings)

                try:
                    tib.transition_phase(PentestPhase.OS_IDENTIFICATION)
                except ValueError:
                    pass
                from Discovery.os_identifier import OSIdentificationPhase
                os_phase = OSIdentificationPhase(pcf_dag=self.context.pcf_dag)
                os_phase.run([tib])
                if tib.signals.nmap_os_guess:
                    result["findings"].append({"type": "os_id", "os": tib.signals.nmap_os_guess})

        elif phase == "SERVICE_PROBE":
            # Phase 5: Service probing — banner grabbing on open ports.
            # Identifies what software is running on each port.
            try:
                tib.transition_phase(PentestPhase.SERVICE_PROBE)
            except ValueError:
                pass
            from Discovery.service_probe import ServiceProbePhase
            phase5 = ServiceProbePhase(
                pcf_dag=self.context.pcf_dag,
                max_threads=min(self.context.max_threads, 3),
            )
            phase5.run([tib])
            # Collect findings: service banners + vulnerability findings
            result["findings"] = [{"type": "service", "port": p, "banner": b}
                                  for p, b in tib.signals.banners.items()]
            # Add vulnerability findings from service probe
            vuln_findings = getattr(tib.state, 'vuln_findings', [])
            if vuln_findings:
                result["findings"].extend(vuln_findings)

        elif phase == "OS_IDENTIFICATION":
            # Phase 6: OS identification — TCP/IP stack fingerprinting.
            # Uses techniques like TTL analysis, TCP window size, and
            # nmap-style OS detection.
            try:
                tib.transition_phase(PentestPhase.OS_IDENTIFICATION)
            except ValueError:
                pass
            from Discovery.os_identifier import OSIdentificationPhase
            phase6 = OSIdentificationPhase(pcf_dag=self.context.pcf_dag)
            phase6.run([tib])
            # Only record a finding if an OS guess was obtained
            if tib.signals.nmap_os_guess:
                result["findings"] = [{"type": "os_id",
                                       "os": tib.signals.nmap_os_guess}]

        elif phase == "EXPLOITATION":
            # Phase 7: Exploitation — CVE database matching, real credential testing, active config verification
            try:
                tib.transition_phase(PentestPhase.EXPLOITATION)
            except ValueError:
                pass
            from exploitation.safe_exploit_runner import SafeExploitRunner
            self.context.progress(
                f"           ⚡ {ip} — exploitation ({node.safe_mode} mode, "
                f"tier={tib.tier.name})..."
            )
            runner = SafeExploitRunner(self.context.pcf_dag)
            exploit_results = runner.run_for_device(tib, node.safe_mode)
            result["findings"] = exploit_results

            # Store exploitation findings in tib.state.vuln_findings so they
            # appear in the report alongside service probe vulnerabilities
            if exploit_results:
                if not hasattr(tib.state, 'vuln_findings'):
                    tib.state.vuln_findings = []
                for er in exploit_results:
                    success = er.get("success", False)
                    eid = er.get("exploit_id", "?")
                    status = "SUCCESS" if success else "checked"
                    self.context.progress(
                        f"             {ip} exploit: {eid} — {status}"
                    )
                    # Add successful exploits and dry-run results as vulnerability findings
                    if success or er.get("dry_run"):
                        tib.state.vuln_findings.append({
                            "type": "exploit",
                            "exploit_id": eid,
                            "severity": er.get("evidence", {}).get("severity", "HIGH") if success else "INFO",
                            "detail": f"Exploit {eid}: {er.get('evidence', {}).get('description', er.get('evidence', {}).get('weakness', str(er.get('evidence', {}))[:100]))}",
                            "confidence": er.get("confidence", 0),
                            "success": success,
                            "dry_run": er.get("dry_run", False),
                        })

        elif node.tool_id == "__internal_tib_classify":
            # Internal pseudo-node: TIB classification has already been done
            # by the TargetProfilingAgent in Phase 3. This node exists in the
            # PTG for completeness/tracking but requires no action.
            pass

        elif phase in ("PASSIVE_RECON", "HOST_DISCOVERY", "FINGERPRINTING"):
            # These phases were already handled by the DiscoveryAgent and
            # TargetProfilingAgent respectively. The PTG includes them as
            # nodes for tracking/evidence purposes, but they are no-ops here.
            pass

        # Record the budget spent by this action (read from TIB state which
        # is updated by the phase modules as they consume budget)
        result["budget_cost"] = tib.state.budget_spent
        # Calculate execution duration in milliseconds
        result["duration_ms"] = (time.time() - start_time) * 1000

        # ── Record the action in the PCF DAG ────────────────────────────────
        # Every tool invocation gets a PROBE node in the evidence chain,
        # creating a tamper-evident record of what was done, when, and how.
        pcf_id = self.context.pcf_dag.add_node(
            node_type=NodeType.PROBE,          # This was an active probe
            phase=phase,                       # Which pentest phase it belongs to
            payload={"tool_id": node.tool_id, "safe_mode": node.safe_mode,
                     "duration_ms": result["duration_ms"]},
            parent_ids=[tib.pcf_device_root_id],  # Link to device's PCF root
            evidence_approaches=EvidenceApproach.ACTIVE,   # Active observation (we sent packets)
            device_ip=ip,
        )
        # Store the PCF node ID on the PTG node for cross-referencing
        # between the attack plan (PTG) and the evidence chain (PCF)
        node.pcf_node_id = pcf_id

        return result
