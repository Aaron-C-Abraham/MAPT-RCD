import time
import json
import os
import logging
from typing import Optional, List

from TIB_and_PCF.TIB.TIB_structures import DeviceTier
from agents.session_context import SessionContext
from agents.discovery_agent import DiscoveryAgent
from agents.target_profiling_agent import TargetProfilingAgent
from agents.planner_agent import PlannerAgent
from agents.tool_orchestrator_agent import ToolOrchestratorAgent
from agents.impact_monitor_agent import ImpactMonitorAgent
from agents.validator_agent import ValidatorAgent
from agents.safety_officer_agent import SafetyOfficerAgent
from agents.evidence_agent import EvidenceAgent
from agents.fleet_reasoner_agent import FleetReasonerAgent

logger = logging.getLogger(__name__)


class AgentCoordinator:
    """
    Top-level coordinator for the TRUCE-PT multi-agent system.

    NOT a BaseAgent subclass — the coordinator does not participate in
    inter-agent messaging. It is the external driver that calls each
    agent's execute() method in the correct order and collects results.
    """

    def __init__(self, context: SessionContext):
        self.context = context

        # Each agent receives the same SessionContext, giving it access to:
        #   - The device registry (devices dict)
        #   - The PCF DAG (evidence chain)
        #   - The message bus (inter-agent communication)
        #   - PTG graphs, fleet clusters, metrics, etc.
        self.discovery_agent = DiscoveryAgent(context)         # Step 1
        self.profiling_agent = TargetProfilingAgent(context)   # Step 2
        self.planner_agent = PlannerAgent(context)             # Step 4
        self.tool_orchestrator = ToolOrchestratorAgent(context)  # Step 6
        self.impact_monitor = ImpactMonitorAgent(context)      # Step 7
        self.validator_agent = ValidatorAgent(context)         # Step 8
        self.safety_officer = SafetyOfficerAgent(context)      # Step 5
        self.evidence_agent = EvidenceAgent(context)           # Step 9
        self.fleet_reasoner = FleetReasonerAgent(context)      # Step 3 + POST

        # Stores per-step results for inclusion in the final report
        self._results = {}

    def _progress(self, msg):
        """Print progress to stdout if callback is set."""
        if self._progress_cb:
            self._progress_cb(msg)

    def run(self, cmdp_policy=None, progress_cb=None) -> dict:
        """Execute the full multi-agent workflow."""
        self._progress_cb = progress_cb
        self.context.progress_cb = progress_cb  # Share with all agents/modules
        if cmdp_policy:
            self.tool_orchestrator.set_cmdp_policy(cmdp_policy)

        self._progress("[Step 1/9] Discovery — scanning for live hosts...")
        self._progress("           Sending ICMP pings (round 1)...")
        discovery_result = self.discovery_agent.execute()
        self._results["discovery"] = discovery_result.data
        device_count = discovery_result.data.get("discovered", 0)
        self._progress(f"           Found {device_count} devices")
        if not discovery_result.success:
            self._progress("           No devices found. Aborting.")
            return self._finalize()

        # Show discovered devices
        for tib in self.context.all_tibs():
            s = tib.get_summary()
            name = s.get("device_name") or s.get("hostname") or ""
            mac = s.get("mac", "")
            vendor = s.get("vendor", "Unknown")[:25]
            name_str = f" ({name})" if name else ""
            self._progress(f"             {s['ip']:<17} {mac:<19} {vendor}{name_str}")

        self._progress(f"[Step 2/9] Target Profiling — fingerprinting {device_count} devices...")
        profiling_result = self.profiling_agent.execute()
        self._results["profiling"] = profiling_result.data
        tier_info = profiling_result.data.get("tier_summary", {})
        if tier_info:
            parts = [f"{k}:{v}" for k, v in tier_info.items() if v > 0]
            self._progress(f"           Tiers: {' | '.join(parts)}")
        # Show tier assignments
        for tib in self.context.all_tibs():
            s = tib.get_summary()
            ports = s["findings"]["open_ports"]
            ports_str = ",".join(str(p) for p in ports[:8]) if ports else "none"
            os_h = s["findings"]["os_hint"]
            self._progress(f"             {s['ip']:<17} {s['current_tier']:<10} ports=[{ports_str}]  os={os_h}")

        self._progress("[Step 3/9] Fleet Reasoner — clustering similar devices...")
        fleet_result = self.fleet_reasoner.execute()
        self._results["fleet"] = fleet_result.data
        clusters = fleet_result.data.get("clusters", 0)
        self._progress(f"           {clusters} cluster(s) formed")
        # Show cluster details
        shown_clusters = set()
        for key, val in self.context.fleet_clusters.items():
            if not isinstance(val, dict):
                continue
            cid = val.get("cluster_id", "")
            if not cid or cid in shown_clusters:
                continue
            shown_clusters.add(cid)
            members = val.get("member_ips", [])
            rep = val.get("representative_ip", "")
            hypothesis = val.get("hypothesis", "")
            confidence = val.get("confidence", 0)
            self._progress(f"             Cluster {cid[:12]}: {len(members)} devices, "
                           f"confidence={confidence:.0%}")
            self._progress(f"               Hypothesis: {hypothesis}")
            self._progress(f"               Representative: {rep}")
            for m_ip in members:
                role = "★ REP" if m_ip == rep else "  member"
                tib = self.context.get_device(m_ip)
                vendor = tib.signals.oui_vendor[:20] if tib else "?"
                self._progress(f"               {role}  {m_ip:<17} {vendor}")

        self._progress("[Step 4/9] Planner — building attack plans (PTG)...")
        planner_result = self.planner_agent.execute()
        self._results["planner"] = planner_result.data
        graphs = planner_result.data.get("graphs_built", 0)
        self._progress(f"           {graphs} Per-Target Graphs built")

        if self.context.safety_officer_active:
            self._progress("[Step 5/9] Safety Officer — reviewing OT safety constraints...")
            safety_result = self.safety_officer.execute()
            self._results["safety"] = safety_result.data
            vetoes = safety_result.data.get("vetoes_issued", 0)
            self._progress(f"           {vetoes} action(s) vetoed")
        else:
            self._progress("[Step 5/9] Safety Officer — skipped (no OT devices)")
            self._results["safety"] = {"skipped": True}

        self._progress("[Step 6/9] Tool Orchestrator — port scan, service probe, exploitation, OS ID...")
        execution_result = self.tool_orchestrator.execute()
        self._results["execution"] = execution_result.data
        actions = execution_result.data.get("actions", 0)
        findings = execution_result.data.get("findings", 0)
        self._progress(f"           {actions} actions, {findings} findings")
        # Show per-device results summary
        self._progress(f"           {'IP':<17} {'TYPE':<22} {'PORTS':>5} {'VULNS':>5} "
                        f"{'OS':<25} {'BREAKER':<8} {'BUDGET'}")
        for tib in self.context.all_tibs():
            s = tib.get_summary()
            ports = s["findings"]["open_ports"]
            vulns = s["findings"].get("vulnerabilities", [])
            os_h = s["findings"]["os_hint"][:24]
            dtype = (s.get("device_type", "") or s["current_tier"])[:21]
            breaker = s["circuit_breaker"]
            b = s["budget"]
            self._progress(
                f"           {s['ip']:<17} {dtype:<22} {len(ports):>5} {len(vulns):>5} "
                f"{os_h:<25} {breaker:<8} "
                f"{b['budget_spent']:.0f}/{b['budget_total']:.0f}"
            )
        # Show PTG execution summary per device
        self._progress("")
        self._progress("           PTG Execution Summary:")
        for ip, graph in self.context.ptg_graphs.items():
            summary = graph.summary()
            by_st = summary.get("by_status", {})
            completed = by_st.get("completed", 0) + by_st.get("validated", 0)
            skipped = by_st.get("skipped", 0)
            failed = by_st.get("failed", 0)
            total_n = summary.get("total_nodes", 0)
            # Check if exploitation nodes were in this PTG
            exploit_nodes = [n for n in graph.get_all_nodes() if n.phase == "EXPLOITATION"]
            exploit_ran = [n for n in exploit_nodes if n.status.value in ("completed", "validated")]
            exploit_skip = [n for n in exploit_nodes if n.status.value == "skipped"]
            exploit_str = ""
            if exploit_nodes:
                exploit_str = f" | exploits: {len(exploit_ran)} ran, {len(exploit_skip)} skipped"
            self._progress(
                f"             {ip:<17} {completed}/{total_n} completed, "
                f"{skipped} skipped, {failed} failed{exploit_str}"
            )

        self._progress("[Step 7/9] Impact Monitor — checking device health...")
        monitor_result = self.impact_monitor.execute()
        self._results["monitoring"] = monitor_result.data
        alerts = monitor_result.data.get("alerts", 0)
        self._progress(f"           {alerts} alert(s)")

        self._progress("[Step 8/9] Validator — validating findings with oracles...")
        validator_result = self.validator_agent.execute()
        self._results["validation"] = validator_result.data
        validated = validator_result.data.get("validated", 0)
        rejected = validator_result.data.get("rejected", 0)
        self._progress(f"           {validated} validated, {rejected} rejected")

        self._progress("[Step 9/9] Evidence — building proof bundles...")
        evidence_result = self.evidence_agent.execute()
        self._results["evidence"] = evidence_result.data
        bundles = evidence_result.data.get("bundles_created", 0)
        self._progress(f"           {bundles} proof bundle(s) created")

        if fleet_result.data.get("clusters", 0) > 0:
            self._progress("[Post]     Fleet hypothesis propagation...")
            fleet_post = self.fleet_reasoner.execute()
            self._results["fleet_post"] = fleet_post.data

        # Finalize and return results 
        return self._finalize()

    def _finalize(self) -> dict:
        """
        Finalize session and produce the comprehensive results dict
        """
        # Verify the PCF DAG's cryptographic hash chain one final time
        valid, errors = self.context.pcf_dag.integrity_verification()

        results = {
            "session_start": self.context.start_time,
            "session_end": time.time(),
            "duration_sec": round(time.time() - self.context.start_time, 1),
            "networks": self.context.networks,
            "device_count": len(self.context.devices),
            "exploit_all": self.context.exploit_all,
            "pcf_integrity": {"valid": valid, "error_count": len(errors)},
            "metrics": self.context.get_session_metrics(),
            "agent_results": self._results,
            # Build tier summary using dynamic import of DeviceTier enum
            "tier_summary": {
                tier.name: len(self.context.tibs_by_tier(tier))
                for tier in DeviceTier
            },
            # Per-device summaries with key stats (IP, vendor, tier, ports, budget)
            "devices": [tib.get_summary() for tib in self.context.all_tibs()],
        }

        # Include the Safety Officer's compliance report if OT mode was active.
        # This provides audit-ready documentation of what was vetoed and why.
        if self.context.safety_officer_active:
            results["safety_compliance"] = self.safety_officer.get_compliance_report()

        # Include the total number of proof bundles (the bundles themselves
        # are in the engagement ledger, not in the results JSON)
        results["proof_bundles"] = len(self.evidence_agent.get_proof_bundles())

        # Include PTG execution summaries for each device. Each summary
        # contains node counts by status (completed, skipped, failed, etc.)
        results["ptg_summaries"] = {
            ip: graph.summary()
            for ip, graph in self.context.ptg_graphs.items()
        }

        return results

    def save_results(self, output_path: str = "results.json",
                     pcf_path: str = "pcf_evidence.json",
                     ledger_path: str = "engagement_ledger.json") -> None:
        """
        Save all session outputs to disk
        """
        # Generate the final results dict
        results = self._finalize()

        # Write the main results file (session summary + per-agent data)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to {output_path}")

        # Save the PCF DAG (all evidence nodes with hashes)
        self.context.pcf_dag.save(pcf_path)
        logger.info(f"PCF DAG saved to {pcf_path}")

        # Export the engagement ledger (proof bundles + integrity checks)
        try:
            self.evidence_agent.export_engagement_ledger(ledger_path)
        except Exception as e:
            logger.error(f"Ledger export error: {e}")

    def print_summary(self) -> None:
        metrics = self.context.get_session_metrics()
        # ANSI escape codes for bold text in terminal output
        BOLD = "\033[1m"
        RESET = "\033[0m"

        #  Header section: key session metrics 
        print(f"\n{'='*72}")
        print(f"  {BOLD} MAPT-RCD SCAN COMPLETE{RESET}")
        print(f"  Duration: {metrics['duration_sec']:.0f}s  |  "
              f"Devices: {metrics['device_count']}  |  "
              f"Findings: {metrics['total_findings']}  |  "
              f"Validated: {metrics['validated_findings']}")
        print(f"  Instability Events: {metrics['instability_events']}  |  "
              f"Vetoed: {metrics['vetoed_actions']}  |  "
              f"Fleet Clusters: {metrics['fleet_clusters']}")
        print(f"  PCF Nodes: {metrics['pcf_nodes']}  |  "
              f"PTG Graphs: {metrics['ptg_graphs']}")
        print(f"{'='*72}")

        # Per-tier device breakdown
        # Group devices by their tier and print a summary for each device
        # showing IP, vendor, open ports, and budget consumption.
        from TIB_and_PCF.TIB.TIB_structures import DeviceTier
        for tier in DeviceTier:
            devices = self.context.tibs_by_tier(tier)
            if not devices:
                continue  # Skip tiers with no devices
            print(f"\n  {BOLD}{tier.name}{RESET} ({len(devices)} devices)")
            for tib in devices:
                s = tib.get_summary()
                b = s["budget"]
                ports = s["findings"]["open_ports"] or "none"
                mac = s.get("mac", "")
                # Format: IP, MAC, vendor, ports, budget
                print(f"    {s['ip']:16}  {mac:18}  {s['vendor'][:25]:25}  "
                      f"ports={ports}  "
                      f"budget={b['budget_spent']:.0f}/{b['budget_total']}pts")

        print(f"\n{'='*72}\n")

def run_agent_scan(
    networks: List[str],
    oui_db_path: Optional[str] = None,
    passive_only: bool = False,
    max_threads: int = 10,
    output_path: str = "results.json",
    pcf_path: str = "pcf_evidence.json",
    use_cmdp: bool = False,
    exploit_all: bool = False,
    progress_cb=None,
) -> dict:
    """
    Entry point for the agent-based scan workflow
    """
    from TIB_and_PCF.TIB.device_classifier import OUIDatabase
    from IC_ToolSpec.builtin_tools import register_all_builtin_tools

    # Load OUI database 
    # The OUI database maps MAC address prefixes (first 3 bytes) to vendor
    # names. This is used during discovery
    # and TIB classification to identify device manufacturers.
    oui_db = None
    if oui_db_path:
        try:
            oui_db = OUIDatabase(oui_db_path)
        except FileNotFoundError:
            logger.warning(f"OUI database not found: {oui_db_path}")

    # Register built-in tools
    # Load all IC-ToolSpec tool definitions (port scanners, service probers,
    # OS fingerprinters, exploit runners, etc.) into the global registry.
    # This is idempotent — safe to call multiple times.
    register_all_builtin_tools()

    #  Create session context
    # The SessionContext is the single source of truth for the entire session.
    # It is shared by all agents and holds devices, PCF DAG, message bus, etc.
    # output_dir is derived from the output_path so all agents can write to it.
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)
    context = SessionContext(
        networks=networks,
        oui_db=oui_db,
        passive_only=passive_only,
        max_threads=max_threads,
        output_dir=output_dir,
        exploit_all=exploit_all,
    )

    #  Create coordinator
    # The coordinator instantiates all 9 agents and drives the pipeline.
    coordinator = AgentCoordinator(context)

    # If use_cmdp is True, try to load a CMDP (Constrained Markov Decision
    # Process) policy. This policy uses reinforcement learning to select
    # which PTG node to execute next, balancing information gain against
    # risk and budget constraints. Falls back to heuristic if unavailable.
    cmdp_policy = None
    if use_cmdp:
        try:
            from cmdp.policy import HeuristicPolicy
            cmdp_policy = HeuristicPolicy()
        except ImportError:
            logger.warning("CMDP policy not available, using heuristic")

    results = coordinator.run(cmdp_policy=cmdp_policy, progress_cb=progress_cb)

    # Produces three files: results.json, pcf_evidence.json, engagement_ledger.json
    # Put the ledger in the same directory as results
    ledger_path = os.path.join(os.path.dirname(output_path), "engagement_ledger.json")
    coordinator.save_results(output_path, pcf_path, ledger_path)

    # Only print summary if no progress callback (standalone mode)
    if not progress_cb:
        coordinator.print_summary()

    return results
