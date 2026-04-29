"""
agents/planner_agent.py — Planner Agent.

PURPOSE:
    The Planner Agent is the FOURTH agent in the 9-step pipeline (Step 4).
    It builds a Per-Target Graph (PTG) for each device — a DAG of tool
    invocations that defines WHAT to run, in WHAT order, and with WHAT
    fallback strategies.

    Each PTG is tailored to the device's tier and known signals:
      - STANDARD devices get full graphs (port scan, service probe, OS ID,
        exploitation).
      - FRAGILE devices get reduced graphs (no aggressive exploitation).
      - CRITICAL devices get minimal, safe-mode-only graphs.
      - Devices that are non-representative members of a fleet cluster get
        pruned graphs (skip deep probing; rely on the representative's results).

INTER-AGENT COMMUNICATION:
    Receives:
        TargetProfilingAgent ──RESULT──> PlannerAgent
          (tier summary and device count)
        FleetReasonerAgent   ──RESULT──> PlannerAgent
          (cluster info for probe reduction)

    Sends:
        PlannerAgent ──RESULT──> ToolOrchestratorAgent
          (PTGs are built and ready for execution)

FLEET OPTIMIZATION:
    If the FleetReasonerAgent has clustered devices, non-representative
    devices (i.e., devices similar to the cluster representative) get
    pruned PTGs. Exploitation and deep port scan nodes are marked as SKIPPED,
    since the representative's results can be propagated to them later.

Uses the CMDP policy to prioritize nodes when available.

Paper reference: Section VI-B item 3
"""

import logging
from agents.base import BaseAgent, AgentRole, AgentResult, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class PlannerAgent(BaseAgent):
    """
    Agent responsible for building Per-Target Graphs (PTGs) for all devices.

    A PTG defines the scanning plan for a single device as a DAG of nodes,
    where each node represents a tool invocation (port scan, banner grab,
    OS fingerprint, exploit attempt, etc.). Nodes have dependencies,
    fallback edges, stop conditions, and risk tiers.
    """

    def __init__(self, context: SessionContext):
        # Register with the PLANNER role for message bus addressing
        super().__init__(AgentRole.PLANNER, context)

    def execute(self) -> AgentResult:
        """
        Build TIB-PTG for each device based on tier and signals.

        FLOW:
            1. Ensure all built-in tools are registered in the IC-ToolSpec registry.
            2. For each device:
               a. Determine if it has OT/industrial ports.
               b. Build a full PTG from the device's tier and known signals.
               c. If the device is a non-representative fleet member, prune
                  the PTG to skip deep probing (exploitation, full port scan).
               d. Store the PTG in SessionContext.
            3. Notify ToolOrchestratorAgent that PTGs are ready.

        Returns:
            AgentResult with graphs_built count and any errors.
        """
        from ptg.builder import PTGBuilder
        from IC_ToolSpec.builtin_tools import register_all_builtin_tools
        from TIB_and_PCF.TIB.device_classifier import INDUSTRIAL_PORTS  # Ports like 502 (Modbus), 102 (S7)

        # Ensure all IC-ToolSpec tool definitions are loaded into the registry.
        # This is idempotent — safe to call multiple times.
        register_all_builtin_tools()

        # Create the PTG builder with access to the tool registry so it can
        # look up tool contracts (preconditions, cost, risk tier) when adding
        # nodes to the graph.
        builder = PTGBuilder(self.context.tool_registry)
        graphs_built = 0
        errors = []

        # ── Build a PTG for each registered device ───────────────────────────
        for ip, tib in self.context.devices.items():
            try:
                # Check if this device has any industrial/OT protocol ports open.
                # INDUSTRIAL_PORTS includes Modbus (502), S7 (102), EtherNet/IP
                # (44818), BACnet (47808), DNP3 (20000), etc.
                # This flag tells the builder to include OT-specific tool nodes.
                is_ot = any(p in INDUSTRIAL_PORTS for p in tib.signals.open_ports)

                # Build the base PTG for this device. The builder selects nodes
                # based on the device's tier (how aggressive to be) and known
                # signals (which ports/services to probe).
                graph = builder.build(
                    target_ip=ip,
                    tier=tib.tier,                          # STANDARD/FRAGILE/CRITICAL
                    known_ports=tib.signals.open_ports,     # Ports already discovered
                    has_snmp=bool(tib.signals.snmp_sysdescr),  # SNMP available?
                    is_ot=is_ot,                            # Industrial device?
                )

                # ── Fleet optimization: prune non-representative devices ─────
                # If this device belongs to a fleet cluster and is NOT the
                # representative, we don't need full probing — the representative's
                # results will be propagated to this device by FleetReasonerAgent.
                cluster_id = self.context.fleet_clusters.get(ip, {}).get("cluster_id")
                if cluster_id:
                    cluster = self.context.fleet_clusters.get(cluster_id, {})
                    rep_ip = cluster.get("representative_ip", "")
                    # Only prune if there IS a representative and it's NOT this device
                    if rep_ip and rep_ip != ip:
                        # Rebuild with a simpler config (no SNMP probing)
                        graph = builder.build(
                            target_ip=ip,
                            tier=tib.tier,
                            known_ports=tib.signals.open_ports,
                            has_snmp=False,  # Skip SNMP — representative will cover it
                            is_ot=is_ot,
                        )
                        # Skip deep probing phases for non-representative devices.
                        # Keep discovery + fingerprint + TIB phases since they are
                        # needed for basic confirmation that the device matches
                        # the cluster hypothesis.
                        for node in graph.get_all_nodes():
                            if node.phase in ("EXPLOITATION", "PORT_SCAN"):
                                graph.mark_skipped(
                                    node.node_id,
                                    "Fleet non-representative: skip deep probing"
                                )

                # Store the finished PTG in the session context so the
                # ToolOrchestratorAgent can execute it.
                self.context.set_ptg(ip, graph)
                graphs_built += 1

            except Exception as e:
                errors.append(f"PTG build error for {ip}: {e}")

        # ── Notify ToolOrchestratorAgent ─────────────────────────────────────
        # Send a RESULT message so the orchestrator knows PTGs are ready
        # for execution at Step 6 of the pipeline.
        self.send_message(
            AgentRole.TOOL_ORCHESTRATOR, MessageType.RESULT,
            {"phase": "planning", "graphs_built": graphs_built},
        )

        return AgentResult(
            success=graphs_built > 0,  # Fail if we couldn't build any PTGs
            data={"graphs_built": graphs_built},
            errors=errors,
        )
