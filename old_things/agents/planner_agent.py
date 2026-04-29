import logging
from agents.base import BaseAgent, AgentRole, AgentResult, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class PlannerAgent(BaseAgent):
    """
    Agent responsible for building Per-Target Graphs (PTGs) for all devices
    """

    def __init__(self, context: SessionContext):
        super().__init__(AgentRole.PLANNER, context)

    def execute(self) -> AgentResult:
        """
        Build TIB-PTG for each device based on tier and signal
        """
        from ptg.builder import PTGBuilder
        from IC_ToolSpec.builtin_tools import register_all_builtin_tools
        from TIB_and_PCF.TIB.device_classifier import INDUSTRIAL_PORTS 
        register_all_builtin_tools()
        builder = PTGBuilder(self.context.tool_registry)
        graphs_built = 0
        errors = []

        for ip, tib in self.context.devices.items():
            try:
                is_ot = any(p in INDUSTRIAL_PORTS for p in tib.signals.open_ports)
                graph = builder.build(
                    target_ip=ip,
                    tier=tib.tier,                    
                    known_ports=tib.signals.open_ports,   
                    has_snmp=bool(tib.signals.snmp_sysdescr),
                    is_ot=is_ot,                        
                )
                cluster_id = self.context.fleet_clusters.get(ip, {}).get("cluster_id")
                if cluster_id:
                    cluster = self.context.fleet_clusters.get(cluster_id, {})
                    rep_ip = cluster.get("representative_ip", "")
                    if rep_ip and rep_ip != ip:
                        graph = builder.build(
                            target_ip=ip,
                            tier=tib.tier,
                            known_ports=tib.signals.open_ports,
                            has_snmp=False,
                            is_ot=is_ot,
                        )
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
