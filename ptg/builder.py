import uuid
import logging
from typing import List, Optional

# DeviceTier: fragility classification (CRITICAL, FRAGILE, MODERATE, ROBUST, UNKNOWN)
# PentestPhase: enumeration of pentest phases
# TIER_TIB_DEFAULTS: tier -> TIB configuration mapping (budget, thresholds, etc.)
from TIB_and_PCF.TIB.TIB_structures import DeviceTier, PentestPhase, TIER_TIB_DEFAULTS
# ToolCategory: categorization of tools (scanner, discovery, etc.)
from IC_ToolSpec.models import ToolCategory
# ToolSpecRegistry: registry of all available tools and their safe mode configurations
from IC_ToolSpec.registry import ToolSpecRegistry
from ptg.models import (
    PTGNode, PTGNodeStatus, RiskTier, ValidationOracle, StopCondition,
)
from ptg.graph import PTGGraph

logger = logging.getLogger(__name__)


def _make_id(prefix: str) -> str:
    """
    Generate a unique node ID with a human-readable prefix.

    The prefix encodes the phase (e.g., "p0" for passive recon, "p1" for
    discovery) and the UUID suffix ensures uniqueness even when multiple
    nodes are created for the same phase.

    Args:
        prefix: Phase identifier prefix (e.g., "p0", "p1", "p2", "p4", "p5", "p6", "p7")

    Returns:
        String like "p1-a3f8c012" (prefix + 8 hex chars from a UUID4)
    """
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class PTGBuilder:
    """
    Builds a TIB-PTG (Penetration Task Graph) for a single target device.

    This class implements Algorithm 2 from the paper. Given a target device's
    IP address, fragility tier, and known attributes (open ports, SNMP
    availability, OT flag), it generates a complete DAG of pentest actions
    with proper dependencies, budget constraints, and safety mechanisms.

    The builder uses the IC-ToolSpec registry to look up tool specifications
    and select the safest allowed mode for each tool based on the device's
    fragility tier. Tools that are too aggressive for the tier are not
    included in the graph at all.

    Paper Algorithm 2:
      For all action class a in ALLOWED_ACTIONS(policy, profile):
        Create node with bounded grammar, impact cost, risk tier,
        ordered oracles (passive-first), stop conditions, fallback.
      Compute edges (preconditions + escalation).
    """

    def __init__(self, registry: Optional[ToolSpecRegistry] = None):
        """
        Initialize the builder with a tool specification registry.

        Args:
            registry: The IC-ToolSpec registry containing all available tools
                      and their safe mode configurations. If not provided, a
                      default empty registry is created.
        """
        # Use the provided registry or create a default one.
        # The registry maps tool_id -> ToolSpec, which contains safe modes,
        # budget costs, and tier compatibility for each tool.
        self.registry = registry or ToolSpecRegistry()

    def build(self, target_ip: str, tier: DeviceTier,
              known_ports: List[int] = None,
              has_snmp: bool = False,
              is_ot: bool = False) -> PTGGraph:
        """
        Generate a complete TIB-PTG for a target device.

        This is the main entry point that implements Algorithm 2. It builds
        the graph phase by phase, wiring dependencies between phases so that
        each phase's actions only execute after the previous phase completes.

        Phase ordering:
          Phase 0: Passive recon       — Listen for broadcasts (mDNS, SSDP, etc.)
          Phase 1: Host discovery      — ARP, ICMP, TCP probes to confirm host is up
          Phase 2: Fingerprinting      — DNS, ICMP/TCP fingerprint, SNMP to identify device
          Phase 3: TIB assignment      — Classify device into a fragility tier
          Phase 4: Port scanning       — TCP SYN scan to discover open ports
          Phase 5: Service probing     — Banner grab, HTTP probe, industrial protocols
          Phase 6: OS identification   — Passive and active OS detection
          Phase 7: Exploitation        — CVE database matching, real credential testing,
                                         active config verification (ROBUST and MODERATE only)

        Args:
            target_ip: Target IP address to build the graph for.
            tier: Device fragility tier (determines which tools/modes are allowed
                  and how aggressive the testing can be).
            known_ports: Already-known open ports from prior discovery phases.
                         Used to estimate banner grab costs (more ports = higher cost).
            has_snmp: Whether SNMP is known to be available on the target.
                      If True, an SNMP probe node is added to fingerprinting.
            is_ot: Whether this is an OT/industrial device (e.g., PLC, SCADA).
                   If True, industrial protocol probes (Modbus, S7) are added,
                   and default credential checks are skipped (too risky for OT).

        Returns:
            PTGGraph with all nodes, edges, and constraints ready for execution.
        """
        # Look up the TIB configuration for this tier (budget, thresholds, etc.)
        # Falls back to UNKNOWN tier defaults if the tier isn't in the mapping
        config = TIER_TIB_DEFAULTS.get(tier, TIER_TIB_DEFAULTS[DeviceTier.UNKNOWN])
        # Extract the maximum budget points allowed for this target
        budget = config.max_budget_points
        # Create the graph container with the target IP and budget
        graph = PTGGraph(target_ip, total_budget=budget)

        # Default to empty list if no known ports provided
        known_ports = known_ports or []

        # Generate stop conditions calibrated to this device's fragility tier.
        # Critical devices get very tight thresholds; robust devices are lenient.
        default_stops = self._default_stop_conditions(tier)

        # ── Phase 0: Passive recon (always allowed, zero cost) ────────────
        # Passive listeners (mDNS, SSDP, DHCP, NetBIOS) that capture broadcast
        # traffic without sending any packets. Safe for all device tiers.
        passive_nodes = self._build_passive_nodes(graph, tier, default_stops)

        # ── Phase 1: Host discovery ───────────────────────────────────────
        # Lightweight probes (ARP, ICMP, TCP) to confirm the host is alive.
        # Depends on passive recon completing first (to avoid redundant probing
        # if passive data already confirms host presence).
        discovery_nodes = self._build_discovery_nodes(
            graph, tier, default_stops, passive_nodes
        )

        # ── Phase 2: Fingerprinting ───────────────────────────────────────
        # More targeted probes (DNS reverse lookup, ICMP fingerprint, TCP
        # fingerprint, SNMP) to identify the device type and characteristics.
        # Depends on discovery completing so we know the host is alive.
        fingerprint_nodes = self._build_fingerprint_nodes(
            graph, tier, default_stops, discovery_nodes, has_snmp
        )

        # ── Phase 3: TIB assignment (inference, zero cost) ────────────────
        # Internal classification step that assigns the device to a fragility
        # tier based on fingerprinting results. This is a local computation
        # (no packets sent), so it has zero budget cost and TIER_0 risk.
        # Depends on ALL fingerprint nodes completing to have maximum data.
        tib_node = PTGNode(
            node_id=_make_id("tib"),
            name="TIB Classification",
            tool_id="__internal_tib_classify",  # Internal tool, not in registry
            safe_mode="passive",
            phase="TIB_ASSIGNMENT",
            estimated_budget_cost=0.0,         # Pure computation, no network traffic
            risk_tier=RiskTier.TIER_0,         # Zero impact on target
            dependencies=[n.node_id for n in fingerprint_nodes],  # Wait for all fingerprinting
            priority=70.0,                     # High priority — needed before port scanning
            validation_oracles=[ValidationOracle.passive_check("tier_consistency")],
            stop_conditions=default_stops,
        )
        graph.add_node(tib_node)

        # ── Phase 4: Port scan ────────────────────────────────────────────
        # TCP SYN scan to discover open ports. This is a more aggressive action
        # (TIER_2) that depends on TIB assignment so the scan parameters can
        # be calibrated to the device's actual fragility tier.
        scan_nodes = self._build_port_scan_nodes(
            graph, tier, default_stops, [tib_node], config
        )

        # ── Phase 5: Service probing ──────────────────────────────────────
        # Banner grabbing, HTTP probing, and industrial protocol identification.
        # Depends on port scanning so we know which ports to probe.
        service_nodes = self._build_service_probe_nodes(
            graph, tier, default_stops, scan_nodes, known_ports, is_ot
        )

        # ── Phase 6: OS identification ────────────────────────────────────
        # Passive and active OS detection using fingerprint data and service
        # probe results. Depends on both fingerprinting AND service probing
        # to maximize the data available for OS inference.
        os_nodes = self._build_os_id_nodes(
            graph, tier, default_stops, fingerprint_nodes + service_nodes
        )

        # ── Phase 7: Exploitation (if tier allows) ────────────────────────
        # CVE database matching (1 400+ CVEs with version ranges), real
        # credential testing (SSH/Telnet/HTTP/FTP/SNMP/MQTT), and active
        # config weakness verification.  Only allowed for ROBUST and MODERATE
        # tiers — fragile and critical devices are never subjected to
        # exploitation to avoid causing damage.
        if tier in (DeviceTier.ROBUST, DeviceTier.MODERATE):
            exploit_nodes = self._build_exploit_nodes(
                graph, tier, default_stops, service_nodes + os_nodes, is_ot
            )

        # ── Budget pruning ────────────────────────────────────────────────
        # After building all nodes, prune any that exceed the total budget.
        # Use float("inf") for zero-budget (unlimited) to skip pruning.
        remaining = budget if budget > 0 else float("inf")
        if remaining != float("inf"):
            # prune_by_budget removes lowest-priority nodes first, activating
            # fallbacks where possible, until the remaining cost fits in budget
            graph.prune_by_budget(remaining)

        logger.info(
            f"[PTGBuilder] Built graph for {target_ip} (tier={tier.name}): "
            f"{len(graph.get_all_nodes())} nodes, budget={budget}"
        )
        return graph

    # ── Phase builders ─────────────────────────────────────────────────────────
    # Each method below builds the nodes for one pentest phase. They all follow
    # the same pattern:
    #   1. Look up the tool specification from the registry
    #   2. Select the safest allowed mode for the device tier
    #   3. Create a PTGNode with proper cost, risk tier, oracles, and stops
    #   4. Add the node to the graph (which wires up dependency edges)
    #   5. Return the list of created nodes (used as dependencies for next phase)

    def _build_passive_nodes(self, graph: PTGGraph, tier: DeviceTier,
                             stops: List[StopCondition]) -> List[PTGNode]:
        """
        Build Phase 0: Passive reconnaissance nodes.

        Creates listener nodes for mDNS, SSDP, DHCP, and NetBIOS. These
        capture broadcast traffic on the network without sending any packets,
        making them safe for ALL device tiers (TIER_0 risk, zero budget cost).

        Passive nodes have no dependencies (they are the root of the DAG)
        and no stop conditions (passive listening cannot harm the target).

        Args:
            graph: The PTGGraph to add nodes to.
            tier: Device tier (not used for filtering — passive is always allowed).
            stops: Default stop conditions (not applied to passive nodes).

        Returns:
            List of created passive recon PTGNode instances.
        """
        nodes = []
        # Iterate over the four passive listener tools
        for tool_id in ["mdns_listener", "ssdp_listener", "dhcp_listener", "netbios_listener"]:
            # Look up the tool specification from the IC-ToolSpec registry
            spec = self.registry.get(tool_id)
            if not spec:
                continue  # Tool not registered — skip (registry may be partial)
            node = PTGNode(
                node_id=_make_id("p0"),           # "p0" prefix = Phase 0 (passive)
                name=spec.name,                    # Human-readable name from the registry
                tool_id=tool_id,
                safe_mode="passive",               # Passive listeners only have one mode
                phase="PASSIVE_RECON",
                estimated_budget_cost=0.0,         # Passive listening costs nothing
                risk_tier=RiskTier.TIER_0,         # Zero impact on target
                priority=100.0,                    # Highest priority — always runs first
                validation_oracles=[ValidationOracle.passive_check("passive_data_present")],
                stop_conditions=[],                # Passive nodes never need stop conditions
            )
            graph.add_node(node)
            nodes.append(node)
        return nodes

    def _build_discovery_nodes(self, graph: PTGGraph, tier: DeviceTier,
                               stops: List[StopCondition],
                               parents: List[PTGNode]) -> List[PTGNode]:
        """
        Build Phase 1: Host discovery nodes.

        Creates ARP, ICMP, and TCP discovery nodes with a fallback chain:
          ARP discovery (primary, most reliable on local networks)
           -> ICMP discovery (fallback, works across subnets)
              -> TCP discovery (fallback for ICMP, works when ICMP is blocked)

        The fallback chain means: if ICMP discovery fails or is too expensive,
        TCP discovery can be activated as an alternative. This ensures host
        presence is confirmed even in restrictive network environments.

        All discovery nodes depend on the passive recon phase completing first,
        so any broadcast data is already available before sending active probes.

        Args:
            graph: The PTGGraph to add nodes to.
            tier: Device tier (used to select the safest allowed tool mode).
            stops: Default stop conditions applied to each node.
            parents: Passive recon nodes that must complete first (dependencies).

        Returns:
            List of created discovery PTGNode instances.
        """
        # Extract parent node IDs for the dependency list
        parent_ids = [n.node_id for n in parents]
        nodes = []

        # ── ARP discovery (always first, most reliable on local networks) ──
        arp_spec = self.registry.get("arp_discovery")
        if arp_spec:
            # get_safest_mode returns the least aggressive mode allowed for this tier
            mode = arp_spec.get_safest_mode(tier)
            if mode:
                arp_node = PTGNode(
                    node_id=_make_id("p1"),                  # "p1" = Phase 1 (discovery)
                    name="ARP Discovery",
                    tool_id="arp_discovery",
                    safe_mode=mode.name,                     # Safest mode for this tier
                    phase="HOST_DISCOVERY",
                    estimated_budget_cost=mode.max_budget_cost,  # Cost from tool spec
                    risk_tier=RiskTier.TIER_1,               # Gentle — single ARP request
                    dependencies=parent_ids,                 # Must wait for passive recon
                    priority=95.0,                           # Very high — discovery is essential
                    validation_oracles=[ValidationOracle.passive_check("mac_present")],
                    stop_conditions=stops,
                )
                graph.add_node(arp_node)
                nodes.append(arp_node)

        # ── ICMP discovery (second choice, works across subnets) ──────────
        icmp_spec = self.registry.get("icmp_discovery")
        if icmp_spec:
            mode = icmp_spec.get_safest_mode(tier)
            if mode:
                icmp_node = PTGNode(
                    node_id=_make_id("p1"),
                    name="ICMP Discovery",
                    tool_id="icmp_discovery",
                    safe_mode=mode.name,
                    phase="HOST_DISCOVERY",
                    estimated_budget_cost=mode.max_budget_cost,
                    risk_tier=RiskTier.TIER_1,
                    dependencies=parent_ids,
                    priority=90.0,                           # Slightly lower than ARP
                    validation_oracles=[
                        # First try passive check: does the response contain a TTL?
                        ValidationOracle.passive_check("ttl_present"),
                        # If passive check is inconclusive, actively re-ping
                        ValidationOracle.active_recheck("ping_verify", 1.0, ["icmp_echo"]),
                    ],
                    stop_conditions=stops,
                )
                graph.add_node(icmp_node)
                nodes.append(icmp_node)

        # ── TCP discovery (fallback for ICMP, works when ICMP is blocked) ─
        tcp_spec = self.registry.get("tcp_discovery")
        if tcp_spec:
            mode = tcp_spec.get_safest_mode(tier)
            if mode:
                tcp_node = PTGNode(
                    node_id=_make_id("p1"),
                    name="TCP Discovery",
                    tool_id="tcp_discovery",
                    safe_mode=mode.name,
                    phase="HOST_DISCOVERY",
                    estimated_budget_cost=mode.max_budget_cost,
                    risk_tier=RiskTier.TIER_1,
                    dependencies=parent_ids,
                    priority=85.0,                           # Lower than ICMP
                    stop_conditions=stops,
                )
                # Link TCP discovery as a fallback for the previous node (ICMP).
                # If ICMP fails or is too expensive, TCP discovery is activated.
                if nodes:
                    nodes[-1].fallback_node_id = tcp_node.node_id
                graph.add_node(tcp_node)
                nodes.append(tcp_node)

        return nodes

    def _build_fingerprint_nodes(self, graph: PTGGraph, tier: DeviceTier,
                                 stops: List[StopCondition],
                                 parents: List[PTGNode],
                                 has_snmp: bool) -> List[PTGNode]:
        """
        Build Phase 2: Fingerprinting nodes.

        Creates nodes for DNS reverse lookup, ICMP fingerprinting, TCP
        fingerprinting, and optionally SNMP probing. These nodes gather
        detailed information about the target device to support TIB
        classification (Phase 3).

        All fingerprint nodes depend on host discovery completing first,
        since there is no point fingerprinting a host that has not been
        confirmed as alive.

        Args:
            graph: The PTGGraph to add nodes to.
            tier: Device tier (used to select safest mode and gate SNMP).
            stops: Default stop conditions applied to each node.
            parents: Discovery nodes that must complete first (dependencies).
            has_snmp: Whether SNMP is known to be available. If True, or if
                      the device is ROBUST/MODERATE, an SNMP probe is added.

        Returns:
            List of created fingerprinting PTGNode instances.
        """
        parent_ids = [n.node_id for n in parents]
        nodes = []

        # ── DNS reverse lookup (zero cost, zero risk) ─────────────────────
        # Reverse DNS is a simple query to the DNS server, not the target.
        # It reveals the hostname associated with the IP address.
        dns_spec = self.registry.get("dns_reverse")
        if dns_spec:
            node = PTGNode(
                node_id=_make_id("p2"),                  # "p2" = Phase 2 (fingerprinting)
                name="Reverse DNS",
                tool_id="dns_reverse",
                safe_mode="standard",                    # DNS queries are always safe
                phase="FINGERPRINTING",
                estimated_budget_cost=0.0,               # Query goes to DNS server, not target
                risk_tier=RiskTier.TIER_0,               # No impact on target device
                dependencies=parent_ids,
                priority=80.0,
                stop_conditions=stops,
            )
            graph.add_node(node)
            nodes.append(node)

        # ── ICMP fingerprinting ───────────────────────────────────────────
        # Sends specific ICMP packets and analyzes response characteristics
        # (TTL, window size, etc.) to infer the OS/device type.
        icmp_spec = self.registry.get("icmp_fingerprint")
        if icmp_spec:
            mode = icmp_spec.get_safest_mode(tier)
            if mode:
                node = PTGNode(
                    node_id=_make_id("p2"),
                    name="ICMP Fingerprint",
                    tool_id="icmp_fingerprint",
                    safe_mode=mode.name,
                    phase="FINGERPRINTING",
                    estimated_budget_cost=mode.max_budget_cost,
                    risk_tier=RiskTier.TIER_1,           # Gentle — few ICMP packets
                    dependencies=parent_ids,
                    priority=78.0,
                    validation_oracles=[
                        # Check if TTL values are consistent across responses
                        ValidationOracle.passive_check("ttl_consistency"),
                        # Verify that an RTT baseline was established (needed for
                        # stop condition RTT spike detection in later phases)
                        ValidationOracle.cross_reference("rtt_baseline_established"),
                    ],
                    stop_conditions=stops,
                )
                graph.add_node(node)
                nodes.append(node)

        # ── TCP fingerprinting ────────────────────────────────────────────
        # Analyzes TCP stack behavior (window sizes, options, sequence numbers)
        # to identify the OS. More informative than ICMP but slightly more impactful.
        tcp_spec = self.registry.get("tcp_fingerprint")
        if tcp_spec:
            mode = tcp_spec.get_safest_mode(tier)
            if mode:
                node = PTGNode(
                    node_id=_make_id("p2"),
                    name="TCP Fingerprint",
                    tool_id="tcp_fingerprint",
                    safe_mode=mode.name,
                    phase="FINGERPRINTING",
                    estimated_budget_cost=mode.max_budget_cost,
                    risk_tier=RiskTier.TIER_1,
                    dependencies=parent_ids,
                    priority=76.0,
                    validation_oracles=[
                        # Check if TCP window size and options were captured
                        ValidationOracle.passive_check("window_options_present"),
                    ],
                    stop_conditions=stops,
                )
                graph.add_node(node)
                nodes.append(node)

        # ── SNMP probe (conditional on SNMP availability or tier) ─────────
        # SNMP can reveal extensive device information (sysDescr, model, firmware).
        # Only probe if SNMP is known to exist OR the device is robust/moderate
        # (where probing unknown SNMP is acceptable risk).
        if has_snmp or tier in (DeviceTier.ROBUST, DeviceTier.MODERATE):
            snmp_spec = self.registry.get("snmp_probe")
            if snmp_spec:
                mode = snmp_spec.get_safest_mode(tier)
                if mode:
                    node = PTGNode(
                        node_id=_make_id("p2"),
                        name="SNMP Probe",
                        tool_id="snmp_probe",
                        safe_mode=mode.name,
                        phase="FINGERPRINTING",
                        estimated_budget_cost=mode.max_budget_cost,
                        risk_tier=RiskTier.TIER_1,
                        dependencies=parent_ids,
                        priority=74.0,                   # Lowest fingerprint priority
                        stop_conditions=stops,
                    )
                    graph.add_node(node)
                    nodes.append(node)

        return nodes

    def _build_port_scan_nodes(self, graph: PTGGraph, tier: DeviceTier,
                               stops: List[StopCondition],
                               parents: List[PTGNode],
                               config) -> List[PTGNode]:
        """
        Build Phase 4: Port scanning nodes.

        Creates a TCP SYN scan node with an optional fallback to a less
        aggressive scan mode. Port scanning is TIER_2 (standard active
        probing) and has an additional budget stop condition at 20% to
        prevent port scanning from consuming too much of the total budget.

        The fallback mechanism works as follows: if the primary scan mode
        (e.g., full SYN scan) is too expensive or fails, a safer/cheaper
        mode is activated automatically.

        Args:
            graph: The PTGGraph to add nodes to.
            tier: Device tier (used to select allowed scan modes).
            stops: Default stop conditions.
            parents: TIB classification node(s) that must complete first.
            config: TIB configuration object (used for tier-specific scan params).

        Returns:
            List of created port scan PTGNode instances.
        """
        parent_ids = [n.node_id for n in parents]
        nodes = []

        # Look up the TCP SYN scan tool specification
        scan_spec = self.registry.get("tcp_syn_scan")
        if not scan_spec:
            return nodes  # Tool not registered — skip port scanning entirely

        # Get all scan modes allowed for this tier, ordered by safety (safest first)
        allowed_modes = scan_spec.get_allowed_modes(tier)
        if not allowed_modes:
            return nodes  # No scan modes allowed for this tier — skip

        # Use the safest allowed mode as the primary scan configuration
        mode = allowed_modes[0]
        main_node = PTGNode(
            node_id=_make_id("p4"),              # "p4" = Phase 4 (port scanning)
            name=f"Port Scan ({mode.name})",
            tool_id="tcp_syn_scan",
            safe_mode=mode.name,
            phase="PORT_SCAN",
            estimated_budget_cost=mode.max_budget_cost,
            risk_tier=RiskTier.TIER_2,           # Standard active probing
            dependencies=parent_ids,
            priority=60.0,
            validation_oracles=[
                # Passive check: were any ports discovered?
                ValidationOracle.passive_check("ports_discovered"),
                # Active recheck: re-probe discovered ports to confirm they are open
                # (costs 3.0 budget points, uses TCP SYN probes)
                ValidationOracle.active_recheck("port_recheck", 3.0, ["tcp_syn"]),
            ],
            # Add an extra budget stop condition at 20%: if less than 20% of
            # the budget remains, stop scanning to preserve budget for later phases
            stop_conditions=stops + [StopCondition.budget_threshold(20.0)],
        )

        # ── Create a fallback node with a less aggressive scan mode ───────
        # If multiple modes are available, the fallback uses the safest one.
        # This allows the graph to degrade gracefully under budget pressure.
        if len(allowed_modes) > 1:
            fallback_mode = allowed_modes[0]     # Safest mode (first in sorted list)
            # Only create a fallback if it's actually a different mode
            if fallback_mode.name != mode.name:
                fb_node = PTGNode(
                    node_id=_make_id("p4fb"),    # "p4fb" = Phase 4 fallback
                    name=f"Port Scan Fallback ({fallback_mode.name})",
                    tool_id="tcp_syn_scan",
                    safe_mode=fallback_mode.name,
                    phase="PORT_SCAN",
                    estimated_budget_cost=fallback_mode.max_budget_cost,
                    risk_tier=RiskTier.TIER_1,   # Fallback is gentler than primary
                    dependencies=parent_ids,
                    priority=55.0,               # Lower priority than primary scan
                    stop_conditions=stops,
                )
                graph.add_node(fb_node)
                # Link the fallback to the main scan node
                main_node.fallback_node_id = fb_node.node_id

        graph.add_node(main_node)
        nodes.append(main_node)
        return nodes

    def _build_service_probe_nodes(self, graph: PTGGraph, tier: DeviceTier,
                                   stops: List[StopCondition],
                                   parents: List[PTGNode],
                                   known_ports: List[int],
                                   is_ot: bool) -> List[PTGNode]:
        """
        Build Phase 5: Service probing nodes.

        Creates nodes for banner grabbing, HTTP probing, and (for OT devices)
        industrial protocol identification (Modbus, S7). These nodes connect
        to discovered services to identify software versions and configurations.

        The banner grab cost is scaled by the number of known ports: more
        open ports means more connections, which costs more budget.

        For OT devices, industrial protocol probes (Modbus, S7) are added
        to identify PLCs, HMIs, and other industrial controllers.

        Args:
            graph: The PTGGraph to add nodes to.
            tier: Device tier (used to select safest mode).
            stops: Default stop conditions.
            parents: Port scan nodes that must complete first.
            known_ports: List of known open ports (used to estimate banner grab cost).
            is_ot: Whether this is an OT/industrial device.

        Returns:
            List of created service probe PTGNode instances.
        """
        parent_ids = [n.node_id for n in parents]
        nodes = []

        # ── Banner grab ───────────────────────────────────────────────────
        # Connects to each open port and reads the initial banner/greeting.
        # Cost scales with number of ports (more ports = more connections).
        banner_spec = self.registry.get("banner_grab")
        if banner_spec:
            mode = banner_spec.get_safest_mode(tier)
            if mode:
                # Scale cost by number of ports, with a minimum of 5 ports assumed
                # if no ports are known yet (they will be discovered by port scanning)
                estimated_port_count = max(len(known_ports), 5)
                node = PTGNode(
                    node_id=_make_id("p5"),              # "p5" = Phase 5 (service probing)
                    name="Banner Grab",
                    tool_id="banner_grab",
                    safe_mode=mode.name,
                    phase="SERVICE_PROBE",
                    # Cost per port * number of ports to probe
                    estimated_budget_cost=mode.max_budget_cost * estimated_port_count,
                    risk_tier=RiskTier.TIER_2,           # Active connections to target
                    dependencies=parent_ids,
                    priority=50.0,
                    stop_conditions=stops,
                )
                graph.add_node(node)
                nodes.append(node)

        # ── HTTP probe ────────────────────────────────────────────────────
        # Sends HTTP requests to web services to identify web server software,
        # frameworks, and potential web application vulnerabilities.
        http_spec = self.registry.get("http_probe")
        if http_spec:
            mode = http_spec.get_safest_mode(tier)
            if mode:
                node = PTGNode(
                    node_id=_make_id("p5"),
                    name="HTTP Probe",
                    tool_id="http_probe",
                    safe_mode=mode.name,
                    phase="SERVICE_PROBE",
                    estimated_budget_cost=mode.max_budget_cost,
                    risk_tier=RiskTier.TIER_2,
                    dependencies=parent_ids,
                    priority=48.0,                       # Slightly lower than banner grab
                    stop_conditions=stops,
                )
                graph.add_node(node)
                nodes.append(node)

        # ── Industrial protocol probes (only for OT devices) ──────────────
        # Modbus and S7 (Siemens) protocol identification for industrial
        # control systems. These probes are only added for OT devices because
        # they use industrial-specific protocols that are irrelevant (and
        # potentially confusing) for IT devices.
        if is_ot:
            for tool_id in ["modbus_identify", "s7_identify"]:
                spec = self.registry.get(tool_id)
                if spec:
                    mode = spec.get_safest_mode(tier)
                    if mode:
                        node = PTGNode(
                            node_id=_make_id("p5"),
                            name=spec.name,              # Use registry name (e.g., "Modbus Identify")
                            tool_id=tool_id,
                            safe_mode=mode.name,
                            phase="SERVICE_PROBE",
                            estimated_budget_cost=mode.max_budget_cost,
                            risk_tier=RiskTier.TIER_2,
                            dependencies=parent_ids,
                            priority=45.0,               # Lower priority than standard probes
                            stop_conditions=stops,
                        )
                        graph.add_node(node)
                        nodes.append(node)

        return nodes

    def _build_os_id_nodes(self, graph: PTGGraph, tier: DeviceTier,
                           stops: List[StopCondition],
                           parents: List[PTGNode]) -> List[PTGNode]:
        """
        Build Phase 6: OS identification nodes.

        Creates passive and active OS identification nodes with a fallback
        relationship: active OS ID falls back to passive OS ID if the active
        probe is too expensive or fails.

        Passive OS ID (TIER_0): Infers the OS from already-collected data
        (banners, TTL values, TCP options) without sending new traffic.

        Active OS ID (TIER_2 or TIER_3): Sends specific probe packets
        designed to elicit OS-specific responses. More accurate than passive
        but consumes budget. If the mode is "full", it's classified as
        TIER_3 (aggressive) requiring additional approval.

        Args:
            graph: The PTGGraph to add nodes to.
            tier: Device tier (gates whether active OS ID is allowed).
            stops: Default stop conditions.
            parents: Fingerprint and service probe nodes that must complete first.

        Returns:
            List of created OS identification PTGNode instances.
        """
        parent_ids = [n.node_id for n in parents]
        nodes = []

        # ── Passive OS ID (always available, zero cost) ───────────────────
        # Analyzes existing fingerprint data to infer the OS. No new packets
        # are sent, so this is TIER_0 and costs zero budget.
        passive_spec = self.registry.get("os_passive_id")
        if passive_spec:
            node = PTGNode(
                node_id=_make_id("p6"),                  # "p6" = Phase 6 (OS identification)
                name="Passive OS ID",
                tool_id="os_passive_id",
                safe_mode="passive",
                phase="OS_IDENTIFICATION",
                estimated_budget_cost=0.0,               # Pure analysis of existing data
                risk_tier=RiskTier.TIER_0,               # No impact on target
                dependencies=parent_ids,
                priority=40.0,
                validation_oracles=[
                    # Cross-reference: does the OS inferred from stack analysis
                    # match the OS suggested by service banners?
                    ValidationOracle.cross_reference("os_banner_consistency"),
                ],
                stop_conditions=stops,
            )
            graph.add_node(node)
            nodes.append(node)

        # ── Active OS ID (tier-gated, with passive as fallback) ───────────
        # Sends crafted packets to elicit OS-specific responses. More accurate
        # but more impactful. Falls back to passive OS ID if too expensive.
        active_spec = self.registry.get("os_active_id")
        if active_spec:
            mode = active_spec.get_safest_mode(tier)
            if mode:
                # "full" mode is TIER_3 (aggressive, requires approval);
                # all other modes are TIER_2 (standard active probing)
                active_risk = RiskTier.TIER_2 if mode.name != "full" else RiskTier.TIER_3
                active_node = PTGNode(
                    node_id=_make_id("p6"),
                    name=f"Active OS ID ({mode.name})",
                    tool_id="os_active_id",
                    safe_mode=mode.name,
                    phase="OS_IDENTIFICATION",
                    estimated_budget_cost=mode.max_budget_cost,
                    risk_tier=active_risk,
                    dependencies=parent_ids,
                    priority=38.0,                       # Lower than passive OS ID
                    validation_oracles=[
                        # Check if the OS confidence level is above a minimum threshold
                        ValidationOracle.passive_check("os_confidence_above_threshold"),
                        # Cross-reference the OS detection result against banner data
                        ValidationOracle.cross_reference("os_matches_banner"),
                    ],
                    stop_conditions=stops,
                )
                # Set passive OS ID as the fallback: if active is too expensive
                # or fails, the passive analysis result is used instead
                if nodes:
                    active_node.fallback_node_id = nodes[0].node_id
                graph.add_node(active_node)
                nodes.append(active_node)

        return nodes

    def _build_exploit_nodes(self, graph: PTGGraph, tier: DeviceTier,
                             stops: List[StopCondition],
                             parents: List[PTGNode],
                             is_ot: bool) -> List[PTGNode]:
        """
        Build Phase 7: Exploitation nodes.

        Creates nodes for CVE database matching, real credential testing,
        and active exploit execution.  This phase is only built for ROBUST
        and MODERATE tiers (checked in the build() method before calling this).

        The nodes are ordered by risk:
          1. CVE version match (TIER_0) — local lookup against the CVE database
             (1 400+ entries) with semantic version range comparison.  No traffic
             sent to the target.  Zero cost.
          2. Default credential check (TIER_2) — performs real network login
             attempts (SSH/Telnet/HTTP/FTP/SNMP/MQTT) with known default
             credentials.  Skipped for OT devices because failed login attempts
             could trigger lockouts on PLCs.
          3. Safe exploit runner (TIER_3) — runs the full exploitation pipeline
             including active config weakness verification.  Requires the highest
             risk tier and has additional budget and validation requirements.

        The exploit runner depends on BOTH the parent phase nodes AND any
        earlier exploit nodes (CVE match, cred check), ensuring all
        reconnaissance data is available before attempting exploitation.

        Args:
            graph: The PTGGraph to add nodes to.
            tier: Device tier (gates which exploit tools are allowed).
            stops: Default stop conditions.
            parents: Service probe and OS ID nodes that must complete first.
            is_ot: Whether this is an OT device (disables credential checks).

        Returns:
            List of created exploitation PTGNode instances.
        """
        parent_ids = [n.node_id for n in parents]
        nodes = []

        # ── CVE version matching (zero target impact) ─────────────────────
        # Matches discovered service banners and versions against the local
        # CVE database (1 400+ entries with semantic version ranges).  This is
        # a local computation — no packets are sent to the target, so it has
        # zero cost and TIER_0 risk.
        cve_spec = self.registry.get("cve_version_match")
        if cve_spec:
            node = PTGNode(
                node_id=_make_id("p7"),                  # "p7" = Phase 7 (exploitation)
                name="CVE Version Match",
                tool_id="cve_version_match",
                safe_mode="lookup_only",                 # Database lookup, no target interaction
                phase="EXPLOITATION",
                estimated_budget_cost=0.0,               # No network traffic
                risk_tier=RiskTier.TIER_0,               # Zero impact on target
                dependencies=parent_ids,
                priority=30.0,
                stop_conditions=stops,
            )
            graph.add_node(node)
            nodes.append(node)

        # ── Default credential check (not for OT devices) ────────────────
        # Performs real network login attempts with known default credentials
        # against discovered services (SSH, Telnet, HTTP, FTP, SNMP, MQTT).
        # Skipped for OT devices because failed login attempts could trigger
        # account lockouts or alarm systems on industrial controllers.
        if not is_ot:
            cred_spec = self.registry.get("default_cred_check")
            if cred_spec:
                mode = cred_spec.get_safest_mode(tier)
                if mode:
                    node = PTGNode(
                        node_id=_make_id("p7"),
                        name="Default Credential Check",
                        tool_id="default_cred_check",
                        safe_mode=mode.name,
                        phase="EXPLOITATION",
                        estimated_budget_cost=mode.max_budget_cost,
                        risk_tier=RiskTier.TIER_2,       # Active login attempts
                        dependencies=parent_ids,
                        priority=28.0,
                        # Extra budget stop at 10%: credential checking is low
                        # priority and should not consume the last 10% of budget
                        stop_conditions=stops + [StopCondition.budget_threshold(10.0)],
                    )
                    graph.add_node(node)
                    nodes.append(node)

        # ── Safe exploit runner (tier-gated, highest risk) ────────────────
        # Runs actual exploits in a controlled, sandboxed manner. This is
        # TIER_3 (aggressive) and requires the most budget. The "dry_run"
        # mode is excluded because it doesn't actually test anything.
        exploit_spec = self.registry.get("safe_exploit_runner")
        if exploit_spec:
            mode = exploit_spec.get_safest_mode(tier)
            # Skip "dry_run" mode — it simulates but doesn't actually exploit,
            # so it would not produce useful results in the exploitation phase
            if mode and mode.name != "dry_run":
                node = PTGNode(
                    node_id=_make_id("p7"),
                    name=f"Exploitation ({mode.name})",
                    tool_id="safe_exploit_runner",
                    safe_mode=mode.name,
                    phase="EXPLOITATION",
                    estimated_budget_cost=mode.max_budget_cost,
                    risk_tier=RiskTier.TIER_3,           # Aggressive — actual exploitation
                    # Depends on BOTH the phase parents AND earlier exploit nodes
                    # (CVE match, cred check) to ensure all intel is gathered first
                    dependencies=parent_ids + [n.node_id for n in nodes],
                    priority=20.0,                       # Lowest priority — runs last
                    validation_oracles=[
                        # Active recheck: verify the exploit result by re-running
                        # a safe version of the exploit (costs 5.0 budget points)
                        ValidationOracle.active_recheck(
                            "exploit_verification", 5.0, ["exploit_safe"]
                        ),
                    ],
                    # Extra budget stop at 15%: exploitation is expensive and
                    # should not be attempted if budget is nearly exhausted
                    stop_conditions=stops + [StopCondition.budget_threshold(15.0)],
                )
                graph.add_node(node)
                nodes.append(node)

        return nodes

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _default_stop_conditions(self, tier: DeviceTier) -> List[StopCondition]:
        """
        Generate default stop conditions calibrated to the device's fragility tier.

        Every node gets these stop conditions by default. The thresholds become
        progressively tighter as the device becomes more fragile:

        CRITICAL tier (e.g., life-support equipment, safety PLCs):
          - Stop if budget < 50% (preserve most of the budget)
          - Stop if RTT spikes > 1.5x baseline (very sensitive to delays)
          - Stop after 1 consecutive timeout (any unresponsiveness is alarming)

        FRAGILE tier (e.g., legacy switches, older PLCs):
          - Stop if budget < 30%
          - Stop if RTT spikes > 2.0x baseline
          - Stop after 3 consecutive timeouts

        MODERATE tier (e.g., managed switches, modern PLCs):
          - Stop if budget < 15%
          - Stop if RTT spikes > 3.0x baseline
          - Stop after 5 consecutive timeouts

        ROBUST / UNKNOWN tier (e.g., Linux servers, modern workstations):
          - Stop if budget < 5% (use almost all the budget)
          - Stop if RTT spikes > 5.0x baseline (very tolerant)
          - Stop after 10 consecutive timeouts

        ALL tiers get a circuit breaker trip condition — this is the ultimate
        safety mechanism that stops all testing immediately.

        Args:
            tier: The device's fragility tier.

        Returns:
            List of StopCondition instances appropriate for the tier.
        """
        # Circuit breaker stop condition is ALWAYS included for all tiers.
        # When the TIB-PCF circuit breaker trips, all testing must cease.
        conditions = [StopCondition.breaker_trip()]

        if tier == DeviceTier.CRITICAL:
            # CRITICAL: most restrictive — preserve budget, detect any degradation
            conditions.extend([
                StopCondition.budget_threshold(50.0),     # Stop if < 50% budget left
                StopCondition.rtt_spike(1.5),             # Stop if RTT > 1.5x baseline
                StopCondition.consecutive_timeouts(1),    # Stop after 1 timeout
            ])
        elif tier == DeviceTier.FRAGILE:
            # FRAGILE: moderately restrictive — some tolerance for delays
            conditions.extend([
                StopCondition.budget_threshold(30.0),     # Stop if < 30% budget left
                StopCondition.rtt_spike(2.0),             # Stop if RTT > 2.0x baseline
                StopCondition.consecutive_timeouts(3),    # Stop after 3 timeouts
            ])
        elif tier == DeviceTier.MODERATE:
            # MODERATE: balanced — reasonable budget usage, moderate tolerance
            conditions.extend([
                StopCondition.budget_threshold(15.0),     # Stop if < 15% budget left
                StopCondition.rtt_spike(3.0),             # Stop if RTT > 3.0x baseline
                StopCondition.consecutive_timeouts(5),    # Stop after 5 timeouts
            ])
        else:  # ROBUST, UNKNOWN
            # ROBUST/UNKNOWN: most permissive — use nearly all budget, high tolerance
            conditions.extend([
                StopCondition.budget_threshold(5.0),      # Stop if < 5% budget left
                StopCondition.rtt_spike(5.0),             # Stop if RTT > 5.0x baseline
                StopCondition.consecutive_timeouts(10),   # Stop after 10 timeouts
            ])

        return conditions
