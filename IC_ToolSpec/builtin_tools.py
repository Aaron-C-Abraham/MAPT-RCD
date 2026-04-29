from TIB_and_PCF.TIB.TIB_structures import DeviceTier
from IC_ToolSpec.models import (
    ToolSpec, SafeMode, OutputSchema, InvocationGrammar, ToolCategory,
)
from IC_ToolSpec.registry import ToolSpecRegistry


def register_all_builtin_tools(): 
    registry = ToolSpecRegistry()
    registry.register(ToolSpec(
        tool_id="arp_discovery",
        name="ARP Host Discovery",
        description="Discover hosts via ARP broadcast on local subnet",
        category=ToolCategory.DISCOVERY,
        requires_root=True,
        safe_modes=[
            SafeMode(
                name="standard",
                description="Single ARP request per target",
                impact_score=0.05,
                probe_types_used=["arp"],
                max_budget_cost=0.5,
                max_packets=1,
                timeout_sec=3.0,
            ),
        ],
        output_schema=OutputSchema(
            fields={"ip": "str", "mac": "str", "vendor": "str"},
            evidence_node_type="discovery",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_network"],
            max_targets_per_call=256,
        ),
    ))
    registry.register(ToolSpec(
        tool_id="icmp_discovery",
        name="ICMP Host Discovery",
        description="Discover hosts via ICMP echo requests",
        category=ToolCategory.DISCOVERY,
        requires_root=True,
        safe_modes=[
            SafeMode(
                name="single_ping",
                description="One ICMP echo per target",
                impact_score=0.1,
                probe_types_used=["icmp_echo"],
                max_budget_cost=1.0,
                max_packets=1,
                timeout_sec=3.0,
            ),
            SafeMode(
                name="triple_ping",
                description="Three ICMP echos for RTT baseline",
                impact_score=0.15,
                probe_types_used=["icmp_echo"],
                max_budget_cost=3.0,
                max_packets=3,
                timeout_sec=5.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
        ],
        output_schema=OutputSchema(
            fields={"ip": "str", "alive": "bool", "rtt_ms": "float"},
            evidence_node_type="discovery",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
        ),
    ))

    registry.register(ToolSpec(
        tool_id="tcp_discovery",
        name="TCP SYN Discovery",
        description="Discover hosts via TCP SYN to common ports",
        category=ToolCategory.DISCOVERY,
        safe_modes=[
            SafeMode(
                name="single_port",
                description="SYN to port 80 only",
                impact_score=0.1,
                probe_types_used=["tcp_syn"],
                max_budget_cost=1.0,
                max_packets=1,
                timeout_sec=3.0,
            ),
            SafeMode(
                name="common_ports",
                description="SYN to ports 80, 443, 22",
                impact_score=0.2,
                probe_types_used=["tcp_syn"],
                max_budget_cost=3.0,
                max_packets=3,
                timeout_sec=5.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
        ],
        output_schema=OutputSchema(
            fields={"ip": "str", "alive": "bool", "responding_port": "int"},
            evidence_node_type="discovery",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
            optional_params={"ports": "80"},
        ),
    ))
    registry.register(ToolSpec(
        tool_id="mdns_listener",
        name="mDNS Passive Listener",
        description="Listen for mDNS announcements (zero impact)",
        category=ToolCategory.DISCOVERY,
        safe_modes=[
            SafeMode(
                name="passive",
                description="Listen only, no packets sent",
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
                timeout_sec=30.0,
            ),
        ], 
        output_schema=OutputSchema(
            fields={"ip": "str", "services": "list"},
            evidence_node_type="passive",
        ),
    ))
    registry.register(ToolSpec(
        tool_id="ssdp_listener",
        name="SSDP Passive Listener",
        description="Listen for SSDP/UPnP announcements (zero impact)",
        category=ToolCategory.DISCOVERY,
        safe_modes=[
            SafeMode(
                name="passive",
                description="Listen only",
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
            ),
        ],
        output_schema=OutputSchema(
            fields={"ip": "str", "server": "str", "location": "str"},
            evidence_node_type="passive",
        ),
    ))
    registry.register(ToolSpec(
        tool_id="dhcp_listener",
        name="DHCP Passive Listener",
        description="Listen for DHCP traffic (zero impact)",
        category=ToolCategory.DISCOVERY,
        safe_modes=[
            SafeMode(
                name="passive",
                description="Listen only",
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
            ),
        ],
        output_schema=OutputSchema(
            fields={"ip": "str", "option55": "str"},
            evidence_node_type="passive",
        ),
    ))
    registry.register(ToolSpec(
        tool_id="netbios_listener",
        name="NetBIOS Passive Listener",
        description="Listen for NetBIOS broadcasts (zero impact)",
        category=ToolCategory.DISCOVERY,
        safe_modes=[
            SafeMode(
                name="passive",
                description="Listen only",
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
            ),
        ],
        output_schema=OutputSchema(
            fields={"ip": "str", "netbios_name": "str"},
            evidence_node_type="passive",
        ),
    ))
    registry.register(ToolSpec(
        tool_id="icmp_fingerprint",
        name="ICMP Fingerprinting Battery",
        description="ICMP echo, timestamp, and large ping for TTL/RTT profiling",
        category=ToolCategory.FINGERPRINT,
        requires_root=True,
        safe_modes=[
            SafeMode(
                name="echo_only",
                description="Single ICMP echo for TTL",
                impact_score=0.1,
                probe_types_used=["icmp_echo"],
                max_budget_cost=1.0,
                max_packets=1,
                timeout_sec=3.0,
            ),
            SafeMode(
                name="standard",
                description="Echo + timestamp probes",
                impact_score=0.2,
                probe_types_used=["icmp_echo", "icmp_timestamp"],
                max_budget_cost=2.0,
                max_packets=2,
                timeout_sec=5.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
            SafeMode(
                name="full",
                description="Echo + timestamp + large ping",
                impact_score=0.35,
                probe_types_used=["icmp_echo", "icmp_timestamp", "icmp_large"],
                max_budget_cost=3.5,
                max_packets=3,
                timeout_sec=5.0,
                tier_restrictions=[DeviceTier.CRITICAL, DeviceTier.FRAGILE],
            ),
        ],
        output_schema=OutputSchema(
            fields={"ttl": "int", "rtt_ms": "float", "timestamp_supported": "bool"},
            confidence_field="confidence",
            evidence_node_type="probe",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
            max_retries=2,
        ),
    ))
    registry.register(ToolSpec(
        tool_id="tcp_fingerprint",
        name="TCP Stack Fingerprinting",
        description="TCP SYN probe to extract window size, options, ISN",
        category=ToolCategory.FINGERPRINT,
        safe_modes=[
            # Mode 1: Single SYN to one open port — minimal footprint.
            SafeMode(
                name="syn_only",
                description="Single SYN to open port",
                impact_score=0.15,
                probe_types_used=["tcp_syn"],
                max_budget_cost=1.0,
                max_packets=1,
                timeout_sec=5.0,
            ),
            SafeMode(
                name="syn_multi",
                description="SYN to 3 ports for better fingerprint",
                impact_score=0.3,
                probe_types_used=["tcp_syn"],
                max_budget_cost=3.0,
                max_packets=3,
                timeout_sec=10.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
        ],
        output_schema=OutputSchema(
            fields={"window_size": "int", "tcp_options": "list", "isn_entropy": "float"},
            evidence_node_type="probe",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
            optional_params={"port": "80"},
        ),
    ))
    registry.register(ToolSpec(
        tool_id="snmp_probe",
        name="SNMP sysDescr Query",
        description="SNMP GET for sysDescr (community=public)",
        category=ToolCategory.FINGERPRINT,
        safe_modes=[
            SafeMode(
                name="standard",
                description="Single SNMP GET with public community",
                impact_score=0.15,
                probe_types_used=["snmp_query"],
                max_budget_cost=1.5,
                max_packets=1,
                timeout_sec=5.0,
            ),
        ],
        output_schema=OutputSchema(
            fields={"sysdescr": "str", "community": "str"},
            evidence_node_type="probe",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
            optional_params={"community": "public"},
        ),
    ))
    registry.register(ToolSpec(
        tool_id="dns_reverse",
        name="Reverse DNS Lookup",
        description="Reverse DNS lookup for hostname",
        category=ToolCategory.FINGERPRINT,
        safe_modes=[
            SafeMode(
                name="standard",
                description="Single PTR query",
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
                timeout_sec=5.0,
            ),
        ],
        output_schema=OutputSchema(
            fields={"hostname": "str"},
            evidence_node_type="probe",
        ),
    ))
    registry.register(ToolSpec(
        tool_id="tcp_syn_scan",
        name="TCP SYN Port Scan",
        description="SYN scan to discover open TCP ports",
        category=ToolCategory.PORT_SCAN,
        requires_root=True,
        safe_modes=[
            SafeMode(
                name="top_20",
                description="Scan top 20 common ports only",
                impact_score=0.2,
                probe_types_used=["tcp_syn"],
                max_budget_cost=20.0,
                max_packets=20,
                max_rate_pps=5.0,
                timeout_sec=30.0,
            ),
            SafeMode(
                name="top_100",
                description="Scan top 100 ports",
                impact_score=0.4,
                probe_types_used=["tcp_syn"],
                max_budget_cost=100.0,
                max_packets=100,
                max_rate_pps=20.0,
                timeout_sec=60.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
            SafeMode(
                name="top_1000",
                description="Scan top 1000 ports",
                impact_score=0.6,
                probe_types_used=["tcp_syn"],
                max_budget_cost=1000.0,
                max_packets=1000,
                max_rate_pps=50.0,
                timeout_sec=120.0,
                tier_restrictions=[DeviceTier.CRITICAL, DeviceTier.FRAGILE],
            ),
            SafeMode(
                name="full_65535",
                description="Full 65535-port scan",
                impact_score=0.9,
                probe_types_used=["tcp_syn"],
                max_budget_cost=65535.0,
                max_packets=65535,
                max_rate_pps=500.0,
                timeout_sec=600.0,
                tier_restrictions=[DeviceTier.CRITICAL, DeviceTier.FRAGILE, DeviceTier.UNKNOWN],
            ),
        ],
        output_schema=OutputSchema(
            fields={"open_ports": "list", "closed_count": "int", "filtered_count": "int"},
            evidence_node_type="port_scan",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
            optional_params={"ports": "top_20"},
            max_ports_per_call=65535,
        ),
    ))
    registry.register(ToolSpec(
        tool_id="banner_grab",
        name="TCP Banner Grab",
        description="Connect and read banner from open port",
        category=ToolCategory.SERVICE_PROBE,
        safe_modes=[
            SafeMode(
                name="passive_read",
                description="Connect and read (no send)",
                impact_score=0.2,
                probe_types_used=["tcp_banner_grab"],
                max_budget_cost=2.0,
                max_packets=1,
                timeout_sec=5.0,
            ),
            SafeMode(
                name="probe_send",
                description="Send HTTP HEAD/GET or protocol probe",
                impact_score=0.35,
                probe_types_used=["tcp_banner_grab", "http_head"],
                max_budget_cost=4.0,
                max_packets=2,
                timeout_sec=10.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
        ],
        output_schema=OutputSchema(
            fields={"port": "int", "banner": "str", "service": "str"},
            evidence_node_type="service_probe",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip", "port"],
            max_retries=1,
        ),
    ))
    registry.register(ToolSpec(
        tool_id="http_probe",
        name="HTTP Service Probe",
        description="HTTP HEAD/GET to identify web services",
        category=ToolCategory.SERVICE_PROBE,
        safe_modes=[
            SafeMode(
                name="head_only",
                description="HTTP HEAD request only",
                impact_score=0.2,
                probe_types_used=["http_head"],
                max_budget_cost=2.0,
                max_packets=1,
                timeout_sec=10.0,
            ),
            SafeMode(
                name="get_root",
                description="HTTP GET / for full response",
                impact_score=0.3,
                probe_types_used=["http_get"],
                max_budget_cost=2.5,
                max_packets=1,
                timeout_sec=10.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
        ],
        output_schema=OutputSchema(
            fields={"status_code": "int", "server": "str", "headers": "dict"},
            evidence_node_type="service_probe",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip", "port"],
        ),
    ))
    registry.register(ToolSpec(
        tool_id="os_passive_id",
        name="Passive OS Identification",
        description="Infer OS from previously collected TTL, window, options",
        category=ToolCategory.OS_IDENTIFICATION,
        safe_modes=[
            SafeMode(
                name="passive",
                description="No new packets — inference only",
                # Zero impact — no network activity at all.
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
            ),
        ],
        output_schema=OutputSchema(
            fields={"os_guess": "str", "confidence": "float", "method": "str"},
            confidence_field="confidence",
            evidence_node_type="os_id",
        ),
    ))
    registry.register(ToolSpec(
        tool_id="os_active_id",
        name="Active OS Fingerprinting",
        description="Nmap-style active OS fingerprinting probes",
        category=ToolCategory.OS_IDENTIFICATION,
        requires_root=True,
        safe_modes=[
            SafeMode(
                name="minimal",
                description="Standard TCP probes only (no malformed)",
                impact_score=0.3,
                probe_types_used=["os_probe_standard"],
                max_budget_cost=3.0,
                max_packets=3,
                timeout_sec=15.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
            SafeMode(
                name="standard",
                description="Standard nmap-style probes",
                impact_score=0.5,
                probe_types_used=["os_probe_standard", "tcp_syn"],
                max_budget_cost=5.0,
                max_packets=5,
                timeout_sec=20.0,
                tier_restrictions=[DeviceTier.CRITICAL, DeviceTier.FRAGILE],
            ),
            SafeMode(
                name="full",
                description="Full nmap probes including malformed packets",
                impact_score=0.8,
                probe_types_used=["os_probe_full", "tcp_malformed", "tcp_xmas"],
                max_budget_cost=15.0,
                max_packets=8,
                timeout_sec=30.0,
                tier_restrictions=[DeviceTier.CRITICAL, DeviceTier.FRAGILE, DeviceTier.UNKNOWN],
                fragility_warnings=["May crash lwIP/uIP stacks", "Known to reset some PLCs"],
            ),
        ],
        output_schema=OutputSchema(
            fields={"os_guess": "str", "confidence": "float", "fingerprint": "dict"},
            confidence_field="confidence",
            evidence_node_type="os_id",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
            optional_params={"open_port": "80", "closed_port": "1"},
        ),
        fallback_tool_ids=["os_passive_id"],
    ))
    registry.register(ToolSpec(
        tool_id="default_cred_check",
        name="Default Credential Check",
        description="Try known default credentials for identified services",
        category=ToolCategory.EXPLOITATION,
        safe_modes=[
            SafeMode(
                name="top_5",
                description="Try top 5 default creds only",
                impact_score=0.3,
                probe_types_used=["exploit_safe"],
                max_budget_cost=50.0,
                max_packets=5,
                timeout_sec=30.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
            SafeMode(
                name="comprehensive",
                description="Try full default credential database",
                impact_score=0.5,
                probe_types_used=["exploit_safe"],
                max_budget_cost=200.0,
                max_packets=20,
                timeout_sec=120.0,
                tier_restrictions=[DeviceTier.CRITICAL, DeviceTier.FRAGILE],
            ),
        ],
        output_schema=OutputSchema(
            fields={"service": "str", "credential": "str", "success": "bool"},
            evidence_node_type="exploit",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip", "port", "service"],
            max_retries=1,
        ),
    ))
    registry.register(ToolSpec(
        tool_id="cve_version_match",
        name="CVE Version Matcher",
        description="Match service versions against known CVEs (no exploitation)",
        category=ToolCategory.EXPLOITATION,
        safe_modes=[
            SafeMode(
                name="lookup_only",
                description="Local CVE database lookup — zero target impact",
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
            ),
        ],
        output_schema=OutputSchema(
            fields={"cve_id": "str", "severity": "str", "description": "str",
                     "affected_version": "str"},
            evidence_node_type="exploit",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["service", "version"],
        ),
    ))
    registry.register(ToolSpec(
        tool_id="safe_exploit_runner",
        name="Safe Exploit Runner",
        description="Execute exploitation with TIB constraints and approval gates",
        category=ToolCategory.EXPLOITATION,
        safe_modes=[
            SafeMode(
                name="dry_run",
                description="Simulate exploit without sending payloads",
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
            ),
            SafeMode(
                name="safe",
                description="Safe exploits only (info disclosure, auth bypass)",
                impact_score=0.5,
                probe_types_used=["exploit_safe"],
                max_budget_cost=10.0,
                max_packets=5,
                timeout_sec=30.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
            SafeMode(
                name="moderate",
                description="Moderate exploits (requires human approval for non-ROBUST)",
                impact_score=0.7,
                probe_types_used=["exploit_moderate"],
                max_budget_cost=20.0,
                max_packets=10,
                timeout_sec=60.0,
                tier_restrictions=[DeviceTier.CRITICAL, DeviceTier.FRAGILE],
                fragility_warnings=["May cause service restart"],
            ),
        ],
        output_schema=OutputSchema(
            fields={"exploit_id": "str", "success": "bool", "evidence": "dict"},
            evidence_node_type="exploit",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip", "exploit_id"],
            max_retries=1,
        ),
    ))
    registry.register(ToolSpec(
        tool_id="finding_validator",
        name="Finding Validator",
        description="Validate a finding by re-checking evidence and conditions",
        category=ToolCategory.VALIDATION,
        safe_modes=[
            SafeMode(
                name="passive_check",
                description="Validate from existing evidence only",
                impact_score=0.0,
                probe_types_used=[],
                max_budget_cost=0.0,
                max_packets=0,
            ),
            SafeMode(
                name="active_recheck",
                description="Re-probe to confirm finding",
                impact_score=0.2,
                probe_types_used=["tcp_syn", "tcp_banner_grab"],
                max_budget_cost=3.0,
                max_packets=2,
                timeout_sec=10.0,
                tier_restrictions=[DeviceTier.CRITICAL],
            ),
        ],
        output_schema=OutputSchema(
            fields={"finding_id": "str", "validated": "bool", "confidence": "float"},
            confidence_field="confidence",
            evidence_node_type="probe",
        ),
    ))
    registry.register(ToolSpec(
        tool_id="modbus_identify",
        name="Modbus Device Identification",
        description="Modbus function code 43 (Read Device ID)",
        category=ToolCategory.SERVICE_PROBE,
        safe_modes=[
            SafeMode(
                name="read_id",
                description="Read Device ID only — non-destructive",
                impact_score=0.3,
                probe_types_used=["modbus_identify"],
                max_budget_cost=3.0,
                max_packets=1,
                timeout_sec=10.0,
                fragility_warnings=["Some PLCs log Modbus queries"],
            ),
        ],
        output_schema=OutputSchema(
            fields={"vendor": "str", "product": "str", "version": "str"},
            evidence_node_type="service_probe",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
            optional_params={"port": "502"},
        ),
    ))
    registry.register(ToolSpec(
        tool_id="s7_identify",
        name="S7 Device Identification",
        description="Siemens S7 identification probe",
        category=ToolCategory.SERVICE_PROBE,
        safe_modes=[
            SafeMode(
                name="read_szl",
                description="Read SZL (system status list) — non-destructive",
                impact_score=0.3,
                probe_types_used=["s7_identify"],
                max_budget_cost=3.0,
                max_packets=1,
                timeout_sec=10.0,
                fragility_warnings=["S7 probes may trigger PLC logging"],
            ),
        ],
        output_schema=OutputSchema(
            fields={"module_type": "str", "serial": "str", "firmware": "str"},
            evidence_node_type="service_probe",
        ),
        invocation_grammar=InvocationGrammar(
            required_params=["target_ip"],
            optional_params={"port": "102"},
        ),
    ))
    if not registry._initialized:
        registry._initialized = True
