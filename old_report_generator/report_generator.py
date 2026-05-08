"""
Comprehensive HTML Penetration Test Report Generator for TRUCE-PT.
Produces a self-contained, detailed HTML report with:
  - Executive summary with metrics
  - Tier classification breakdown
  - 9-step pipeline execution summary
  - Per-device detailed reports (tests run, findings, timeline, budget)
  - PTG execution status per device
  - Raspberry Pi dedicated section
  - Validation oracle results
  - Evidence chain & compliance summary
"""

import json
import os
from datetime import datetime
from html import escape


def _h(text):
    """HTML-escape helper."""
    return escape(str(text)) if text else ""


def generate_html_report(results: dict, output_path: str = "output/pt_report.html") -> str:
    devices = results.get("devices", [])
    metrics = results.get("metrics", {})
    tier_summary = results.get("tier_summary", {})
    pcf = results.get("pcf_integrity", {})
    duration = results.get("duration_sec", 0)
    networks = results.get("networks", [])
    agent_results = results.get("agent_results", {})
    ptg_summaries = results.get("ptg_summaries", {})

    exploit_all = results.get("exploit_all", False)
    rpis = [d for d in devices if "raspberry pi" in d.get("vendor", "").lower()]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    exec_data = agent_results.get("execution", {})
    val_data = agent_results.get("validation", {})
    fleet_data = agent_results.get("fleet", {})
    evidence_data = agent_results.get("evidence", {})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TRUCE-PT Penetration Test Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;background:#f0f2f5;color:#1a1a2e;line-height:1.7;font-size:14px}}
.container{{max-width:1200px;margin:0 auto;padding:20px}}
.header{{background:linear-gradient(135deg,#0a0a23 0%,#1a1a3e 40%,#0f3460 100%);color:#fff;padding:50px 40px;border-radius:14px;margin-bottom:25px}}
.header h1{{font-size:2.2em;letter-spacing:-0.5px}}
.header .sub{{opacity:.7;font-size:1.05em;margin-top:4px}}
.header .meta{{margin-top:18px;display:flex;gap:25px;flex-wrap:wrap;font-size:.9em;opacity:.85}}
.header .meta span{{background:rgba(255,255,255,.1);padding:4px 12px;border-radius:6px}}
.card{{background:#fff;border-radius:12px;padding:28px;margin-bottom:22px;box-shadow:0 1px 8px rgba(0,0,0,.06)}}
.card h2{{color:#0f3460;border-bottom:2px solid #e4e8ee;padding-bottom:10px;margin-bottom:18px;font-size:1.25em}}
.card h3{{color:#16213e;margin:18px 0 8px;font-size:1.05em}}
.card h4{{color:#333;margin:12px 0 6px;font-size:.95em}}
.mg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}}
.m{{background:#f4f6fb;border-radius:8px;padding:14px;text-align:center;border-left:4px solid #0f3460}}
.m .v{{font-size:1.7em;font-weight:700;color:#0f3460}}
.m .l{{font-size:.78em;color:#666;margin-top:2px}}
.m.red{{border-color:#e74c3c}}.m.red .v{{color:#e74c3c}}
.m.green{{border-color:#27ae60}}.m.green .v{{color:#27ae60}}
.m.orange{{border-color:#f39c12}}.m.orange .v{{color:#f39c12}}
table{{width:100%;border-collapse:collapse;margin:10px 0;font-size:.88em}}
th{{background:#0f3460;color:#fff;padding:9px 12px;text-align:left;font-weight:600}}
td{{padding:7px 12px;border-bottom:1px solid #eee}}
tr:nth-child(even){{background:#fafbfd}}
tr:hover{{background:#f0f4ff}}
.tb{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.78em;font-weight:700;color:#fff}}
.tb-ROBUST{{background:#27ae60}}.tb-MODERATE{{background:#f39c12}}.tb-FRAGILE{{background:#e74c3c}}.tb-CRITICAL{{background:#8e44ad}}.tb-UNKNOWN{{background:#95a5a6}}
.st{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:600}}
.st-completed{{background:#d4edda;color:#155724}}.st-failed{{background:#f8d7da;color:#721c24}}.st-skipped{{background:#fff3cd;color:#856404}}
.rpi{{border-left:4px solid #c0392b}}
.rpi-card{{background:#fdf2f2;border-radius:8px;padding:16px;margin:10px 0;border:1px solid #f5c6cb}}
.finding{{border-radius:6px;padding:8px 14px;margin:5px 0;font-size:.88em;border-left:3px solid #27ae60;background:#eaf7ea}}
.finding.warn{{border-color:#f39c12;background:#fff8e1}}
.finding.info{{border-color:#3498db;background:#ebf5fb}}
.finding.danger{{border-color:#e74c3c;background:#fdf2f2}}
.step{{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid #f0f0f0}}
.sn{{width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.8em;font-weight:700;color:#fff}}
.sn-ok{{background:#27ae60}}.sn-skip{{background:#f39c12}}.sn-err{{background:#e74c3c}}
.timeline{{border-left:3px solid #0f3460;margin-left:12px;padding-left:18px}}
.tl-item{{position:relative;padding:4px 0;font-size:.82em;color:#555}}
.tl-item::before{{content:'';position:absolute;left:-24px;top:8px;width:10px;height:10px;border-radius:50%;background:#0f3460}}
.tl-item.alert::before{{background:#e74c3c}}
.bar{{height:20px;border-radius:4px;background:#e0e0e0;overflow:hidden;margin:4px 0}}
.bar-fill{{height:100%;border-radius:4px;background:linear-gradient(90deg,#27ae60,#2ecc71)}}
.bar-fill.high{{background:linear-gradient(90deg,#e74c3c,#c0392b)}}
.oracle{{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:.8em;margin:2px}}
.oracle.pass{{background:#d4edda;color:#155724}}.oracle.fail{{background:#f8d7da;color:#721c24}}
.port{{display:inline-block;background:#e74c3c;color:#fff;padding:1px 8px;border-radius:10px;font-size:.8em;margin:1px;font-weight:600}}
.footer{{text-align:center;padding:25px;color:#999;font-size:.82em}}
details{{margin:8px 0}}
summary{{cursor:pointer;font-weight:600;color:#0f3460;padding:6px 0}}
summary:hover{{color:#e74c3c}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:15px}}
@media(max-width:768px){{.two-col{{grid-template-columns:1fr}}.mg{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
<div class="container">

<div class="header">
<h1>Penetration Test Report</h1>
<div class="sub">TRUCE-PT Multi-Agent Risk-Tiered Network Assessment</div>
<div class="meta">
<span>Date: {now}</span>
<span>Target: {', '.join(networks)}</span>
<span>Duration: {duration:.1f}s</span>
<span>Devices: {len(devices)}</span>
<span>Actions: {exec_data.get('actions', 0)}</span>
{'<span style="background:rgba(231,76,60,.3);border:1px solid rgba(231,76,60,.6)">--exploit-all ACTIVE</span>' if exploit_all else ''}
</div>
</div>

<!-- ═══ EXECUTIVE SUMMARY ═══ -->
<div class="card">
<h2>1. Executive Summary</h2>
<p>Automated penetration test conducted on <strong>{', '.join(networks)}</strong> using the TRUCE-PT multi-agent framework.
The 9-step pipeline discovered <strong>{len(devices)} devices</strong>, executed <strong>{exec_data.get('actions', 0)} test actions</strong>,
produced <strong>{metrics.get('total_findings', 0)} findings</strong>, and validated <strong>{val_data.get('validated', 0)}</strong> of them via oracle checks.
<strong>{len(rpis)} Raspberry Pi</strong> device(s) were identified.
All evidence is recorded in a <strong>{metrics.get('pcf_nodes', 0)}-node</strong> cryptographic proof chain (PCF DAG).
{'<br><strong style="color:#e74c3c">Exploitation Override (--exploit-all):</strong> Exploitation was forced on ALL discovered devices, including CRITICAL-tier. CRITICAL devices received dry-run analysis only (zero packets sent).' if exploit_all else ''}</p>
<div class="mg" style="margin-top:16px">
<div class="m"><div class="v">{len(devices)}</div><div class="l">Devices Discovered</div></div>
<div class="m green"><div class="v">{exec_data.get('actions', 0)}</div><div class="l">Tests Executed</div></div>
<div class="m{'red' if metrics.get('total_findings',0)>0 else ''} "><div class="v">{metrics.get('total_findings', 0)}</div><div class="l">Findings</div></div>
<div class="m green"><div class="v">{val_data.get('validated', 0)}</div><div class="l">Validated</div></div>
<div class="m orange"><div class="v">{val_data.get('rejected', 0)}</div><div class="l">Rejected</div></div>
<div class="m"><div class="v">{metrics.get('vetoed_actions', 0)}</div><div class="l">Safety Vetoes</div></div>
<div class="m"><div class="v">{metrics.get('pcf_nodes', 0)}</div><div class="l">Evidence Nodes</div></div>
<div class="m"><div class="v">{len(rpis)}</div><div class="l">Raspberry Pi</div></div>
</div>
</div>

<!-- ═══ TESTS PERFORMED ═══ -->
<div class="card">
<h2>2. Penetration Tests Performed</h2>
<p>The following test categories were executed across all devices via the Per-Target Graph (PTG) engine:</p>
<table>
<tr><th>Phase</th><th>Test Name</th><th>Tool ID</th><th>Description</th><th>Risk Tier</th></tr>
<tr><td>Phase 0</td><td>mDNS Listener</td><td>mdns_listener</td><td>Passive multicast DNS service discovery</td><td><span class="tb tb-ROBUST">TIER 0</span></td></tr>
<tr><td>Phase 0</td><td>SSDP Listener</td><td>ssdp_listener</td><td>Passive UPnP device discovery</td><td><span class="tb tb-ROBUST">TIER 0</span></td></tr>
<tr><td>Phase 0</td><td>DHCP Listener</td><td>dhcp_listener</td><td>Passive DHCP fingerprint capture</td><td><span class="tb tb-ROBUST">TIER 0</span></td></tr>
<tr><td>Phase 0</td><td>NetBIOS Listener</td><td>netbios_listener</td><td>Passive NetBIOS name resolution</td><td><span class="tb tb-ROBUST">TIER 0</span></td></tr>
<tr><td>Phase 1</td><td>ARP Discovery</td><td>arp_discovery</td><td>ARP table + ICMP ping sweep for host detection</td><td><span class="tb tb-MODERATE">TIER 1</span></td></tr>
<tr><td>Phase 1</td><td>ICMP Discovery</td><td>icmp_discovery</td><td>ICMP echo probes with TTL analysis</td><td><span class="tb tb-MODERATE">TIER 1</span></td></tr>
<tr><td>Phase 1</td><td>TCP Discovery</td><td>tcp_discovery</td><td>TCP connect probes on common ports</td><td><span class="tb tb-MODERATE">TIER 1</span></td></tr>
<tr><td>Phase 2</td><td>Reverse DNS</td><td>dns_reverse</td><td>Hostname resolution via reverse DNS lookup</td><td><span class="tb tb-ROBUST">TIER 0</span></td></tr>
<tr><td>Phase 2</td><td>ICMP Fingerprint</td><td>icmp_fingerprint</td><td>TTL + RTT jitter analysis for OS family detection</td><td><span class="tb tb-MODERATE">TIER 1</span></td></tr>
<tr><td>Phase 2</td><td>TCP Fingerprint</td><td>tcp_fingerprint</td><td>TCP window size, options, ISN entropy analysis</td><td><span class="tb tb-MODERATE">TIER 1</span></td></tr>
<tr><td>Phase 2</td><td>SNMP Probe</td><td>snmp_probe</td><td>SNMPv1/v2c sysDescr.0 query for device identification</td><td><span class="tb tb-MODERATE">TIER 1</span></td></tr>
<tr><td>Phase 3</td><td>TIB Classification</td><td>__internal_tib_classify</td><td>Risk tier assignment based on collected signals</td><td><span class="tb tb-ROBUST">TIER 0</span></td></tr>
<tr><td>Phase 4</td><td>TCP Port Scan</td><td>tcp_syn_scan</td><td>TCP connect scan on top ports (tier-gated count)</td><td><span class="tb tb-FRAGILE">TIER 2</span></td></tr>
<tr><td>Phase 5</td><td>Banner Grab</td><td>banner_grab</td><td>Service banner capture on open ports</td><td><span class="tb tb-FRAGILE">TIER 2</span></td></tr>
<tr><td>Phase 5</td><td>HTTP Probe</td><td>http_probe</td><td>HTTP header analysis for web server identification</td><td><span class="tb tb-FRAGILE">TIER 2</span></td></tr>
<tr><td>Phase 6</td><td>Passive OS ID</td><td>os_passive_id</td><td>OS inference from TTL, banners, vendor (zero packets)</td><td><span class="tb tb-ROBUST">TIER 0</span></td></tr>
<tr><td>Phase 6</td><td>Active OS ID</td><td>os_active_id</td><td>TCP stack fingerprinting for OS detection</td><td><span class="tb tb-FRAGILE">TIER 2</span></td></tr>
</table>
</div>

<!-- ═══ 9-STEP PIPELINE ═══ -->
<div class="card">
<h2>3. Pipeline Execution (9 Steps)</h2>"""

    steps_info = [
        ("1", "Discovery Agent", "discovery", "Passive listening (mDNS, SSDP, DHCP, NetBIOS) + Active scanning (ICMP, ARP, TCP)"),
        ("2", "Target Profiling", "profiling", "Fingerprinting (TTL, banners, SNMP, TCP) + TIB tier classification"),
        ("3", "Fleet Reasoner", "fleet", f"Device clustering — {fleet_data.get('clusters', 0)} clusters, {fleet_data.get('probing_reduction_pct', 0):.0f}% probe reduction"),
        ("4", "Planner Agent", "planner", f"Built {agent_results.get('planner', {}).get('graphs_built', 0)} Per-Target Graphs (16 nodes each)"),
        ("5", "Safety Officer", "safety", "OT safety review — vetoes unsafe actions on CRITICAL/FRAGILE devices"),
        ("6", "Tool Orchestrator", "execution", f"Executed {exec_data.get('actions', 0)} PTG nodes — port scan, service probe, OS ID"),
        ("7", "Impact Monitor", "monitoring", f"Health check — {agent_results.get('monitoring', {}).get('alerts', 0)} alerts, {agent_results.get('monitoring', {}).get('vetoes', 0)} vetoes"),
        ("8", "Validator Agent", "validation", f"Oracle validation — {val_data.get('validated', 0)} passed, {val_data.get('rejected', 0)} rejected"),
        ("9", "Evidence Agent", "evidence", f"Recorded {evidence_data.get('nodes_recorded', 0)} nodes, {evidence_data.get('bundles_created', 0)} proof bundles"),
    ]
    for num, name, key, desc in steps_info:
        data = agent_results.get(key, {})
        skipped = data.get("skipped", False)
        css = "sn-skip" if skipped else "sn-ok"
        tag = " (SKIPPED)" if skipped else ""
        html += f"""
<div class="step"><div class="sn {css}">{num}</div><div><strong>Step {num}: {name}</strong>{tag}<br><span style="color:#666;font-size:.88em">{desc}</span></div></div>"""

    html += "\n</div>\n"

    # ═══ TIER CLASSIFICATION ═══
    html += """<div class="card"><h2>4. Device Tier Classification</h2>
<p>Each device is classified into a risk tier that determines scanning intensity, budget limits, and allowed actions:</p>
<table><tr><th>Tier</th><th>Count</th><th>Budget Limit</th><th>Scanning Intensity</th><th>Exploitation</th></tr>"""
    tier_info = {
        "ROBUST": ("Unlimited", "Full 65535-port scan", "Aggressive"),
        "MODERATE": ("5,000 pts", "Top 1000 ports", "Moderate"),
        "FRAGILE": ("1,000 pts", "Top 100 ports, 5 pps rate limit", "Safe only"),
        "CRITICAL": ("200 pts", "Top 20 ports, 1 pps rate limit", "None"),
        "UNKNOWN": ("1,000 pts", "Top 100 ports, conservative", "None"),
    }
    for tn, cnt in tier_summary.items():
        if cnt > 0:
            info = tier_info.get(tn, ("?", "?", "?"))
            html += f'<tr><td><span class="tb tb-{tn}">{tn}</span></td><td><strong>{cnt}</strong></td><td>{info[0]}</td><td>{info[1]}</td><td>{info[2]}</td></tr>'
    html += "</table></div>"

    # ═══ DEVICE INVENTORY ═══
    html += """<div class="card"><h2>5. Device Inventory</h2>
<table><tr><th>IP</th><th>Device Name</th><th>Type</th><th>MAC</th><th>Vendor</th><th>Tier</th><th>Open Ports</th><th>OS</th><th>Breaker</th><th>Budget</th></tr>"""
    for d in devices:
        ip = _h(d.get("ip", ""))
        mac = _h(d.get("mac", ""))
        vendor = _h(d.get("vendor", "Unknown"))
        device_name = _h(d.get("device_name", ""))
        device_type = _h(d.get("device_type", ""))
        tier = d.get("current_tier", "UNKNOWN")
        ports = d.get("findings", {}).get("open_ports", [])
        os_hint = _h(d.get("findings", {}).get("os_hint", "Unknown"))
        breaker = d.get("circuit_breaker", "ACTIVE")
        budget = d.get("budget", {})
        spent = budget.get("budget_spent", 0)
        total = budget.get("budget_total", 0)
        pct = (spent / total * 100) if total else 0
        ports_html = " ".join(f'<span class="port">{p}</span>' for p in ports) if ports else '<span style="color:#999">none</span>'
        breaker_cls = "color:#e74c3c;font-weight:bold" if breaker == "TRIPPED" else ""
        name_html = f"<strong>{device_name}</strong>" if device_name else '<span style="color:#999">—</span>'
        type_html = f"{device_type}" if device_type else '<span style="color:#999">—</span>'
        html += f'<tr><td><strong>{ip}</strong></td><td>{name_html}</td><td>{type_html}</td><td>{mac}</td><td>{vendor[:28]}</td><td><span class="tb tb-{tier}">{tier}</span></td><td>{ports_html}</td><td>{os_hint}</td><td style="{breaker_cls}">{breaker}</td><td>{spent:.0f}/{total:.0f} ({pct:.0f}%)</td></tr>'
    html += "</table></div>"

    # ═══ PTG EXECUTION STATUS ═══
    html += """<div class="card"><h2>6. Test Execution Status Per Device</h2>
<p>Each device has a 16-node Per-Target Graph (PTG). Status of each node after pipeline completion:</p>
<table><tr><th>Device</th><th>Vendor</th><th>Total Nodes</th><th>Completed</th><th>Failed</th><th>Skipped</th><th>Budget Used</th><th>Completion</th></tr>"""
    for d in devices:
        ip = d.get("ip", "")
        vendor = _h(d.get("vendor", "?"))[:20]
        ptg = ptg_summaries.get(ip, {})
        total_n = ptg.get("total_nodes", 0)
        by_st = ptg.get("by_status", {})
        comp = by_st.get("completed", 0)
        fail = by_st.get("failed", 0)
        skip = by_st.get("skipped", 0)
        budget = d.get("budget", {})
        spent = budget.get("budget_spent", 0)
        total_b = budget.get("budget_total", 0)
        pct = (comp / total_n * 100) if total_n else 0
        bar_cls = "high" if pct < 50 else ""
        html += f'<tr><td><strong>{ip}</strong></td><td>{vendor}</td><td>{total_n}</td><td><span class="st st-completed">{comp}</span></td><td><span class="st st-failed">{fail}</span></td><td><span class="st st-skipped">{skip}</span></td><td>{spent:.0f}/{total_b:.0f}</td><td><div class="bar"><div class="bar-fill {bar_cls}" style="width:{pct:.0f}%"></div></div>{pct:.0f}%</td></tr>'
    html += "</table></div>"

    # ═══ EXPLOITATION RESULTS ═══
    # Collect all exploit findings across devices for the summary table
    all_exploit_findings = []
    for d in devices:
        ip = d.get("ip", "")
        tier = d.get("current_tier", "UNKNOWN")
        for v in d.get("findings", {}).get("vulnerabilities", []):
            if v.get("type") == "exploit":
                all_exploit_findings.append({**v, "ip": ip, "tier": tier})

    exploit_successes = [e for e in all_exploit_findings if e.get("success")]
    exploit_dry_runs = [e for e in all_exploit_findings if e.get("dry_run") and not e.get("success")]
    exploit_devices = set(e["ip"] for e in all_exploit_findings)

    html += '<div class="card"><h2>7. Exploitation Results</h2>'
    if exploit_all:
        html += '<div style="background:#fdf2f2;border:1px solid #f5c6cb;border-radius:8px;padding:12px 18px;margin-bottom:16px;font-size:.92em">'
        html += '<strong style="color:#e74c3c">--exploit-all override active:</strong> '
        html += 'Exploitation was run on all discovered devices regardless of tier restrictions. '
        html += 'CRITICAL-tier devices received <strong>dry-run</strong> analysis only (zero network packets). '
        html += 'Budget was topped up where needed to ensure exploitation could proceed.'
        html += '</div>'

    html += f"""<div class="mg" style="margin-bottom:16px">
<div class="m red"><div class="v">{len(exploit_successes)}</div><div class="l">Successful Exploits</div></div>
<div class="m orange"><div class="v">{len(exploit_dry_runs)}</div><div class="l">Dry-Run Findings</div></div>
<div class="m"><div class="v">{len(all_exploit_findings)}</div><div class="l">Total Exploit Checks</div></div>
<div class="m"><div class="v">{len(exploit_devices)}</div><div class="l">Devices Tested</div></div>
</div>"""

    if all_exploit_findings:
        sev_colors = {"CRITICAL": "#8e44ad", "HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#3498db", "INFO": "#95a5a6"}
        html += '<table><tr><th>Device</th><th>Tier</th><th>Exploit ID</th><th>Severity</th><th>Result</th><th>Confidence</th><th>Details</th></tr>'
        for e in sorted(all_exploit_findings, key=lambda x: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.get("severity", "INFO").upper()),
            not x.get("success", False)
        )):
            ip = _h(e.get("ip", ""))
            tier = e.get("tier", "UNKNOWN")
            eid = _h(e.get("exploit_id", "?"))
            sev = e.get("severity", "INFO")
            sev = sev.upper()
            sev_color = sev_colors.get(sev, "#333")
            success = e.get("success", False)
            dry_run = e.get("dry_run", False)
            conf = e.get("confidence", 0)
            detail = _h(str(e.get("detail", ""))[:150])

            if success:
                result_html = '<span style="color:#e74c3c;font-weight:bold">EXPLOITED</span>'
            elif dry_run:
                result_html = '<span style="color:#f39c12;font-weight:bold">DRY-RUN</span>'
            else:
                result_html = '<span style="color:#95a5a6">checked</span>'

            conf_pct = f"{conf*100:.0f}%" if conf else "—"
            html += f'<tr><td><strong>{ip}</strong></td><td><span class="tb tb-{tier}">{tier}</span></td>'
            html += f'<td><code>{eid}</code></td>'
            html += f'<td><span style="color:{sev_color};font-weight:bold">{sev}</span></td>'
            html += f'<td>{result_html}</td><td>{conf_pct}</td><td>{detail}</td></tr>'
        html += '</table>'
    else:
        html += '<div class="finding warn">No exploitation findings — no exploitable services were detected on any device.</div>'

    html += '</div>'

    # ═══ POST-EXPLOITATION: LATERAL MOVEMENT & ATTACK GRAPH ═══
    pe_data = results.get("post_exploitation", {})
    if pe_data and not pe_data.get("skipped"):
        html += '<div class="card"><h2>7.5. Post-Exploitation Analysis</h2>'

        # Summary metrics
        html += f"""<div class="mg" style="margin-bottom:16px">
        <div class="m red"><div class="v">{pe_data.get('shells_established', 0)}</div><div class="l">Shells Established</div></div>
        <div class="m red"><div class="v">{pe_data.get('total_pivot_paths', 0)}</div><div class="l">Pivot Paths</div></div>
        <div class="m red"><div class="v">{pe_data.get('confirmed_pivots', 0)}</div><div class="l">Confirmed Pivots</div></div>
        <div class="m orange"><div class="v">{pe_data.get('kill_chains', 0)}</div><div class="l">Kill Chains</div></div>
        </div>"""

        # C2 Risk Distribution
        risk_dist = pe_data.get("risk_distribution", {})
        if risk_dist:
            html += '<h3>C2 / Reverse Shell Risk Distribution</h3>'
            html += '<div class="mg" style="margin-bottom:12px">'
            risk_colors = {"critical": "red", "high": "red", "moderate": "orange", "low": "", "minimal": "green"}
            for level, count in risk_dist.items():
                cls = risk_colors.get(level, "")
                html += f'<div class="m {cls}"><div class="v">{count}</div><div class="l">{level.upper()}</div></div>'
            html += '</div>'

        # Kill Chains
        kill_chains = results.get("kill_chains", [])
        if kill_chains:
            html += f'<h3>Kill Chains ({len(kill_chains)} found)</h3>'
            html += '<p style="font-size:.88em;color:#666;margin-bottom:8px">Attack paths from compromised devices to high-value targets:</p>'
            html += '<table><tr><th>#</th><th>Attack Path</th><th>Hops</th><th>Score</th><th>Feasibility</th><th>Target Value</th></tr>'
            for i, kc in enumerate(kill_chains[:10], 1):
                path_html = ' &rarr; '.join(f'<strong>{_h(ip)}</strong>' for ip in kc.get("path", []))
                score = kc.get("total_score", 0)
                feasibility = _h(kc.get("feasibility_summary", ""))
                target_val = _h(kc.get("target_value", ""))
                hops = kc.get("chain_length", 0)
                score_cls = "color:#e74c3c" if score > 0.5 else "color:#f39c12" if score > 0.2 else ""
                html += f'<tr><td>{i}</td><td>{path_html}</td><td>{hops}</td><td style="{score_cls};font-weight:bold">{score:.3f}</td><td>{feasibility}</td><td>{target_val}</td></tr>'
            html += '</table>'

        # Subnet Risks
        subnet_risks = pe_data.get("subnet_risks", [])
        if subnet_risks:
            html += f'<h3>Subnet Risk Assessment ({len(subnet_risks)} subnets)</h3>'
            html += '<table><tr><th>Subnet</th><th>Risk</th><th>Devices</th><th>Compromised</th><th>High-Value</th><th>Confirmed Pivots</th><th>Recommendations</th></tr>'
            for sr in subnet_risks:
                risk_level = sr.get("risk_level", "LOW")
                risk_cls = {"CRITICAL": "#8e44ad", "HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#27ae60"}.get(risk_level, "#333")
                recs = "<br>".join(_h(r) for r in sr.get("recommendations", [])[:3])
                html += f'<tr><td><strong>{_h(sr.get("subnet", ""))}</strong></td>'
                html += f'<td><span style="color:{risk_cls};font-weight:bold">{risk_level}</span></td>'
                html += f'<td>{sr.get("device_count", 0)}</td>'
                html += f'<td>{sr.get("compromised_count", 0)}</td>'
                html += f'<td>{sr.get("high_value_count", 0)}</td>'
                html += f'<td>{sr.get("confirmed_pivots", 0)}</td>'
                html += f'<td style="font-size:.82em">{recs}</td></tr>'
            html += '</table>'

        # Per-device lateral movement details
        has_lateral = any(d.get("lateral_movement") for d in devices)
        if has_lateral:
            html += '<h3>Per-Device Lateral Movement Details</h3>'
            for d in devices:
                lm = d.get("lateral_movement")
                if not lm or lm.get("pivot_count", 0) == 0:
                    continue
                ip = _h(d.get("ip", ""))
                html += f'<details><summary>{ip} — {lm.get("pivot_count", 0)} pivot path(s), {lm.get("confirmed_pivots", 0)} confirmed</summary>'
                html += '<div style="padding:8px 0">'

                # Trust relationships
                trust_rels = lm.get("trust_relationships", [])
                if trust_rels:
                    html += f'<h4>Trust Relationships ({len(trust_rels)})</h4>'
                    html += '<table><tr><th>Target</th><th>Type</th><th>Confidence</th><th>Evidence</th></tr>'
                    for tr in trust_rels[:15]:
                        html += f'<tr><td>{_h(tr.get("target_ip", ""))}</td><td>{_h(tr.get("trust_type", ""))}</td>'
                        html += f'<td>{tr.get("confidence", 0):.0%}</td><td style="font-size:.82em">{_h(str(tr.get("evidence", {}))[:100])}</td></tr>'
                    html += '</table>'

                # Pivot paths
                pivots = lm.get("pivot_paths", [])
                if pivots:
                    html += f'<h4>Pivot Paths ({len(pivots)})</h4>'
                    for p in pivots[:5]:
                        f_cls = {"confirmed": "danger", "likely": "warn", "possible": "info"}.get(p.get("feasibility", ""), "info")
                        html += f'<div class="finding {f_cls}">'
                        html += f'<strong>{_h(p.get("feasibility", "").upper())}</strong> '
                        html += f'{ip} &rarr; {_h(p.get("target_ip", ""))} '
                        html += f'via <code>{_h(p.get("attack_vector", ""))}</code> '
                        html += f'(score: {p.get("score", 0):.3f})'
                        if p.get("services_available"):
                            html += f' | services: {", ".join(p["services_available"])}'
                        html += '</div>'

                html += '</div></details>'

        # Per-device C2 risk details
        has_c2 = any(d.get("c2_risk") for d in devices)
        if has_c2:
            html += '<h3>Per-Device C2 / Reverse Shell Risk</h3>'
            html += '<table><tr><th>Device</th><th>RSRS Score</th><th>Risk Level</th><th>Outbound</th><th>Auth Weakness</th><th>Writable Svc</th><th>DNS Tunnel</th><th>Covert Ch.</th><th>Persistence</th><th>C2 Channels</th></tr>'
            for d in devices:
                c2 = d.get("c2_risk")
                if not c2 or c2.get("skipped"):
                    continue
                ip = _h(d.get("ip", ""))
                score = c2.get("composite_score", 0)
                level = c2.get("risk_level", "minimal")
                level_cls = {"critical": "#8e44ad", "high": "#e74c3c", "moderate": "#f39c12", "low": "#27ae60", "minimal": "#95a5a6"}.get(level, "#333")

                dims = {ds.get("dimension", ""): ds.get("score", 0) for ds in c2.get("dimension_scores", [])}
                channels = len(c2.get("c2_channels_feasible", []))

                def _dim_bar(val):
                    pct = int(val * 100)
                    cls = "high" if val >= 0.5 else ""
                    return f'<div class="bar" style="width:80px;display:inline-block"><div class="bar-fill {cls}" style="width:{pct}%"></div></div> {pct}%'

                html += f'<tr><td><strong>{ip}</strong></td>'
                html += f'<td style="font-weight:bold;color:{level_cls}">{score:.2f}</td>'
                html += f'<td><span style="color:{level_cls};font-weight:bold">{level.upper()}</span></td>'
                html += f'<td>{_dim_bar(dims.get("outbound_connectivity", 0))}</td>'
                html += f'<td>{_dim_bar(dims.get("auth_weakness", 0))}</td>'
                html += f'<td>{_dim_bar(dims.get("writable_service", 0))}</td>'
                html += f'<td>{_dim_bar(dims.get("dns_tunneling", 0))}</td>'
                html += f'<td>{_dim_bar(dims.get("covert_channel", 0))}</td>'
                html += f'<td>{_dim_bar(dims.get("persistence_mechanism", 0))}</td>'
                html += f'<td>{channels}</td></tr>'
            html += '</table>'

        html += '</div>'

    # ═══ DETAILED DEVICE REPORTS ═══
    html += '<div class="card"><h2>8. Detailed Device Reports</h2>'
    for d in devices:
        ip = _h(d.get("ip", ""))
        mac = _h(d.get("mac", ""))
        vendor = _h(d.get("vendor", "Unknown"))
        device_name = _h(d.get("device_name", ""))
        device_type = _h(d.get("device_type", ""))
        tier = d.get("current_tier", "UNKNOWN")
        findings = d.get("findings", {})
        ports = findings.get("open_ports", [])
        os_hint = _h(findings.get("os_hint", "Unknown"))
        breaker = d.get("circuit_breaker", "ACTIVE")
        trip = _h(d.get("trip_reason", ""))
        budget = d.get("budget", {})
        rtt = d.get("rtt_stats", {})
        event_log = d.get("event_log", [])
        class_hist = d.get("classification_history", [])
        ptg = ptg_summaries.get(d.get("ip", ""), {})
        by_st = ptg.get("by_status", {})
        breakdown = budget.get("breakdown_by_type", {})
        is_rpi = "raspberry pi" in vendor.lower()
        summary_label = device_name or device_type or vendor

        html += f"""
<details{"open" if is_rpi else ""}>
<summary>{ip} — {summary_label} <span class="tb tb-{tier}">{tier}</span> {"🔴" if breaker=="TRIPPED" else "🟢"}</summary>
<div style="padding:10px 0">
<div class="two-col">
<div>
<h4>Identity</h4>
<table>
<tr><td>Device Name</td><td><strong>{device_name or '<span style="color:#999">—</span>'}</strong></td></tr>
<tr><td>Device Type</td><td>{device_type or '<span style="color:#999">—</span>'}</td></tr>
<tr><td>IP Address</td><td><strong>{ip}</strong></td></tr>
<tr><td>MAC Address</td><td>{mac}</td></tr>
<tr><td>Vendor</td><td>{vendor}</td></tr>
<tr><td>Tier</td><td><span class="tb tb-{tier}">{tier}</span></td></tr>
<tr><td>OS Detection</td><td><strong>{os_hint}</strong></td></tr>
<tr><td>Circuit Breaker</td><td>{"<span style='color:#e74c3c;font-weight:bold'>TRIPPED</span> — "+trip if breaker=="TRIPPED" else "<span style='color:#27ae60'>ACTIVE</span>"}</td></tr>
</table>
</div>
<div>
<h4>Budget Consumption</h4>
<table>
<tr><td>Total Budget</td><td>{budget.get('budget_total',0):.0f} pts</td></tr>
<tr><td>Budget Spent</td><td><strong>{budget.get('budget_spent',0):.0f} pts</strong></td></tr>
<tr><td>Remaining</td><td>{budget.get('budget_total',0)-budget.get('budget_spent',0):.0f} pts</td></tr>
</table>"""
        if breakdown:
            html += "<h4>Budget Breakdown by Probe Type</h4><table>"
            for probe_type, cost in sorted(breakdown.items(), key=lambda x: -x[1]):
                html += f"<tr><td>{_h(probe_type)}</td><td>{cost:.1f} pts</td></tr>"
            html += "</table>"
        html += "</div></div>"

        # Findings: ports, OS, banners, vulnerabilities
        html += "<h4>Open Ports</h4>"
        if ports:
            for p in ports:
                html += f'<div class="finding danger">Port <strong>{p}/tcp</strong> — OPEN</div>'
        else:
            html += '<div class="finding warn">No open ports detected</div>'

        if os_hint and os_hint != "Unknown":
            html += f'<div class="finding info">OS Identified: <strong>{os_hint}</strong></div>'

        # Service banners
        svc_banners = findings.get("banners", {})
        if svc_banners:
            html += "<h4>Service Banners</h4><table><tr><th>Port</th><th>Banner</th></tr>"
            for bp, bb in svc_banners.items():
                html += f"<tr><td>{bp}</td><td><code>{_h(str(bb)[:120])}</code></td></tr>"
            html += "</table>"

        # Vulnerability findings
        vulns = findings.get("vulnerabilities", [])
        if vulns:
            sev_cls = {"CRITICAL": "danger", "HIGH": "danger", "MEDIUM": "warn", "LOW": "info", "INFO": "info"}
            exploit_vulns = [v for v in vulns if v.get("type") == "exploit"]
            probe_vulns = [v for v in vulns if v.get("type") != "exploit"]
            html += f"<h4>Vulnerability Findings ({len(vulns)})</h4>"
            for v in sorted(probe_vulns, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO").upper())):
                sev = v.get("severity", "INFO").upper()
                cls = sev_cls.get(sev, "info")
                html += f'<div class="finding {cls}"><strong>[{sev}]</strong> Port {v.get("port","?")} — {_h(v.get("detail",""))}</div>'
            if exploit_vulns:
                html += f"<h4>Exploitation Findings ({len(exploit_vulns)})</h4>"
                for v in sorted(exploit_vulns, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO").upper())):
                    sev = v.get("severity", "INFO").upper()
                    cls = sev_cls.get(sev, "info")
                    eid = _h(v.get("exploit_id", "?"))
                    success = v.get("success", False)
                    dry_run = v.get("dry_run", False)
                    tag = " [EXPLOITED]" if success else (" [DRY-RUN]" if dry_run else "")
                    html += f'<div class="finding {cls}"><strong>[{sev}]{tag}</strong> {eid} — {_h(v.get("detail",""))}</div>'
        elif not ports:
            html += '<div class="finding warn">No vulnerability findings — device may be firewalled or unresponsive</div>'

        # PTG execution
        html += "<h4>Test Execution (PTG Nodes)</h4>"
        html += f'<table><tr><th>Status</th><th>Count</th></tr>'
        for st_name, st_count in by_st.items():
            cls = f"st-{st_name}"
            html += f'<tr><td><span class="st {cls}">{st_name.upper()}</span></td><td>{st_count}</td></tr>'
        html += "</table>"

        # RTT stats
        if rtt and rtt.get("samples", 0) and rtt.get("samples", 0) > 0:
            baseline = rtt.get('baseline_ms') or 0
            current = rtt.get('current_ms') or 0
            mean = rtt.get('mean_ms') or 0
            stddev = rtt.get('stddev_ms') or 0
            html += f"""<h4>Network Metrics (RTT)</h4>
<table>
<tr><td>Samples</td><td>{rtt.get('samples',0)}</td></tr>
<tr><td>Baseline RTT</td><td>{baseline:.1f} ms</td></tr>
<tr><td>Current RTT</td><td>{current:.1f} ms</td></tr>
<tr><td>Mean RTT</td><td>{mean:.1f} ms</td></tr>
<tr><td>Std Dev</td><td>{stddev:.2f} ms</td></tr>
<tr><td>Stress Events</td><td>{rtt.get('stress_events',0)}</td></tr>
</table>"""

        # Timeline
        if event_log:
            html += "<h4>Event Timeline</h4><div class='timeline'>"
            for ev in event_log[:20]:
                cls = "alert" if "ERROR" in str(ev) or "TRIPPED" in str(ev) or "RECLASSIFY" in str(ev) else ""
                html += f'<div class="tl-item {cls}">{_h(str(ev))}</div>'
            if len(event_log) > 20:
                html += f'<div class="tl-item">... and {len(event_log)-20} more events</div>'
            html += "</div>"

        html += "</div></details>"
    html += "</div>"

    # ═══ RASPBERRY PI SECTION ═══
    if rpis:
        html += '<div class="card rpi"><h2>9. Raspberry Pi Devices</h2>'
        html += f'<p><strong>{len(rpis)}</strong> Raspberry Pi device(s) identified via OUI MAC prefix (B8:27:EB = Raspberry Pi Foundation).</p>'
        for d in rpis:
            ip = _h(d.get("ip", ""))
            mac = _h(d.get("mac", ""))
            vendor = _h(d.get("vendor", ""))
            tier = d.get("current_tier", "UNKNOWN")
            ports = d.get("findings", {}).get("open_ports", [])
            os_hint = _h(d.get("findings", {}).get("os_hint", "Unknown"))
            budget = d.get("budget", {})
            ports_html = " ".join(f'<span class="port">{p}</span>' for p in ports) if ports else "none"
            html += f"""<div class="rpi-card">
<h3>{ip} — {vendor}</h3>
<table>
<tr><td><strong>MAC</strong></td><td>{mac}</td></tr>
<tr><td><strong>Tier</strong></td><td><span class="tb tb-{tier}">{tier}</span></td></tr>
<tr><td><strong>Open Ports</strong></td><td>{ports_html}</td></tr>
<tr><td><strong>OS Detection</strong></td><td><strong>{os_hint}</strong></td></tr>
<tr><td><strong>Budget Used</strong></td><td>{budget.get('budget_spent',0):.0f} / {budget.get('budget_total',0):.0f} pts</td></tr>
<tr><td><strong>Circuit Breaker</strong></td><td>{d.get('circuit_breaker','N/A')}</td></tr>
</table>
</div>"""
        html += "</div>"

    # ═══ ISSUES & RECOMMENDATIONS ═══
    html += '<div class="card"><h2>10. Issues Found & Recommendations</h2>'

    issues = []
    for d in devices:
        ip = d.get("ip", "")
        findings_d = d.get("findings", {})
        ports = findings_d.get("open_ports", [])
        os_hint = findings_d.get("os_hint", "Unknown")
        vendor = d.get("vendor", "").lower()
        breaker = d.get("circuit_breaker", "ACTIVE")
        vulns = findings_d.get("vulnerabilities", [])
        banners_d = findings_d.get("banners", {})
        is_rpi = "raspberry pi" in vendor

        # Pull real vulnerability findings from service probe
        for v in vulns:
            issues.append((v.get("severity", "INFO").upper(), ip, v.get("detail", ""), v.get("type", ""), "probe"))

        # ── Port-based security analysis ──
        port_set = set(ports)
        for p in ports:
            if p == 22:
                banner_text = str(banners_d.get(str(p), banners_d.get(p, ""))).lower()
                issues.append(("HIGH", ip, f"SSH service (port 22) exposed to network — restrict access via firewall rules or SSH AllowUsers", "ssh_open", "port"))
                if is_rpi:
                    issues.append(("HIGH", ip, f"Raspberry Pi SSH open — default user 'pi' with password 'raspberry' may be active. Run 'passwd' to change immediately", "rpi_default_creds", "rpi"))
                    issues.append(("MEDIUM", ip, f"Raspberry Pi SSH — disable password auth, use key-based auth only (set PasswordAuthentication no in sshd_config)", "rpi_ssh_password", "rpi"))
                if "openssh" in banner_text:
                    # Extract version for CVE check
                    issues.append(("MEDIUM", ip, f"OpenSSH version disclosed in banner — consider adding 'DebianBanner no' to sshd_config to reduce fingerprinting", "ssh_banner_leak", "service"))
                if not any(v.get("type") == "ssh_v1" for v in vulns):
                    issues.append(("INFO", ip, f"SSH Protocol v2 in use (good) — verify no SSHv1 fallback is configured", "ssh_v2_ok", "info"))
            elif p == 80:
                issues.append(("MEDIUM", ip, f"HTTP (port 80) unencrypted — implement HTTPS redirect, sensitive data may be transmitted in plaintext", "http_unencrypted", "port"))
                if is_rpi:
                    issues.append(("MEDIUM", ip, f"Raspberry Pi web server on port 80 — check for default admin panels (e.g., /admin, /config)", "rpi_http_admin", "rpi"))
            elif p == 443 or p == 8443:
                issues.append(("LOW", ip, f"HTTPS (port {p}) — verify TLS 1.2+ enforced, check certificate validity and cipher suite strength", "https_check", "port"))
            elif p == 21:
                issues.append(("HIGH", ip, f"FTP (port 21) — plaintext protocol transmits credentials in clear. Migrate to SFTP/SCP", "ftp_plaintext", "port"))
                issues.append(("HIGH", ip, f"FTP (port 21) — check for anonymous login access (test: 'ftp {ip}' with user 'anonymous')", "ftp_anon_check", "port"))
            elif p == 23:
                issues.append(("CRITICAL", ip, f"Telnet (port 23) — unencrypted remote shell. Disable immediately and replace with SSH", "telnet_open", "port"))
            elif p == 445 or p == 139:
                issues.append(("HIGH", ip, f"SMB/NetBIOS (port {p}) — check for EternalBlue (MS17-010), null sessions, and guest access", "smb_open", "port"))
                issues.append(("MEDIUM", ip, f"SMB (port {p}) — verify SMBv1 is disabled (vulnerable to WannaCry/NotPetya)", "smb_v1", "port"))
            elif p == 3306:
                issues.append(("HIGH", ip, f"MySQL (port 3306) — database port exposed. Restrict to localhost, verify authentication required", "mysql_exposed", "port"))
            elif p == 5900:
                issues.append(("HIGH", ip, f"VNC (port 5900) — remote desktop protocol often weakly authenticated. Use SSH tunneling instead", "vnc_open", "port"))
            elif p == 8080:
                issues.append(("MEDIUM", ip, f"HTTP-Alt (port 8080) — often admin/dev panel, check for default credentials and restrict access", "http_alt", "port"))
            elif p == 135:
                issues.append(("MEDIUM", ip, f"RPC (port 135) — Windows RPC endpoint mapper exposed, potential attack surface for DCOM exploits", "rpc_open", "port"))
            elif p == 3389:
                issues.append(("HIGH", ip, f"RDP (port 3389) — remote desktop exposed. Enable NLA, use strong passwords, consider VPN access only", "rdp_open", "port"))
            elif p == 5432:
                issues.append(("HIGH", ip, f"PostgreSQL (port 5432) — database port exposed. Restrict access, verify pg_hba.conf authentication", "postgres_open", "port"))
            elif p == 6379:
                issues.append(("CRITICAL", ip, f"Redis (port 6379) — often runs without authentication. Test with 'redis-cli -h {ip} PING'", "redis_open", "port"))
            elif p == 27017:
                issues.append(("HIGH", ip, f"MongoDB (port 27017) — check for no-auth access, enable authentication in mongod.conf", "mongodb_open", "port"))
            elif p == 1883:
                issues.append(("MEDIUM", ip, f"MQTT (port 1883) — IoT messaging protocol, check for anonymous publish/subscribe access", "mqtt_open", "port"))
            else:
                issues.append(("LOW", ip, f"Port {p}/tcp open — verify this service is intentional and running latest patches", "unknown_port", "port"))

        # ── Raspberry Pi specific findings ──
        if is_rpi:
            issues.append(("HIGH", ip, f"Raspberry Pi Foundation device detected (MAC OUI: B8:27:EB) — apply all Raspberry Pi OS security hardening", "rpi_detected", "rpi"))
            issues.append(("MEDIUM", ip, f"Raspberry Pi — verify OS and packages are up to date: 'sudo apt update && sudo apt full-upgrade'", "rpi_updates", "rpi"))
            issues.append(("MEDIUM", ip, f"Raspberry Pi — check if default 'pi' user still exists: 'id pi'. If so, rename or remove it", "rpi_default_user", "rpi"))
            issues.append(("LOW", ip, f"Raspberry Pi — enable automatic security updates: 'sudo apt install unattended-upgrades'", "rpi_auto_update", "rpi"))
            issues.append(("LOW", ip, f"Raspberry Pi — enable UFW firewall: 'sudo ufw enable' and allow only required ports", "rpi_firewall", "rpi"))
            if os_hint and "raspbian" in os_hint.lower():
                issues.append(("INFO", ip, f"Running Raspbian OS (legacy) — consider migrating to Raspberry Pi OS (64-bit) for better security support", "rpi_legacy_os", "rpi"))
            if 22 in port_set:
                issues.append(("LOW", ip, f"Raspberry Pi — consider changing SSH port from default 22 to reduce automated scanning exposure", "rpi_ssh_port", "rpi"))
                issues.append(("LOW", ip, f"Raspberry Pi — install fail2ban to protect SSH from brute-force: 'sudo apt install fail2ban'", "rpi_fail2ban", "rpi"))

        # ── OS-based findings ──
        if os_hint and os_hint != "Unknown":
            if "linux" in os_hint.lower():
                issues.append(("LOW", ip, f"Linux detected ({os_hint}) — verify kernel is up to date, check for known CVEs with 'uname -r'", "linux_kernel", "os"))

        # ── Network infrastructure findings ──
        if breaker == "TRIPPED":
            issues.append(("MEDIUM", ip, f"Circuit breaker tripped during scan — device may be resource-constrained or has aggressive rate limiting", "breaker_trip", "infra"))
        if not ports and os_hint == "Unknown":
            issues.append(("INFO", ip, f"No open ports or OS detected — device may be behind a firewall or host-based IPS blocking probes", "no_findings", "infra"))

    # ── Render issues table ──
    if issues:
        sev_colors = {"CRITICAL": "#8e44ad", "HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#3498db", "INFO": "#95a5a6"}
        sev_icons = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~", "INFO": "i"}

        # Summary counts
        sev_counts = {}
        for sev, *_ in issues:
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        html += '<div class="mg" style="margin-bottom:15px">'
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in sev_counts:
                cls = "red" if sev in ("CRITICAL", "HIGH") else ("orange" if sev == "MEDIUM" else "")
                html += f'<div class="m {cls}"><div class="v">{sev_counts[sev]}</div><div class="l">{sev}</div></div>'
        html += '</div>'

        html += '<table><tr><th>Sev</th><th>Device</th><th>Category</th><th>Finding & Recommendation</th></tr>'
        for sev, ip, desc, typ, cat in sorted(issues, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x[0])):
            cat_label = {"port": "Open Port", "service": "Service", "rpi": "Raspberry Pi", "os": "OS", "infra": "Infrastructure", "probe": "Probe", "info": "Info"}.get(cat, cat)
            html += f'<tr><td><span style="color:{sev_colors.get(sev,"#333")};font-weight:bold">{sev}</span></td><td><strong>{ip}</strong></td><td>{cat_label}</td><td>{_h(desc)}</td></tr>'
        html += "</table>"
    else:
        html += '<div class="finding warn">No specific issues identified — all scanned ports are closed or filtered.</div>'
    html += "</div>"

    # ═══ EVIDENCE & COMPLIANCE ═══
    html += f"""<div class="card"><h2>11. Evidence Chain & Compliance</h2>
<div class="two-col">
<div>
<h4>PCF Evidence DAG</h4>
<table>
<tr><td>Total Evidence Nodes</td><td><strong>{metrics.get('pcf_nodes', 0)}</strong></td></tr>
<tr><td>Proof Bundles</td><td><strong>{evidence_data.get('bundles_created', 0)}</strong></td></tr>
<tr><td>DAG Integrity</td><td>{"<span style='color:#27ae60'>VALID</span>" if pcf.get('valid') else f"<span style='color:#e74c3c'>WARNINGS ({pcf.get('error_count',0)} issues)</span>"}</td></tr>
<tr><td>Evidence Recording</td><td>{evidence_data.get('nodes_recorded', 0)} actions recorded</td></tr>
</table>
</div>
<div>
<h4>Safety & Monitoring</h4>
<table>
<tr><td>Safety Officer</td><td>{"Active" if not agent_results.get("safety", {}).get("skipped") else "Skipped (no OT devices)"}</td></tr>
<tr><td>Actions Vetoed</td><td>{metrics.get('vetoed_actions', 0)}</td></tr>
<tr><td>Instability Events</td><td>{metrics.get('instability_events', 0)}</td></tr>
<tr><td>Fleet Clusters</td><td>{fleet_data.get('clusters', 0)}</td></tr>
<tr><td>Probe Reduction</td><td>{fleet_data.get('probing_reduction_pct', 0):.0f}%</td></tr>
</table>
</div>
</div>
</div>

<div class="footer">
Generated by <strong>TRUCE-PT</strong> Multi-Agent Penetration Testing Framework<br>
Report generated on {now} | Duration: {duration:.1f}s | {len(devices)} devices scanned
</div>

</div>
</body></html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
