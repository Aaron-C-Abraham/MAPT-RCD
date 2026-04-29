import sys
import os
import time
import logging
import subprocess
import re
import ipaddress
import argparse
import warnings
warnings.filterwarnings("ignore", message=".*libpcap.*")
warnings.filterwarnings("ignore", message=".*Dropping unsupported.*")
warnings.filterwarnings("ignore", message=".*No libpcap.*")
warnings.filterwarnings("ignore", message=".*pcap.*")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def auto_detect_subnet() -> str:
    """Auto-detect the local subnet from the active network adapter.

    Strategy:
      1. Platform-specific command: ipconfig (Windows) or ifconfig/ip (macOS/Linux)
      2. Fallback: UDP socket trick to find the local IP, then assume /24
    """
    import platform
    ip_addr, mask = None, None

    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(["ipconfig"], text=True, timeout=10)
            for line in output.splitlines():
                line = line.strip()
                if "IPv4 Address" in line:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        ip_addr = m.group(1)
                if "Subnet Mask" in line and ip_addr:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        mask = m.group(1)
                        break
        except Exception:
            pass
    else:
        # macOS / Linux: use ifconfig or ip addr
        try:
            try:
                output = subprocess.check_output(["ifconfig"], text=True, timeout=10)
            except FileNotFoundError:
                output = subprocess.check_output(["ip", "addr"], text=True, timeout=10)
            # Parse inet lines: "inet 192.168.0.10 netmask 255.255.255.0" (macOS)
            #                or "inet 192.168.0.10/24" (Linux)
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    # macOS format: inet 192.168.x.x netmask 0xffffff00
                    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        ip_addr = m.group(1)
                    # Check for CIDR notation (Linux: inet 192.168.0.10/24)
                    cidr_m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if cidr_m:
                        ip_addr = cidr_m.group(1)
                        prefix_len = int(cidr_m.group(2))
                        return str(ipaddress.ip_network(f"{ip_addr}/{prefix_len}", strict=False))
                    # macOS netmask formats: "netmask 255.255.255.0" or "netmask 0xffffff00"
                    mask_m = re.search(r'netmask\s+(0x[0-9a-fA-F]+|[\d.]+)', line)
                    if mask_m and ip_addr:
                        mask_str = mask_m.group(1)
                        if mask_str.startswith("0x"):
                            # Convert hex netmask to dotted decimal
                            mask_int = int(mask_str, 16)
                            mask = f"{(mask_int >> 24) & 0xff}.{(mask_int >> 16) & 0xff}.{(mask_int >> 8) & 0xff}.{mask_int & 0xff}"
                        else:
                            mask = mask_str
                        break
        except Exception:
            pass

    if ip_addr and mask:
        return str(ipaddress.ip_network(f"{ip_addr}/{mask}", strict=False))

    # Fallback: UDP socket trick to find local IP, assume /24
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        pass
    raise RuntimeError("Could not auto-detect subnet. Pass it as argument: python run_pt.py 192.168.0.0/24")


def progress(msg):
    """Print a timestamped progress message."""
    ts = time.strftime("%H:%M:%S")
    print(f"  {ts}  {msg}", flush=True)


def main():
    # Suppress all internal logging — we use our own progress output
    logging.basicConfig(level=logging.CRITICAL, format='%(message)s')

    # ── Parse command-line arguments ─────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog="run_pt.py",
        description="MAPT-RCD — Multi-Agent Penetration Testing Framework",
    )
    parser.add_argument(
        "networks", nargs="*", default=[],
        help="Target CIDR ranges (e.g. 192.168.1.0/24). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--exploit-all", action="store_true", dest="exploit_all",
        help="Force exploitation across ALL discovered devices, including "
             "CRITICAL-tier. Overrides tier-based exploitation restrictions "
             "and ensures every device receives sufficient exploitation budget.",
    )
    args = parser.parse_args()

    # ── Determine target networks ────────────────────────────────────────
    if args.networks:
        networks = args.networks
        for net in networks:
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError:
                print(f"  [!] Invalid network: {net}")
                sys.exit(1)
    else:
        networks = [auto_detect_subnet()]

    exploit_all = args.exploit_all

    # ── Paths ────────────────────────────────────────────────────────────
    project_dir = os.path.dirname(os.path.abspath(__file__))
    oui_db_path = os.path.join(project_dir, "database", "mac-vendors-export.csv")
    report_dir = os.path.join(project_dir, "output")
    os.makedirs(report_dir, exist_ok=True)
    results_path = os.path.join(report_dir, "results.json")
    pcf_path = os.path.join(report_dir, "pcf_evidence.json")
    report_path = os.path.join(report_dir, "pt_report.html")

    # ── Banner ───────────────────────────────────────────────────────────
    print()
    print("=" * 68)
    print("  MAPT-RCD  Multi-Agent Penetration Testing Framework")
    print("=" * 68)
    print(f"  Target:   {', '.join(networks)}")
    if exploit_all:
        print(f"  Mode:     --exploit-all (exploitation on ALL devices)")
    print(f"  Started:  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 68)
    print()

    # ── Run pipeline ─────────────────────────────────────────────────────
    from agents.coordinator import run_agent_scan

    start = time.time()

    results = run_agent_scan(
        networks=networks,
        oui_db_path=oui_db_path,
        passive_only=False,
        max_threads=10,
        output_path=results_path,
        pcf_path=pcf_path,
        use_cmdp=True,
        exploit_all=exploit_all,
        progress_cb=progress,
    )

    elapsed = time.time() - start

    # ── Generate HTML report ─────────────────────────────────────────────
    progress("[Report]   Generating HTML penetration test report...")
    from report_generator import generate_html_report
    generate_html_report(results, report_path)
    progress(f"           Report saved to {report_path}")

    # ── Final summary ────────────────────────────────────────────────────
    metrics = results.get("metrics", {})
    tier = results.get("tier_summary", {})

    print()
    print("=" * 68)
    print(f"  SCAN COMPLETE  ({elapsed:.0f}s)")
    print("=" * 68)
    print(f"  Devices:       {results.get('device_count', 0)}")
    print(f"  Findings:      {metrics.get('total_findings', 0)}")
    print(f"  Validated:     {metrics.get('validated_findings', 0)}")
    print(f"  PCF Nodes:     {metrics.get('pcf_nodes', 0)}")
    tiers_str = " | ".join(f"{k}:{v}" for k, v in tier.items() if v > 0)
    print(f"  Tiers:         {tiers_str or 'none'}")
    print()

    # Device table
    print(f"  {'IP':<17} {'MAC':<19} {'TYPE':<22} {'VENDOR':<20} {'OS'}")
    print(f"  {'-'*16} {'-'*18} {'-'*21} {'-'*19} {'-'*30}")
    for d in results.get("devices", []):
        ip = d.get("ip", "")
        mac = d.get("mac", "") or ""
        dtype = d.get("device_type", "") or d.get("current_tier", "?")
        vendor = (d.get("vendor", "Unknown") or "Unknown")[:19]
        os_h = d.get("findings", {}).get("os_hint", "Unknown")
        name = d.get("device_name", "")
        vulns = d.get("findings", {}).get("vulnerabilities", [])
        v_str = f" [{len(vulns)} vulns]" if vulns else ""
        name_str = f" ({name})" if name else ""
        print(f"  {ip:<17} {mac:<19} {dtype:<22} {vendor:<20} {os_h}{v_str}{name_str}")

    # Raspberry Pi
    rpis = [d for d in results.get("devices", []) if "raspberry pi" in d.get("vendor", "").lower()]
    if rpis:
        print(f"\n  Raspberry Pi: {len(rpis)} found")
        for d in rpis:
            v = d.get("findings", {}).get("vulnerabilities", [])
            print(f"    {d['ip']}  mac={d.get('mac', '?')}  "
                  f"tier={d.get('current_tier')}  "
                  f"ports={d['findings'].get('open_ports', [])}  "
                  f"os={d['findings'].get('os_hint', '?')}  "
                  f"vulns={len(v)}")

    print()
    ledger_path = os.path.join(report_dir, "engagement_ledger.json")
    print("=" * 68)
    print(f"  Output Directory:  {report_dir}")
    print(f"    HTML Report:     pt_report.html")
    print(f"    Results JSON:    results.json")
    print(f"    PCF Evidence:    pcf_evidence.json")
    print(f"    Engagement Ledger: engagement_ledger.json")
    print("=" * 68)
    print()


if __name__ == "__main__":
    main()
