import logging
import socket
import subprocess
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from TIB_and_PCF.PCF import PCFDAG,NodeType,EvidenceApproach
from TIB_and_PCF.TIB.device_TIB_manager import TIBManager
from TIB_and_PCF.TIB.TIB_structures import DeviceTier
from TIB_and_PCF.TIB.circuit_breaker import TIBViolation, TIBExhausted


logger=logging.getLogger(__name__)

TOP_100_PORTS=[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,# Web, Telnet, FTP, SSH, SMTP, RDP, POP3, SMB
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,# IMAP, DNS, RPC, MySQL, HTTP-alt, VPN, NFS, VNC
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,# SMTP-sub, H.323, SMTPS, AFP, Auth, HTTP-alt
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 1027,# Webmin, Syslog, SIP, BGP, HTTPS-alt
    554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1028, 9100,# RTSP, MSSQL, WinRPC, LPD, JetDirect
    1029, 2049, 88, 79, 6667, 49153, 5222, 1030, 443, 4662,# NFS, Kerberos, Finger, IRC, XMPP
    9200, 1521, 3128, 8009, 2222, 10443, 7070, 3000, 8500, 1080,# Elasticsearch, Oracle, Squid, AJP
    5432, 9090, 3690, 1900, 3987, 13, 1031, 17, 1719, 9,# PostgreSQL, Prometheus, SVN, UPnP
    49155, 5800, 1032, 2121, 1723, 2811, 8443, 17988, 7001, 7777,# VNC-HTTP, FTP-alt, PPTP, WebLogic
    1900, 27017, 6379, 5984, 9160, 61616, 4848, 4444, 6000, 1080,# MongoDB, Redis, CouchDB, Cassandra, ActiveMQ
]

TOP_1000_PORTS=TOP_100_PORTS+list(range(1024, 1100)) + [
    1194, 1433, 1521, 1701, 1723, 2049, 2082, 2083, 2086, 2087,# OpenVPN, MSSQL, Oracle, L2TP, cPanel
    2095, 2096, 2375, 2376, 3000, 3001, 3306, 3389, 4000, 4001,# Docker, Grafana, MySQL, RDP
    4443, 4444, 4567, 5000, 5001, 5432, 5900, 5984, 6000, 6379,# Metasploit, Flask, PostgreSQL, VNC, Redis
    6443, 6800, 7000, 7001, 7443, 8000, 8080, 8081, 8086, 8088,# K8s API, Aria2, Cassandra, WebLogic, InfluxDB
    8090, 8161, 8443, 8444, 8500, 8888, 9000, 9090, 9200, 9300,# Confluence, ActiveMQ-Web, Consul, Elasticsearch
    9418, 27017, 27018, 28017 # Git, MongoDB, MongoDB-Web
]

PRINTER_PRIORITY_PORTS=[9100,515,631,443,80,21,23]
IOT_PRIORITY_PORTS=[80,443,8080,8443,1883,8883,4343]
WINDOWS_PRIORITY_PORTS=[445,3389,135,139,443,80,5985,5986]
INDUSTRIAL_PRIORITY_PORTS=[502,102,44818,4840,20000,1883,8883]
APPLE_PRIORITY_PORTS=[7000,7100,62078,5000,548,3689,443,80,22,8080,5900]
ANDROID_PRIORITY_PORTS=[5555,8008,8009,8443,443,80,8080,1883]
TV_PRIORITY_PORTS=[8001,8002,8008,8009,7000,7100,443,80,8080,9080,55000]

class PortScanPhase:
    """
    Performs priority-ordered TCP connect port scans within each device's
    TIB budget, rate limits, and circuit breaker constraints.
    """
    def __init__(self,pcf_dag:PCFDAG,max_threads:int=10):
        self.pcf_dag=pcf_dag
        self.max_threads=max_threads
    def run(self,tib_managers:List[TIBManager])->None:
        logger.info(f" Port scanning {len(tib_managers)} devices")
        with ThreadPoolExecutor(max_workers=self.max_threads,thread_name_prefix="scan") as executor:
            futures={
                executor.submit(self.scan_one,tib): tib
                for tib in tib_managers
            }
            for future in as_completed(futures):
                tib=futures[future]
                try:
                    future.result()  # Re-raises any exception from _scan_one
                except Exception as e:
                    logger.error(f" Scan error {tib.device_ip}: {e}")

        logger.info("Port scanning complete")
    def scan_one(self,tib:TIBManager)->None:
        """
        Scan a single device's ports within its TIB limits.
        CRITICAL devices are routed to scan_critical() for minimal scanning.
        """
        ip=tib.device_ip
        if tib.tier==DeviceTier.CRITICAL:
            logger.info(f" {ip} is CRITICAL — minimal scan only")
            self.scan_critical(tib)
            return
        ports=self.build_port_list(tib)
        logger.info(
            f"[Port Scan] {ip} tier={tib.tier.name} "
            f"scanning {len(ports)} ports at "
            f"{tib.config.port_scan_rate_pps}pps"
        )
        open_ports=list(tib.signals.open_ports)
        packet_count=0
        for port in ports:
            if tib.state.ports_scanned>=tib.config.max_ports_to_scan:
                logger.debug(f"[Port Scan] {ip} port scan limit reached")
                break
            try:
                tib.breaker.request_packet_permission(1,"tcp_syn")
            except TIBExhausted as e:
                logger.info(f"[Port Scan] {ip} budget exhausted: {e}")
                break
            except TIBViolation as e:
                logger.warning(f"[Port Scan] {ip} breaker tripped: {e}")
                break
            tib.state.ports_scanned+=1
            packet_count+=1
            is_open=self.probe_port(ip,port,tib.config.min_inter_packet_delay_ms,tib)
            if is_open:
                if port not in open_ports:
                    open_ports.append(port)
                    tib.signals.update_open_ports(open_ports)
                    if tib.tier==DeviceTier.CRITICAL:
                        logger.warning(
                            f"[Port Scan] {ip} re-tiered to CRITICAL mid-scan "
                            f"(port {port} opened). Stopping scan."
                        )
                        break
                    self.pcf_dag.add_node(
                        node_type=NodeType.PORT_SCAN,
                        phase="PORT_SCAN",
                        payload={"ip": ip, "port": port, "state": "open"},
                        parent_ids=[tib.pcf_device_root_id],
                        evidence_approaches=EvidenceApproach.ACTIVE,
                        device_ip=ip,
                    )
            if packet_count%10==0:
                self.check_rtt(ip,tib)
                if not tib.breaker.is_operational():
                    logger.warning(
                        f"[Port Scan] {ip} breaker tripped during scan "
                        f"at port {port}"
                    )
                    break
        logger.info(
            f"[Port Scan] {ip} scan complete — "
            f"{tib.state.ports_scanned} ports scanned, "
            f"{len(open_ports)} open"
        )
    def scan_critical(self,tib:TIBManager)->None:
        """
        Minimal scan for CRITICAL-tier devices — probes only the first 10
        industrial protocol ports (Modbus, S7, EtherNet/IP, etc.).
        """
        ip=tib.device_ip
        for port in INDUSTRIAL_PRIORITY_PORTS[:10]:
            try:
                tib.breaker.request_packet_permission(1, "tcp_syn")
            except (TIBViolation, TIBExhausted):
                break
            is_open=self.probe_port(ip, port,tib.config.min_inter_packet_delay_ms,tib)
            if is_open:
                existing=list(tib.signals.open_ports)
                if port not in existing:
                    existing.append(port)
                    tib.signals.update_open_ports(existing)
                self.pcf_dag.add_node(
                    node_type=NodeType.PORT_SCAN,
                    phase="PORT_SCAN",
                    payload={"ip": ip, "port": port, "state": "open",
                            "note": "CRITICAL tier minimal scan"},
                    parent_ids=[tib.pcf_device_root_id],
                    evidence_approaches=EvidenceApproach.ACTIVE,
                    device_ip=ip,
                )
            tib.state.ports_scanned+=1
    def probe_port(self,ip:str,port:int,delay_ms:int=0,tib:TIBManager=None) -> bool:
        """
        TCP connect probe. Returns True if port is open, False otherwise.
        Records response/timeout on the breaker to distinguish closed ports
        (device alive, port filtered) from true timeouts (device unresponsive).
        """
        if delay_ms>0:
            time.sleep(delay_ms/1000)
        try:
            sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result=sock.connect_ex((ip, port))
            sock.close()
            if result==0:
                if tib: tib.breaker.record_response()
                return True
            else:
                if tib: tib.breaker.record_response()
                return False
        except socket.timeout:
            if tib: tib.breaker.record_timeout()
            return False
        except OSError:
            return False
    def check_rtt(self,ip:str,tib:TIBManager)->None:
        """Measure RTT using subprocess ping. Does NOT record timeout on
        failure — many consumer devices block ICMP but are still healthy."""
        try:
            tib.breaker.request_packet_permission(1, "icmp_echo")
        except (TIBViolation, TIBExhausted):
            return
        t_start=time.time()
        try:
            import platform as _plat
            if _plat.system()=="Windows":
                _pcmd=["ping","-n","1","-w","1000",ip]
            else:
                _pcmd=["ping","-c","1","-W","1",ip]
            out=subprocess.check_output(
                _pcmd,
                text=True,timeout=3,stderr=subprocess.DEVNULL)
            rtt_ms=(time.time()-t_start)*1000
            m=re.search(r'time[=<](\d+)',out,re.IGNORECASE)
            if m:
                rtt_ms=float(m.group(1))
            tib.breaker.record_rtt(rtt_ms)
            tib.breaker.record_response()
        except Exception:
            # ICMP blocked is normal for phones/laptops — don't trip breaker.
            # RTT monitoring simply has no data for this device.
            pass
    def build_port_list(self,tib:TIBManager)->List[int]:
        """Build a priority-ordered port list based on vendor, hostname, banners, mDNS, and tier."""
        seen=set()
        result=[]
        def add_ports(ports):
            """Append ports to result in order, skipping duplicates and out-of-range values."""
            for p in ports:
                if p not in seen and 1 <= p <= 65535:
                    seen.add(p)
                    result.append(p)
        vendor  = tib.signals.oui_vendor.lower()
        banners = " ".join(tib.signals.banners.values()).lower()
        hostname = (tib.signals.mdns_device_name or tib.signals.reverse_dns or "").lower()
        mdns_str = " ".join(tib.signals.mdns_services).lower() if tib.signals.mdns_services else ""
        combined = vendor + " " + banners + " " + hostname + " " + mdns_str

        # Device-specific priority ports
        if any(kw in combined for kw in ["print", "canon", "epson", "brother","xerox", "ricoh", "lexmark"]):
            add_ports(PRINTER_PRIORITY_PORTS)
        if any(kw in combined for kw in ["espressif", "arduino", "tuya","shelly", "iot", "esp32", "esp8266"]):
            add_ports(IOT_PRIORITY_PORTS)
        if any(kw in combined for kw in ["windows", "microsoft", "netbios", "desktop-", "-pc"]) \
                or tib.signals.netbios_present:
            add_ports(WINDOWS_PRIORITY_PORTS)
        if any(kw in combined for kw in ["apple", "iphone", "ipad", "macbook", "airplay"]):
            add_ports(APPLE_PRIORITY_PORTS)
        if any(kw in combined for kw in ["android", "galaxy", "pixel", "oneplus", "xiaomi",
                                          "googlecast", "_androidtvremote"]):
            add_ports(ANDROID_PRIORITY_PORTS)
        if any(kw in combined for kw in ["samsung", "roku", "fire", "chromecast", "tv",
                                          "vizio", "hisense", "lg electronics", "sony"]):
            add_ports(TV_PRIORITY_PORTS)

        # Always include the common ports
        add_ports(TOP_100_PORTS)
        if tib.tier in (DeviceTier.MODERATE, DeviceTier.ROBUST):
            add_ports(TOP_1000_PORTS)
        if tib.tier == DeviceTier.ROBUST:
            add_ports(range(1, 65536))
        max_ports = tib.config.max_ports_to_scan
        return result[:max_ports]
    