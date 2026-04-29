import logging
import socket
import statistics
import subprocess
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from TIB_and_PCF.PCF import PCFDAG, NodeType, EvidenceApproach
from TIB_and_PCF.TIB.device_TIB_manager import TIBManager
from TIB_and_PCF.TIB.circuit_breaker import TIBExhausted, TIBViolation
from typing import List, Dict, Optional
logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.all import IP, UDP, SNMP, SNMPget, SNMPvarbind, ASN1_OID, sr1, conf,sr,TCP
conf.verb = 0
from impacket.smbconnection import SMBConnection
TCP_PROBE_PORTS = [
    80, 443, 22, 8080, 8443, 21, 25, 110, 143,# Standard services
    445, 3389, 139, 135,# Windows (SMB, RDP, NetBIOS, RPC)
    7000, 7100, 62078, 5000,# Apple (AirPlay, iDevice, AirTunes)
    5555, 8008, 8009,# Android ADB, Chromecast
    8001, 8002,# Samsung Smart TV
    548, 5900, 554,# AFP, VNC, RTSP
]
BANNER_PORTS = [22, 80, 21, 25, 443, 8080, 8008, 554]


class FingerprintingPhase:
    """
    Runs fingerprinting on all discovered devices using pure Python sockets.
    Collects reverse DNS, ICMP RTT/TTL, TCP connect fingerprints, SNMP
    sysDescr, and service banners — all within TIB budget constraints.
    """

    def __init__(self, pcf_dag: PCFDAG, max_threads: int = 10):
        self.pcf_dag = pcf_dag
        self.max_threads = max_threads
        self._progress_cb = None  # Set externally for progress output

    def _p(self, msg):
        if self._progress_cb:
            self._progress_cb(msg)

    def run(self, tib_managers: List[TIBManager]) -> None:
        total=len(tib_managers)
        self._p(f"Fingerprinting {total} devices ({self.max_threads} threads)...")
        completed=0
        with ThreadPoolExecutor(max_workers=self.max_threads,thread_name_prefix="fp") as executor:
            futures={executor.submit(self.fingerprint_one, tib): tib for tib in tib_managers}
            for future in as_completed(futures):
                tib=futures[future]
                completed+=1
                try:
                    future.result()
                    ports=len(tib.signals.open_ports)
                    has_banner=bool(tib.signals.banners)
                    has_snmp=bool(tib.signals.snmp_sysdescr)
                    smb="SMB" if 445 in tib.signals.open_ports else ""
                    self._p(
                        f"[{completed}/{total}] {tib.device_ip:<17} "
                        f"ports={ports} banner={'Y' if has_banner else 'N'} "
                        f"snmp={'Y' if has_snmp else 'N'} {smb}"
                    )
                except Exception as e:
                    self._p(f"[{completed}/{total}] {tib.device_ip:<17} ERROR: {e}")
                    logger.error(f"Fingerprinting {tib.device_ip} failed: {e}")
        logger.info("Fingerprinting complete")

    def fingerprint_one(self, tib: TIBManager) -> None:
        """Fingerprint a single device: reverse DNS, ICMP ping, TCP connect, SNMP, and banners."""
        ip=tib.device_ip

        # 1. Reverse DNS
        try:
            hostname=socket.gethostbyaddr(ip)[0]
            tib.signals.reverse_dns = hostname
            self.pcf_dag.add_node(
                node_type=NodeType.PROBE, phase="FINGERPRINTING",
                payload={"ip": ip, "hostname": hostname, "probe": "reverse_dns"},
                parent_ids=[tib.pcf_device_root_id],
                evidence_approaches=EvidenceApproach.PASSIVE, device_ip=ip,
            )
        except (socket.herror, socket.gaierror):
            pass

        # 2. ICMP RTT + TTL via subprocess ping
        rtts = []
        ttl_val = 0
        for i in range(5):
            try:
                tib.breaker.request_packet_permission(1, "icmp_echo")
            except (TIBExhausted, TIBViolation):
                break
            t0 = time.time()
            try:
                import platform as plat
                if plat.system() == "Windows":
                    ping_cmd = ["ping", "-n", "1", "-w", "1000", ip]
                else:
                    ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
                out = subprocess.check_output(
                    ping_cmd,
                    text=True, timeout=3, stderr=subprocess.DEVNULL,
                )
                rtt_ms = (time.time() - t0) * 1000
                # Parse TTL from output
                m = re.search(r'TTL[=:](\d+)', out, re.IGNORECASE)
                if m:
                    ttl_val = int(m.group(1))
                # Parse actual RTT from output
                m2 = re.search(r'time[=<](\d+)', out, re.IGNORECASE)
                if m2:
                    rtt_ms = float(m2.group(1))
                rtts.append(rtt_ms)
                tib.breaker.record_response()
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass
            except Exception:
                pass
            if i < 4:
                time.sleep(0.2)
        try:
            import platform as _plat
            if _plat.system() == "Windows":
                trace_cmd = ["tracert", "-d", "-h", "30", ip]
            else:
                trace_cmd = ["traceroute", "-n", "-m", "30", ip]
            out = subprocess.check_output(
                trace_cmd,
                text=True,
                timeout=10,
                stderr=subprocess.DEVNULL,
            )
            hop_lines=[]
            for line in out.splitlines():
                if re.match(r"^\s*\d+\s+", line):
                    hop_lines.append(line)

            if hop_lines:
                tib.signals.hops_for_ttl=len(hop_lines)

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
        except Exception:
            pass

        if rtts:
            tib.signals.update_icmp_rtt_samples(rtts)
            self.pcf_dag.add_node(
                node_type=NodeType.PROBE, phase="FINGERPRINTING",
                payload={
                    "ip": ip, "probe": "icmp_ping",
                    "ttl": ttl_val,
                    # "rtt_mean_ms": round(statistics.mean(rtts), 3),
                    # "rtt_stddev_ms": round(statistics.stdev(rtts) if len(rtts) > 1 else 0.0, 3),
                    "samples": len(rtts),
                },
                parent_ids=[tib.pcf_device_root_id],
                evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
            )

        # 3. TCP connect fingerprint — get window size
        for port in TCP_PROBE_PORTS:
            try:
                tib.breaker.request_packet_permission(1, "tcp_syn")
            except (TIBExhausted, TIBViolation):
                break
                # sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # sock.settimeout(1.5)
                # result=sock.connect_ex((ip, port))
                # if result==0:
                #     # Port is open — device responded
                #     tib.breaker.record_response()
                #     current_ports=list(tib.signals.open_ports)
                #     if port not in current_ports:
                #         current_ports.append(port)
                #         tib.signals.update_open_ports(current_ports)
                #     self.pcf_dag.add_node(
                #         node_type=NodeType.PROBE, phase="FINGERPRINTING",
                #         payload={"ip": ip, "probe": "tcp_connect", "port": port, "state": "open"},
                #         parent_ids=[tib.pcf_device_root_id],
                #         evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
                #     )
                # else:
                #     tib.breaker.record_response()
                # sock.close()
                # def _scapy_syn_scan(self, ip: str, ports: List[int], timeout: float = 1.5) -> List[int]:
            """SYN scan specific ports on a single host. Returns list of open ports."""
            # open_ports = []
            got_window=False
            try:
                # Send SYN to all ports at once
                pkts = IP(dst=ip) / TCP(dport=port, flags="S")
                answered, _ = sr1(pkts, timeout=1.5, verbose=0)
                sent, received = answered
                # SYN-ACK (flags=0x12) means port is open
                if received.haslayer(TCP) and received[TCP].flags == 0x12:
                    # open_ports.append(received[TCP].sport)
                    tib.signals.update_tcp_window_size(received[TCP].window)
                    got_window=True
                    # Send RST to close the half-open connection
                    sr1(IP(dst=ip)/TCP(dport=received[TCP].sport, flags="R"),
                        timeout=0.5, verbose=0)
                    break
                
                    
                        
            except socket.timeout:
                tib.breaker.record_timeout()
            except OSError:
                pass

        # 4. SNMP sysDescr
        try:
            tib.breaker.request_packet_permission(1, "snmp_query")
            sysdesc = self.snmp_get_sysdesc(ip)
            if sysdesc:
                tib.signals.update_snmp_sysdescr(sysdesc)
                self.pcf_dag.add_node(
                    node_type=NodeType.PROBE, phase="FINGERPRINTING",
                    payload={"ip": ip, "probe": "snmp_sysdescr", "sysdescr": sysdesc},
                    parent_ids=[tib.pcf_device_root_id],
                    evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
                )
        except (TIBExhausted, TIBViolation):
            pass

        # 5. Banner grabbing
        for port in BANNER_PORTS:
            try:
                tib.breaker.request_packet_permission(1, "tcp_banner_grab")
                tib.breaker.request_service_probe_permission()
            except (TIBExhausted, TIBViolation):
                break
            banner = self.grab_banner(ip, port)
            if banner:
                existing = dict(tib.signals.banners)
                existing[port] = banner
                tib.signals.update_banners(existing)
                self.pcf_dag.add_node(
                    node_type=NodeType.SERVICE_PROBE, phase="FINGERPRINTING",
                    payload={"ip": ip, "port": port, "banner": banner[:200]},
                    parent_ids=[tib.pcf_device_root_id],
                    evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
                )
                break

        # 6. SMB-based Windows version detection 
        if 445 in [p for p in tib.signals.open_ports]:
            try:
                tib.breaker.request_packet_permission(1, "tcp_banner_grab")
                smb_info = self.smb_detect(ip)
                if smb_info:
                    # Store SMB info as a banner on port 445
                    existing = dict(tib.signals.banners)
                    existing[445] = f"SMB: {smb_info.get('os', '')} | {smb_info.get('hostname', '')}"
                    tib.signals.update_banners(existing)
                    # Set Windows OS directly
                    if smb_info.get("os"):
                        tib.signals.update_nmap_os_guess(smb_info["os"])
                    # Use SMB hostname as device name
                    if smb_info.get("hostname") and not tib.signals.mdns_device_name:
                        tib.signals.mdns_device_name = smb_info["hostname"]
                    tib.signals.update_netbios_present(True)
                    self.pcf_dag.add_node(
                        node_type=NodeType.PROBE, phase="FINGERPRINTING",
                        payload={"ip": ip, "probe": "smb_version",
                                 "os": smb_info.get("os", ""),
                                 "hostname": smb_info.get("hostname", ""),
                                 "domain": smb_info.get("domain", "")},
                        parent_ids=[tib.pcf_device_root_id],
                        evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
                    )
                    logger.info(f"[SMB] {ip}: {smb_info}")
            except (TIBExhausted, TIBViolation):
                pass
            except Exception as e:
                logger.debug(f"[SMB] {ip}: {e}")

        logger.debug(f"Fingerprint complete: {ip}")

    def snmp_get_sysdesc(self, ip: str) -> str:
        """Sends SNMP GET requests for system MIB OIDs."""
        # MIB-2 system group OIDs
        oids_to_query = [
            ("sysDescr", "1.3.6.1.2.1.1.1.0"),
            ("sysName", "1.3.6.1.2.1.1.5.0"),
        ]
        results = {}
        for community in ["public", "private"]:
            for oid_name, oid_str in oids_to_query:
                try:
                    pkt = (IP(dst=ip) / UDP(sport=16161, dport=161)/
                           SNMP(community=community,
                                PDU=SNMPget(varbindlist=[
                                    SNMPvarbind(oid=ASN1_OID(oid_str))
                                ])))
                    resp = sr1(pkt, timeout=2, verbose=0)
                    if resp and resp.haslayer(SNMP):
                        snmp_layer=resp[SNMP]
                        try:
                            val_raw=snmp_layer.PDU.varbindlist[0].value
                            val=val_raw.val if hasattr(val_raw,'val') else str(val_raw)
                            val=str(val).strip()
                            if val and len(val) > 2:
                                results[oid_name] = val
                        except (IndexError, AttributeError):
                            pass
                except Exception as e:
                    logger.debug(f"[SNMP] {ip} {oid_name}: {e}")
            if results:
                break  
        if not results:
            return ""
        parts = []
        if results.get("sysDescr"):
            parts.append(results["sysDescr"])
        if results.get("sysName"):
            parts.append(f"Name: {results['sysName']}")
        logger.info(f"[SNMP] {ip}: {results}")
        return " | ".join(parts) if parts else ""

    def grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> str:
        """Grab a service banner from a TCP port. Sends an HTTP HEAD for port 80/8080."""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                if port in (80, 8080):
                    s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                elif port == 443:
                    return "HTTPS_PORT_OPEN"
                banner = s.recv(512).decode("utf-8", errors="replace").strip()
                return banner[:300]
        except (socket.timeout, ConnectionRefusedError, OSError):
            return ""

    def smb_detect(self, ip: str) -> Optional[Dict[str, str]]:
        """
        To detect Windows version via SMB negotiation.
        A single SMB session setup reveals the exact Windows build number,
        hostname, and domain
        """
        try:
            conn = SMBConnection(ip, ip, sess_port=445, timeout=3)
            # Attempt anonymous/guest login — sufficient to get server info
            try:
                conn.login("", "")
            except Exception:
                pass  # Login may fail but we still get the SMB header info

            server_os=conn.getServerOS() or ""
            server_name=conn.getServerName() or ""
            server_domain=conn.getServerDomain() or ""

            conn.close()

            if server_os or server_name:
                return {
                    "os": server_os,
                    "hostname": server_name,
                    "domain": server_domain,
                }
        except Exception as e:
            logger.debug(f"[SMB] {ip}: {e}")
        return None
