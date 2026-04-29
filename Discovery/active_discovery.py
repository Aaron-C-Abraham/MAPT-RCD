import logging
import platform
import subprocess
import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional
from TIB_and_PCF.PCF import PCFDAG, NodeType, EvidenceApproach
from TIB_and_PCF.TIB.device_classifier import OUIDatabase
logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)
import warnings
warnings.filterwarnings("ignore", message=".*libpcap.*")
warnings.filterwarnings("ignore", message=".*Dropping unsupported.*")
warnings.filterwarnings("ignore", message=".*No libpcap.*")
from scapy.all import ARP, Ether, IP, TCP, ICMP, srp, sr1, sr, conf

TCP_PROBE_PORTS = [
    # High-priority: most common services on consumer devices
    80, 443, 22, 8080, 3389, 445,
    # Apple ecosystem
    7000, 7100, 62078, 5000,     
    # Android / Smart TV / Streaming
    5555, 8008, 8009, 8443,      
    8001, 8002,                  
    # Other common services
    5900, 554, 21, 139, 135,     
    # Smart home / IoT
    1883, 8883, 1900,
    # Media / streaming
    32400, 8096,
    # NAS
    5001, 9090, 
]


@dataclass
class DiscoveredHost:
    ip: str
    mac: str = ""
    vendor: str = "Unknown"
    hostname: str = ""
    discovery_method: str = "arp"
    pcf_node_id: str = ""


def auto_detect_subnet() -> str:
    """
    Auto-detect the local subnet from this machine's active adapter.
    """
    ip_addr,mask=None,None

    if platform.system()=="Windows":
        try:
            output = subprocess.check_output(["ipconfig"],text=True,timeout=10)
            for line in output.splitlines():
                line=line.strip()
                if "IPv4 Address" in line:
                    m=re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        ip_addr=m.group(1)
                if "Subnet Mask" in line and ip_addr:
                    m=re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        mask=m.group(1)
                        break
        except Exception:
            pass
    else:
        try:
            try:
                output=subprocess.check_output(["ifconfig"], text=True, timeout=10)
            except FileNotFoundError:
                output=subprocess.check_output(["ip", "addr"], text=True, timeout=10)
            for line in output.splitlines():
                line=line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    cidr_m=re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if cidr_m:
                        return str(ipaddress.ip_network(
                            f"{cidr_m.group(1)}/{cidr_m.group(2)}", strict=False))
                    m=re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        ip_addr=m.group(1)
                    mask_m=re.search(r'netmask\s+(0x[0-9a-fA-F]+|[\d.]+)', line)
                    if mask_m and ip_addr:
                        mask_str=mask_m.group(1)
                        if mask_str.startswith("0x"):
                            mi=int(mask_str, 16)
                            mask=f"{(mi>>24)&0xff}.{(mi>>16)&0xff}.{(mi>>8)&0xff}.{mi&0xff}"
                        else:
                            mask=mask_str
                        break
        except Exception:
            pass

    if ip_addr and mask:
        return str(ipaddress.ip_network(f"{ip_addr}/{mask}",strict=False))

    # Fallback: UDP socket trick
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        pass
    raise RuntimeError("Could not auto-detect subnet")


class ActiveDiscoveryPhase:
    _progress_cb = None  # Set externally to emit per-step progress

    def __init__(self, oui_db: Optional[OUIDatabase], pcf_dag: PCFDAG, session_root_id: str):
        self.oui_db = oui_db
        self.pcf_dag = pcf_dag
        self.session_root_id = session_root_id

    def run(self,networks:List[str],arp_timeout:int = 3, icmp_timeout: int = 2) -> List[DiscoveredHost]:
        all_discovered=[]
        seen_ips=set()

        for network in networks:
            if not network or network=="auto":
                network = auto_detect_subnet()

            net = ipaddress.ip_network(network, strict=False)
            logger.info(f"Scanning {network}")

            # ARP scan — resolves ALL hosts + MACs instantly 
            mac_map={}
            alive_ips=set()
            try:
                arp_request=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(net))
                answered,_=srp(arp_request, timeout=arp_timeout, retry=2, verbose=0)
                for _,received in answered:
                    ip=received.psrc
                    mac=received.hwsrc.lower()
                    mac_map[ip]=mac
                    alive_ips.add(ip)
                logger.info(f"[ARP] {len(alive_ips)} hosts found with MACs")
            except Exception as e:
                logger.warning(f"[ARP] Failed: {e}, falling back to arp -a")
                arp_entries=self._read_arp_table(net)
                mac_map={e["ip"]:e["mac"] for e in arp_entries}
                alive_ips=set(mac_map.keys())

            # TCP SYN scan to get the open ports
            # Is this not a violation of the whole TIB principle?
            # syn_ports = [80, 443, 22, 445, 3389, 8080, 7000, 62078, 5555,
            #              8008, 8001, 139, 21, 5900, 554, 1883, 548, 135]
            # for ip in list(alive_ips):
            #     try:
            #         open_ports = self._scapy_syn_scan(ip, syn_ports)
            #         if open_ports:
            #             mac_map.setdefault(ip, "")
            #     except Exception as e:
            #         logger.debug(f"[SYN] {ip}: {e}")

            #  ICMP ping for any hosts missed by ARP 
            all_ips=[str(ip) for ip in net.hosts()]
            missed=[ip for ip in all_ips if ip not in alive_ips]
            if missed and len(missed)<512:
                try:
                    for batch_start in range(0,len(missed),64):
                        batch=missed[batch_start:batch_start+64]
                        pkts=[IP(dst=ip)/ICMP() for ip in batch]
                        answered,_=sr(pkts, timeout=2, verbose=0)
                        for sent,received in answered:
                            ip=received.src
                            alive_ips.add(ip)
                    logger.info(f"[ICMP] Total hosts after ICMP: {len(alive_ips)}")
                except Exception as e:
                    logger.debug(f"[ICMP] {e}")

            # Resolve hostnames
            hostname_map=self._resolve_hostnames(alive_ips)
            logger.info(f"[DNS/NetBIOS] {len(hostname_map)} hostnames resolved")

            # Build results 
            for ip_str in sorted(alive_ips, key=lambda x: ipaddress.ip_address(x)):
                if ip_str in seen_ips:
                    continue
                seen_ips.add(ip_str)

                mac = mac_map.get(ip_str, "")
                vendor = self.oui_db.lookup(mac) if (self.oui_db and mac) else "Unknown"
                hostname = hostname_map.get(ip_str, "")
                method = "arp" if mac else "icmp"

                node_id = self.pcf_dag.add_node(
                    node_type=NodeType.DISCOVERY, phase="HOST_DISCOVERY",
                    payload={"ip": ip_str, "mac": mac, "vendor": vendor,
                             "hostname": hostname, "method": method},
                    parent_ids=[self.session_root_id],
                    evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip_str,
                )
                all_discovered.append(DiscoveredHost(
                    ip=ip_str, mac=mac, vendor=vendor, hostname=hostname,
                    discovery_method=method, pcf_node_id=node_id,
                ))

        logger.info(f" Discovery complete: {len(all_discovered)} hosts found")
        return all_discovered

    # def _scapy_syn_scan(self, ip: str, ports: List[int], timeout: float = 1.5) -> List[int]:
    #     """SYN scan specific ports on a single host. Returns list of open ports."""
    #     open_ports = []
    #     try:
    #         # Send SYN to all ports at once
    #         pkts = IP(dst=ip) / TCP(dport=ports, flags="S")
    #         answered, _ = sr(pkts, timeout=timeout, verbose=0)
    #         for sent, received in answered:
    #             # SYN-ACK (flags=0x12) means port is open
    #             if received.haslayer(TCP) and received[TCP].flags == 0x12:
    #                 open_ports.append(received[TCP].sport)
    #                 # Send RST to close the half-open connection
    #                 sr1(IP(dst=ip)/TCP(dport=received[TCP].sport, flags="R"),
    #                     timeout=0.5, verbose=0)
    #     except Exception as e:
    #         logger.debug(f"[SYN scan] {ip}: {e}")
    #     return open_ports

    def _p(self, msg):
        """Emit progress if callback is set."""
        if self._progress_cb:
            self._progress_cb(msg)

    def _read_arp_table(self,net:ipaddress.IPv4Network)->List[dict]:
        """Parse arp -a and return entries within the target network."""
        entries = []
        try:
            output=subprocess.check_output(["arp","-a"], text=True, timeout=10)
        except Exception as e:
            logger.error(f"Failed to read ARP table: {e}")
            return entries

        for line in output.splitlines():
            match = re.search(
                r'(\d+\.\d+\.\d+\.\d+)\s+'
                r'([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-]'
                r'[\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})',
                line,
            )
            if not match:
                continue
            ip_str = match.group(1)
            mac = match.group(2).lower().replace("-", ":")
            if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:"):
                continue
            try:
                if ipaddress.ip_address(ip_str) not in net:
                    continue
            except ValueError:
                continue
            entries.append({"ip": ip_str, "mac": mac})
        return entries

    def _resolve_hostnames(self, ips: set) -> dict:
        hostname_map = {}
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(self._resolve_one_hostname, ip): ip for ip in ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    name = future.result()
                    if name:
                        hostname_map[ip] = name
                except Exception:
                    pass
        return hostname_map

    def _resolve_one_hostname(self, ip: str) -> str:
        """Try reverse DNS, then NetBIOS name query for a single IP."""
        # Try reverse DNS first
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip and not hostname.startswith("192.168"):
                return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        # Try NetBIOS name query (Windows/SMB devices)
        try:
            # NetBIOS Name Service query — send a NBNS wildcard query
            # Transaction ID + flags + questions + answer/authority/additional RRs
            nbns_query = (
                b'\x80\x94'     # Transaction ID
                b'\x00\x00'     # Flags: query
                b'\x00\x01'     # Questions: 1
                b'\x00\x00'     # Answer RRs
                b'\x00\x00'     # Authority RRs
                b'\x00\x00'     # Additional RRs
                b'\x20'         # Name length (32)
                # Encoded "*" (wildcard) padded to 16 bytes, then NetBIOS encoded
                b'\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
                b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
                b'\x41\x41\x41\x41\x41\x41\x41\x41'
                b'\x00'         # Null terminator
                b'\x00\x21'     # Type: NBSTAT
                b'\x00\x01'     # Class: IN
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.sendto(nbns_query, (ip, 137))
            data, _ = sock.recvfrom(1024)
            sock.close()
            if len(data) > 57:
                # Parse the NBNS response — name starts at byte 57
                num_names = data[56]
                if num_names > 0 and len(data) > 57 + 18:
                    raw_name = data[57:72].decode('ascii', errors='replace').strip()
                    if raw_name and len(raw_name) > 1:
                        return raw_name
        except (socket.timeout, OSError):
            pass

        return ""

    def enumerate_ips(self, network: str) -> List[str]:
        """Return all host IP addresses in a given CIDR network."""
        try:
            net = ipaddress.ip_network(network, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError as e:
            logger.error(f"Invalid network '{network}': {e}")
            return []
