import socket
import struct
import threading
import logging
from typing import Dict, Optional,List

from TIB_and_PCF.PCF import PCFDAG,NodeType,EvidenceApproach
logger=logging.getLogger(__name__)

class PassiveFindings:
    """
    Thread-safe accumulator for passive network listener findings.
    """

    def __init__(self):
        self.lock=threading.Lock()
        self.mdns:Dict[str,list]={}
        self.mdns_names:Dict[str,str]={}   
        self.ssdp:Dict[str,list]={}
        self.dhcp:Dict[str,list]={}
        self.netbios:set=set()
    def add_mdns(self,ip:str,service:str)->None:
        with self.lock:
            if ip not in self.mdns:
                self.mdns[ip]=[]
            if service not in self.mdns[ip]:
                self.mdns[ip].append(service)
    def add_mdns_name(self,ip:str,name:str)->None:
        with self.lock:
            if ip not in self.mdns_names:
                self.mdns_names[ip]=name
    def add_ssdp(self,ip:str,server_header:str)->None:
        with self.lock:
            if server_header not in self.ssdp[ip]:
                self.ssdp[ip].append(server_header)
    def add_dhcp(self,ip:str,option55:str)->None:
        with self.lock:
            if option55 not in self.dhcp[ip]:
                self.dhcp[ip].append(option55)
    def add_netbios(self,ip:str)->None:
        with self.lock:
            self.netbios.add(ip)
    def get_all_ips(self)->set:
        with self.lock:
            ips=set(self.mdns.keys())
            ips.update(self.ssdp.keys())
            ips.update(self.dhcp.keys())
            ips.update(self.netbios)
            return ips

def listen_mdns(
        findings:PassiveFindings,
        stop_event:threading.Event,
        pcf_dag:PCFDAG,
        session_root_id:str
    ):
    MDNS_GROUP="224.0.0.251"
    MDNS_PORT=5353
    try:
        # Creates a UDP socket for receiving multicast datagrams
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1) # To allow multiple sockets to bind to the same port on the same machine
        sock.bind(("0.0.0.0",MDNS_PORT))
        mreq=struct.pack("4sL",socket.inet_aton(MDNS_GROUP),socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
        sock.settimeout(1.0)
    except OSError as e:
        logger.warning(f"[mDNS] Could not bind: {e}. "
                       f"mDNS listener disabled. (Run as root?)")
        return
    
    logger.info("[mDNS] Listening on 224.0.0.251:5353")

    while not stop_event.is_set():
        try:
            data,addr=sock.recvfrom(4096)
            src_ip=addr[0]
            decoded=data.decode("latin-1",errors="replace")
            services_found=[]
            for known in [
                # IoT / Smart Home
                "_hap._tcp", "_matter._tcp", "_miio._udp", "_tuya._tcp",
                "_esphomelib._tcp", "_homekit._tcp", "_mqtt._tcp",
                # Printers
                "_ipp._tcp", "_ipps._tcp", "_pdl-datastream._tcp",
                # Apple ecosystem
                "_airplay._tcp", "_companion-link._tcp", "_rdlink._tcp",
                "_sleep-proxy._udp",
                # Google / Android
                "_googlecast._tcp", "_androidtvremote._tcp",
                "_androidtvremote2._tcp",
                # Amazon
                "_amzn-wplay._tcp",
                # Roku
                "_roku-rcp._tcp",
                # Media / streaming
                "_spotify-connect._tcp",
                # General services
                "_http._tcp", "_https._tcp", "_ssh._tcp", "_ftp._tcp",
                "_smb._tcp", "_afpovertcp._tcp", "_nfs._tcp",
            ]:
                if known in decoded:
                    services_found.append(known)

            if services_found:
                device_name=""
                for svc in services_found:
                    idx=decoded.find(svc)
                    if idx>1:
                        raw_name = decoded[:idx].split("\x00")[-1]
                        cleaned = "".join(c for c in raw_name if 32<=ord(c)<127).strip(". \t")
                        if len(cleaned)>2 and cleaned not in ("_tcp","_udp","local"):
                            device_name=cleaned
                            break
                if device_name:
                    findings.add_mdns_name(src_ip, device_name)
                    logger.debug(f"[mDNS] {src_ip} name='{device_name}'")

                for svc in services_found:
                    findings.add_mdns(src_ip,svc)
                    logger.debug(f"[mDNS] {src_ip} -> {svc}")
                    pcf_dag.add_node(
                        node_type=NodeType.PASSIVE,
                        phase="PASSIVE_LISTENING",
                        payload={"ip": src_ip, "service": svc,"protocol": "mDNS"},
                        parent_ids=[session_root_id],
                        evidence_approaches=EvidenceApproach.PASSIVE,
                        device_ip=src_ip,
                    )
        except socket.timeout:
            continue
        except Exception as e:
            logger.debug(f"[mDNS] Recv error: {e}")
        sock.close()
        logger.info("[mDNS] Listener stopped")

def listen_ssdp(findings:PassiveFindings,stop_event:threading.Event,pcf_dag:PCFDAG,session_root_id:str):
    SSDP_GROUP="239.255.255.250"
    SSDP_PORT=1900
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0",SSDP_PORT))
        mreq = struct.pack("4sL",socket.inet_aton(SSDP_GROUP),socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
        sock.settimeout(1.0)
    except OSError as e:
        logger.warning(f"[SSDP] Could not bind: {e}. "
                       f"SSDP listener disabled. (Run as root?)")
        return
    
    while not stop_event.is_set():
        try:
            data,addr=sock.recvfrom(4096)
            src_ip=addr[0]
            text=data.decode("utf-8", errors="replace")

            if not text.startswith("NOTIFY"):
                continue

            server_header = ""
            for line in text.splitlines():
                if line.upper().startswith("SERVER:"):
                    server_header = line.split(":", 1)[1].strip()
                    break

            if server_header:
                findings.add_ssdp(src_ip, server_header)
                logger.debug(f"[SSDP] {src_ip} -> SERVER: {server_header}")
                pcf_dag.add_node(
                    node_type=NodeType.PASSIVE,
                    phase="PASSIVE_LISTENING",
                    payload={"ip": src_ip, "server_header": server_header,
                                    "protocol": "SSDP"},
                    parent_ids=[session_root_id],
                    evidence_approaches=EvidenceApproach.PASSIVE,
                    device_ip=src_ip,
                )

        except socket.timeout:
            continue
        except Exception as e:
            logger.debug(f"[SSDP] Recv error: {e}")

    sock.close()
    logger.info("[SSDP] Listener stopped")

def parse_dchp_option55(data:bytes)->Optional[str]:
    """
    Parse a raw DHCP packet and extract option 55 (Parameter Request List).
    """
    if len(data)<240:
        return 
    magic=data[236:240]
    if magic!=b'\x63\x82\x53\x63':
        return 
    i=240
    while i<len(data):
        opt=data[i]
        if opt==255:
            break
        if opt==0:
            i+=1
            continue
        if i+1>=len(data):  
            break
        length=data[i+1]    
        if i+2+length>len(data):  
            break
        value=data[i+2:i+2+length]  # Extract the value bytes
        if opt==55:
            return ",".join(str(b) for b in value)
        i+=2+length
    return None

def listen_dhcp(findings:PassiveFindings,stop_event:threading.Event,pcf_dag:PCFDAG,session_root_id:str):
    DHCP_PORT=67
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        sock.bind(("0.0.0.0", DHCP_PORT))
        sock.settimeout(1.0)
    except OSError as e:
        logger.warning(
            f"[DHCP] Could not bind port 67: {e}. "
            f"DHCP listener disabled. (Run as root?)"
        )
        return
    logger.info("[DHCP] Listening on UDP port 67")

    while not stop_event.is_set():
        try:
            data,addr=sock.recvfrom(1500)
            src_ip=addr[0]
            option55=parse_dchp_option55(data)
            if option55:
                findings.add_dhcp(src_ip,option55)
                logger.debug(f"[DHCP] {src_ip} option55={option55}")
            pcf_dag.add_node(
                    node_type=NodeType.PASSIVE,
                    phase="PASSIVE_LISTENING",
                    payload={"ip":src_ip,"dhcp_option55":option55,"protocol":"DHCP"},
                    parent_ids=[session_root_id],
                    evidence_approaches=EvidenceApproach.PASSIVE,
                    device_ip=src_ip,
                )
        except socket.timeout:
            continue
        except Exception as e:
            logger.debug(f"[DHCP] Recv error: {e}")
    sock.close()
    logger.info("[DHCP] Listener stopped")

def listen_netbios(findings:PassiveFindings,stop_event:threading.Event,pcf_dag:PCFDAG,session_root_id:str):
    NETBIOS_PORT=137
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        sock.bind(("0.0.0.0", NETBIOS_PORT))
        sock.settimeout(1.0)
    except OSError as e:
        logger.warning(
            f"[NetBIOS] Could not bind port 137: {e}. "
            f"NetBIOS listener disabled. (Run as root?)"
           )
        return
    logger.info("[NetBIOS] Listening on UDP port 137")
    while not stop_event.is_set():
        try:
            _,addr=sock.recvfrom(1500)
            src_ip=addr[0]
            if src_ip not in findings.netbios:
                findings.add_netbios(src_ip)
                logger.debug(f"[NetBIOS] Windows host detected: {src_ip}")
                pcf_dag.add_node(
                    node_type=NodeType.PASSIVE,
                    phase="PASSIVE_LISTENING",
                    payload={"ip":src_ip,"protocol":"NetBIOS","inference":"Windows host"},
                    parent_ids=[session_root_id],
                    evidence_approaches=EvidenceApproach.PASSIVE,
                    device_ip=src_ip,
                )
        except socket.timeout:
            continue
        except Exception as e:
            logger.debug(f"[NetBIOS] Recv error: {e}")
    sock.close()
    logger.info("[NetBIOS] Listener stopped")

class PassiveReconPhase:
    """
    Manages the four passive listeners (mDNS, SSDP, DHCP, NetBIOS) as
    background daemon threads.
    """
    def __init__(self,pcf_dag:PCFDAG,session_root_id:str):
        self.pcf_dag=pcf_dag
        self.session_root_id=session_root_id
        self.findings=PassiveFindings()
        self.stop_event=threading.Event()
        self.threads:List[threading.Thread]=[]

    def start(self)->None:
        listeners=[
            ('mDNS',listen_mdns),
            ('SSDP',listen_ssdp),
            ('DHCP',listen_dhcp),
            ('NetBIOS',listen_netbios),
        ]
        for name,fn in listeners:
            t=threading.Thread(
                target=fn,
                args=(self.findings,self.stop_event,self.pcf_dag,self.session_root_id),
                name=f"passive-{name}",
                daemon=True
            )
            t.start()
            self.threads.append(t)
        logger.info('All passive listeners have been started')
    
    def stop(self)->None:
        self.stop_event.set()
        for t in self.threads:
            t.join(timeout=3.0)
        logger.info("All passive listeners have been stopped")

    def get_findings(self)->PassiveFindings:
        return self.findings
    def get_known_ips(self)->set:
        return self.findings.get_all_ips()