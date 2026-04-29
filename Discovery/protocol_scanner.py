import socket
import struct
import logging
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError

from TIB_and_PCF.PCF import PCFDAG, NodeType, EvidenceApproach

logger = logging.getLogger(__name__)

# mDNS-to-OS mapping 
MDNS_OS_MAP = {
    "_companion-link._tcp": "iOS / iPadOS",
    "_rdlink._tcp": "iOS / iPadOS",
    "_airplay._tcp": "macOS / Apple Device",
    "_raop._tcp": "macOS / Apple Device",
    "_googlecast._tcp": "Android / ChromeOS",
    "_androidtvremote._tcp": "Android TV",
    "_androidtvremote2._tcp": "Android TV",
    "_roku-rcp._tcp": "Roku OS",
    "_amzn-wplay._tcp": "Amazon Fire OS",
    "_hap._tcp": "HomeKit Device",
    "_homekit._tcp": "HomeKit Device",
    "_ipp._tcp": "Printer OS",
    "_ipps._tcp": "Printer OS",
    "_spotify-connect._tcp": "Media Device",
}

# mDNS-to-device-type mapping 
MDNS_TYPE_MAP = {
    "_companion-link._tcp": "Phone / Tablet (Apple)",
    "_rdlink._tcp": "Phone / Tablet (Apple)",
    "_airplay._tcp": "Apple Device",
    "_raop._tcp": "Apple Device",
    "_googlecast._tcp": "Smart TV / Chromecast",
    "_androidtvremote._tcp": "Smart TV (Android)",
    "_androidtvremote2._tcp": "Smart TV (Android)",
    "_roku-rcp._tcp": "Smart TV (Roku)",
    "_amzn-wplay._tcp": "Smart TV (Fire TV)",
    "_hap._tcp": "Smart Home Device",
    "_homekit._tcp": "Smart Home Device",
    "_ipp._tcp": "Printer",
    "_ipps._tcp": "Printer",
    "_pdl-datastream._tcp": "Printer",
    "_scanner._tcp": "Scanner / Printer",
    "_smb._tcp": "Desktop / Laptop / NAS",
    "_afpovertcp._tcp": "Mac / NAS",
    "_sftp-ssh._tcp": "Server / Workstation",
    "_ssh._tcp": "Server / Workstation",
    "_spotify-connect._tcp": "Media Player",
    "_sleep-proxy._udp": "Apple Device",
    "_matter._tcp": "Smart Home Device",
    "_miio._udp": "Smart Home Device (Xiaomi)",
    "_tuya._tcp": "Smart Home Device (Tuya)",
    "_esphomelib._tcp": "IoT Device (ESPHome)",
}


class ProtocolScanner:
    """
    Active protocol-level device scanner. 
    """

    def __init__(self, pcf_dag: Optional[PCFDAG] = None, session_root_id: str = ""):
        self.pcf_dag = pcf_dag
        self.session_root_id = session_root_id

    # mDNS Active Browse

    def scan_mdns(self, timeout: float = 5.0) -> Dict[str, dict]:
        """
        Send DNS-SD browse queries to discover all mDNS-capable devices.
        Returns dict mapping IP -> {device_name, services, os_hint, device_type}.
        """
        results: Dict[str, dict] = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 0)) 
            mreq = struct.pack("4sL", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(0.5)
        except OSError as e:
            logger.warning(f"[mDNS-Active] Could not create socket: {e}")
            return results

        # Build DNS-SD browse query: PTR for _services._dns-sd._udp.local
        query = self._build_dns_query("_services._dns-sd._udp.local", qtype=0x000C)

        # Also send specific queries for common consumer device services
        targeted_queries = [
            "_airplay._tcp.local",
            "_companion-link._tcp.local",
            "_googlecast._tcp.local",
            "_androidtvremote._tcp.local",
            "_roku-rcp._tcp.local",
            "_amzn-wplay._tcp.local",
            "_raop._tcp.local",
            "_ipp._tcp.local",
            "_smb._tcp.local",
            "_hap._tcp.local",
            "_spotify-connect._tcp.local",
            "_http._tcp.local",
            "_ssh._tcp.local",
        ]

        # Send queries 
        for attempt in range(3):
            try:
                sock.sendto(query, ("224.0.0.251", 5353))
                for svc in targeted_queries:
                    sock.sendto(self._build_dns_query(svc, qtype=0x000C), ("224.0.0.251", 5353))
            except OSError:
                pass
            if attempt<2:
                time.sleep(0.3)

        # Collect responses
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                parsed = self._parse_mdns_response(data)
                if not parsed:
                    continue

                if src_ip not in results:
                    results[src_ip] = {
                        "device_name": "",
                        "services": [],
                        "os_hint": "",
                        "device_type": "",
                    }

                entry = results[src_ip]
                for name, rtype, rdata in parsed:
                    # PTR records: service type instances 
                    if rtype==0x000C:  # PTR
                        svc_type = self._extract_service_type(name)
                        if svc_type and svc_type not in entry["services"]:
                            entry["services"].append(svc_type)
                        # Extract device name from instance name
                        instance_name = self._extract_instance_name(rdata, svc_type)
                        if instance_name and not entry["device_name"]:
                            entry["device_name"] = instance_name

                    # TXT records often contain model info
                    elif rtype == 0x0010:  # TXT
                        txt_data = self._parse_txt_record(rdata)
                        if "model" in txt_data and not entry["device_name"]:
                            entry["device_name"] = txt_data["model"]
                        if "md" in txt_data and not entry["device_name"]:
                            entry["device_name"] = txt_data["md"]

                    # A records: hostname-to-IP mapping
                    elif rtype == 0x0001 and len(rdata) == 4:  # A record
                        resolved_ip = socket.inet_ntoa(rdata)
                        if resolved_ip != src_ip:
                            # Sometimes mDNS responses carry A records for other IPs
                            pass

                # Derive OS hint from services
                for svc in entry["services"]:
                    if svc in MDNS_OS_MAP and not entry["os_hint"]:
                        entry["os_hint"] = MDNS_OS_MAP[svc]
                    if svc in MDNS_TYPE_MAP and not entry["device_type"]:
                        entry["device_type"] = MDNS_TYPE_MAP[svc]

            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"[mDNS-Active] Parse error: {e}")

        sock.close()

        # Record in PCF
        for ip, info in results.items():
            if self.pcf_dag and info["services"]:
                self.pcf_dag.add_node(
                    node_type=NodeType.DISCOVERY, phase="PROTOCOL_SCAN",
                    payload={"ip": ip, "protocol": "mDNS_active",
                             "device_name": info["device_name"],
                             "services": info["services"][:10],
                             "os_hint": info["os_hint"]},
                    parent_ids=[self.session_root_id],
                    evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
                )

        logger.info(f"[mDNS-Active] Discovered {len(results)} devices")
        return results

    # SSDP M-SEARCH
    def scan_ssdp(self, timeout: float = 5.0) -> Dict[str, dict]:
        """
        Send SSDP M-SEARCH to discover UPnP devices (TVs, routers, consoles).
        Returns dict mapping IP -> {device_name, server_header, manufacturer, model, description}.
        """
        results: Dict[str, dict] = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)
        except OSError as e:
            logger.warning(f"[SSDP] Could not create socket: {e}")
            return results

        # M-SEARCH request
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 3\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode("utf-8")

        # Send 3 times for reliability
        for _ in range(3):
            try:
                sock.sendto(msearch,("239.255.255.250", 1900))
            except OSError:
                pass
            time.sleep(0.2)

        # Collect responses
        location_urls: Dict[str, str] = {}  # IP -> LOCATION URL
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                text = data.decode("utf-8", errors="replace")

                if "200 OK" not in text and "NOTIFY" not in text:
                    continue

                headers = {}
                for line in text.splitlines():
                    if ":" in line:
                        key, val = line.split(":", 1)
                        headers[key.strip().upper()] = val.strip()

                if src_ip not in results:
                    results[src_ip] = {
                        "device_name": "",
                        "server_header": "",
                        "manufacturer": "",
                        "model": "",
                        "description": "",
                    }

                entry = results[src_ip]
                if headers.get("SERVER") and not entry["server_header"]:
                    entry["server_header"] = headers["SERVER"]
                if headers.get("LOCATION") and src_ip not in location_urls:
                    location_urls[src_ip] = headers["LOCATION"]

            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"[SSDP] Parse error: {e}")

        sock.close()

        # Fetch UPnP XML descriptions concurrently
        if location_urls:
            logger.info(f"[SSDP] Fetching {len(location_urls)} UPnP descriptions...")
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {
                    pool.submit(self._fetch_upnp_description, url): ip
                    for ip, url in location_urls.items()
                }
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        desc = future.result()
                        if desc and ip in results:
                            entry = results[ip]
                            if desc.get("friendly_name"):
                                entry["device_name"] = desc["friendly_name"]
                            if desc.get("manufacturer"):
                                entry["manufacturer"] = desc["manufacturer"]
                            if desc.get("model_name"):
                                entry["model"] = desc["model_name"]
                            if desc.get("model_description"):
                                entry["description"] = desc["model_description"]
                    except Exception:
                        pass

        # Record in PCF
        for ip, info in results.items():
            if self.pcf_dag and (info["server_header"] or info["device_name"]):
                self.pcf_dag.add_node(
                    node_type=NodeType.DISCOVERY, phase="PROTOCOL_SCAN",
                    payload={"ip": ip, "protocol": "SSDP_MSEARCH",
                             "device_name": info["device_name"],
                             "server": info["server_header"],
                             "manufacturer": info["manufacturer"],
                             "model": info["model"]},
                    parent_ids=[self.session_root_id],
                    evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
                )

        logger.info(f"[SSDP] Discovered {len(results)} devices")
        return results

    # WSD (Web Services Discovery) Probe
    def scan_wsd(self, timeout: float = 3.0) -> Dict[str, dict]:
        """
        Send WS-Discovery probe to find Windows devices and network printers.
        """
        results: Dict[str, dict] = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)
        except OSError as e:
            logger.warning(f"[WSD] Could not create socket: {e}")
            return results

        import uuid as uuid_mod
        msg_id = str(uuid_mod.uuid4())
        # WS-Discovery Probe SOAP message (broadcast discovery)
        wsd_probe = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Probe/>
  </soap:Body>
</soap:Envelope>""".encode("utf-8")

        # Send to WSD multicast address
        for _ in range(2):
            try:
                sock.sendto(wsd_probe, ("239.255.255.250", 3702))
            except OSError:
                pass
            time.sleep(0.2)

        # Collect responses
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(8192)
                src_ip = addr[0]
                text = data.decode("utf-8", errors="replace")

                if src_ip not in results:
                    results[src_ip] = {"device_name": "", "device_type": "Windows Device"}

                # Try to extract device type from WSD response
                if "Device" in text or "Computer" in text:
                    results[src_ip]["device_type"] = "Laptop/Desktop (Windows)"
                if "Printer" in text or "print" in text.lower():
                    results[src_ip]["device_type"] = "Printer"

                # Extract any XAddrs (endpoint URLs)
                if "<wsd:Types>" in text:
                    try:
                        types_start = text.index("<wsd:Types>") + len("<wsd:Types>")
                        types_end = text.index("</wsd:Types>")
                        types_str = text[types_start:types_end].strip()
                        if "pub:Computer" in types_str or "wsdp:Device" in types_str:
                            results[src_ip]["device_type"] = "Laptop / Desktop (Windows)"
                    except (ValueError, IndexError):
                        pass

            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"[WSD] Parse error: {e}")

        sock.close()

        # Record in PCF
        for ip, info in results.items():
            if self.pcf_dag:
                self.pcf_dag.add_node(
                    node_type=NodeType.DISCOVERY, phase="PROTOCOL_SCAN",
                    payload={"ip": ip, "protocol": "WSD",
                             "device_type": info["device_type"]},
                    parent_ids=[self.session_root_id],
                    evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
                )

        logger.info(f"[WSD] Discovered {len(results)} Windows/WSD devices")
        return results

    #DNS Helpers
    def _build_dns_query(self, qname: str, qtype: int = 0x000C) -> bytes:
        """Build a DNS query packet for the given name and type."""
        # Header: ID=0, flags=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
        # Encode QNAME as DNS labels
        labels = b""
        for part in qname.rstrip(".").split("."):
            labels += bytes([len(part)]) + part.encode("utf-8")
        labels += b"\x00"
        # QTYPE and QCLASS (IN)
        question = struct.pack(">HH", qtype, 0x0001)
        return header + labels + question

    def _parse_mdns_response(self, data: bytes) -> List[Tuple[str, int, bytes]]:
        """Parse an mDNS response. Returns list of (name, record_type, rdata)."""
        records = []
        if len(data) < 12:
            return records

        # Parse header
        _id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        offset = 12

        # Skip questions
        for _ in range(qdcount):
            _, offset = self._parse_dns_name(data, offset)
            offset += 4  # Skip QTYPE + QCLASS

        # Parse answer + authority + additional sections
        total_records = ancount + nscount + arcount
        for _ in range(total_records):
            if offset >= len(data):
                break
            try:
                name, offset = self._parse_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
                offset += 10
                if offset + rdlength > len(data):
                    break
                rdata = data[offset:offset+rdlength]
                offset += rdlength

                # For PTR records, decode RDATA as a DNS name
                if rtype == 0x000C:
                    ptr_name, _ = self._parse_dns_name(data, offset - rdlength)
                    records.append((name, rtype, ptr_name.encode("utf-8")))
                else:
                    records.append((name, rtype, rdata))
            except Exception:
                break

        return records

    def _parse_dns_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Decode a DNS name from wire format, handling label compression."""
        parts = []
        original_offset = offset
        jumped = False
        max_jumps = 15
        jumps = 0

        while offset < len(data) and jumps < max_jumps:
            length = data[offset]
            if length == 0:
                if not jumped:
                    offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                # Pointer — follow the compression reference
                if offset + 1 >= len(data):
                    break
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = pointer
                jumps += 1
            else:
                offset += 1
                if offset + length > len(data):
                    break
                parts.append(data[offset:offset+length].decode("utf-8", errors="replace"))
                offset += length

        name = ".".join(parts)
        return (name, original_offset if jumped else offset)

    def _extract_service_type(self, name: str) -> str:
        """Extract the service type from a DNS-SD name"""
        parts = name.split(".")
        for i, part in enumerate(parts):
            if part.startswith("_") and i+1 < len(parts) and parts[i+1] in ("_tcp", "_udp"):
                return f"{part}.{parts[i+1]}"
        return ""

    def _extract_instance_name(self, rdata: bytes, svc_type: str) -> str:
        """Extract the instance name from a PTR record's RDATA."""
        try:
            full_name = rdata.decode("utf-8", errors="replace")
            # Instance name is the part before the service type
            if svc_type and svc_type in full_name:
                instance = full_name.split(svc_type)[0].rstrip(".")
                if instance and len(instance) > 1:
                    return instance
            # Fallback: take everything before the first underscore-prefixed label
            parts = full_name.split(".")
            non_svc = []
            for p in parts:
                if p.startswith("_"):
                    break
                non_svc.append(p)
            if non_svc:
                return ".".join(non_svc)
        except Exception:
            pass
        return ""

    def _parse_txt_record(self, rdata: bytes) -> dict:
        """Parse a DNS TXT record into key=value pairs."""
        result = {}
        offset = 0
        while offset < len(rdata):
            length = rdata[offset]
            offset += 1
            if offset + length > len(rdata):
                break
            entry = rdata[offset:offset+length].decode("utf-8", errors="replace")
            if "=" in entry:
                key, val = entry.split("=", 1)
                result[key.strip().lower()] = val.strip()
            offset += length
        return result

    #UPnP Description Fetch
    def _fetch_upnp_description(self, url: str, timeout: float = 3.0) -> dict:
        """Fetch and parse a UPnP device description XML."""
        result = {}
        try:
            req = Request(url, headers={"User-Agent": "MAPT-RCD/1.0 UPnP/1.1"})
            resp = urlopen(req, timeout=timeout)
            xml_text = resp.read(32768).decode("utf-8", errors="replace")

            # Try both UPnP 1.0 and 2.0 namespaces
            for ns_uri in ["urn:schemas-upnp-org:device-1-0","urn:schemas-upnp-org:device-2-0",]:
                ns = {"upnp": ns_uri}
                try:
                    root = ET.fromstring(xml_text)
                    device = root.find(".//upnp:device", ns)
                    if device is not None:
                        result["friendly_name"] = device.findtext("upnp:friendlyName","",ns).strip()
                        result["manufacturer"] = device.findtext("upnp:manufacturer","",ns).strip()
                        result["model_name"] = device.findtext("upnp:modelName","",ns).strip()
                        result["model_description"] = device.findtext("upnp:modelDescription","",ns).strip()
                        if result["friendly_name"]:
                            return result
                except ET.ParseError:
                    pass

            # Fallback: try without namespace
            try:
                root = ET.fromstring(xml_text)
                device = root.find(".//{*}device")
                if device is not None:
                    result["friendly_name"] = (device.findtext("{*}friendlyName") or "").strip()
                    result["manufacturer"] = (device.findtext("{*}manufacturer") or "").strip()
                    result["model_name"] = (device.findtext("{*}modelName") or "").strip()
                    result["model_description"] = (device.findtext("{*}modelDescription") or "").strip()
            except ET.ParseError:
                pass

        except (URLError, OSError, Exception) as e:
            logger.debug(f"[UPnP] Failed to fetch {url}: {e}")

        return result
