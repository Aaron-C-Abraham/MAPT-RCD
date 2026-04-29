import logging
import socket
from typing import Optional, List
from TIB_and_PCF.PCF import PCFDAG, NodeType, EvidenceApproach
from TIB_and_PCF.TIB.device_TIB_manager import TIBManager
from TIB_and_PCF.TIB.TIB_structures import OsProbeIntensity
from TIB_and_PCF.TIB.circuit_breaker import TIBViolation, TIBExhausted

logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.all import IP, TCP, sr1, conf
conf.verb = 0
from database.nmap_os_parser import NmapOSMatcher
_NMAP_MATCHER = NmapOSMatcher()

class OSIdentificationPhase:
    """
    Tier-gated OS identification using pure Python. Uses passive synthesis
    (TTL, banners, SNMP, vendor) and minimal active probing (TCP connect +
    banner analysis) based on the device's OsProbeIntensity setting.
    """
    def __init__(self, pcf_dag: PCFDAG):
        self.pcf_dag = pcf_dag

    def run(self, tib_managers: list) -> None:
        logger.info(f"OS identification for {len(tib_managers)} devices")
        for tib in tib_managers:
            self.identify_one(tib)
        logger.info("OS identification complete")

    def identify_one(self, tib: TIBManager) -> None:
        """Identify the OS of a single device using the best available method."""
        ip = tib.device_ip
        intensity = tib.config.os_probe_intensity
        os_guess = None
        if (intensity in (OsProbeIntensity.STANDARD, OsProbeIntensity.FULL) and tib.signals.open_ports):
            os_guess = self._os_fingerprint(tib)
        if not os_guess:
            if intensity == OsProbeIntensity.PASSIVE:
                os_guess = self._passive_synthesise(tib)
            elif intensity == OsProbeIntensity.MINIMAL:
                os_guess = self._minimal_probe(tib) or self._passive_synthesise(tib)
            else:
                os_guess = self._minimal_probe(tib) or self._passive_synthesise(tib)

        if os_guess:
            tib.signals.update_nmap_os_guess(os_guess)
            logger.info(f"[OS Identifier] {ip} -> {os_guess}")
            self.pcf_dag.add_node(
                node_type=NodeType.OS_ID, phase="OS_IDENTIFICATION",
                payload={"ip": ip, "os_guess": os_guess, "method": intensity.name.lower()},
                parent_ids=[tib.pcf_device_root_id],
                evidence_approaches=(EvidenceApproach.INFERRED
                                     if intensity == OsProbeIntensity.PASSIVE
                                     else EvidenceApproach.ACTIVE),
                device_ip=ip,
            )

        # Infer device type from all available signals
        device_type = self._infer_device_type(tib)
        if device_type:
            tib.signals.update_device_type(device_type)
            logger.info(f"[OS Identifier] {ip} type={device_type}")

    def _passive_synthesise(self, tib: TIBManager) -> str:
        """
        Derive OS from already-collected signals
        """
        s = tib.signals
        vendor = s.oui_vendor.lower()
        mdns = s.mdns_services
        mdns_str = " ".join(mdns).lower() if mdns else ""
        hostname = (s.mdns_device_name or s.reverse_dns or "").lower()
        ports = set(s.open_ports)
        if s.snmp_sysdescr:
            return f"SNMP: {s.snmp_sysdescr[:80]}"
        banners = " ".join(s.banners.values()).lower()
        for kw, label in [
            ("ubuntu", "Linux (Ubuntu)"), ("debian", "Linux (Debian)"),
            ("centos", "Linux (CentOS)"), ("red hat", "Linux (Red Hat)"),
            ("windows server", "Windows Server"), ("windows", "Windows"),
            ("freebsd", "FreeBSD"), ("openssh", "Linux/Unix (OpenSSH)"),
            ("dropbear", "Embedded Linux (Dropbear SSH)"),
            ("lwip", "Embedded (lwIP)"), ("freertos", "Embedded (FreeRTOS)"),
            ("vxworks", "Embedded (VxWorks)"), ("busybox", "Embedded Linux (BusyBox)"),
            ("openwrt", "Embedded Linux (OpenWRT)"), ("raspbian", "Linux (Raspbian)"),
            ("raspberry", "Linux (Raspberry Pi OS)"),
            # Smart TV / streaming device banners
            ("roku", "Roku OS"), ("tizen", "Samsung Tizen (Smart TV)"),
            ("webos", "LG webOS (Smart TV)"), ("fire os", "Amazon Fire OS"),
            ("android tv", "Android TV"), ("chromecast", "Google Chromecast OS"),
            ("smarttv", "Smart TV"),
            # Router firmware
            ("tp-link", "Embedded Linux (TP-Link)"), ("archer", "Embedded Linux (TP-Link)"),
            ("netgear", "Embedded Linux (Netgear)"), ("dd-wrt", "Embedded Linux (DD-WRT)"),
            ("mikrotik", "RouterOS (MikroTik)"),
        ]:
            if kw in banners:
                return label
        if mdns_str:
            if "_androidtvremote" in mdns_str:
                return "Android TV"
            if "_roku-rcp" in mdns_str:
                return "Roku OS"
            if "_amzn-wplay" in mdns_str:
                return "Amazon Fire OS"
            if "_companion-link" in mdns_str or "_rdlink" in mdns_str:
                return "iOS / iPadOS"
            if "_airplay" in mdns_str and "_companion-link" not in mdns_str:
                return "macOS / Apple Device"
            if "_googlecast" in mdns_str:
                return "Android / ChromeOS"

        if hostname:
            hostname_os_hints = [
                # Windows patterns
                (["desktop-", "laptop-", "msft", "-pc", "windows", "win10", "win11"], "Windows"),
                # Apple patterns
                (["iphone", "ipod"], "iOS"),
                (["ipad"], "iPadOS"),
                (["macbook", "imac", "mac-", "mac.local"], "macOS"),
                (["appletv", "apple-tv"], "tvOS (Apple TV)"),
                (["homepod"], "audioOS (HomePod)"),
                # Android patterns
                (["android", "galaxy", "pixel", "oneplus", "xiaomi", "redmi",
                  "poco", "oppo", "realme", "huawei", "motorola", "nokia"], "Android"),
                # Linux patterns
                (["ubuntu", "debian", "fedora", "arch", "centos", "raspberrypi",
                  "raspberry", "linux"], "Linux"),
                # Smart TV patterns
                (["roku", "fire-tv", "firetv", "chromecast"], "Smart TV OS"),
                (["samsung-tv", "lg-tv", "sony-tv", "bravia"], "Smart TV OS"),
                # Router patterns
                (["archer", "tp-link", "tplink", "netgear", "router", "gateway"], "Embedded Linux (Router)"),
                # NAS
                (["nas", "synology", "diskstation", "qnap"], "Linux (NAS)"),
            ]
            for keywords, os_label in hostname_os_hints:
                if any(kw in hostname for kw in keywords):
                    return os_label
            if (s.netbios_present or
                    any(p in ports for p in [445, 3389, 135, 139, 5985])):
                return "Windows"
            if any(hostname.endswith(sfx) for sfx in ["-pc", "-laptop", "-desktop","-win", "win", "-pc.local"]):
                return "Windows"

            if "apple" in vendor:
                return "macOS / iOS"
            if hostname and not hostname.startswith("192.") and len(hostname) > 3:
                return "Windows / Linux (hostname present)"
        if "raspberry pi" in vendor:
            return "Linux (Raspberry Pi OS)"
        if "apple" in vendor:
            if "_companion-link" in mdns_str or "_rdlink" in mdns_str:
                return "iOS / iPadOS"
            return "macOS / iOS"
        if "microsoft" in vendor:
            return "Windows"
        if any(kw in vendor for kw in [
            "samsung", "oneplus", "xiaomi", "oppo", "vivo", "huawei",
            "motorola", "google", "realme", "nothing", "honor", "zte",
        ]):
            return "Android"
        if any(kw in vendor for kw in [
            "roku", "amazon technologies", "sony", "vizio", "hisense", "tcl",
        ]):
            return "Smart TV OS"
        if "lg electronics" in vendor:
            return "webOS / Android (LG)"
        if any(kw in vendor for kw in [
            "tp-link", "netgear", "d-link", "asus", "linksys", "belkin",
            "ubiquiti", "mikrotik",
        ]):
            return "Embedded Linux (Router/AP)"
        if any(kw in vendor for kw in [
            "dell", "hewlett packard", "hp inc", "lenovo", "intel corporate",
            "acer", "toshiba", "msi",
        ]):
            if s.netbios_present or any(p in ports for p in [445, 3389, 135]):
                return "Windows"
            return "Windows / Linux"

        if s.ttl:
            t = s.ttl
            initial_ttl = t+(s.hops_for_ttl or 0)
            if initial_ttl<=64:
                if "randomized mac" in vendor:
                    return "Android/iOS"
                return "Linux/Unix"
            if initial_ttl <= 128:
                return "Windows"
            return "Network device"

        # Port-based fallback 
        if ports:
            if 62078 in ports:
                return "iOS (Lockdown port)"
            if 5555 in ports:
                return "Android (ADB)"
            if 445 in ports or 3389 in ports:
                return "Windows"
            if 548 in ports:
                return "macOS (AFP)"
            if 8008 in ports or 8009 in ports:
                return "ChromeOS / Chromecast"
            if 22 in ports:
                return "Linux/Unix (SSH)"
            if 80 in ports or 443 in ports:
                return "Unknown (HTTP device)"

        # Randomized MAC fallback 
        # Devices with randomized MACs and no other signals are almost always modern phones/tablets/laptops 
        if "randomized mac" in vendor:
            return "Phone / Laptop (Randomized MAC)"

        return "Unknown"

    def _os_fingerprint(self, tib: TIBManager) -> Optional[str]:
        """
        Scapy-based TCP/IP stack fingerprinting. Sends a SYN to an open port
        and analyzes the SYN-ACK response to identify the OS from:
          - TTL value (initial TTL before hop decrements)
          - TCP window size
          - DF (Don't Fragment) bit
          - TCP options (MSS, window scale, SACK, timestamps, NOP ordering)

        This replicates nmap's OS detection technique using raw Scapy packets.
        No external tools needed.
        """
        ip = tib.device_ip
        if not tib.signals.open_ports:
            return None

        port = tib.signals.open_ports[0]
        try:
            # Send SYN and capture the SYN-ACK
            syn = IP(dst=ip) / TCP(dport=port, flags="S", options=[
                ("MSS", 1460), ("NOP", None), ("WScale", 8),
                ("NOP", None), ("NOP", None), ("SAckOK", b""),
            ])
            resp = sr1(syn, timeout=3, verbose=0)
            if resp is None or not resp.haslayer(TCP):
                return None
            if resp[TCP].flags != 0x12:  # Not SYN-ACK
                return None

            # Send RST to close the half-open connection
            sr1(IP(dst=ip) / TCP(dport=port, sport=resp[TCP].dport,
                                  seq=resp[TCP].ack, flags="R"),
                timeout=0.5, verbose=0)

            # ── Extract fingerprint signals ────────────────────────────────
            ttl = resp[IP].ttl
            window = resp[TCP].window
            df = bool(resp[IP].flags.DF)
            tcp_opts = [opt[0] for opt in resp[TCP].options] if resp[TCP].options else []
            tcp_opts_str = ",".join(tcp_opts)

            # Store raw signals on the TIB
            if ttl and not tib.signals.ttl:
                tib.signals.ttl = ttl
            if window and not tib.signals.tcp_window_size:
                tib.signals.update_tcp_window_size(window)
            if tcp_opts and not tib.signals.tcp_options:
                tib.signals.update_tcp_options(tcp_opts)

            # Match fingerprint against known OS signatures 
            os_guess = self._match_os_signature(ttl+tib.signals.hops_for_ttl, window, df, tcp_opts)

            if os_guess:
                logger.info(f"[Scapy OS] {ip} -> {os_guess} "
                            f"(TTL={ttl} Win={window} DF={df} Opts={tcp_opts_str})")
                self.pcf_dag.add_node(
                    node_type=NodeType.OS_ID, phase="SCAPY_OS_FINGERPRINT",
                    payload={"ip": ip, "os_guess": os_guess, "method": "scapy_tcp_fingerprint",
                             "ttl": ttl, "window": window, "df": df,
                             "tcp_options": tcp_opts_str},
                    parent_ids=[tib.pcf_device_root_id],
                    evidence_approaches=EvidenceApproach.ACTIVE, device_ip=ip,
                )
                return os_guess

        except Exception as e:
            logger.debug(f"[Scapy OS] {ip}: {e}")
        return None

    def _match_os_signature(self, ttl: int, window: int, df: bool,
                            tcp_opts: List[str]) -> Optional[str]:
        """
        Match TCP/IP fingerprint against known OS signatures.
        """
        # Nmap database matching 
        if _NMAP_MATCHER is not None:
            has_wscale = any(o in ("WScale", "Window Scale", "wscale") for o in tcp_opts)
            has_sack = any(o in ("SAckOK", "SACK", "SAck", "sackOK") for o in tcp_opts)
            has_ts = any(o in ("Timestamp", "TS", "Timestamps") for o in tcp_opts)

            matches = _NMAP_MATCHER.match(
                ttl=ttl, window=window, df=df,
                has_wscale=has_wscale, has_sack=has_sack,
                has_timestamp=has_ts, top_n=3,
            )
            if matches and matches[0]["confidence"] >= 0.5:
                best = matches[0]
                result = best["name"]
                if best["device_type"]:
                    result += f" ({best['device_type']})"
                logger.debug(
                    f"[Nmap OS] Matched: {result} "
                    f"(score={best['score']}, conf={best['confidence']})"
                )
                return result

        # Hardcoded heuristic fallback 
        # Infer initial TTL (before hop decrements)
        if ttl <= 32:
            initial_ttl = 32
        elif ttl <= 64:
            initial_ttl = 64
        elif ttl <= 128:
            initial_ttl = 128
        else:
            initial_ttl = 255

        has_wscale = any(o in ("WScale", "Window Scale", "wscale") for o in tcp_opts)
        has_sack = any(o in ("SAckOK", "SACK", "SAck", "sackOK") for o in tcp_opts)
        has_ts = any(o in ("Timestamp", "TS", "Timestamps") for o in tcp_opts)

        # TTL 255: Network device
        if initial_ttl == 255:
            if window <= 4128:
                return "Cisco IOS"
            return "Network Device (Router/Switch)"

        # TTL 128: Windows family 
        if initial_ttl == 128:
            if has_wscale and has_sack and has_ts:
                if window >= 64000:
                    return "Windows 10/11"
                if window >= 32000:
                    return "Windows Server 2016+"
                return "Windows 8+"
            if window == 8192:
                return "Windows 7 / Windows XP"
            if window == 65535 and not has_wscale:
                return "Windows Vista / Server 2008"
            if window >= 16384:
                return "Windows"
            return "Windows"

        # TTL 64: Linux / macOS / iOS / Android / Embedded 
        if initial_ttl == 64:
            # macOS/iOS: typically window=65535, DF set, has all options
            if window == 65535 and df:
                if has_wscale and has_ts:
                    return "macOS / iOS"
                return "macOS / iOS"

            # Linux: large window, DF, full TCP options
            if df and has_wscale and has_sack and has_ts:
                if window >= 29200:
                    return "Linux (kernel 3.x+)"
                if window >= 14600:
                    return "Linux (kernel 2.6)"
                return "Linux"

            # Android: similar to Linux but often smaller window
            if df and has_sack and window >= 14000:
                return "Linux / Android"

            # Embedded: small window, minimal options
            if window <= 5840:
                if not has_wscale and not has_ts:
                    return "Embedded OS (lwIP/uIP)"
                return "Embedded Linux"

            # FreeBSD
            if window == 65535 and has_wscale and has_sack and not has_ts:
                return "FreeBSD"

            # Generic Unix
            return "Linux / Unix"

        # TTL 32: Older devices 
        if initial_ttl == 32:
            return "Legacy OS / Embedded"

        return None

    def _minimal_probe(self, tib: TIBManager) -> Optional[str]:
        """One TCP connect probe to the first open port, checking banner for OS hints."""
        if not tib.signals.open_ports:
            return None
        try:
            tib.breaker.request_packet_permission(1, "tcp_syn")
        except (TIBViolation, TIBExhausted):
            return None
        port = tib.signals.open_ports[0]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((tib.device_ip, port))
            tib.breaker.record_response()
            # Try to read a banner for OS hints
            try:
                if port in (80, 8080):
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {tib.device_ip}\r\n\r\n".encode())
                data = sock.recv(512).decode("utf-8", errors="replace").lower()
                sock.close()
                if "server:" in data:
                    for kw, label in [
                        ("apache", "Linux (Apache)"), ("nginx", "Linux (nginx)"),
                        ("iis", "Windows (IIS)"), ("lighttpd", "Linux (lighttpd)"),
                        ("openssh", "Linux/Unix (OpenSSH)"),
                    ]:
                        if kw in data:
                            return label
            except Exception:
                pass
        except Exception:
            pass
        finally:
            sock.close()
        return None

    def _infer_device_type(self, tib: TIBManager) -> str:
        """
        Infer the device type using multi-signal fusion
        """
        from TIB_and_PCF.TIB.device_classifier import MDNS_DEVICE_TYPE_HINTS
        s = tib.signals
        vendor = s.oui_vendor.lower()
        os_guess = (s.nmap_os_guess or "").lower()
        name = (s.mdns_device_name or s.reverse_dns or "").lower()
        ports = set(s.open_ports)
        mdns_str = " ".join(s.mdns_services).lower() if s.mdns_services else ""

        # mDNS service-based inference
        for svc in s.mdns_services:
            if svc in MDNS_DEVICE_TYPE_HINTS:
                hint = MDNS_DEVICE_TYPE_HINTS[svc]
                if hint == "Apple Device":
                    if "iphone" in name:
                        return "Phone (iPhone)"
                    if "ipad" in name:
                        return "Tablet (iPad)"
                    if any(kw in name for kw in ["macbook", "mac"]):
                        return "Laptop (Mac)"
                    if "apple tv" in name or "appletv" in name:
                        return "Smart TV (Apple TV)"
                    if "homepod" in name:
                        return "Smart Speaker (HomePod)"
                    if "_companion-link._tcp" in s.mdns_services:
                        return "Phone / Tablet (Apple)"
                    return "Apple Device"
                return hint

        # Device name / hostname inference 
        if name:
            name_hints = [
                # Phones
                (["iphone"], "Phone (iPhone)"),
                (["galaxy", "sm-"], "Phone (Samsung)"),
                (["pixel"], "Phone (Google Pixel)"),
                (["oneplus", "one plus"], "Phone (OnePlus)"),
                (["xiaomi", "redmi", "poco"], "Phone (Xiaomi)"),
                (["huawei", "honor"], "Phone (Huawei)"),
                (["oppo", "realme"], "Phone (Oppo)"),
                (["motorola", "moto"], "Phone (Motorola)"),
                (["android", "phone"], "Phone (Android)"),
                # Tablets
                (["ipad"], "Tablet (iPad)"),
                (["tab", "tablet"], "Tablet"),
                # Laptops / Desktops
                (["macbook"], "Laptop (Mac)"),
                (["imac"], "Desktop (Mac)"),
                (["laptop", "notebook", "thinkpad", "latitude", "elitebook",
                  "spectre", "pavilion", "inspiron", "xps", "surface",
                  "zenbook", "vivobook", "ideapad", "yoga"], "Laptop"),
                (["desktop", "workstation", "tower"], "Desktop"),
                # Routers / Networking
                (["archer", "tp-link", "tplink", "netgear", "router",
                  "gateway", "modem", "dsl", "ont"], "Router / Gateway"),
                (["access point", "ap-", "unifi", "eap"], "Access Point"),
                # Smart TVs
                (["tv", "bravia", "vizio", "roku", "fire stick", "firetv",
                  "chromecast", "smart tv", "tizen", "webos", "shield"], "Smart TV"),
                # Printers
                (["printer", "laserjet", "officejet", "deskjet", "pixma",
                  "ecotank", "mfc-", "hl-"], "Printer"),
                # Speakers
                (["speaker", "echo", "homepod", "nest mini", "sonos",
                  "alexa", "google home"], "Smart Speaker"),
                # Cameras
                (["camera", "cam", "doorbell", "security"], "Camera"),
                # NAS
                (["nas", "diskstation", "synology", "qnap"], "NAS"),
                # Gaming
                (["playstation", "ps4", "ps5", "xbox", "switch"], "Game Console"),
            ]
            for keywords, dtype in name_hints:
                if any(kw in name for kw in keywords):
                    return dtype

            # Windows hostname heuristic: if hostname exists + Windows signals
            if s.netbios_present or any(p in ports for p in [445, 3389, 135, 139]):
                return "Laptop / Desktop (Windows)"

            # Apple vendor + hostname (but no specific device keyword)
            if "apple" in vendor:
                return "Apple Device"

            # Generic computer: hostname exists, not a MAC-derived name,
            # not an IP-like string — likely a user-named computer
            if (name and len(name) > 3
                    and not name.startswith("192.")
                    and not name.startswith("10.")
                    and ":" not in name):
                return "Laptop / Desktop"

        # Vendor-based inference 
        # Routers / APs — check BEFORE phones since some vendors make both
        router_vendors = [
            "tp-link", "netgear", "d-link", "asus", "linksys", "belkin",
            "ubiquiti", "mikrotik", "arris", "humax", "zyxel", "draytek",
        ]
        if any(kw in vendor for kw in router_vendors):
            if 80 in ports or 443 in ports or 8080 in ports:
                return "Router / Gateway"
            return "Router / AP"

        # Phones
        phone_vendors = [
            "oneplus", "xiaomi", "oppo", "vivo", "huawei",
            "motorola", "realme", "nothing", "honor", "zte",
        ]
        if any(kw in vendor for kw in phone_vendors):
            return "Phone"
        if "samsung" in vendor:
            if any(tv_port in ports for tv_port in [8001, 8002]):
                return "Smart TV (Samsung)"
            if "_googlecast" in mdns_str or "_androidtvremote" in mdns_str:
                return "Smart TV (Samsung)"
            return "Phone (Samsung)"
        if "google" in vendor:
            if 8008 in ports or 8009 in ports:
                return "Chromecast / Google Home"
            return "Phone (Google)"

        # Apple
        if "apple" in vendor:
            if "_companion-link" in mdns_str or "_rdlink" in mdns_str:
                return "Phone / Tablet (Apple)"
            if s.netbios_present or 548 in ports:
                return "Laptop / Desktop (Mac)"
            if 7000 in ports or 7100 in ports:
                return "Apple TV"
            return "Apple Device"

        # PCs / Laptops
        pc_vendors = [
            "dell", "hewlett packard", "hp inc", "lenovo", "intel corporate",
            "acer", "toshiba", "msi",
        ]
        if any(kw in vendor for kw in pc_vendors):
            if 3389 in ports or s.netbios_present or 445 in ports:
                return "Laptop / Desktop (Windows)"
            return "Laptop / Desktop"
        if "microsoft" in vendor:
            return "Laptop / Desktop (Windows)"

        # Smart TVs / Streaming
        if "roku" in vendor:
            return "Smart TV (Roku)"
        if "amazon technologies" in vendor:
            return "Smart TV (Fire TV) / Echo"
        if any(kw in vendor for kw in ["sony", "vizio", "hisense", "tcl"]):
            return "Smart TV"
        if "lg electronics" in vendor:
            return "Smart TV / Appliance (LG)"
        if "nvidia" in vendor:
            return "Streaming Device (NVIDIA Shield)"

        # Printers
        if any(kw in vendor for kw in ["canon", "epson", "brother", "lexmark", "xerox", "ricoh"]):
            return "Printer"
        if "sonos" in vendor:
            return "Smart Speaker"
        if any(kw in vendor for kw in ["nest", "ring"]):
            return "Smart Home Device"
        if any(kw in vendor for kw in ["hikvision", "dahua", "axis"]):
            return "IP Camera"
        if "raspberry pi" in vendor:
            return "Single Board Computer (Raspberry Pi)"

        # Port-based inference 
        if 9100 in ports or 515 in ports or 631 in ports:
            return "Printer"
        if 554 in ports:
            return "IP Camera / DVR"
        if 8008 in ports or 8009 in ports:
            return "Chromecast / Smart TV"
        if 62078 in ports:
            return "Phone (iPhone)"
        if 5555 in ports:
            return "Android Device (ADB)"

        # OS-based inference 
        if "android" in os_guess:
            return "Android Device"
        if "ios" in os_guess or "ipados" in os_guess:
            return "Phone / Tablet (Apple)"
        if "router" in os_guess or "embedded linux (tp-link" in os_guess or "embedded linux (router" in os_guess:
            return "Router / Gateway"
        if "windows" in os_guess:
            return "Laptop / Desktop (Windows)"
        if "macos" in os_guess:
            return "Laptop / Desktop (Mac)"

        # Randomized MAC heuristic 
        if "randomized mac" in vendor:
            if s.netbios_present or any(p in ports for p in [445, 3389]):
                return "Laptop (Windows)"
            return "Phone / Laptop"
        return ""
