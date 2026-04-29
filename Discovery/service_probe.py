import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List
from TIB_and_PCF.PCF import PCFDAG, NodeType, EvidenceApproach
from TIB_and_PCF.TIB.device_TIB_manager import TIBManager
from TIB_and_PCF.TIB.circuit_breaker import TIBViolation, TIBExhausted
from TIB_and_PCF.TIB.device_classifier import INDUSTRIAL_PORTS, FRAGILE_BANNER_KEYWORDS

logger = logging.getLogger(__name__)
NO_PROBE_PORTS = set(INDUSTRIAL_PORTS.keys())

PORT_PROBES: Dict[int, bytes] = {
    21: b"", 22: b"", 23: b"", 25: b"",
    80: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    110: b"", 143: b"", 443: None, 445: b"",
    515: b"", 631: b"GET / HTTP/1.0\r\n\r\n",
    3306: b"", 3389: b"", 5432: b"", 5900: b"",
    6379: b"INFO\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    8443: None, 9100: b"", 27017: b"",
}


class ServiceProbePhase:
    """
    Probes open ports for service banners and runs vulnerability checks.
    """
    def __init__(self, pcf_dag: PCFDAG, max_threads: int = 10):
        self.pcf_dag = pcf_dag
        self.max_threads = max_threads

    def run(self, tib_managers: List[TIBManager]) -> None:
        active = [t for t in tib_managers if t.signals.open_ports]
        if not active:
            logger.info("[Service Probe] No devices with open ports — skipping")
            return
        logger.info(f"[Service Probe] Service probing {len(active)} devices")
        with ThreadPoolExecutor(max_workers=self.max_threads, thread_name_prefix="svc") as executor:
            futures = {executor.submit(self.probe_one, tib): tib for tib in active}
            for future in as_completed(futures):
                tib = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"[Service Probe] {tib.device_ip} error: {e}")
        logger.info("[Service Probe] Service probing complete")

    def probe_one(self, tib: TIBManager) -> None:
        """Probe all open ports on a single device for banners and vulnerabilities."""
        ip = tib.device_ip
        new_banners = dict(tib.signals.banners)
        vuln_findings = []

        for port in tib.signals.open_ports:
            if port in NO_PROBE_PORTS:
                protocol = INDUSTRIAL_PORTS[port]
                vuln_findings.append({"type": "industrial_port", "port": port, "protocol": protocol,"severity": "HIGH", "detail": f"Industrial protocol {protocol} open — requires manual assessment"})
                self._record_pcf(tib, port, f"industrial:{protocol}", {"action": "flagged_no_probe"})
                continue
            try:
                tib.breaker.request_service_probe_permission()
                tib.breaker.request_packet_permission(1, "tcp_banner_grab")
            except (TIBViolation, TIBExhausted):
                break

            # --- Banner grab ---
            if port in (443, 8443):
                banner, tls_findings = self._probe_tls(ip, port)
                vuln_findings.extend(tls_findings)
            else:
                probe = PORT_PROBES.get(port, b"")
                banner = self._grab_banner(ip, port, probe)

            if banner:
                new_banners[port] = banner
                self._record_pcf(tib, port, banner[:200], {})

                # Fragile stack detection
                for kw in FRAGILE_BANNER_KEYWORDS:
                    if kw in banner.lower():
                        vuln_findings.append({"type": "fragile_stack", "port": port, "severity": "MEDIUM",
                                              "detail": f"Fragile stack keyword '{kw}' in banner"})
                        break

            # --- Port-specific vulnerability checks ---
            # SSH analysis
            if port == 22 and banner:
                vuln_findings.extend(self._check_ssh(ip, port, banner))

            # HTTP security headers
            if port in (80, 8080, 8443) and banner:
                vuln_findings.extend(self._check_http_headers(ip, port))

            # FTP anonymous login
            if port == 21:
                vuln_findings.extend(self._check_ftp_anonymous(ip, port))

            # Telnet open
            if port == 23:
                vuln_findings.append({"type": "telnet_open", "port": 23, "severity": "CRITICAL",
                                      "detail": "Telnet service running — unencrypted protocol, should be disabled"})

            # Redis no-auth
            if port == 6379 and banner and "redis" in banner.lower():
                vuln_findings.extend(self._check_redis_noauth(ip, port))

            # MongoDB no-auth
            if port == 27017:
                vuln_findings.extend(self._check_mongodb_noauth(ip, port))

            # MQTT no-auth check
            if port == 1883:
                vuln_findings.extend(self._check_mqtt_noauth(ip, port))

            # SNMP community string check
            if port == 161:
                vuln_findings.extend(self._check_snmp_community(ip, port))

            # MySQL version exposure
            if port == 3306 and banner:
                vuln_findings.append({"type": "service_version", "port": port, "severity": "LOW","detail": f"MySQL version exposed: {banner[:80]}"})

            # Server header disclosure (HTTP)
            if port in (80, 8080) and banner:
                for line in banner.split("\r\n"):
                    if line.lower().startswith("server:"):
                        vuln_findings.append({"type": "server_disclosure", "port": port, "severity": "LOW","detail": f"Server header discloses: {line.strip()}"})
                        break
        # Update banners
        if new_banners != tib.signals.banners:
            tib.signals.update_banners(new_banners)

        # Store vulnerability findings in TIB state for report
        if not hasattr(tib.state, 'vuln_findings'):
            tib.state.vuln_findings = []
        tib.state.vuln_findings.extend(vuln_findings)

        if vuln_findings:
            logger.info(f"[Service Probe] {ip}: {len(vuln_findings)} vulnerability findings")

    def _record_pcf(self, tib, port, banner, extra):
        """Record a service probe result as a PCF DAG node."""
        payload = {"ip": tib.device_ip, "port": port, "banner": str(banner)[:200]}
        payload.update(extra)
        self.pcf_dag.add_node(
            node_type=NodeType.SERVICE_PROBE, phase="SERVICE_PROBE",
            payload=payload, parent_ids=[tib.pcf_device_root_id],
            evidence_approaches=EvidenceApproach.ACTIVE, device_ip=tib.device_ip,
        )

    def _grab_banner(self, ip, port, probe, timeout=2.0):
        """Grab a banner from a TCP port, optionally sending a probe payload."""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                if probe:
                    s.sendall(probe.replace(b"target", ip.encode()))
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip()[:500]
        except (socket.timeout, ConnectionRefusedError, OSError):
            return ""

    # -- TLS/SSL Analysis -------------------------------
    def _probe_tls(self, ip, port):
        findings = []
        banner = "HTTPS_OPEN"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    # Protocol version
                    proto = s.version()
                    if proto and ("TLSv1.0" in proto or "TLSv1.1" in proto or "SSLv" in proto):
                        findings.append({"type": "weak_tls", "port": port, "severity": "HIGH", "detail": f"Weak TLS version: {proto} — upgrade to TLS 1.2+"})
                    elif proto:
                        findings.append({"type": "tls_version", "port": port, "severity": "INFO", "detail": f"TLS version: {proto}"})

                    # Cipher suite
                    cipher = s.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        if any(w in cipher_name.upper() for w in ["RC4", "DES", "NULL", "EXPORT"]):
                            findings.append({"type": "weak_cipher", "port": port, "severity": "HIGH", "detail": f"Weak cipher: {cipher_name}"})
                        findings.append({"type": "tls_cipher", "port": port, "severity": "INFO", "detail": f"Cipher: {cipher_name}"})

                    # Certificate analysis
                    cert = s.getpeercert(binary_form=False)
                    if cert:
                        # CN extraction
                        for field in cert.get("subject", []):
                            for key, val in field:
                                if key == "commonName":
                                    banner = f"TLS-CN: {val}"

                        # Expiry check
                        not_after = cert.get("notAfter")
                        if not_after:
                            try:
                                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                if expiry < datetime.now():
                                    findings.append({"type": "cert_expired", "port": port, "severity": "HIGH", "detail": f"SSL certificate EXPIRED on {not_after}"})
                                else:
                                    days = (expiry - datetime.now()).days
                                    if days < 30:
                                        findings.append({"type": "cert_expiring", "port": port, "severity": "MEDIUM", "detail": f"Certificate expires in {days} days"})
                            except ValueError:
                                pass

                        # Self-signed check
                        issuer = cert.get("issuer", ())
                        subject = cert.get("subject", ())
                        if issuer == subject:
                            findings.append({"type": "self_signed", "port": port, "severity": "MEDIUM", "detail": "Self-signed certificate detected"})
                    else:
                        findings.append({"type": "no_cert", "port": port, "severity": "MEDIUM", "detail": "TLS connection succeeded but no certificate presented"})
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
            findings.append({"type": "tls_error", "port": port, "severity": "INFO",
                             "detail": f"TLS probe failed: {type(e).__name__}"})
        return banner, findings

    # -- SSH Analysis ---------------------------------------------------------

    def _check_ssh(self, ip, port, banner):
        findings = []
        bl = banner.lower()
        # Version check
        if "ssh-" in bl:
            findings.append({"type": "ssh_version", "port": port, "severity": "INFO", "detail": f"SSH version: {banner.split(chr(10))[0][:80]}"})
            # Old SSH versions
            if "ssh-1" in bl:
                findings.append({"type": "ssh_v1", "port": port, "severity": "CRITICAL", "detail": "SSH protocol version 1 — vulnerable, upgrade immediately"})
            # Known weak implementations
            if "dropbear" in bl:
                findings.append({"type": "ssh_dropbear", "port": port, "severity": "MEDIUM", "detail": "Dropbear SSH (embedded) — check for known CVEs"})
            # OpenSSH version extraction
            for part in banner.split():
                if part.lower().startswith("openssh"):
                    findings.append({"type": "ssh_openssh_ver", "port": port, "severity": "INFO", "detail": f"OpenSSH detected: {part}"})
                    break
        return findings

    # HTTP Security Headers 
    def _check_http_headers(self, ip, port):
        findings = []
        try:
            with socket.create_connection((ip, port), timeout=2) as s:
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                resp = s.recv(2048).decode("utf-8", errors="replace")

            headers = {}
            for line in resp.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # Missing security headers
            security_headers = {
                "strict-transport-security": ("HSTS", "MEDIUM", "Missing HSTS header — no forced HTTPS"),
                "x-frame-options": ("X-Frame-Options", "LOW", "Missing X-Frame-Options — clickjacking possible"),
                "x-content-type-options": ("X-Content-Type-Options", "LOW", "Missing X-Content-Type-Options"),
                "content-security-policy": ("CSP", "LOW", "Missing Content-Security-Policy header"),
                "x-xss-protection": ("XSS Protection", "LOW", "Missing X-XSS-Protection header"),
            }
            for hdr, (name, sev, detail) in security_headers.items():
                if hdr not in headers:
                    findings.append({"type": f"missing_{hdr.replace('-','_')}", "port": port,
                                     "severity": sev, "detail": detail})

            # Server disclosure
            if "server" in headers:
                findings.append({"type": "http_server_header", "port": port, "severity": "LOW",
                                 "detail": f"HTTP Server header: {headers['server']}"})

            # Powered-by disclosure
            if "x-powered-by" in headers:
                findings.append({"type": "http_powered_by", "port": port, "severity": "LOW",
                                 "detail": f"X-Powered-By disclosed: {headers['x-powered-by']}"})

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return findings

    # -- FTP Anonymous Login ---------------------------------------------------------

    def _check_ftp_anonymous(self, ip, port):
        """Test FTP for anonymous login, then enumerate directory for sensitive files."""
        findings = []
        try:
            with socket.create_connection((ip, port), timeout=3) as s:
                banner = s.recv(512).decode("utf-8", errors="replace")
                if banner:
                    findings.append({"type": "ftp_banner", "port": port, "severity": "INFO", "detail": f"FTP banner: {banner.strip()[:120]}"})

                s.sendall(b"USER anonymous\r\n")
                resp1 = s.recv(512).decode("utf-8", errors="replace")
                if "331" in resp1:
                    s.sendall(b"PASS anonymous@test.com\r\n")
                    resp2 = s.recv(512).decode("utf-8", errors="replace")
                    if "230" in resp2:
                        findings.append({"type": "ftp_anonymous", "port": port, "severity": "HIGH", "detail": "FTP anonymous login ALLOWED — disable anonymous access"})

                        # Enumerate root directory to assess exposure
                        s.sendall(b"PWD\r\n")
                        pwd_resp = s.recv(256).decode("utf-8", errors="replace")

                        # Use PASV + LIST to get directory contents
                        s.sendall(b"PASV\r\n")
                        pasv_resp = s.recv(256).decode("utf-8", errors="replace")
                        if "227" in pasv_resp:
                            # Parse PASV response for data port
                            import re
                            m = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', pasv_resp)
                            if m:
                                data_port = int(m.group(5)) * 256 + int(m.group(6))
                                try:
                                    data_sock = socket.create_connection((ip, data_port), timeout=3)
                                    s.sendall(b"LIST\r\n")
                                    list_data = b""
                                    data_sock.settimeout(2.0)
                                    try:
                                        while True:
                                            chunk = data_sock.recv(4096)
                                            if not chunk:
                                                break
                                            list_data += chunk
                                    except socket.timeout:
                                        pass
                                    data_sock.close()
                                    s.recv(256)  # Consume transfer complete response

                                    listing = list_data.decode("utf-8", errors="replace").strip()
                                    if listing:
                                        file_count = len([l for l in listing.split("\n") if l.strip()])
                                        # Check for sensitive files
                                        sensitive = []
                                        for pattern in ["firmware", "config", "backup", ".bin", ".img", "passwd", "shadow", ".conf", ".key", ".pem"]:
                                            if pattern in listing.lower():
                                                sensitive.append(pattern)
                                        detail = f"FTP anonymous: {file_count} files accessible"
                                        if sensitive:
                                            detail += f" — SENSITIVE FILES: {', '.join(sensitive)}"
                                            findings.append({"type": "ftp_sensitive_files", "port": port, "severity": "CRITICAL", "detail": detail})
                                        else:
                                            findings.append({"type": "ftp_file_listing", "port": port, "severity": "MEDIUM", "detail": detail})
                                except (socket.timeout, ConnectionRefusedError, OSError):
                                    pass
                    else:
                        findings.append({"type": "ftp_anon_denied", "port": port, "severity": "INFO",
                                         "detail": "FTP anonymous login denied (good)"})
                s.sendall(b"QUIT\r\n")
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return findings

    # -- Redis No-Auth ------------------------------------------------

    def _check_redis_noauth(self, ip, port):
        """Test Redis for unauthenticated access, then enumerate server info, config exposure, and database size."""
        findings = []
        try:
            with socket.create_connection((ip, port), timeout=2) as s:
                # Test PING for basic connectivity
                s.sendall(b"PING\r\n")
                resp = s.recv(256).decode("utf-8", errors="replace")
                if "+PONG" in resp:
                    findings.append({"type": "redis_noauth", "port": port, "severity": "CRITICAL", "detail": "Redis accessible WITHOUT authentication — requires immediate remediation"})
                    # Gather server info to assess exposure severity
                    s.sendall(b"INFO server\r\n")
                    info_resp = b""
                    s.settimeout(1.0)
                    try:
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            info_resp += chunk
                            if len(info_resp) > 8192:
                                break
                    except socket.timeout:
                        pass
                    info_text = info_resp.decode("utf-8", errors="replace")
                    # Extract key server details
                    redis_version = ""
                    os_info = ""
                    for line in info_text.split("\r\n"):
                        if line.startswith("redis_version:"):
                            redis_version = line.split(":", 1)[1].strip()
                        elif line.startswith("os:"):
                            os_info = line.split(":", 1)[1].strip()
                    if redis_version:
                        findings.append({"type": "redis_version", "port": port, "severity": "MEDIUM", "detail": f"Redis version: {redis_version} (OS: {os_info})"})

                    # Check if CONFIG is accessible (can read/write server config)
                    s.sendall(b"CONFIG GET dir\r\n")
                    try:
                        cfg_resp = s.recv(1024).decode("utf-8", errors="replace")
                        if "dir" in cfg_resp.lower() and "-ERR" not in cfg_resp:
                            findings.append({"type": "redis_config_exposed", "port": port, "severity": "CRITICAL", "detail": f"Redis CONFIG command accessible — server directory writable: {cfg_resp.strip()[:120]}"})
                    except socket.timeout:
                        pass

                    # Check number of databases/keys
                    s.sendall(b"DBSIZE\r\n")
                    try:
                        db_resp = s.recv(256).decode("utf-8", errors="replace")
                        if ":" in db_resp:
                            key_count = db_resp.strip().split(":")[1] if ":" in db_resp else db_resp
                            findings.append({"type": "redis_db_size", "port": port, "severity": "INFO", "detail": f"Redis database has {key_count.strip()} keys"})
                    except socket.timeout:
                        pass

                elif "-NOAUTH" in resp or "Authentication required" in resp.lower():
                    findings.append({"type": "redis_auth_required", "port": port, "severity": "INFO", "detail": "Redis requires authentication (good)"})
                s.sendall(b"QUIT\r\n")
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return findings

    # -- MongoDB No-Auth --------------------------------------------------------

    def _check_mongodb_noauth(self, ip, port):
        """Check MongoDB for unauthenticated access using the wire protocol."""
        import struct
        findings = []
        try:
            with socket.create_connection((ip, port), timeout=3) as s:
                # Build a MongoDB OP_MSG (opcode 2013) with ismaster command.
                bson_doc = (
                    b"\x13\x00\x00\x00"   # document size (19 bytes)
                    b"\x10"                # int32 type
                    b"ismaster\x00"        # field name
                    b"\x01\x00\x00\x00"   # value = 1
                    b"\x00"                # document terminator
                )

                # OP_MSG header
                flag_bits = b"\x00\x00\x00\x00"  # no flags
                section_kind = b"\x00"            # body section
                payload = flag_bits + section_kind + bson_doc

                # MsgHeader: length(4) + requestID(4) + responseTo(4) + opCode(4)
                request_id = b"\x01\x00\x00\x00"
                response_to = b"\x00\x00\x00\x00"
                op_code = b"\xdd\x07\x00\x00"     # 2013 = OP_MSG

                msg_len = 16 + len(payload)
                header = struct.pack("<I", msg_len) + request_id + response_to + op_code
                full_msg = header + payload

                s.sendall(full_msg)
                s.settimeout(2.0)

                # Read response header (16 bytes)
                resp_header = b""
                while len(resp_header) < 16:
                    chunk = s.recv(16 - len(resp_header))
                    if not chunk:
                        break
                    resp_header += chunk

                if len(resp_header) >= 16:
                    resp_len = struct.unpack("<I", resp_header[:4])[0]
                    # Read remaining response body
                    remaining = resp_len - 16
                    resp_body = b""
                    while len(resp_body) < remaining and remaining < 65536:
                        chunk = s.recv(min(4096, remaining - len(resp_body)))
                        if not chunk:
                            break
                        resp_body += chunk

                    resp_text = resp_body.decode("utf-8", errors="replace")

                    # Check for success indicators in the BSON response
                    if "ismaster" in resp_text.lower() or "maxWireVersion" in resp_text:
                        findings.append({"type": "mongodb_noauth", "port": port, "severity": "CRITICAL", "detail": "MongoDB accessible WITHOUT authentication — ismaster command succeeded"})
                        # Extract version if present
                        if "version" in resp_text.lower():
                            # Try to find version string in BSON response
                            for segment in resp_text.split("\x00"):
                                if segment and any(c.isdigit() for c in segment) and "." in segment:
                                    clean = segment.strip()
                                    if len(clean) < 20 and clean[0].isdigit():
                                        findings.append({"type": "mongodb_version", "port": port, "severity": "MEDIUM", "detail": f"MongoDB version: {clean}"})
                                        break
                    elif "auth" in resp_text.lower() or "unauthorized" in resp_text.lower():
                        findings.append({"type": "mongodb_auth_required", "port": port, "severity": "INFO", "detail": "MongoDB requires authentication (good)"})
                    elif resp_body:
                        findings.append({"type": "mongodb_responds", "port": port, "severity": "HIGH", "detail": "MongoDB responds to wire protocol — check authentication settings"})
        except (socket.timeout, ConnectionRefusedError, OSError, struct.error):
            pass
        return findings

    # -- MQTT No-Auth ---------------------------------------------------

    def _check_mqtt_noauth(self, ip, port):
        """Test MQTT broker for unauthenticated access using CONNECT packet."""
        findings = []
        try:
            with socket.create_connection((ip, port), timeout=3) as s:
                # MQTT CONNECT packet (protocol MQTT 3.1.1, clean session, no creds)
                client_id = b"TRUCE_PROBE"
                var_header = (
                    b"\x00\x04MQTT"     # Protocol Name
                    b"\x04"             # Protocol Level (3.1.1)
                    b"\x02"             # Connect Flags (clean session)
                    b"\x00\x3c"         # Keep Alive (60s)
                )
                payload = len(client_id).to_bytes(2, "big") + client_id
                remaining = len(var_header) + len(payload)
                packet = b"\x10" + bytes([remaining]) + var_header + payload

                s.sendall(packet)
                s.settimeout(3.0)
                resp = s.recv(256)
                if len(resp) >= 4 and resp[0] == 0x20:
                    return_code = resp[3]
                    if return_code == 0x00:
                        findings.append({"type": "mqtt_noauth", "port": port, "severity": "CRITICAL",
                                         "detail": "MQTT broker accepts connections WITHOUT authentication"})
                        # Try subscribing to wildcard to assess exposure
                        # SUBSCRIBE packet to topic '#' (all topics)
                        sub_packet = (
                            b"\x82"             # SUBSCRIBE
                            b"\x09"             # Remaining length
                            b"\x00\x01"         # Packet ID
                            b"\x00\x01" b"#"    # Topic filter '#' (wildcard)
                            b"\x00"             # QoS 0
                        )
                        s.sendall(sub_packet)
                        try:
                            sub_resp = s.recv(256)
                            if len(sub_resp) >= 5 and sub_resp[0] == 0x90:
                                # SUBACK received
                                if sub_resp[4] != 0x80:
                                    findings.append({"type": "mqtt_wildcard_subscribe", "port": port,
                                                     "severity": "CRITICAL",
                                                     "detail": "MQTT wildcard subscribe (#) ALLOWED — all messages readable"})
                                else:
                                    findings.append({"type": "mqtt_wildcard_denied", "port": port,
                                                     "severity": "MEDIUM",
                                                     "detail": "MQTT connected but wildcard subscribe denied (ACL active)"})
                        except socket.timeout:
                            pass
                    elif return_code == 0x05:
                        findings.append({"type": "mqtt_auth_required", "port": port, "severity": "INFO",
                                         "detail": "MQTT broker requires authentication (good)"})
                    elif return_code == 0x04:
                        findings.append({"type": "mqtt_bad_creds", "port": port, "severity": "INFO",
                                         "detail": "MQTT broker rejects empty credentials (good)"})
                # Send DISCONNECT
                s.sendall(b"\xe0\x00")
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return findings

    # -- SNMP Community String Check -----------------------------------------
    def _check_snmp_community(self, ip, port):
        """Test common SNMP community strings via real UDP SNMP GET requests."""
        findings = []
        communities = ["public", "private"]
        for community in communities:
            try:
                community_bytes = community.encode("ascii")
                community_len = len(community_bytes)
                pdu = bytes([
                    0xa0, 0x19,
                    0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
                    0x30, 0x0e, 0x30, 0x0c,
                    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
                    0x05, 0x00,
                ])
                inner = bytes([0x02, 0x01, 0x01]) + \
                        bytes([0x04, community_len]) + community_bytes + pdu
                packet = bytes([0x30, len(inner)]) + inner

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                sock.sendto(packet, (ip, 161))
                data, _ = sock.recvfrom(4096)
                sock.close()
                if len(data) > 20:
                    severity = "CRITICAL" if community == "private" else "HIGH"
                    access_type = "READ-WRITE" if community == "private" else "READ"
                    findings.append({"type": f"snmp_{community}_community", "port": port, "severity": severity, "detail": f"SNMP community '{community}' accepted — {access_type} access to MIB"})
                    # Extract sysDescr from response for context
                    i = 0
                    while i < len(data) - 2:
                        if data[i] == 0x04:
                            slen = data[i + 1]
                            if i + 2 + slen <= len(data) and slen > 3:
                                val = data[i + 2:i + 2 + slen].decode("utf-8", errors="replace")
                                if len(val) > 5:
                                    findings.append({"type": "snmp_sysdescr", "port": port, "severity": "INFO", "detail": f"SNMP sysDescr via '{community}': {val[:120]}"})
                                    break
                            i += 2 + slen
                        else:
                            i += 1
            except socket.timeout:
                continue
            except (OSError, Exception):
                continue
        return findings

    def grab_tls_cn(self, ip, port, timeout=3.0):
        """Extract the TLS certificate Common Name from an HTTPS port."""
        banner, _ = self._probe_tls(ip, port)
        return banner
