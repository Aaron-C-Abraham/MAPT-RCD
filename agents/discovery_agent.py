"""
agents/discovery_agent.py — Discovery Agent (Phases 0-1).

PURPOSE:
    The Discovery Agent is the FIRST agent in the 9-step pipeline. It finds
    hosts on the target network(s) using two phases:

      Phase 0 (Passive Recon):
        Listens for broadcast/multicast traffic (mDNS, SSDP, DHCP, NetBIOS)
        without sending any packets. Zero interaction with targets.

      Phase 1 (Active Host Discovery):
        Sends ARP/ICMP/TCP probes to discover live hosts. Uses the OUI
        database to identify device vendors from MAC addresses.

INTER-AGENT COMMUNICATION:
    After discovering hosts, this agent sends a RESULT message to the
    TargetProfilingAgent, signaling that devices are ready for fingerprinting
    and tier assignment. The payload includes the device count and whether
    the session is passive-only.

    DiscoveryAgent ──RESULT──> TargetProfilingAgent
      payload: { phase: "discovery", device_count: N, [passive_only: bool] }

OUTPUTS:
    - Devices registered in SessionContext.devices (IP -> TIBManager).
    - Passive findings (mDNS services, SSDP headers, DHCP fingerprints,
      NetBIOS presence) applied to each device's TIB signal store.
    - Discovery nodes added to the PCF DAG for evidence tracking.

Paper reference: Section VI-B item 1
"""

import logging
from agents.base import BaseAgent, AgentRole, AgentResult, MessageType
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)


class DiscoveryAgent(BaseAgent):
    """
    Agent responsible for host discovery (Phases 0 and 1).

    Wraps the PassiveReconPhase and HostDiscoveryPhase modules, registering
    every discovered device in the SessionContext so downstream agents
    (TargetProfiling, Planner, etc.) can operate on them.
    """

    def __init__(self, context: SessionContext):
        # Initialize with the DISCOVERY role — this determines the agent's
        # message bus queue address.
        super().__init__(AgentRole.DISCOVERY, context)

    def execute(self) -> AgentResult:
        """
        Run Phase 0 (passive) and Phase 1 (active) discovery.
        Register discovered devices in SessionContext.

        FLOW:
            1. Start Phase 0 passive listener (background sniffer).
            2. If passive_only mode: wait for traffic, register devices, stop.
            3. Otherwise: run Phase 1 active scan, register active hosts.
            4. Merge passive-only hosts not found by active scan.
            5. Apply passive findings (mDNS, SSDP, DHCP, NetBIOS) to TIBs.
            6. Notify TargetProfilingAgent that discovery is complete.

        Returns:
            AgentResult with discovered device count and any errors.
        """
        # Lazy imports to avoid circular dependencies and keep the import
        # footprint small when the module is loaded but not executed.
        from TIB_and_PCF.PCF import NodeType, EvidenceApproach
        from TIB_and_PCF.TIB.TIB_structures import PentestPhase
        from Discovery.passive_listener import PassiveReconPhase
        from Discovery.active_discovery import ActiveDiscoveryPhase

        errors = []          # Collect non-fatal errors across both phases
        discovered_count = 0  # Running total of devices registered

        # Helper for progress output
        def _p(msg):
            self.context.progress(f"           {msg}")

        # ── Phase 0: Passive recon ───────────────────────────────────────────
        _p("Phase 0: Starting passive listeners (mDNS, SSDP, DHCP, NetBIOS)...")
        try:
            phase0 = PassiveReconPhase(
                self.context.pcf_dag, self.context.session_root_id
            )
            phase0.start()
        except Exception as e:
            errors.append(f"Phase 0 error: {e}")
            phase0 = None

        # ── Passive-only mode ────────────────────────────────────────────────
        # If the operator requested passive-only scanning, we wait for the
        # sniffer to accumulate data, then register whatever hosts we observed.
        if self.context.passive_only and phase0:
            import time
            last_count, idle = 0, 0
            # Poll every 5 seconds until we see no new IPs for 30 seconds,
            # indicating the passive listener has likely captured all
            # reachable broadcast/multicast traffic.
            while idle < 30:
                time.sleep(5)
                current = len(phase0.get_known_ips())
                if current > last_count:
                    last_count = current  # New hosts appeared — reset idle counter
                    idle = 0
                else:
                    idle += 5  # No new hosts — increment idle timer
            phase0.stop()  # Stop the background sniffer

            # Register every passively-discovered IP as a device
            for ip in phase0.get_known_ips():
                self.context.register_device(ip, discovery_method="passive")
                discovered_count += 1

            # Notify the TargetProfilingAgent that passive discovery is done
            self.send_message(
                AgentRole.TARGET_PROFILING, MessageType.RESULT,
                {"phase": "discovery", "device_count": discovered_count,
                 "passive_only": True},
            )
            return AgentResult(success=True, data={"discovered": discovered_count},
                               errors=errors)

        # ── Phase 1: Active discovery ────────────────────────────────────────
        _p("Phase 1: Active host discovery (ICMP ping → ARP → TCP connect)...")
        try:
            phase1 = ActiveDiscoveryPhase(
                oui_db=self.context.oui_db,
                pcf_dag=self.context.pcf_dag,
                session_root_id=self.context.session_root_id,
            )
            phase1._progress_cb = self.context.progress_cb  # Wire progress
            hosts = phase1.run(self.context.networks)
            _p(f"Phase 1: {len(hosts)} hosts discovered")

            for host in hosts:
                # If the HostDiscoveryPhase didn't resolve the vendor, try
                # the OUI database as a fallback.
                vendor = host.vendor
                if vendor == "Unknown" and self.context.oui_db and host.mac:
                    vendor = self.context.oui_db.lookup(host.mac)

                # Register the device in the session context. This creates
                # a TIBManager and a PCF DISCOVERY node for the device.
                tib = self.context.register_device(
                    ip=host.ip, mac=host.mac, vendor=vendor,
                    discovery_method=host.discovery_method,
                    pcf_parent_id=host.pcf_node_id or "",
                )

                # Apply hostname from discovery (reverse DNS or NetBIOS)
                if host.hostname:
                    tib.signals.reverse_dns = host.hostname
                    # Also use as device name if no mDNS name was found
                    if not tib.signals.mdns_device_name:
                        tib.signals.mdns_device_name = host.hostname

                # Advance the device's phase state machine to ACTIVE_DISCOVERY
                tib.transition_phase(PentestPhase.ACTIVE_DISCOVERY)
                discovered_count += 1

        except Exception as e:
            import traceback
            self.logger.error(f"Phase 1 error: {e}\n{traceback.format_exc()}")
            errors.append(f"Phase 1 error: {e}")

        # ── Merge passive-only devices ───────────────────────────────────────
        # Some devices may have been seen by the passive sniffer (Phase 0)
        # but NOT by the active scan (Phase 1) — for example, devices that
        # don't respond to ARP/ICMP but do send mDNS announcements.
        # Register them now so they are not lost.
        if phase0:
            try:
                # Get the set of IPs already registered by the active scan
                active_ips = {tib.device_ip for tib in self.context.all_tibs()}
                # Retrieve all passive findings (mDNS, SSDP, DHCP, NetBIOS)
                findings = phase0.get_findings()

                # Register any passive-only IPs that weren't found actively
                for ip in phase0.get_known_ips():
                    if ip not in active_ips:
                        self.context.register_device(ip, discovery_method="passive")
                        discovered_count += 1

                # ── Apply passive findings to TIBs ───────────────────────────
                # Enrich each device's signal store with data gathered by the
                # background sniffer. This data feeds into the TIB classifier
                # during Phase 3 (TIB assignment).

                # mDNS services: e.g., _http._tcp, _ipp._tcp (printers, IoT)
                for ip, services in findings.mdns.items():
                    tib = self.context.get_device(ip)
                    if tib and services:
                        tib.signals.update_mdns_services(services)

                # mDNS device names: e.g., "John's iPhone", "Living Room TV"
                for ip, name in findings.mdns_names.items():
                    tib = self.context.get_device(ip)
                    if tib and name:
                        tib.signals.update_mdns_device_name(name)

                # SSDP Server headers: reveals UPnP device descriptions
                for ip, server_hdr in findings.ssdp.items():
                    tib = self.context.get_device(ip)
                    if tib and server_hdr:
                        # Store as a pseudo-banner on port 1900 (SSDP port)
                        existing = dict(tib.signals.banners)
                        existing[1900] = f"SSDP-SERVER: {server_hdr}"
                        tib.signals.update_banners(existing)

                # DHCP option 55 fingerprint: parameter request list that
                # uniquely identifies device types (similar to browser UA)
                for ip, opt55 in findings.dhcp.items():
                    tib = self.context.get_device(ip)
                    if tib and opt55:
                        tib.signals.update_dhcp_fingerprint(opt55)

                # NetBIOS presence: indicates a Windows/SMB-capable device
                for ip in findings.netbios:
                    tib = self.context.get_device(ip)
                    if tib:
                        tib.signals.update_netbios_present(True)

                # Stop the background sniffer now that we've extracted findings
                phase0.stop()
            except Exception as e:
                errors.append(f"Passive findings error: {e}")

        # ── Phase 1.5: Active Protocol Discovery ────────────────────────────
        # Use application-layer protocols (mDNS, SSDP, WSD) to identify
        # devices that don't respond to TCP/ICMP probes. This is the key
        # technique for discovering phones, tablets, smart TVs, and other
        # consumer devices that firewall incoming connections.
        _p("Phase 1.5: Active protocol discovery (mDNS, SSDP, WSD)...")
        try:
            from Discovery.protocol_scanner import ProtocolScanner
            scanner = ProtocolScanner(
                pcf_dag=self.context.pcf_dag,
                session_root_id=self.context.session_root_id,
            )

            _p("  → mDNS browse (Apple, Chromecast, printers, smart speakers)...")
            mdns_results = scanner.scan_mdns(timeout=5)
            for ip, info in mdns_results.items():
                tib = self.context.get_device(ip)
                if not tib:
                    # mDNS discovered a device not found by ICMP/ARP/TCP
                    tib = self.context.register_device(ip, discovery_method="mdns_active")
                    discovered_count += 1
                if info.get("services"):
                    existing_svcs = list(tib.signals.mdns_services)
                    for svc in info["services"]:
                        if svc not in existing_svcs:
                            existing_svcs.append(svc)
                    tib.signals.update_mdns_services(existing_svcs)
                if info.get("device_name") and not tib.signals.mdns_device_name:
                    tib.signals.update_mdns_device_name(info["device_name"])
                if info.get("os_hint") and not tib.signals.nmap_os_guess:
                    tib.signals.nmap_os_guess = info["os_hint"]
                if info.get("device_type") and not tib.signals.device_type:
                    tib.signals.device_type = info["device_type"]

            for ip, info in mdns_results.items():
                name = info.get("device_name", "")
                svcs = info.get("services", [])
                _p(f"    mDNS: {ip} — {name or 'unnamed'} ({len(svcs)} services)")

            _p("  → SSDP M-SEARCH (TVs, routers, game consoles, DLNA)...")
            ssdp_results = scanner.scan_ssdp(timeout=5)
            for ip, info in ssdp_results.items():
                tib = self.context.get_device(ip)
                if not tib:
                    tib = self.context.register_device(ip, discovery_method="ssdp_active")
                    discovered_count += 1
                # Store SSDP info as a rich banner on port 1900
                ssdp_parts = [p for p in [
                    info.get("manufacturer"), info.get("model"),
                    info.get("description"), info.get("server_header"),
                ] if p]
                if ssdp_parts:
                    existing = dict(tib.signals.banners)
                    existing[1900] = "SSDP: " + " | ".join(ssdp_parts)
                    tib.signals.update_banners(existing)
                if info.get("device_name") and not tib.signals.mdns_device_name:
                    tib.signals.update_mdns_device_name(info["device_name"])

            for ip, info in ssdp_results.items():
                name = info.get("device_name") or info.get("model") or info.get("server_header") or ""
                _p(f"    SSDP: {ip} — {name[:50]}")

            _p("  → WSD probe (Windows PCs, network printers)...")
            wsd_results = scanner.scan_wsd(timeout=3)
            for ip, info in wsd_results.items():
                tib = self.context.get_device(ip)
                if not tib:
                    tib = self.context.register_device(ip, discovery_method="wsd")
                    discovered_count += 1
                if info.get("device_type") and not tib.signals.device_type:
                    tib.signals.device_type = info["device_type"]
                # WSD response confirms it's a Windows device
                if not tib.signals.nmap_os_guess:
                    tib.signals.nmap_os_guess = "Windows"
                tib.signals.update_netbios_present(True)

            for ip, info in wsd_results.items():
                _p(f"    WSD:  {ip} — {info.get('device_type', 'Windows Device')}")

            _p(f"Phase 1.5 complete: mDNS={len(mdns_results)} SSDP={len(ssdp_results)} WSD={len(wsd_results)}")
        except Exception as e:
            self.logger.error(f"Protocol discovery error: {e}")
            errors.append(f"Protocol discovery error: {e}")

        # ── Notify TargetProfilingAgent ──────────────────────────────────────
        # Send a RESULT message so the profiling agent knows discovery is
        # complete and can proceed with fingerprinting (Phase 2).
        self.send_message(
            AgentRole.TARGET_PROFILING, MessageType.RESULT,
            {"phase": "discovery", "device_count": discovered_count},
        )

        return AgentResult(
            success=discovered_count > 0,  # Fail if we found zero devices
            data={"discovered": discovered_count},
            errors=errors,
            actions_taken=discovered_count,  # Each registered device = one action
        )
