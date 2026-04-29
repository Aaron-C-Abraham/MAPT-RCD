"""
agents/session_context.py — Shared state for all agents in a TRUCE-PT session.

PURPOSE:
    SessionContext is the SINGLE SOURCE OF TRUTH for the entire engagement.
    Every agent receives a reference to the same SessionContext at construction
    time, and all reads/writes go through it. This avoids agents holding
    inconsistent local copies of session state.

WHAT IT HOLDS:
    - networks          : Target CIDR ranges for the engagement.
    - pcf_dag           : The Proof-Carrying Findings DAG (cryptographic evidence chain).
    - tool_registry     : IC-ToolSpec registry of available scanning tools.
    - message_bus       : In-process pub/sub bus for inter-agent communication.
    - devices           : Dict mapping IP -> TIBManager (per-device state machine).
    - ptg_graphs        : Dict mapping IP -> PTGGraph (per-device attack plan).
    - fleet_clusters    : Dict holding fleet clustering results for probe reduction.
    - safety/OT flags   : Whether safety officer is active, OT mode enabled.
    - session metrics   : Counters for findings, validations, instabilities, vetoes.

CROSS-DEVICE STRESS CORRELATION:
    When a device is re-tiered (e.g., from STANDARD to FRAGILE due to stress),
    the _on_device_retier callback checks whether multiple devices on the same
    /24 subnet are simultaneously stressed. If so, it triggers a subnet-wide
    rate-limit backoff to protect the entire network segment.

Holds references to all subsystems: TIB managers, PCF DAG, PTG graphs,
IC-ToolSpec registry, fleet state, RAG store, and the message bus.
"""

import time
import logging
from typing import Dict, List, Optional

# TIB/PCF models and managers — core data structures for device classification
from TIB_and_PCF.TIB.TIB_structures import DeviceTier, CircuitBreakerStatus
from TIB_and_PCF.PCF import PCFDAG,NodeType, EvidenceApproach                     # Proof-Carrying Findings DAG
from TIB_and_PCF.TIB.device_TIB_manager import TIBManager          # Per-device state machine
from TIB_and_PCF.TIB.device_classifier import OUIDatabase           # MAC-to-vendor lookup
from IC_ToolSpec.registry import ToolSpecRegistry    # Registry of available scanning tools
from ptg.graph import PTGGraph                       # Per-Target Graph (attack plan per device)
# MessageBus is imported lazily in __init__ to avoid circular import
# (agents.base imports SessionContext, SessionContext imports MessageBus)

logger = logging.getLogger(__name__)


class SessionContext:
    """
    Shared context for a TRUCE-PT engagement session.

    All agents read from and write to this context. It is the single
    source of truth for session state.

    LIFECYCLE:
        1. Created by run_agent_scan() or directly by the caller.
        2. Passed to the AgentCoordinator, which passes it to every agent.
        3. Agents register devices, build PTGs, record PCF nodes, and update
           metrics through this object.
        4. After the session, the Coordinator reads final metrics from here.
    """

    def __init__(
        self,
        networks: List[str],              # Target CIDR ranges (e.g., ["192.168.1.0/24"])
        oui_db: Optional[OUIDatabase] = None,  # Optional MAC vendor database
        passive_only: bool = False,        # If True, skip active scanning entirely
        max_threads: int = 10,             # Max concurrency for threaded scan phases
        output_dir: str = "",              # Directory for output files (results, PCF, reports)
        exploit_all: bool = False,         # If True, force exploitation on ALL devices
    ):
        # Store constructor parameters as instance state
        self.networks = networks           # CIDR ranges to scan
        self.oui_db = oui_db               # OUI database for MAC-to-vendor resolution
        self.passive_only = passive_only   # Flag: restrict to passive recon only
        self.max_threads = max_threads     # Thread pool ceiling for concurrent scanning
        self.output_dir = output_dir       # Output directory for all generated files
        self.exploit_all = exploit_all     # --exploit-all: force exploitation on every device
        self.start_time = time.time()      # Session start timestamp for duration tracking
        self.progress_cb = None            # Progress callback — set by coordinator

        # ── Core subsystems ──────────────────────────────────────────────────
        # PCF DAG: directed acyclic graph that records every probe, finding,
        # and validation with cryptographic hashes for tamper-evident evidence.
        self.pcf_dag = PCFDAG()

        # IC-ToolSpec registry: catalog of all available tools with their
        # contracts (preconditions, postconditions, budget cost, risk tier).
        self.tool_registry = ToolSpecRegistry()

        # Message bus: in-process pub/sub for inter-agent communication.
        # Each AgentRole has its own queue; agents push messages to recipients.
        from agents.base import MessageBus
        self.message_bus = MessageBus()

        # ── Device registry ──────────────────────────────────────────────────
        # Maps device IP -> TIBManager. Each TIBManager encapsulates a single
        # device's tier, signals (open ports, banners, OS guess, etc.), circuit
        # breaker state, budget, and phase transitions.
        self.devices: Dict[str, TIBManager] = {}

        # ── PTG graphs ───────────────────────────────────────────────────────
        # Maps device IP -> PTGGraph. A PTG is the per-device attack plan
        # (a DAG of tool invocations) built by the PlannerAgent.
        self.ptg_graphs: Dict[str, PTGGraph] = {}

        # ── Fleet state ──────────────────────────────────────────────────────
        # Stores clustering results from the FleetReasonerAgent. Keys are
        # either cluster_ids (mapping to full cluster dicts) or device IPs
        # (mapping to their cluster membership).
        self.fleet_clusters: Dict[str, dict] = {}

        # ── Session-level PCF root node ──────────────────────────────────────
        # Create the root node of the PCF DAG for this session. All device
        # discovery nodes will be children of this root, establishing the
        # top-level provenance chain.
        self.session_root_id = self.pcf_dag.add_node(
            node_type=NodeType.SESSION,       # Root node type for the whole session
            phase="INIT",                     # Session initialization phase
            payload={
                "networks": networks,         # Record which networks were targeted
                "start_time": time.strftime("%Y-%m-%dT%H:%M:%S"),  # Human-readable start
                "passive_only": passive_only, # Record the scanning mode
            },
            evidence_approaches=EvidenceApproach.PASSIVE, # No active probing at session init
        )

        # ── Safety officer state ─────────────────────────────────────────────
        # safety_officer_active: set to True by TargetProfilingAgent when any
        # CRITICAL-tier device is detected. When active, the SafetyOfficer
        # reviews all pending PTG nodes before the ToolOrchestrator executes.
        self.safety_officer_active = False

        # ot_mode: Operational Technology mode — set when industrial/SCADA
        # devices are found. Enables stricter safety constraints (e.g., no
        # Tier 3 actions on CRITICAL devices, preflight checks for Tier 2).
        self.ot_mode = False

        # ── Session-level metrics ────────────────────────────────────────────
        # These counters are incremented by various agents during the session
        # and read by the Coordinator at finalization time for the summary.
        self.total_findings = 0       # All findings discovered (any confidence)
        self.validated_findings = 0   # Findings that passed validation oracles
        self.instability_events = 0   # Cross-device stress correlation events
        self.vetoed_actions = 0       # Actions blocked by SafetyOfficer or ImpactMonitor

    def progress(self, msg: str) -> None:
        """Emit a progress message if a callback is registered."""
        if self.progress_cb:
            self.progress_cb(msg)

    # ── Device management ──────────────────────────────────────────────────────

    def register_device(self, ip: str, mac: str = "",
                        vendor: str = "Unknown",
                        discovery_method: str = "active",
                        pcf_parent_id: str = "") -> TIBManager:
        """
        Register a discovered device and create its TIBManager.

        Called by the DiscoveryAgent for each host found during Phase 0/1.
        If the device is already registered (duplicate IP), returns the
        existing TIBManager without creating a new one (idempotent).

        This method:
          1. Creates a DISCOVERY node in the PCF DAG (evidence of how the
             device was found).
          2. Instantiates a TIBManager with the device's IP, MAC, and a
             callback for cross-device stress correlation.
          3. Sets the OUI vendor on the TIB's signals.
          4. Stores the TIBManager in self.devices[ip].

        Args:
            ip               — Device IP address (used as the unique key).
            mac              — Device MAC address (may be empty for remote hosts).
            vendor           — Vendor name from OUI database lookup.
            discovery_method — How the device was found ("active" or "passive").
            pcf_parent_id    — PCF node ID of the discovery action that found
                               this device. Defaults to session_root_id.

        Returns:
            The TIBManager for this device (new or existing).
        """
        # Idempotency: if the device is already registered, return existing TIB
        if ip in self.devices:
            return self.devices[ip]

        # Determine the parent node in the PCF DAG. If the caller provided a
        # specific parent (e.g., from a Phase 1 scan result), use that;
        # otherwise, hang the device off the session root.
        parent_ids = [pcf_parent_id] if pcf_parent_id else [self.session_root_id]

        # Create a DISCOVERY node in the PCF DAG recording how this device
        # was found. This establishes the start of the evidence chain for
        # everything we subsequently learn about this device.
        device_root_id = self.pcf_dag.add_node(
            node_type=NodeType.DISCOVERY,
            phase="HOST_DISCOVERY",
            payload={"ip": ip, "mac": mac, "vendor": vendor,
                     "method": discovery_method},
            parent_ids=parent_ids,
            evidence_approaches=EvidenceApproach.ACTIVE,  # Device discovery is an active observation
            device_ip=ip,
        )

        # Create the TIBManager (Target Intelligence Brief) for this device.
        # The TIBManager holds:
        #   - Device tier (STANDARD, FRAGILE, CRITICAL, etc.)
        #   - Signal store (open ports, banners, OS guesses, etc.)
        #   - Circuit breaker state (rate limiting, budget tracking)
        #   - Phase state machine (which pentest phase the device is in)
        # The retier callback enables cross-device stress correlation.
        tib = TIBManager(
            device_ip=ip,
            device_mac=mac,
            session_retier_callback=self._on_device_retier,  # Cross-device stress hook
            pcf_dag=self.pcf_dag,
            pcf_device_root_id=device_root_id,  # Link TIB to its PCF root
        )
        # Set the vendor from OUI lookup on the TIB's signal store
        tib.signals.oui_vendor = vendor

        # Store in the device registry — all other agents access devices via this dict
        self.devices[ip] = tib
        logger.info(f"[SessionContext] Registered device {ip} ({mac}) vendor={vendor}")
        return tib

    def get_device(self, ip: str) -> Optional[TIBManager]:
        """Look up a device's TIBManager by IP. Returns None if not registered."""
        return self.devices.get(ip)

    def all_tibs(self) -> List[TIBManager]:
        """Return a list of all registered TIBManagers (all devices)."""
        return list(self.devices.values())

    def tibs_by_tier(self, tier: DeviceTier) -> List[TIBManager]:
        """
        Filter devices by their current tier classification.

        Used by the Coordinator for tier summaries, by the SafetyOfficer to
        find CRITICAL devices, and by ImpactMonitor to identify stressed devices.
        """
        return [t for t in self.devices.values() if t.tier == tier]

    # ── PTG management ─────────────────────────────────────────────────────────

    def set_ptg(self, ip: str, graph: PTGGraph) -> None:
        """Store a Per-Target Graph (PTG) for a device. Called by PlannerAgent."""
        self.ptg_graphs[ip] = graph

    def get_ptg(self, ip: str) -> Optional[PTGGraph]:
        """Retrieve the PTG for a device. Returns None if no PTG was built."""
        return self.ptg_graphs.get(ip)

    # ── Cross-device stress correlation ────────────────────────────────────────

    # If 3+ devices on the same /24 subnet have stress events within a short
    # window, we treat it as a subnet-wide issue and reduce probing intensity
    # across the entire subnet. This prevents cascading failures.
    _STRESS_THRESHOLD = 3       # Minimum stressed devices to trigger subnet backoff
    _STRESS_WINDOW_SEC = 60.0   # Time window (not currently used but reserved)
    _last_backoff_time = 0.0    # Cooldown to avoid rapid-fire backoff adjustments

    def _on_device_retier(self, device_ip: str,
                          old_tier: DeviceTier,
                          new_tier: DeviceTier) -> None:
        """
        Cross-device stress correlation callback.

        WHEN IS THIS CALLED?
            The TIBManager calls this whenever a device's tier changes (e.g.,
            from STANDARD to FRAGILE). It is registered as the
            session_retier_callback in register_device().

        WHAT DOES IT DO?
            1. Ignores downgrades (new_tier <= old_tier) — only upgrades
               (towards more restrictive tiers) indicate stress.
            2. Enforces a 30-second cooldown to prevent thrashing.
            3. Counts how many devices on the same /24 subnet have stress.
            4. If >= 3 devices are stressed, halves the rate limit on all
               active devices in that subnet (minimum 10% of max).

        WHY?
            A single stressed device might be a local issue, but multiple
            stressed devices on the same subnet likely indicates we are
            overloading a shared resource (switch, gateway, etc.).
        """
        # Only care about tier upgrades (more restrictive = higher stress)
        if new_tier.value <= old_tier.value:
            return

        now = time.time()
        # Cooldown: don't trigger another backoff within 30 seconds
        if now - self._last_backoff_time < 30.0:
            return

        # Extract the /24 subnet prefix from the IP address
        parts = device_ip.split(".")
        if len(parts) != 4:
            return  # Not a valid IPv4 address — skip
        subnet = ".".join(parts[:3])  # e.g., "192.168.1" from "192.168.1.42"

        # Count how many devices on this subnet have experienced stress
        stressed = [
            ip for ip, tib in self.devices.items()
            if ip.startswith(subnet + ".") and tib.state.stress_events > 0
        ]

        # If enough devices are stressed, trigger subnet-wide rate reduction
        if len(stressed) >= self._STRESS_THRESHOLD:
            self.instability_events += 1  # Increment session-level metric
            logger.warning(
                f"[SessionContext] Subnet {subnet}.0/24 correlated stress: "
                f"{len(stressed)} devices"
            )
            # Iterate all devices on this subnet and reduce their rate limits
            for ip, tib in self.devices.items():
                if not ip.startswith(subnet + "."):
                    continue  # Skip devices on other subnets
                # Only reduce rate on devices whose circuit breaker is still ACTIVE
                # (devices already TRIPPED or EXHAUSTED are already stopped)
                if tib.state.circuit_breaker_status != CircuitBreakerStatus.ACTIVE:
                    continue
                old_rate = tib.state.current_rate_limit
                # Floor: never go below 10% of the configured maximum rate
                min_rate = tib.config.max_packets_per_second * 0.10
                # Halve the current rate, but respect the floor
                tib.state.current_rate_limit = max(min_rate, old_rate * 0.5)
            # Record the time so we respect the 30-second cooldown
            self._last_backoff_time = now

    # ── Metrics ────────────────────────────────────────────────────────────────

    def get_session_metrics(self) -> dict:
        """
        Produce a summary dict of key session metrics.

        Called by the Coordinator at the end of the session to populate the
        results JSON and the human-readable summary printed to the console.

        Returns a dict with:
          - duration_sec       : Wall-clock time since session start.
          - device_count       : Number of registered devices.
          - tier_summary       : Device count per tier (CRITICAL, FRAGILE, etc.).
          - total_findings     : Raw finding count from all tools.
          - validated_findings : Findings that passed validation oracles.
          - instability_events : Subnet-wide stress correlation triggers.
          - vetoed_actions     : Actions blocked by safety or impact agents.
          - ptg_graphs         : Number of PTGs built (one per device).
          - fleet_clusters     : Number of fleet clusters formed.
          - pcf_nodes          : Total nodes in the PCF evidence DAG.
        """
        return {
            "duration_sec": round(time.time() - self.start_time, 1),
            "device_count": len(self.devices),
            "tier_summary": {
                tier.name: len(self.tibs_by_tier(tier))
                for tier in DeviceTier  # Iterate all possible tiers
            },
            "total_findings": self.total_findings,
            "validated_findings": self.validated_findings,
            "instability_events": self.instability_events,
            "vetoed_actions": self.vetoed_actions,
            "ptg_graphs": len(self.ptg_graphs),
            "fleet_clusters": len(self.fleet_clusters),
            "pcf_nodes": self.pcf_dag.summary()["total_nodes"],
        }
