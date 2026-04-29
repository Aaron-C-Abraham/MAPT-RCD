
from dataclasses import dataclass,field
from enum import Enum,auto
from typing import Optional

class DeviceTier(Enum):
    """
    Classifies the fragility/robustness of a target device.
    """
    ROBUST=1 
    MODERATE=2
    FRAGILE=3 
    CRITICAL=4
    UNKNOWN=5 

class PentestPhase(Enum):
    """
    Sequential phases of a penetration testing engagement.
    """
    PASSIVE_LISTENING=auto()
    ACTIVE_DISCOVERY=auto()
    FINGERPRINTING=auto()
    TIB_ASSIGNMENT=auto()
    PORT_SCAN=auto()
    SERVICE_PROBE=auto()
    OS_IDENTIFICATION=auto()
    EXPLOITATION=auto()
    POST_EXPLOITATION=auto()
    REPORT_GENERATION=auto()

class OsProbeIntensity(Enum):
    """
    Controls the aggressiveness of OS fingerprinting probes allowed on a device.
    """
    PASSIVE=1
    MINIMAL=2
    STANDARD=3
    FULL=4 

class CircuitBreakerStatus(Enum):
    """
    State of circuit breaker 
    """
    ACTIVE='ACTIVE' 
    PAUSED='PAUSED' 
    TRIPPED='TRIPPED'
    EXHAUSTED='EXHAUSTED'

class ExploitIntensity(Enum):
    """
    Controls the maximum exploitation aggressiveness allowed on a device.
    """
    NONE=0
    SAFE=1 
    MODERATE=2
    AGGRESIVE=3

DEFAULT_PROBE_COSTS:dict[str:float]={
    # Discovery
    "arp":0.5,
    "icmp_echo":1.0,
    "icmp_timestamp":1.0,
    "icmp_large":1.5,
    # UDP probes
    "udp_probe":1.5,
    "snmp_query":1.5,
    "udp_malformed":3.0,
    # Application layer
    "http_head":2.0,
    "http_get":2.5,
    "http_malformed":4.0,
    "ssh_banner":2.0,
    "ftp_banner":2.0,
    "modbus_identify":3.0,
    "s7_identify":3.0,
    #OS fingerprinting
    "os_probe_standard":3.0,
    "os_probe_full":5.0,
    # exploitation
    "exploit_safe":10.0,
    "exploit_moderate":20.0,
    "exploit_aggressive":40.0
}

@dataclass
class TIBConfig:
    """
    Static budget limits and scanning constraints configured per device tier.
    Determines rate limits, port scan scope, service probe caps, exploitation
    policy, and circuit breaker thresholds.
    """
    max_budget_points:float # Weighted budget for probing.
    # Rate Limits
    max_packets_per_second:int # Max number of packets per second
    min_inter_packet_delay_ms:int # Minimun delay between sending 2 packets
    max_concurrent_connections:int # maximum number of simultaneous open connections
    # Port Scan
    max_ports_to_scan:int # How many ports can be scanned 
    port_scan_rate_pps:int # Rate limit for port scanning
    # Service Probing
    max_service_probes:int # max number of application-layer probes
    max_probe_payload_bytes:int # maximum payload size in bytes per probe
    # OS Identification
    os_probe_intensity:OsProbeIntensity # Which OS fingerprinting technique to use 
    # Exploitation
    weighted_exploit_attempts_budget:int # Weighted budget for exploit attempts.
    exploit_intensity:ExploitIntensity # Permitted Exploit intensity
    # Post-exploitation
    max_persistence_attempts:int # Max number of persistence attempts.
    allow_lateral_movement:bool # Whether lateral movement is allowed or not 
    allow_simulated_data_exfil:bool # Whether simulated data exfiltration is allowed or not
    # Circuit Breaker Thresholds
    rtt_pause_multiplier:float # Threshold for circuit-breaker to pause operations
    rtt_trip_multiplier:float # Threshold for circuit-breaker to stop operations
    consecutive_timeout_limit:int # consecutive timeout limit for between packets
    auto_pause_on_stress:bool # Whether breaker should automatically pause if the network is discovered to be in under stress
    override_probe_cost:dict=field(default_factory=dict) # to override the probe_table so that we can assign higher weights on probes for critical devices.

    def get_probe_cost(self,probe_type:str)->float:
        """
        Return the weighted budget cost for a probe type, checking tier-specific
        overrides first, then falling back to DEFAULT_PROBE_COSTS.
        """
        if probe_type in self.override_probe_cost:
            return self.override_probe_cost[probe_type]
        return DEFAULT_PROBE_COSTS.get(probe_type,1.0)

@dataclass
class TIBState:
    """
    Dynamic runtime state of a device's TIB. Tracks budget consumption,
    packet counts, RTT samples, circuit breaker status, and phase history.
    """
    # Weighted Budget
    budget_spent:float=0.0
    budget_spent_by_type: dict=field(default_factory=dict)
    # Live Rate Limit 
    current_rate_limit:float=0.0
    packets_sent_total:int=0
    last_packet_time_ms:float=0.0
    active_connections:int=0
    total_connections_opened:int=0
    # Port Scan
    ports_scanned:int=0
    open_ports_found:list=field(default_factory=list)
    # Service Probes
    service_probes_sent:int=0
    # Exploration
    exploit_attempts:int=0
    # Post-Exploitation
    persistence_attempts:int=0
    # RTT/Stress
    baseline_rtt_ms:Optional[float]=None
    current_rtt_ms:Optional[float]=None
    rtt_samples:list=field(default_factory=list)
    consecutive_timeouts:int=0
    stress_events:int=0
    # Circuit Breaker
    circuit_breaker_status:CircuitBreakerStatus=CircuitBreakerStatus.ACTIVE
    pause_for_ms: float=0.0
    trip_reason:str=""
    # Phase
    current_phase:PentestPhase=PentestPhase.PASSIVE_LISTENING
    phase_history:list=field(default_factory=list)

TIER_TIB_DEFAULTS:dict[DeviceTier,TIBConfig]={

    DeviceTier.ROBUST: TIBConfig(
        max_budget_points=float('inf'),          
        override_probe_cost={},            
        max_packets_per_second=500,           
        min_inter_packet_delay_ms=0,             
        max_concurrent_connections=20,            
        max_ports_to_scan=65535,         
        port_scan_rate_pps=500,           
        max_service_probes=200,           
        max_probe_payload_bytes=65535,        
        os_probe_intensity=OsProbeIntensity.FULL,       
        weighted_exploit_attempts_budget=float('inf'),             
        exploit_intensity=ExploitIntensity.AGGRESIVE, 
        max_persistence_attempts=float('inf'),             
        allow_lateral_movement=True,          
        allow_simulated_data_exfil=True,          
        rtt_pause_multiplier=5.0,           
        rtt_trip_multiplier=10.0,          
        consecutive_timeout_limit=20,            
        auto_pause_on_stress=True,          
    ),

    DeviceTier.MODERATE: TIBConfig(
        max_budget_points=10000.0,
        override_probe_cost={},
        max_packets_per_second=50,
        min_inter_packet_delay_ms=20,
        max_concurrent_connections=5,
        max_ports_to_scan=10000,
        port_scan_rate_pps=50,
        max_service_probes=20,
        max_probe_payload_bytes=4096,
        os_probe_intensity=OsProbeIntensity.STANDARD,
        weighted_exploit_attempts_budget=50,
        exploit_intensity=ExploitIntensity.MODERATE,
        max_persistence_attempts=3,
        allow_lateral_movement=True,
        allow_simulated_data_exfil=True,
        rtt_pause_multiplier=2.0,
        rtt_trip_multiplier=4.0,
        consecutive_timeout_limit=10,
        auto_pause_on_stress=True,
    ),

    DeviceTier.FRAGILE: TIBConfig(
        max_budget_points=3000.0,
        override_probe_cost={
            "tcp_syn":1.0,
            "tcp_banner_grab":2.0,
            "tcp_xmas":20.0,
            "tcp_null":20.0,
            "tcp_malformed":25.0,
            "os_probe_full":50.0
        },
        max_packets_per_second=20,
        min_inter_packet_delay_ms=100,
        max_concurrent_connections=3,
        max_ports_to_scan=1024,
        port_scan_rate_pps=20,
        max_service_probes=30,
        max_probe_payload_bytes=1024,
        os_probe_intensity=OsProbeIntensity.STANDARD,
        weighted_exploit_attempts_budget=30,
        exploit_intensity=ExploitIntensity.SAFE,
        max_persistence_attempts=1,
        allow_lateral_movement=False,
        allow_simulated_data_exfil=False,
        rtt_pause_multiplier=3.0,
        rtt_trip_multiplier=5.0,
        consecutive_timeout_limit=10,
        auto_pause_on_stress=True,
    ),

    DeviceTier.UNKNOWN: TIBConfig(
        max_budget_points=5000.0,
        override_probe_cost={
            "tcp_syn":1.0,
            "tcp_xmas":20.0,
            "tcp_null":20.0,
            "tcp_malformed":25.0,
            "os_probe_full":50.0
        },
        max_packets_per_second=50,
        min_inter_packet_delay_ms=50,
        max_concurrent_connections=5,
        max_ports_to_scan=1024,
        port_scan_rate_pps=50,
        max_service_probes=50,
        max_probe_payload_bytes=1024,
        os_probe_intensity=OsProbeIntensity.STANDARD,
        weighted_exploit_attempts_budget=30,
        exploit_intensity=ExploitIntensity.SAFE,
        max_persistence_attempts=0,
        allow_lateral_movement=False,
        allow_simulated_data_exfil=False,
        rtt_pause_multiplier=3.0,
        rtt_trip_multiplier=5.0,
        consecutive_timeout_limit=15,
        auto_pause_on_stress=True,
    ),
    DeviceTier.CRITICAL: TIBConfig(
        max_budget_points=200.0,
        override_probe_cost={
            "arp":1.5,
            "icmp_echo":3.0,
            "tcp_syn":3.0,
            "snmp_query":4.5,
            "tcp_xmas":100.0,
            "tcp_null":100.0,
            "tcp_malformed":100.0,
            "os_probe_standard":100.0,
            "os_probe_full":100.0,
            "exploit_safe":100.0,
            "exploit_moderate":100.0,
            "exploit_aggressive":100.0,
        },
        max_packets_per_second=5,           
        min_inter_packet_delay_ms=2000,             
        max_concurrent_connections=1,            
        max_ports_to_scan=100,         
        port_scan_rate_pps=1,           
        max_service_probes=1,           
        max_probe_payload_bytes=128,        
        os_probe_intensity=OsProbeIntensity.PASSIVE,       
        weighted_exploit_attempts_budget=0,             
        exploit_intensity=ExploitIntensity.NONE, 
        max_persistence_attempts=0,             
        allow_lateral_movement=False,          
        allow_simulated_data_exfil=False,          
        rtt_pause_multiplier=1.5,
        rtt_trip_multiplier=3.0,
        consecutive_timeout_limit=5,
        auto_pause_on_stress=True,
    ),
}