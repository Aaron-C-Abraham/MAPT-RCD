from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from TIB_and_PCF.TIB.TIB_structures import DeviceTier


class ToolCategory(Enum):
    """
    Categorizes tools by their role in the pentesting workflow.
    """
    DISCOVERY = "discovery"              
    FINGERPRINT = "fingerprint"          
    PORT_SCAN = "port_scan"              
    SERVICE_PROBE = "service_probe"     
    OS_IDENTIFICATION = "os_identification"
    EXPLOITATION = "exploitation"        
    POST_EXPLOITATION = "post_exploitation" 
    VALIDATION = "validation"            


@dataclass
class SafeMode:
    """
    A specific operational mode for a tool, with known impact characteristics.
    """

    name: str
    description: str
    # A normalized score from 0.0 (completely passive, no packets sent) to 1.0 fo risk assessment and reporting
    impact_score: float                          
    # List of probe type keys that this mode uses.
    probe_types_used: List[str]                  
    # The worst-case total budget cost if this mode is invoked. This is a pre-computed
    # upper bound used for quick budget checks before detailed estimation. 
    max_budget_cost: float
    # Maximum number of packets this mode will send. Used both for budget estimation
    max_packets: int = 1                        
    # Maximum packet rate in packets per second. A value of 0.0 means "defer to
    # the device tier's rate limit" (each tier has its own max_pps configured in
    # TIBConfig). A non-zero value here acts as a tool-specific cap that may be
    # stricter than the tier's limit but never looser.
    max_rate_pps: float = 0.0                  
    # How long to wait for responses before timing out this mode's operation.
    timeout_sec: float = 10.0
    # List of DeviceTier values where this mode is FORBIDDEN. 
    tier_restrictions: List[DeviceTier] = field(default_factory=list)
    # Warnings about known fragility issues with this mode.
    fragility_warnings: List[str] = field(default_factory=list)

    def is_allowed_for_tier(self, tier: DeviceTier) -> bool:
        """
        Check whether this safe mode is permitted for a given device tier.
        """
        return tier not in self.tier_restrictions

    def estimate_cost(self, tier_config) -> float:
        """
        Estimate total budget cost using the tier's probe cost table.
        """
        total = 0.0
        for pt in self.probe_types_used:
            total += tier_config.get_probe_cost(pt)
        return total * self.max_packets


@dataclass
class OutputSchema:
    """
    Structured output specification for a tool.
    """
    # Maps field names to type descriptions 
    fields: Dict[str, str]         
    # Which field in the output carries a confidence score (0.0 to 1.0).
    # Empty string means the tool does not produce confidence values.
    confidence_field: str = ""     
    # The NodeType value to use when adding this tool's output to the PCF
    evidence_node_type: str = ""   


@dataclass
class InvocationGrammar:
    """
    Bounded invocation grammar — constrains what parameters a tool accepts.
    Prevents unbounded or dangerous parameter combinations.
    """
    # Parameters that MUST be provided for the tool to execute.
    required_params: List[str] = field(default_factory=list)
    # Optional parameters with their default values. 
    optional_params: Dict[str, str] = field(default_factory=dict) 
    # Validation constraints for parameter values
    param_constraints: Dict[str, Dict] = field(default_factory=dict)  # name -> {min, max, enum, regex}
    # Maximum number of target IPs/hosts allowed in a single tool invocation.
    max_targets_per_call: int = 1
    # Maximum number of ports that can be scanned in a single invocation.
    max_ports_per_call: int = 100
    # Maximum number of retry attempts if the tool fails or times out.
    max_retries: int = 3
    # Maximum number of concurrent instances of this tool that can run
    # simultaneously.
    max_concurrent: int = 1


@dataclass
class ToolSpec:
    """
    Impact-Contract Tool Specification.
    """
    # Unique identifier for this tool
    tool_id: str
    # Name for display in reports.
    name: str
    # Detailed description of what the tool does.
    description: str
    # The functional category this tool belongs to
    category: ToolCategory
    # List of safe modes, ORDERED FROM SAFEST (index 0) TO MOST AGGRESSIVE (last).
    safe_modes: List[SafeMode] 
    # Structured specification of what this tool outputs.
    output_schema: OutputSchema
    # Bounded invocation grammar that constrains parameters.
    invocation_grammar: InvocationGrammar = field(default_factory=InvocationGrammar)
    # Whether the tool needs root/administrator privileges to run.
    requires_root: bool = False
    # List of tool IDs to try if this tool cannot be used 
    fallback_tool_ids: List[str] = field(default_factory=list)
    # Version string for the tool specification. 
    version: str = "1.0"

    def get_safest_mode(self, tier: DeviceTier) -> Optional[SafeMode]:
        """
        Return the safest allowed mode for a given device tier.
        """
        for mode in self.safe_modes:
            if mode.is_allowed_for_tier(tier):
                return mode
        # No mode is allowed for this tier — the tool is completely off-limits
        return None

    def get_mode_by_name(self, mode_name: str) -> Optional[SafeMode]:
        """
        Look up a specific safe mode by its name string.
        """
        for mode in self.safe_modes:
            if mode.name == mode_name:
                return mode
        return None

    def get_allowed_modes(self, tier: DeviceTier) -> List[SafeMode]:
        """
        Return all modes allowed for a device tier, safest first.
        """
        return [m for m in self.safe_modes if m.is_allowed_for_tier(tier)]

    def estimate_min_cost(self, tier_config) -> float:
        """
        Estimate minimum budget cost (using safest mode).
        """
        if not self.safe_modes:
            return 0.0
        # Index 0 is always the safest mode due to the ordering invariant
        return self.safe_modes[0].estimate_cost(tier_config)

    def estimate_max_cost(self, tier_config) -> float:
        """
        Estimate maximum budget cost (using most aggressive mode).
        """
        if not self.safe_modes:
            return 0.0
        # Index -1 is always the most aggressive mode due to the ordering invariant
        return self.safe_modes[-1].estimate_cost(tier_config)
