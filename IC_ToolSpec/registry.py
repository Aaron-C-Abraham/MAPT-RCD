import logging
from typing import Dict, List, Optional
from TIB_and_PCF.TIB.TIB_structures import DeviceTier, TIER_TIB_DEFAULTS
from IC_ToolSpec.models import ToolSpec, SafeMode, ToolCategory

logger = logging.getLogger(__name__)


class ToolSpecRegistry:
    """
    Singleton registry holding all known ToolSpecs.
    """

    # Class-level reference to the single instance. None until first instantiation.
    _instance = None

    def __new__(cls):
        """
        Override __new__ to implement the singleton pattern.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # Internal dictionary mapping tool_id -> ToolSpec
            cls._instance._tools=dict()
            # Flag to track whether the builtin tools have been registered.
            # Prevents double-registration of builtins.
            cls._instance._initialized = False
        return cls._instance

    def register(self, spec: ToolSpec) -> None:
        """
        Register a tool specification in the registry.
        """
        if spec.tool_id in self._tools:
            logger.debug(f"Overwriting ToolSpec '{spec.tool_id}'")
        self._tools[spec.tool_id] = spec
        logger.debug(f"Registered ToolSpec '{spec.tool_id}' ({spec.category.value})")

    def get(self, tool_id: str) -> Optional[ToolSpec]:
        """
        Get a tool specification by its unique ID.
        """
        return self._tools.get(tool_id)

    def get_all(self) -> List[ToolSpec]:
        """
        Return all registered tool specifications as a list.
        """
        return list(self._tools.values())

    def get_tools_for_category(self, category: ToolCategory) -> List[ToolSpec]:
        """
        Return all tools in a specific category.
        """
        return [t for t in self._tools.values() if t.category == category]

    def get_tools_for_tier(self, tier: DeviceTier) -> List[ToolSpec]:
        """
        Return all tools that have at least one allowed mode for the given tier.
        """
        return [
            t for t in self._tools.values()
            if t.get_safest_mode(tier) is not None
        ]

    def get_safest_mode(self, tool_id: str, tier: DeviceTier) -> Optional[SafeMode]:
        """
        Return the safest allowed mode for a specific tool and tier.
        """
        spec = self.get(tool_id)
        if spec:
            return spec.get_safest_mode(tier)
        return None

    def estimate_budget_cost(self, tool_id: str, safe_mode_name: str,
                             tier: DeviceTier) -> float:
        """
        Estimate budget cost for a tool in a specific mode and tier.
        """
        spec = self.get(tool_id)
        if not spec:
            return float("inf")
        mode = spec.get_mode_by_name(safe_mode_name)
        if not mode:
            return float("inf")
        config = TIER_TIB_DEFAULTS.get(tier)
        if not config:
            return float("inf")
        return mode.estimate_cost(config)

    def find_cheapest_tool(self, category: ToolCategory,
                           tier: DeviceTier) -> Optional[ToolSpec]:
        """
        Find the tool with the lowest minimum cost for a given tier and category.
        """
        tools = self.get_tools_for_category(category)
        # Get the tier's TIB config for cost estimation
        config = TIER_TIB_DEFAULTS.get(tier)
        if not config:
            return None

        best = None
        best_cost = float("inf")
        for tool in tools:
            # Get the safest mode for this tier (may be None if all modes restricted)
            mode = tool.get_safest_mode(tier)
            if mode:
                cost = mode.estimate_cost(config)
                # Track the tool with the lowest cost seen so far
                if cost < best_cost:
                    best_cost = cost
                    best = tool
        return best

    def find_fallback_chain(self, tool_id: str, tier: DeviceTier,
                            max_depth: int = 5) -> List[ToolSpec]:
        """
        Follow fallback_tool_ids to build a chain of alternatives.
        """
        chain = []
        visited = set()         
        current_id = tool_id    

        for _ in range(max_depth):
            # To detect any cycles and stop at that instance
            if current_id in visited:
                break
            visited.add(current_id)

            # Look up the current tool in the registry
            spec = self.get(current_id)
            if not spec:
                break

            # Only include tools that have at least one allowed mode for this tier
            if spec.get_safest_mode(tier) is not None:
                chain.append(spec)

            # Follow the first fallback reference to continue the chain.
            if spec.fallback_tool_ids:
                current_id = spec.fallback_tool_ids[0]
            else:
                break
        return chain

    def summary(self) -> Dict:
        # Count tools per category
        by_category = {}
        for t in self._tools.values():
            cat = t.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
        return {
            "total_tools": len(self._tools),
            "by_category": by_category,
            "tool_ids": list(self._tools.keys()),
        }

    
