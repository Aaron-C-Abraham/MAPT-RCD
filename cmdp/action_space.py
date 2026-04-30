from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CMDPAction:
    """
    A single action in the CMDP.

    The action selects:
    - Which PTG node to execute (identified by ptg_node_id)
    - Which tool and safe mode to use (e.g., nmap with syn_only mode)
    - Timing parameters (rate multiplier to scale probe intensity, backoff delay)
    - Whether to skip the node entirely (no probe sent)

    The combination of tool_id + safe_mode determines the probe's intrusiveness.
    The rate_multiplier scales the current TIB rate limit (0.1 = 10% of max rate,
    1.0 = full speed).  backoff_seconds adds a delay before execution to let a
    stressed target recover.
    """

    # ptg_node_id: Identifier of the PTG node this action targets.
    # Each PTG node represents a specific reconnaissance or exploitation step.
    ptg_node_id: str = ""

    # tool_id: Identifier of the tool to use (e.g., "nmap", "nikto", "modbus_scanner").
    tool_id: str = ""

    # safe_mode: The safety/aggressiveness mode for the tool.
    # Examples: "passive" (no packets sent), "syn_only" (SYN scan only),
    # "full" (complete scan), "echo_only" (ICMP ping only).
    # Higher-impact modes yield more information but carry greater risk.
    safe_mode: str = ""

    # rate_multiplier: Scales the TIB's current rate limit.
    # Range [0.1, 1.0].  Lower values send fewer packets per second,
    # reducing target impact at the cost of slower scanning.
    rate_multiplier: float = 1.0     # 0.1-1.0, scales current rate limit

    # backoff_seconds: Delay (in seconds) before executing the probe.
    # Used when the target shows signs of stress (high RTT ratio).
    # Gives the target time to recover before the next probe.
    backoff_seconds: float = 0.0     # Wait before executing

    # skip: If True, the node is skipped entirely (no probe sent).
    # Used when budget is exhausted, the target is stressed, or the node's
    # expected information gain is not worth the cost.
    skip: bool = False               # True = skip this node entirely

    def to_dict(self) -> dict:
        """Serialize the action to a dictionary for logging/storage.

        Returns:
            Dictionary with all action parameters.
        """
        return {
            "ptg_node_id": self.ptg_node_id,
            "tool_id": self.tool_id,
            "safe_mode": self.safe_mode,
            "rate_multiplier": self.rate_multiplier,
            "backoff_seconds": self.backoff_seconds,
            "skip": self.skip,
        }

    def to_index(self) -> int:
        """
        Convert action to a discrete index for the DRL policy.

        The DRL policy outputs a probability distribution over 5 discrete action
        types (indices 0-4).  This method maps a continuous CMDPAction back to
        its discrete index based on the rate_multiplier value.

        The mapping is:
          0 — Skip (no probe at all)
          1 — Very conservative (rate < 0.3, i.e., < 30% of max packet rate)
          2 — Conservative (rate 0.3-0.6, moderate caution)
          3 — Normal (rate 0.6-0.9, standard scanning speed)
          4 — Full speed (rate >= 0.9, maximum throughput)

        Returns:
            Integer index in [0, 4].
        """
        # Skip action always maps to index 0 regardless of rate_multiplier.
        if self.skip:
            return 0

        # Classify by rate_multiplier thresholds.
        # These thresholds correspond to the RATE_OPTIONS in ActionSpace.
        if self.rate_multiplier < 0.3:
            return 1  # Very conservative — for fragile/stressed targets
        if self.rate_multiplier < 0.6:
            return 2  # Conservative — moderate caution
        if self.rate_multiplier < 0.9:
            return 3  # Normal — standard scanning speed
        return 4      # Full speed — maximum throughput for robust targets


class ActionSpace:
    """
    Defines the available actions for a given state.

    The action space is dynamic — it depends on:
    - Which PTG nodes are READY (only ready nodes can be executed)
    - Device tier (restricts safe modes — CRITICAL devices cannot use aggressive modes)
    - Remaining budget (if budget is exhausted, only passive/skip actions are available)

    For each READY PTG node, the action space includes:
    - 1 skip action (do not execute this node)
    - len(RATE_OPTIONS) execute actions (one per rate multiplier level)
    Total: (1 + len(RATE_OPTIONS)) * num_ready_nodes actions per decision step.

    The DRL policy sees a fixed-size output (5 action types) and maps the chosen
    index back to a concrete CMDPAction via index_to_action().
    """

    # RATE_OPTIONS: Discrete rate multiplier levels available to the policy.
    # These values scale the TIB's current packet rate limit:
    #   0.1  = 10% speed — minimal impact, used for CRITICAL/stressed targets
    #   0.3  = 30% speed — very conservative
    #   0.5  = 50% speed — conservative, good for FRAGILE devices
    #   0.75 = 75% speed — normal operation
    #   1.0  = 100% speed — full throughput for ROBUST targets
    RATE_OPTIONS = [0.1, 0.3, 0.5, 0.75, 1.0]

    # BACKOFF_OPTIONS: Discrete backoff delay levels (in seconds).
    # Backoff gives a stressed target time to recover before the next probe.
    #   0.0  = no delay (target is healthy)
    #   1.0  = short pause (mild stress detected)
    #   5.0  = moderate pause (significant RTT increase)
    #   10.0 = long pause (target near circuit breaker trip threshold)
    BACKOFF_OPTIONS = [0.0, 1.0, 5.0, 10.0]

    def __init__(self):
        # Fixed action dimensionality for the DRL policy: 1 skip + 4 rate levels.
        # This matches the DRL policy's output layer size.
        self._action_dim = 5  # skip + 4 rate levels

    @property
    def action_dim(self) -> int:
        """Number of discrete action types for the DRL policy output layer."""
        return self._action_dim

    def get_available_actions(self, ready_nodes: list, tier=None) -> List[CMDPAction]:
        """
        Generate all available actions for the current state.

        For each READY PTG node, creates:
        - One skip action (always available — the policy can always choose not to probe)
        - One action per rate multiplier level in RATE_OPTIONS

        This enumeration lets the heuristic policy score and rank all possibilities.
        The DRL policy does not use this method directly (it uses index_to_action).

        Args:
            ready_nodes: PTG nodes in READY status (prerequisites met, can execute now).
            tier: Device tier (for safe mode filtering — currently unused but reserved
                  for future filtering of aggressive modes on fragile devices).

        Returns:
            List of valid CMDPAction options, one skip + len(RATE_OPTIONS) per node.
        """
        actions = []

        for node in ready_nodes:
            # Skip action: always available for every node.
            # The policy can decide that the information gain from this node
            # is not worth the budget cost or target impact risk.
            actions.append(CMDPAction(
                ptg_node_id=node.node_id,
                tool_id=node.tool_id,
                safe_mode=node.safe_mode,
                skip=True,
            ))

            # Execute actions: one per rate level.
            # Each rate multiplier represents a different speed/safety tradeoff.
            # The tool_id and safe_mode come from the PTG node's specification.
            for rate in self.RATE_OPTIONS:
                actions.append(CMDPAction(
                    ptg_node_id=node.node_id,
                    tool_id=node.tool_id,
                    safe_mode=node.safe_mode,
                    rate_multiplier=rate,
                ))

        return actions

    def index_to_action(self, index: int, node) -> CMDPAction:
        """
        Convert a discrete action index (from DRL policy output) to a CMDPAction.

        The DRL policy outputs probabilities over 5 indices (0-4).  This method
        converts the sampled index into a concrete action targeting the given PTG node.

        Mapping:
          0 -> skip (do not execute this node)
          1 -> execute at RATE_OPTIONS[0] = 0.1 (very conservative)
          2 -> execute at RATE_OPTIONS[1] = 0.3 (conservative)
          3 -> execute at RATE_OPTIONS[2] = 0.5 (normal)
          4 -> execute at RATE_OPTIONS[3] = 0.75 or RATE_OPTIONS[4] = 1.0

        Args:
            index: Discrete action index from the DRL policy (0-4).
            node: The PTG node to target (must have node_id, tool_id, safe_mode attributes).

        Returns:
            A CMDPAction configured for the given node and rate level.
        """
        # Index 0 always means skip — no probe is sent.
        if index == 0:
            return CMDPAction(
                ptg_node_id=node.node_id,
                tool_id=node.tool_id,
                safe_mode=node.safe_mode,
                skip=True,
            )

        # For indices 1-4, map to RATE_OPTIONS.  Subtract 1 because index 0 is skip.
        # min() clamps to the last rate option if the index exceeds the list length,
        # providing a safe fallback to maximum rate.
        rate_idx = min(index - 1, len(self.RATE_OPTIONS) - 1)
        return CMDPAction(
            ptg_node_id=node.node_id,
            tool_id=node.tool_id,
            safe_mode=node.safe_mode,
            rate_multiplier=self.RATE_OPTIONS[rate_idx],
        )
