
import math
import logging
import random
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

import numpy as np

from cmdp.state import CMDPState
from cmdp.action_space import CMDPAction, ActionSpace
from cmdp.reward import RewardFunction
from cmdp.constraints import SafetyConstraints
from utils.constants import CMDP_STATE_DIM, CMDP_HIDDEN_DIM, CMDP_LEARNING_RATE

logger = logging.getLogger(__name__)


class BasePolicy(ABC):
    """
    Abstract policy interface for the CMDP.

    Both HeuristicPolicy and DRLPolicy implement this interface, so the
    orchestrator can swap between them transparently.  The interface consists
    of a single method: select_action(state, available_actions) -> action.
    """

    @abstractmethod
    def select_action(self, state: CMDPState,
                      available_actions: List[CMDPAction]) -> CMDPAction:
        """Select an action given the current state and list of legal actions."""
        pass


class HeuristicPolicy(BasePolicy):
    """
    Rule-based heuristic policy for safe IoT/OT penetration testing.

    Encodes expert knowledge about IoT/OT penetration testing as a priority system:

    Rule 1 (Breaker check): If the circuit breaker is tripped or exhausted, ALWAYS skip.
        WHY: A tripped breaker means the target is in distress — any further probing
        could cause permanent damage or data loss.

    Rule 2 (Budget guard): If budget < 10%, only allow passive/zero-cost probes.
        WHY: Preserves the last bit of budget for critical passive reconnaissance
        that can still yield findings without spending resources.

    Rule 3 (Rate scaling): Scale the probe rate based on stress indicators.
        WHY: Adaptively reduces probe intensity when the target shows signs of
        overload (high RTT, many stress events), preventing breaker trips.

    Rule 4 (Aggression level): Compute an aggression score [0, 1] based on
        device tier, stress history, budget, and OT mode.
        WHY: Encodes the expert intuition that fragile devices, stressed targets,
        and OT environments all warrant more conservative probing.

    Rule 5 (Action scoring): Score each candidate action by its safe mode,
        weighted by the aggression level.
        WHY: Passive probes always score highest (safe regardless of context).
        Aggressive modes only score well when aggression is high (robust targets
        with budget to spare).

    Rule 6 (Backoff injection): Add a delay before execution if RTT ratio > 1.5.
        WHY: Gives the target time to recover between probes, reducing the
        chance of cascading stress events.

    Fleet optimization: Non-representative devices get a 70% score discount
    on non-passive actions, because findings from the representative device
    will be propagated to them — probing them individually wastes budget.
    """

    def select_action(self, state: CMDPState,
                      available_actions: List[CMDPAction]) -> CMDPAction:
        """
        Select the best action using heuristic rules.

        Evaluates rules in priority order and scores all non-skip actions.
        The highest-scored action is returned, with rate and backoff adjustments
        applied based on the target's current stress level.

        Args:
            state: Current CMDP state (device info, budget, stress, etc.).
            available_actions: List of legal CMDPActions (from ActionSpace).

        Returns:
            The best CMDPAction according to the heuristic rules, or a skip
            action if no safe action is available.
        """
        # No actions available — return a skip as a safe default.
        if not available_actions:
            return CMDPAction(skip=True)

        # Separate skip actions from executable actions.
        # We always consider skipping as a fallback, but we want to evaluate
        # executable actions first to find the best one.
        non_skip = [a for a in available_actions if not a.skip]
        if not non_skip:
            return available_actions[0]  # Only skips available — return the first one.

        # ── Rule 1: Circuit breaker check ──────────────────────────────────
        # If the circuit breaker has tripped (critical target impact detected)
        # or is exhausted (budget fully consumed), skip ALL actions unconditionally.
        # This is a hard safety rule — no probe is worth risking further harm.
        from TIB_and_PCF.TIB.TIB_structures import CircuitBreakerStatus
        if state.circuit_breaker_status in (
            CircuitBreakerStatus.TRIPPED, CircuitBreakerStatus.EXHAUSTED
        ):
            return CMDPAction(skip=True)

        # ── Rule 2: Budget guard ───────────────────────────────────────────
        # When budget is nearly exhausted (< 10% remaining), restrict to passive
        # probes that cost zero budget points.  This preserves the last bit of
        # budget in case the operator wants to manually run a critical probe.
        if state.budget_remaining_pct < 10:
            # Filter to zero-cost probe modes only.
            zero_cost = [a for a in non_skip
                         if a.safe_mode in ("passive", "passive_check", "lookup_only")]
            if zero_cost:
                return zero_cost[0]
            # No zero-cost probes available — must skip to conserve budget.
            return CMDPAction(skip=True)

        # ── Rule 3: Compute rate multiplier based on stress level ──────────
        # The rate multiplier scales the TIB's packet rate.  Lower values = fewer
        # packets per second = less impact on the target but slower scanning.
        rate_multiplier = self._compute_rate_multiplier(state)

        # ── Rule 4: Compute aggression level ───────────────────────────────
        # Aggression [0.0, 1.0] determines which probe modes are appropriate.
        # 0.0 = only passive probes; 1.0 = all modes including full scans.
        aggression = self._compute_aggression(state)

        # ── Rule 5: Score and rank all candidate actions ───────────────────
        scored = []
        for action in non_skip:
            # Score the action based on its safe mode and current aggression level.
            score = self._score_action(action, state, aggression)
            # Override the action's rate multiplier with the stress-adjusted value.
            # This ensures all actions respect the current stress level regardless
            # of what rate they were originally generated with.
            action.rate_multiplier = rate_multiplier
            scored.append((score, action))

        # Sort by score descending — highest-scored action is the best choice.
        scored.sort(key=lambda x: x[0], reverse=True)
        best_action = scored[0][1]

        # ── Rule 6: Inject backoff delay if target is stressed ─────────────
        # When RTT ratio exceeds 1.5x baseline, the target is showing signs of
        # load.  We add a delay before the next probe to let it recover.
        # The delay is proportional to the RTT ratio, capped at 5 seconds.
        if state.rtt_ratio > 1.5:
            best_action.backoff_seconds = min(state.rtt_ratio, 5.0)

        return best_action

    def _compute_rate_multiplier(self, state: CMDPState) -> float:
        """
        Compute the probe rate multiplier based on device stress indicators.

        The rate multiplier scales the TIB's configured max packets-per-second.
        It adapts in real-time to the target's health:

        - RTT ratio > 3.0 (3x baseline latency): Use 10% rate.
          WHY: The target is severely overloaded. Minimal probing only.

        - RTT ratio > 2.0 (2x baseline): Use 30% rate.
          WHY: Significant latency increase. Reduce to prevent further degradation.

        - RTT ratio > 1.5 (50% above baseline): Use 50% rate.
          WHY: Noticeable stress. Moderate reduction.

        - More than 3 stress events: Use 50% rate.
          WHY: Multiple stress indicators suggest the target is fragile,
          even if RTT hasn't spiked yet (e.g., service restarts without latency change).

        - Budget < 30% remaining: Use 50% rate.
          WHY: Conserve remaining budget by scanning more slowly, allowing
          the policy to make better decisions about which probes to run.

        - Otherwise: Use 100% rate (full speed).
          WHY: No stress signals detected — safe to probe at full speed.

        Returns:
            Float in [0.1, 1.0] — the rate multiplier.
        """
        if state.rtt_ratio > 3.0:
            return 0.1  # Severe overload — minimum rate
        if state.rtt_ratio > 2.0:
            return 0.3  # Significant latency — heavy throttle
        if state.rtt_ratio > 1.5:
            return 0.5  # Moderate latency — moderate throttle
        if state.stress_events > 3:
            return 0.5  # Multiple stress events — moderate throttle
        if state.budget_remaining_pct < 30:
            return 0.5  # Low budget — conserve by going slower
        return 1.0      # No stress detected — full speed

    def _compute_aggression(self, state: CMDPState) -> float:
        """
        Compute the aggression level [0.0, 1.0] based on device properties.

        Aggression determines which probe modes the policy considers appropriate.
        Higher aggression allows more intrusive probes (full port scans, exploit checks).
        Lower aggression restricts to passive and lightweight probes.

        The aggression is computed as a base value (from device tier) modified by
        multiplicative penalties for stress, budget consumption, and OT mode.

        Base values per device tier:
        - ROBUST (0.9): Enterprise-grade devices that can handle aggressive probing.
          WHY: Robust devices (servers, firewalls) are designed for high traffic.
        - MODERATE (0.6): Standard network devices.
          WHY: Can handle moderate probing but may degrade under heavy load.
        - FRAGILE (0.3): IoT devices, embedded systems, legacy equipment.
          WHY: These devices often have limited resources and can crash under load.
        - CRITICAL (0.1): Safety-critical systems (medical, industrial controllers).
          WHY: Disruption could cause physical harm. Near-passive probing only.
        - UNKNOWN (0.4): Unclassified devices — use moderate caution.
          WHY: Unknown fragility means we err on the side of caution.

        Multiplicative modifiers (each reduces the base):
        - Stress events: Each event reduces aggression by 10%, down to 30% of base.
          WHY: Historical stress indicates the target is sensitive.
        - Low budget (< 50%): Scales aggression proportionally.
          WHY: With limited budget, prefer cheap/safe probes over expensive/risky ones.
        - OT environment: 70% multiplier (30% reduction).
          WHY: OT/ICS networks require extra caution due to physical-world consequences.

        Returns:
            Float in [0.0, 1.0] — the aggression level.
        """
        from TIB_and_PCF.TIB.TIB_structures import DeviceTier

        # Base aggression per device tier.
        base = {
            DeviceTier.ROBUST: 0.9,
            DeviceTier.MODERATE: 0.6,
            DeviceTier.FRAGILE: 0.3,
            DeviceTier.CRITICAL: 0.1,
            DeviceTier.UNKNOWN: 0.4,
        }.get(state.device_tier, 0.4)  # Default to 0.4 for any unexpected tier value.

        # Reduce aggression with stress history.
        # Each stress event applies a 10% reduction, but the floor is 30% of original
        # (max(0.3, ...)) to ensure we never go completely passive — some information
        # gathering is always needed.
        if state.stress_events > 0:
            base *= max(0.3, 1.0 - state.stress_events * 0.1)

        # Reduce aggression when budget is below 50%.
        # At 25% budget remaining, aggression is halved (25/50 = 0.5).
        # At 0% budget, aggression goes to zero (but budget guard in select_action
        # already handles this case with Rule 2).
        if state.budget_remaining_pct < 50:
            base *= state.budget_remaining_pct / 50.0

        # Apply OT mode penalty.
        # 70% multiplier means a ROBUST device in OT mode gets 0.9 * 0.7 = 0.63
        # aggression instead of 0.9 — roughly equivalent to a MODERATE device.
        if state.is_ot_environment:
            base *= 0.7

        # Clamp to [0.0, 1.0] to ensure valid range.
        return min(1.0, max(0.0, base))

    def _score_action(self, action: CMDPAction, state: CMDPState,
                      aggression: float) -> float:
        """
        Score a candidate action based on its safe mode and the current aggression level.

        The scoring system encodes expert knowledge about probe mode intrusiveness:

        Passive modes (passive, passive_check, lookup_only) always score 10.0:
          WHY: Zero target impact, always safe to run.  These are preferred
          when aggression is low (fragile/critical devices).

        Low-impact modes (echo_only, syn_only, single_ping) score 7-8:
          WHY: Minimal packets sent, low risk of disruption.
          Not scaled by aggression because they're safe for most devices.

        Moderate modes (standard, read_id, read_szl) score 5.0 * aggression:
          WHY: Send non-trivial traffic.  Safe on ROBUST devices (5.0 * 0.9 = 4.5)
          but risky on FRAGILE devices (5.0 * 0.3 = 1.5).

        Aggressive modes (full, full_65535) score 0.5-1.0 * aggression:
          WHY: Send maximum traffic.  Only appropriate for ROBUST devices with
          plenty of budget.  Score is very low when aggression is low.

        Dry run (8.0) is always safe because it only simulates the probe.

        Fleet discount: Non-representative devices get a 70% score penalty
        on non-passive actions because probing them individually is wasteful —
        findings from the representative are propagated to the whole cluster.

        Args:
            action: The candidate CMDPAction to score.
            state: Current CMDP state.
            aggression: Aggression level [0.0, 1.0] from _compute_aggression().

        Returns:
            Float score — higher is better.
        """
        score = 0.0

        # Mode-to-score mapping.
        # Passive modes have fixed high scores (not multiplied by aggression).
        # Active modes are scaled by aggression so they only score well when
        # the target can handle them.
        mode_scores = {
            "passive": 10.0,              # Zero impact — always preferred
            "passive_check": 10.0,        # Zero impact — always preferred
            "lookup_only": 10.0,          # Zero impact — always preferred
            "echo_only": 8.0,             # ICMP echo only — very low impact
            "syn_only": 7.0,              # SYN scan — low impact, no full handshake
            "single_ping": 7.0,           # One ICMP packet — minimal impact
            "standard": 5.0 * aggression, # Standard scan — moderate impact
            "read_id": 5.0 * aggression,  # Read device ID (e.g., Modbus) — moderate
            "read_szl": 5.0 * aggression, # Read S7 SZL list — moderate
            "top_20": 6.0 * aggression,   # Top 20 ports — moderate scope
            "top_100": 4.0 * aggression,  # Top 100 ports — broader scope
            "top_1000": 2.0 * aggression, # Top 1000 ports — wide scope
            "full": 1.0 * aggression,     # Full port scan — high impact
            "full_65535": 0.5 * aggression,# All 65535 ports — maximum impact
            "dry_run": 8.0,               # Simulation only — no real impact
            "top_5": 3.0 * aggression,    # Top 5 exploit checks — moderate risk
            "safe": 2.0 * aggression,     # Safe exploit check — controlled risk
            "moderate": 1.0 * aggression, # Moderate exploit check — higher risk
        }
        # Use the mode's score, or a default of 3.0 * aggression for unknown modes.
        score += mode_scores.get(action.safe_mode, 3.0 * aggression)

        # Fleet discount for non-representative devices.
        # If this device is NOT the cluster representative, penalize non-passive
        # probes by 70% (multiply by 0.3).  Passive probes are exempt because
        # they're free and can still yield device-specific information.
        if not state.is_representative and action.safe_mode not in ("passive", "passive_check"):
            score *= 0.3  # Heavily discount probing non-representative devices

        return score


class DRLPolicy(BasePolicy):
    """
    Deep Reinforcement Learning policy using PPO-Lagrangian.

    Architecture:
    - Input layer: CMDPState vector (20 dimensions) — see state.py for dimension details.
    - Hidden layer 1: CMDP_HIDDEN_DIM units with ReLU activation.
    - Hidden layer 2: CMDP_HIDDEN_DIM units with ReLU activation.
    - Policy head: Softmax over action_dim (5) outputs — action probabilities.
    - Value head: Single linear output — estimated state value V(s).
    - Cost head: Single ReLU output — estimated constraint cost C(s).

    WHY this architecture:
    - Two hidden layers with ReLU provide sufficient capacity for the 20-dim state
      space without overfitting (the state space is relatively low-dimensional).
    - Separate value and cost heads enable the PPO-Lagrangian algorithm to
      independently estimate the reward value and constraint cost.
    - The cost head uses ReLU to ensure non-negative cost estimates (costs are
      always >= 0 by definition).

    The Lagrangian multiplier (lambda) enforces the constraint cost threshold:
    - When the estimated cost exceeds 80% of the threshold, the policy's action
      probabilities are blended with a safety bias that favors conservative actions.
    - This "soft" enforcement complements the hard constraints in constraints.py.

    Training uses constrained PPO (PPO-Lagrangian):
    - Policy gradient with advantage estimation maximizes reward.
    - Lagrangian penalty subtracts lambda * cost from the advantage.
    - Lambda is updated via dual gradient ascent based on the constraint violation.

    Open-source implementation — uses only numpy for inference.
    Training requires PyTorch (optional dependency) for full autograd support.
    The simplified numpy training loop here is for lightweight on-policy updates.
    """

    def __init__(self, state_dim: int = CMDP_STATE_DIM,
                 action_dim: int = 5,
                 hidden_dim: int = CMDP_HIDDEN_DIM,
                 constraint_threshold: float = 1.0):
        """
        Initialize the DRL policy.

        Args:
            state_dim: Dimensionality of the state vector (default 20).
            action_dim: Number of discrete action types (default 5: skip + 4 rates).
            hidden_dim: Width of hidden layers (from CMDP_HIDDEN_DIM constant).
            constraint_threshold: The 'd' in E[Sigma c(s,a)] <= d.
                This is the maximum acceptable cumulative constraint cost per episode.
                Default 1.0 means the policy should keep total target impact below 1.0.
        """
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim
        # constraint_threshold is the 'd' in the CMDP formulation:
        # the maximum acceptable expected cumulative constraint cost.
        self.constraint_threshold = constraint_threshold

        # Lagrangian multiplier (lambda): balances reward maximization vs constraint satisfaction.
        # Initialized to 0.1 (small positive value) so the policy starts with mild
        # constraint awareness rather than being purely reward-greedy.
        self.lagrange_lambda = 0.1

        # Initialize neural network weights with Xavier initialization.
        self._init_weights()

        # Experience buffer stores (s, a, r, s', cost, done) tuples for training.
        # This is an on-policy buffer — cleared periodically to avoid off-policy bias.
        self._experience_buffer = []

        # Training statistics for monitoring convergence.
        self.episode_count = 0
        self.total_reward = 0.0

    def _init_weights(self):
        """
        Initialize neural network weights using Xavier (Glorot) initialization.

        Xavier initialization sets the weight scale to sqrt(2 / (fan_in + fan_out)),
        which ensures that:
        1. The variance of activations stays roughly constant across layers.
        2. Gradients neither explode nor vanish during backpropagation.
        3. ReLU activations receive inputs centered around zero.

        WHY Xavier over other initializations:
        - Kaiming/He init is designed for ReLU but Xavier works well in practice
          for shallow networks (2 layers) with the moderate fan widths we use.
        - Zero initialization would cause all neurons to learn the same thing
          (symmetry problem).
        - Large random initialization would cause activations to saturate.

        The network has three weight matrices:
        - w1: state_dim -> hidden_dim (input to first hidden layer)
        - w2: hidden_dim -> hidden_dim (first hidden to second hidden layer)
        - w_policy: hidden_dim -> action_dim (second hidden to action probabilities)
        - w_value: hidden_dim -> 1 (second hidden to state value estimate)
        - w_cost: hidden_dim -> 1 (second hidden to constraint cost estimate)

        Biases are initialized to zero (standard practice — Xavier handles
        only weight matrices).
        """
        # Xavier scale factors for each layer pair.
        # sqrt(2 / (fan_in + fan_out)) ensures variance preservation.
        scale1 = np.sqrt(2.0 / (self.state_dim + self.hidden_dim))   # Input -> Hidden1
        scale2 = np.sqrt(2.0 / (self.hidden_dim + self.hidden_dim))  # Hidden1 -> Hidden2
        scale3 = np.sqrt(2.0 / (self.hidden_dim + self.action_dim))  # Hidden2 -> Heads

        # Hidden layer 1 weights: maps 20-dim state to hidden_dim features.
        self.w1 = np.random.randn(self.state_dim, self.hidden_dim).astype(np.float32) * scale1
        self.b1 = np.zeros(self.hidden_dim, dtype=np.float32)

        # Hidden layer 2 weights: maps hidden_dim features to hidden_dim features.
        self.w2 = np.random.randn(self.hidden_dim, self.hidden_dim).astype(np.float32) * scale2
        self.b2 = np.zeros(self.hidden_dim, dtype=np.float32)

        # Policy head weights: maps hidden features to action_dim logits.
        # These logits are passed through softmax to produce action probabilities.
        self.w_policy = np.random.randn(self.hidden_dim, self.action_dim).astype(np.float32) * scale3
        self.b_policy = np.zeros(self.action_dim, dtype=np.float32)

        # Value head weights: maps hidden features to a single scalar V(s).
        # V(s) estimates the expected cumulative reward from state s onward.
        # Used to compute the advantage A(s,a) = r + gamma*V(s') - V(s).
        self.w_value = np.random.randn(self.hidden_dim, 1).astype(np.float32) * scale3
        self.b_value = np.zeros(1, dtype=np.float32)

        # Constraint cost head weights: maps hidden features to a scalar C(s).
        # C(s) estimates the expected cumulative constraint cost from state s onward.
        # Used for the Lagrangian adjustment: if C(s) is high, the policy shifts
        # toward safer actions.
        self.w_cost = np.random.randn(self.hidden_dim, 1).astype(np.float32) * scale3
        self.b_cost = np.zeros(1, dtype=np.float32)

    def _forward(self, state_vec: np.ndarray) -> Tuple[np.ndarray, float, float]:
        """
        Forward pass through the neural network.

        Computes action probabilities, state value, and constraint cost estimate
        from the 20-dimensional state vector.

        The forward pass has two stages:
        1. Shared feature extraction (layers 1-2 with ReLU):
           - Transforms the raw state vector into a learned feature representation.
           - ReLU activation (max(0, x)) introduces non-linearity, allowing the
             network to learn non-linear decision boundaries.
           - Two layers provide enough capacity for the 20-dim state space.

        2. Three output heads (applied to the shared features):
           - Policy head (softmax): Produces a probability distribution over actions.
           - Value head (linear): Estimates V(s) for advantage computation.
           - Cost head (ReLU): Estimates cumulative constraint cost (non-negative).

        Args:
            state_vec: 20-dimensional numpy array from CMDPState.to_vector().

        Returns:
            Tuple of:
            - action_probs: numpy array of shape (action_dim,), sums to 1.0.
            - state_value: float, estimated V(s).
            - cost_estimate: float >= 0, estimated cumulative constraint cost.
        """
        # ── Layer 1: Linear transformation + ReLU activation ──────────────
        # h1 = ReLU(state_vec @ w1 + b1)
        # The matrix multiplication projects the 20-dim state into hidden_dim space.
        # ReLU zeros out negative activations, creating sparse representations
        # that help the network learn selective feature detectors.
        h1 = np.maximum(0, state_vec @ self.w1 + self.b1)  # ReLU

        # ── Layer 2: Linear transformation + ReLU activation ──────────────
        # h2 = ReLU(h1 @ w2 + b2)
        # Second layer combines features from layer 1 into higher-level representations
        # (e.g., "device is fragile AND under stress" as a single feature).
        h2 = np.maximum(0, h1 @ self.w2 + self.b2)  # ReLU

        # ── Policy head: Compute action probabilities via softmax ──────────
        # logits = h2 @ w_policy + b_policy  (raw unnormalized scores per action)
        logits = h2 @ self.w_policy + self.b_policy

        # Subtract the max logit for numerical stability before exponentiation.
        # Without this, large logit values cause exp() to overflow to infinity.
        # This is a standard softmax trick: softmax(x - max(x)) = softmax(x).
        logits -= logits.max()  # numerical stability

        # Softmax: convert logits to probabilities that sum to 1.0.
        # P(action_i) = exp(logit_i) / sum(exp(logit_j))
        exp_logits = np.exp(logits)
        action_probs = exp_logits / exp_logits.sum()

        # ── Value head: Estimate V(s) ─────────────────────────────────────
        # Linear projection to a scalar — no activation function because V(s)
        # can be any real number (positive for good states, negative for bad).
        state_value = float(h2 @ self.w_value + self.b_value)

        # ── Cost head: Estimate cumulative constraint cost ─────────────────
        # ReLU ensures the cost estimate is non-negative (costs are always >= 0).
        cost_estimate = float(np.maximum(0, h2 @ self.w_cost + self.b_cost))

        return action_probs, state_value, cost_estimate

    def select_action(self, state: CMDPState,
                      available_actions: List[CMDPAction]) -> CMDPAction:
        """
        Select an action using the neural network policy.

        The process:
        1. Convert the CMDP state to a 20-dim vector.
        2. Run the forward pass to get action probabilities, value, and cost estimate.
        3. Apply Lagrangian safety adjustment if the estimated cost is high.
        4. Sample an action from the (possibly adjusted) probability distribution.
        5. Map the sampled index to a concrete CMDPAction.

        Lagrangian adjustment (step 3):
        When the estimated cumulative cost exceeds 80% of the constraint threshold,
        the policy blends its learned probabilities with a hand-crafted safety bias:
            adjusted_probs = (1 - lambda) * learned_probs + lambda * safety_bias
        The safety_bias = [0.4, 0.3, 0.2, 0.05, 0.05] concentrates probability
        on skip (0.4) and very conservative (0.3) actions.
        WHY 80% trigger: This gives the policy a "buffer zone" to start being more
        cautious before actually hitting the constraint limit.

        Args:
            state: Current CMDP state.
            available_actions: List of legal CMDPActions.

        Returns:
            A CMDPAction selected according to the neural network policy.
        """
        # No actions available — return skip as a safe default.
        if not available_actions:
            return CMDPAction(skip=True)

        # Convert the structured state to a numeric vector for the neural network.
        state_vec = state.to_vector()

        # Run the forward pass to get action probabilities and estimates.
        action_probs, value, cost_est = self._forward(state_vec)

        # ── Lagrangian safety adjustment ───────────────────────────────────
        # If the estimated cumulative constraint cost is within 80% of the threshold,
        # blend the policy's learned probabilities with a safety-biased distribution.
        # This makes the policy progressively more conservative as it approaches
        # the constraint boundary.
        if cost_est > self.constraint_threshold * 0.8:
            # Safety bias: hand-crafted distribution that favors conservative actions.
            # [skip=0.4, very_conservative=0.3, conservative=0.2, normal=0.05, full=0.05]
            # WHY these specific values: Skip and very conservative together get 70%
            # of the probability mass, strongly discouraging aggressive probing.
            safety_bias = np.array([0.4, 0.3, 0.2, 0.05, 0.05], dtype=np.float32)

            # Blend: (1-lambda)*learned + lambda*safety.
            # When lambda is small (0.1), the learned policy dominates.
            # When lambda is large (trained up due to constraint violations),
            # the safety bias dominates, forcing conservative behavior.
            action_probs = (1 - self.lagrange_lambda) * action_probs + self.lagrange_lambda * safety_bias

        # ── Sample an action from the probability distribution ─────────────
        # Stochastic sampling (not argmax) is essential for exploration during
        # training.  During inference, the learned probabilities already encode
        # the policy's preference, so sampling still produces good actions.
        action_idx = np.random.choice(len(action_probs), p=action_probs)

        # ── Map the sampled index to a concrete CMDPAction ─────────────────
        action_space = ActionSpace()
        if available_actions:
            # Find executable (non-skip) actions to use as the base for constructing
            # the concrete CMDPAction (we need the node_id, tool_id, safe_mode).
            node_actions = [a for a in available_actions if not a.skip]
            if node_actions:
                # Use the first non-skip action as the template.
                # The DRL policy selects the rate level; the PTG node determines
                # which tool/mode to use.
                base_action = node_actions[0]

                # Create a lightweight object with the attributes index_to_action needs.
                # This avoids importing the full PTG node class just for attribute access.
                result = action_space.index_to_action(action_idx, type('', (), {
                    'node_id': base_action.ptg_node_id,
                    'tool_id': base_action.tool_id,
                    'safe_mode': base_action.safe_mode,
                })())
                return result

        # Fallback: no executable actions — skip.
        return CMDPAction(skip=True)

    def store_experience(self, state: CMDPState, action: CMDPAction,
                         reward: float, next_state: CMDPState,
                         constraint_cost: float, done: bool) -> None:
        """
        Store a transition (s, a, r, s', c, done) in the experience buffer.

        These transitions are used by train_step() for on-policy PPO updates.
        Each transition records:
        - state/next_state: as numeric vectors (20-dim)
        - action: as a discrete index (0-4)
        - reward: scalar reward from RewardFunction.compute()
        - constraint_cost: scalar cost from SafetyConstraints.get_constraint_cost()
        - done: whether this transition ends the episode

        Args:
            state: State before the action.
            action: Action that was taken.
            reward: Reward received.
            next_state: State after the action.
            constraint_cost: Constraint cost incurred.
            done: True if the episode ended after this transition.
        """
        self._experience_buffer.append({
            "state": state.to_vector(),          # 20-dim numpy array
            "action": action.to_index(),          # Integer 0-4
            "reward": reward,                     # Scalar
            "next_state": next_state.to_vector(), # 20-dim numpy array
            "constraint_cost": constraint_cost,   # Non-negative scalar
            "done": done,                         # Boolean
        })

    def train_step(self, learning_rate: float = CMDP_LEARNING_RATE) -> dict:
        """
        Perform one PPO-Lagrangian training step using the experience buffer.

        This is a SIMPLIFIED training loop using numpy only.  For production
        training with full PPO (clipped surrogate objective, GAE advantages,
        multiple epochs per batch), use the PyTorch implementation.

        The simplified algorithm:
        1. Take the last 32 transitions from the buffer (mini-batch).
        2. For each transition:
           a. Forward pass to get action probabilities and value estimate.
           b. Compute advantage: A = r - V(s)  (simplified; full PPO uses GAE).
           c. Compute policy gradient: scale by advantage.
           d. Subtract Lagrangian penalty: lambda * constraint_cost.
           e. Update policy weights via simplified SGD.
        3. Update Lagrangian multiplier lambda via dual gradient ascent:
           lambda <- max(0, lambda + lr_lambda * (avg_cost - threshold))
           - If avg_cost > threshold: lambda increases, making the policy more conservative.
           - If avg_cost < threshold: lambda decreases, giving the policy more freedom.
        4. Prune old experiences to prevent unbounded memory growth.

        PPO-Lagrangian details:
        - In full PPO, the policy gradient uses a clipped surrogate objective:
          L = min(ratio * A, clip(ratio, 1-eps, 1+eps) * A)
          where ratio = pi_new(a|s) / pi_old(a|s).
        - The Lagrangian augments the reward: r_augmented = r - lambda * c
          This converts the constrained optimization into an unconstrained one
          via the method of Lagrange multipliers.
        - Lambda update is dual gradient ascent on the Lagrangian dual function:
          max_lambda min_pi L(pi, lambda) = E[r] - lambda * (E[c] - d)

        Args:
            learning_rate: Step size for weight updates (from CMDP_LEARNING_RATE constant).

        Returns:
            Dict with training statistics:
            - avg_reward: Mean reward over the batch.
            - avg_cost: Mean constraint cost (compared to threshold for lambda update).
            - lagrange_lambda: Current Lagrangian multiplier value.
            - total_loss: Average policy gradient loss over the batch.
        """
        # Require at least 32 transitions for a meaningful gradient estimate.
        # Smaller batches produce high-variance gradients that destabilize training.
        if len(self._experience_buffer) < 32:
            return {"error": "Not enough experience (need 32+)"}

        # Use the most recent 32 transitions (on-policy: these were collected
        # under the current policy, which is important for PPO's assumptions).
        batch = self._experience_buffer[-32:]

        # Extract arrays for batch-level statistics.
        states = np.array([e["state"] for e in batch])     # (32, 20)
        actions = np.array([e["action"] for e in batch])   # (32,) integers
        rewards = np.array([e["reward"] for e in batch])   # (32,) floats
        costs = np.array([e["constraint_cost"] for e in batch])  # (32,) floats

        # ── Per-transition policy gradient update (simplified PPO) ─────────
        total_loss = 0.0
        for i, exp in enumerate(batch):
            # Forward pass: get current action probabilities and value estimate.
            probs, value, cost_est = self._forward(exp["state"])
            action_idx = exp["action"]

            # Advantage estimation (simplified).
            # Full PPO uses Generalized Advantage Estimation (GAE):
            #   A_t = sum_{l=0}^{T-t} (gamma*lambda)^l * delta_{t+l}
            #   delta_t = r_t + gamma*V(s_{t+1}) - V(s_t)
            # Here we use the simple 1-step advantage: A = r - V(s).
            # This has higher variance but is computationally simpler.
            advantage = exp["reward"] - value

            # Log probability of the taken action (for the policy gradient).
            # The 1e-8 epsilon prevents log(0) which would produce -infinity.
            log_prob = np.log(probs[action_idx] + 1e-8)

            # Lagrangian penalty: lambda * c(s, a).
            # This term subtracts from the gradient, penalizing actions that
            # incur high constraint costs.  The higher lambda is, the more
            # the policy avoids costly actions.
            cost_penalty = self.lagrange_lambda * exp["constraint_cost"]

            # Compute the gradient signal (simplified).
            # In full PPO, this would be: grad_theta log(pi(a|s)) * A_clipped
            # Here we use a simplified version:
            # - The gradient magnitude is the advantage (positive = reinforce,
            #   negative = discourage).
            # - The threshold (probs > 0.01) prevents updates to near-zero
            #   probability actions, which would cause numerical instability
            #   (similar to PPO's clipping mechanism).
            grad = advantage * (1.0 if probs[action_idx] > 0.01 else 0.0)

            # Subtract the Lagrangian cost penalty from the gradient.
            # This is the key PPO-Lagrangian step: it converts the constrained
            # optimization into an unconstrained one by augmenting the objective.
            grad -= cost_penalty

            # Update policy head weights via simplified SGD.
            # Only updates the column corresponding to the taken action.
            # The 0.01 factor is an additional learning rate scaling to prevent
            # large weight updates from single transitions.
            self.w_policy[:, action_idx] += learning_rate * grad * 0.01

            # Accumulate the policy gradient loss for monitoring.
            # Loss = -log_prob * advantage (standard REINFORCE loss).
            total_loss += -log_prob * advantage

        # ── Lagrangian multiplier update (dual gradient ascent) ────────────
        # lambda <- max(0, lambda + lr_lambda * (E[c] - d))
        # - If avg_cost > threshold: (E[c] - d) > 0, so lambda increases.
        #   This makes the policy more conservative (higher cost penalty).
        # - If avg_cost < threshold: (E[c] - d) < 0, so lambda decreases.
        #   This relaxes the constraint, letting the policy take riskier actions.
        # - max(0, ...) ensures lambda stays non-negative (it's a dual variable).
        # - 0.01 is the dual learning rate — kept small for stability.
        avg_cost = costs.mean()
        self.lagrange_lambda = max(0, self.lagrange_lambda + 0.01 * (
            avg_cost - self.constraint_threshold
        ))

        # Update training counters.
        self.episode_count += 1
        self.total_reward += rewards.sum()

        # ── Buffer management ──────────────────────────────────────────────
        # Prune old experiences to prevent unbounded memory growth.
        # Keep the most recent 500 transitions when the buffer exceeds 1000.
        # This balances memory efficiency with having enough recent data for
        # the next training step.
        if len(self._experience_buffer) > 1000:
            self._experience_buffer = self._experience_buffer[-500:]

        return {
            "avg_reward": rewards.mean(),           # Mean reward (should increase over training)
            "avg_cost": avg_cost,                   # Mean cost (should stay below threshold)
            "lagrange_lambda": self.lagrange_lambda, # Current lambda (converges to optimal dual value)
            "total_loss": total_loss / len(batch),  # Average loss (should decrease over training)
        }

    def save(self, path: str) -> None:
        """
        Save all policy weights and the Lagrangian multiplier to a .npz file.

        The saved file contains all weight matrices, bias vectors, and the
        current Lagrangian multiplier.  This allows the trained policy to be
        loaded later for inference without retraining.

        Args:
            path: File path for the .npz archive (e.g., "policy_weights.npz").
        """
        np.savez(path,
                 w1=self.w1, b1=self.b1,           # Hidden layer 1
                 w2=self.w2, b2=self.b2,           # Hidden layer 2
                 w_policy=self.w_policy, b_policy=self.b_policy,  # Policy head
                 w_value=self.w_value, b_value=self.b_value,      # Value head
                 w_cost=self.w_cost, b_cost=self.b_cost,          # Cost head
                 lagrange_lambda=np.array([self.lagrange_lambda])) # Lagrangian multiplier

    def load(self, path: str) -> None:
        """
        Load policy weights and Lagrangian multiplier from a .npz file.

        Restores the full network state from a previously saved checkpoint.
        After loading, the policy can be used for inference immediately
        without any training.

        Args:
            path: File path of the .npz archive to load.
        """
        data = np.load(path)
        # Restore all weight matrices and bias vectors.
        self.w1 = data["w1"]
        self.b1 = data["b1"]
        self.w2 = data["w2"]
        self.b2 = data["b2"]
        self.w_policy = data["w_policy"]
        self.b_policy = data["b_policy"]
        self.w_value = data["w_value"]
        self.b_value = data["b_value"]
        self.w_cost = data["w_cost"]
        self.b_cost = data["b_cost"]
        # Restore the Lagrangian multiplier.
        # Stored as a 1-element array; extract the scalar value.
        self.lagrange_lambda = float(data["lagrange_lambda"][0])
