import logging
from dataclasses import dataclass
from typing import Optional

from cmdp.state import CMDPState
from cmdp.action_space import CMDPAction

logger = logging.getLogger(__name__)


@dataclass
class RewardWeights:
    """
    Configurable weights for the multi-objective reward function.

    These weights control the relative importance of each reward component.
    They can be tuned per engagement type (e.g., OT engagements may increase
    safety_penalty weight, while aggressive pen-tests may increase information_gain).

    Positive weights encourage behavior; negative weights penalize it.
    The magnitudes determine how strongly each component influences the total reward.
    """

    # Weight for discovering new information (ports, services, OS, vulnerabilities).
    # Multiplied by the count of new findings.  Default 1.0 = baseline importance.
    information_gain: float = 1.0

    # Weight for budget efficiency (information gained per budget point).
    # Set to 0.5 because efficiency is secondary to discovery.
    # Also applies a -0.1 penalty when budget is spent with zero findings.
    budget_efficiency: float = 0.5

    # Penalty weight for safety violations (RTT spikes, timeouts).
    # Negative because these are undesirable outcomes.
    # -2.0 means each unit of RTT spike costs twice the base reward.
    safety_penalty: float = -2.0

    # Bonus weight for completing PTG milestones.
    # 0.3 = moderate incentive to make progress through the scan graph.
    completeness_bonus: float = 0.3

    # Penalty weight for target instability (stress events, breaker trips).
    # -3.0 is the heaviest penalty because instability means real harm to the target.
    instability_penalty: float = -3.0

    # Penalty for false positive findings (not currently used in compute(),
    # but available for future refinement when FP detection is integrated).
    false_positive_penalty: float = -1.0


class RewardFunction:
    """
    Computes the reward for a state-action-next_state transition.

    The reward function r(s, a, s') is the objective the CMDP policy maximizes:
        maximize E[Sigma_t gamma^t * r(s_t, a_t, s_{t+1})]

    The reward function encourages:
    - Discovering new information (ports, services, OS)
    - Spending budget efficiently (high information-per-cost ratio)
    - Completing PTG nodes (advancing through the scan plan)

    And penalizes:
    - RTT spikes and stress events (target overload indicators)
    - Breaker trips (emergency stops due to critical target impact)
    - Wasted budget (probes with no new information)
    - Skipping (small penalty to prevent the policy from always choosing "do nothing")
    """

    def __init__(self, weights: Optional[RewardWeights] = None):
        # Use default weights if none provided.
        # Custom weights allow tuning for different engagement types.
        self.weights = weights or RewardWeights()

    def compute(self, state: CMDPState, action: CMDPAction,
                next_state: CMDPState,
                findings_gained: int = 0,
                budget_spent: float = 0.0) -> float:
        """
        Compute the scalar reward for a single transition (s, a, s').

        The reward is a weighted sum of multiple components, each capturing a
        different aspect of the penetration testing objective.
        """
        reward = 0.0

        # ── Information gain ───────────────────────────────────────────────
        # Component 1: Direct findings reward.
        # Each new finding (port, service, vulnerability) adds a flat reward
        # scaled by the information_gain weight.  This is the primary incentive.
        if findings_gained > 0:
            reward += self.weights.information_gain * findings_gained

        # Component 2: OS confidence increase.
        # Improving OS detection confidence is valuable because it helps
        # the PTG select appropriate exploit modules.
        # The 2.0 multiplier makes OS confidence gains worth twice as much
        # as a single finding, because accurate OS identification is critical.
        confidence_delta = next_state.os_confidence - state.os_confidence
        if confidence_delta > 0:
            reward += self.weights.information_gain * confidence_delta * 2.0

        # Component 3: New ports discovered.
        # Each new port is worth 0.1 * information_gain, capped at 1.0 total.
        # The cap prevents a single broad port scan from dominating the reward.
        ports_delta = next_state.open_ports_count - state.open_ports_count
        if ports_delta > 0:
            reward += self.weights.information_gain * min(ports_delta * 0.1, 1.0)

        # ── Budget efficiency ──────────────────────────────────────────────
        # Component 4: Efficiency ratio (findings per budget point spent).
        # Rewards actions that achieve high information density per unit cost.
        # Capped at 2.0 to prevent the policy from over-exploiting a single
        # cheap-but-informative probe type.
        if budget_spent > 0 and findings_gained > 0:
            efficiency = findings_gained / budget_spent
            reward += self.weights.budget_efficiency * min(efficiency, 2.0)
        elif budget_spent > 0 and findings_gained == 0:
            # Wasted budget penalty: spent budget but learned nothing.
            # This discourages blindly running expensive probes on already-known services.
            # The -0.1 factor makes this a mild penalty (budget_efficiency * -0.1 = -0.05).
            reward += self.weights.budget_efficiency * -0.1

        # ── Safety penalties ───────────────────────────────────────────────
        # Component 5: RTT spike penalty.
        # If the target's RTT increased by more than 0.5x (e.g., from 1.0 to 1.5),
        # the target is becoming sluggish under load.  Penalty scales linearly
        # with the magnitude of the spike.
        # safety_penalty is negative (-2.0), so this subtracts from reward.
        rtt_delta = next_state.rtt_ratio - state.rtt_ratio
        if rtt_delta > 0.5:
            reward += self.weights.safety_penalty * rtt_delta

        # Component 6: New stress events penalty.
        # Stress events (connection resets, service restarts, memory pressure)
        # indicate the target is being harmed.  instability_penalty (-3.0) is
        # the heaviest penalty per event because stress events may cause data loss.
        stress_delta = next_state.stress_events - state.stress_events
        if stress_delta > 0:
            reward += self.weights.instability_penalty * stress_delta

        # Component 7: Timeout increase penalty.
        # More consecutive timeouts suggest the target is becoming unresponsive.
        # Penalized at 0.5x the safety_penalty weight because timeouts are less
        # severe than stress events (the target might just be slow, not damaged).
        timeout_delta = next_state.consecutive_timeouts - state.consecutive_timeouts
        if timeout_delta > 0:
            reward += self.weights.safety_penalty * timeout_delta * 0.5

        # Component 8: Circuit breaker trip penalty.
        # A breaker trip is the most severe event — it means the TIB detected
        # critical target impact and halted all probing.  The 5.0 multiplier on
        # instability_penalty (-3.0) makes this a -15.0 penalty, the largest
        # single penalty in the reward function.
        from TIB_and_PCF.TIB.TIB_structures import CircuitBreakerStatus
        if (next_state.circuit_breaker_status == CircuitBreakerStatus.TRIPPED
                and state.circuit_breaker_status != CircuitBreakerStatus.TRIPPED):
            reward += self.weights.instability_penalty * 5.0

        # ── Completeness bonus ─────────────────────────────────────────────
        # Component 9: PTG progress reward.
        # Rewards the policy for advancing through the scan plan.
        # The reward is proportional to the fraction of progress made in this step,
        # multiplied by 10 to scale it into a meaningful range (since progress
        # increments are typically small fractions like 0.05).
        if next_state.ptg_nodes_total > 0:
            progress = next_state.ptg_nodes_completed / next_state.ptg_nodes_total
            prev_progress = state.ptg_nodes_completed / max(state.ptg_nodes_total, 1)
            if progress > prev_progress:
                reward += self.weights.completeness_bonus * (progress - prev_progress) * 10

        # ── Skip penalty (small, to discourage always skipping) ────────────
        # Component 10: Skip penalty.
        # Without this, the policy could learn to always skip (guaranteed zero
        # negative reward) instead of taking informative actions.  The -0.05
        # penalty is small enough that it never outweighs a genuine safety concern.
        if action.skip:
            reward += -0.05

        return reward

    def compute_constraint_cost(self, state: CMDPState,action: CMDPAction,next_state: CMDPState) -> float:
        """
        Compute the constraint cost c(s, a, s') for the CMDP.

        In a CMDP, the policy must satisfy the constraint:
            E[Sigma_t gamma^t * c(s_t, a_t, s_{t+1})] <= d

        where d is the constraint threshold (see DRLPolicy.constraint_threshold).

        The constraint cost measures TARGET IMPACT — how much harm this action
        caused to the target.  This is separate from the reward function because:
        - The reward function is what we MAXIMIZE (information gain minus penalties).
        - The constraint cost is what we BOUND (total acceptable target impact).

        The Lagrangian multiplier lambda balances reward maximization against
        constraint satisfaction.  If cumulative cost exceeds the threshold,
        lambda increases, biasing the policy toward safer (lower-cost) actions.

        Cost components:
        - Budget consumption (each % of budget consumed adds proportional cost)
        - RTT degradation (latency increase indicates target overload)
        - Stress events (direct indicators of target harm)
        """
        cost = 0.0

        # Budget consumption component.
        # Measures what fraction of total budget was consumed by this action.
        # Dividing by 100 converts from percentage to fraction [0, 1].
        # WHY budget is a constraint cost: consuming budget limits future actions,
        # so rapid budget burn is itself a form of "impact" on the engagement.
        budget_delta = state.budget_remaining_pct - next_state.budget_remaining_pct
        if budget_delta > 0:
            cost += budget_delta / 100.0

        # RTT degradation component.
        # Measures how much the target's response time worsened.
        # Weighted by 0.5 because RTT increase is a moderate impact signal —
        # it may indicate overload but could also be due to network congestion.
        rtt_delta = max(0, next_state.rtt_ratio - state.rtt_ratio)
        cost += rtt_delta * 0.5

        # Stress events component.
        # Each new stress event adds 1.0 to the cost.
        # Weighted at 1.0 (the highest weight) because stress events are the
        # most direct indicator of target harm (service disruption, crashes, etc.).
        stress_delta = max(0, next_state.stress_events - state.stress_events)
        cost += stress_delta * 1.0

        return cost
