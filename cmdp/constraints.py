import logging
from typing import Optional
from cmdp.state import CMDPState
from cmdp.action_space import CMDPAction
from TIB_and_PCF.TIB.TIB_structures import DeviceTier, CircuitBreakerStatus

logger = logging.getLogger(__name__)


class ConstraintViolation:
    """
    Describes a constraint that would be violated by a proposed action.

    Used as the return type of SafetyConstraints.check() when an action
    is blocked.  Contains the constraint name, a human-readable reason,
    and a severity level indicating whether the constraint is absolute
    (hard) or advisory (soft).
    """
    def __init__(self, constraint_name: str, reason: str, severity: str = "hard"):
        self.constraint_name = constraint_name
        self.reason = reason
        self.severity = severity  # "hard" = absolute block, "soft" = warning

    def __str__(self):
        """Format for logging: [severity] name: reason."""
        return f"[{self.severity}] {self.constraint_name}: {self.reason}"


class SafetyConstraints:
    """
    Hard safety constraints that the CMDP must respect.

    These are checked BEFORE any action is executed by the orchestrator.
    A constraint violation blocks the action entirely — the policy's output
    is overridden.  This is the "safety layer" that prevents the DRL policy
    from taking catastrophic actions even if its learned policy is imperfect.

    The six constraints are checked in priority order:
    1. Budget cannot exceed TIB maximum.
       WHY hard: Operating beyond budget violates the engagement contract.

    2. Circuit breaker trip halts all actions.
       WHY hard: A tripped breaker means the target is in critical distress;
       further probing could cause permanent damage or crash the device.

    3. CRITICAL devices cannot receive Tier 3+ (aggressive) probes.
       WHY hard: CRITICAL devices include medical equipment, safety PLCs,
       and other systems where disruption could cause physical harm.

    4. Safety officer veto is absolute.
       WHY hard: A human safety officer has engagement-level authority;
       their judgment overrides the automated policy.

    5. OT devices require preflight approval for aggressive probes.
       WHY hard: OT/ICS environments control physical processes;
       unvetted aggressive probes could disrupt manufacturing, power, etc.

    6. Rate limit cannot be set above config maximum.
       WHY soft: An out-of-bounds rate is a configuration error, not a
       safety hazard.  The action can be corrected rather than blocked.
    """

    def check(self, state: CMDPState, action: CMDPAction,
              estimated_cost: float = 0.0) -> Optional[ConstraintViolation]:
        """
        Check if a proposed action violates any hard constraint.

        This method is called by the orchestrator BEFORE executing any action.
        The constraints are checked in priority order: the first violation found
        is returned immediately (fail-fast) because there's no point checking
        further constraints if the action is already blocked.
        """
        # Constraint 1: Budget — check if budget is exhausted or insufficient.
        violation = self._check_budget(state, estimated_cost)
        if violation:
            return violation

        # Constraint 2: Circuit breaker — check if breaker is tripped or exhausted.
        violation = self._check_breaker(state)
        if violation:
            return violation

        # Constraint 3: CRITICAL tier — check if aggressive modes are blocked.
        violation = self._check_critical_tier(state, action)
        if violation:
            return violation

        # Constraint 4: Safety officer — check if OT safety officer blocks exploitation.
        violation = self._check_safety_officer(state, action)
        if violation:
            return violation

        # Constraint 5: Rate bounds — check if rate multiplier is in valid range.
        violation = self._check_rate_bounds(state, action)
        if violation:
            return violation

        # All constraints passed — action is allowed.
        return None

    def _check_budget(self, state: CMDPState,
                      estimated_cost: float) -> Optional[ConstraintViolation]:
        """
        Check budget constraints (HARD).

        Two sub-checks:
        1. Budget fully exhausted (remaining_pct <= 0): No actions are permitted
           because the engagement contract's resource limit has been reached.
        2. Action cost exceeds remaining budget: The specific action is too
           expensive for the remaining budget, even though some budget remains.

        Both only apply when budget_total > 0 (i.e., a budget limit is configured).
        If budget_total is 0, the engagement has no budget limit (unlimited probing).
        """
        # Check 1: Budget fully exhausted.
        if state.budget_total > 0 and state.budget_remaining_pct <= 0:
            return ConstraintViolation(
                "budget_exhausted",
                "TIB budget fully spent — no further actions permitted",
            )

        # Check 2: Action cost exceeds remaining budget.
        # Convert remaining percentage to absolute budget points for comparison.
        # remaining_points = budget_total * budget_remaining_pct / 100
        if (state.budget_total > 0
                and estimated_cost > state.budget_total * state.budget_remaining_pct / 100):
            return ConstraintViolation(
                "budget_insufficient",
                f"Action cost {estimated_cost:.1f} exceeds remaining budget",
            )
        return None

    def _check_breaker(self, state: CMDPState) -> Optional[ConstraintViolation]:
        """
        Check circuit breaker constraint (HARD).

        The circuit breaker is a safety mechanism in the TIB that monitors
        target health in real-time.  It has four states:
        - ACTIVE: Normal operation, probing is allowed.
        - PAUSED: Temporarily halted (e.g., waiting for RTT to recover).
          Not checked here because PAUSED allows resumption after a cooldown.
        - TRIPPED: Emergency stop triggered by critical target impact indicators.
          ALL actions are blocked because the target is in distress.
        - EXHAUSTED: Budget fully consumed (alternative budget enforcement path).
          ALL actions are blocked because no budget remains.
        """
        if state.circuit_breaker_status == CircuitBreakerStatus.TRIPPED:
            return ConstraintViolation(
                "breaker_tripped",
                "Circuit breaker is tripped — all actions blocked",
            )
        if state.circuit_breaker_status == CircuitBreakerStatus.EXHAUSTED:
            return ConstraintViolation(
                "budget_exhausted",
                "Budget exhausted via circuit breaker",
            )
        return None

    def _check_critical_tier(self, state: CMDPState,
                             action: CMDPAction) -> Optional[ConstraintViolation]:
        """
        Check CRITICAL-tier device restrictions (HARD).

        CRITICAL-tier devices include medical equipment, safety PLCs,
        fire suppression controllers, and other systems where disruption
        could cause physical harm to people or damage to equipment.

        These devices can ONLY receive passive, low-impact, or targeted probes.
        The following aggressive modes are BLOCKED:
        - "full": Full TCP port scan (65535 probes)
        - "full_65535": Explicit all-port scan
        - "top_1000": Top 1000 port scan (still too many probes)
        - "moderate": Moderate exploitation check
        - "aggressive": Aggressive exploitation
        - "comprehensive": Comprehensive vulnerability assessment

        WHY these specific modes:
        These modes generate significant network traffic and/or attempt to
        interact deeply with services.  On CRITICAL devices, even a TCP
        handshake with certain ports could trigger safety shutdowns.

        Non-CRITICAL devices skip this check entirely (early return).
        """
        # Early return for non-CRITICAL devices — no restrictions apply.
        if state.device_tier != DeviceTier.CRITICAL:
            return None

        # Set of blocked modes for CRITICAL devices.
        # These generate too much traffic or interact too deeply with services.
        blocked_modes = {
            "full", "full_65535", "top_1000", "moderate",
            "aggressive", "comprehensive",
        }
        if action.safe_mode in blocked_modes:
            return ConstraintViolation(
                "critical_tier_block",
                f"Mode '{action.safe_mode}' is blocked on CRITICAL-tier devices",
            )
        return None

    def _check_safety_officer(self, state: CMDPState,
                              action: CMDPAction) -> Optional[ConstraintViolation]:
        """
        Check safety officer constraints (HARD).

        When a safety officer is active AND the engagement is in OT mode,
        exploitation-class probes are blocked on all devices EXCEPT ROBUST-tier.
        """
        # Early return: no safety officer means no officer-level restrictions.
        if not state.safety_officer_active:
            return None

        # In OT mode, block exploitation on non-ROBUST devices.
        # ROBUST devices (servers, firewalls) can handle exploit checks safely.
        if state.is_ot_environment and state.device_tier != DeviceTier.ROBUST:
            exploit_modes = {"safe", "moderate", "aggressive", "comprehensive", "top_5"}
            if action.safe_mode in exploit_modes:
                return ConstraintViolation(
                    "ot_safety_block",
                    f"OT safety officer blocks exploitation mode '{action.safe_mode}' "
                    f"on {state.device_tier.name} device",
                )
        return None

    def _check_rate_bounds(self, state: CMDPState,
                           action: CMDPAction) -> Optional[ConstraintViolation]:
        """
        Check rate multiplier bounds (SOFT).

        The rate multiplier must be in [0.0, 1.0]:
        - 0.0 = no packets sent (equivalent to skip but with tool overhead)
        - 1.0 = maximum configured packet rate

        Values outside this range indicate a bug in the policy or action space
        rather than a safety hazard.  This is the only SOFT constraint: it
        generates a warning rather than an absolute block.

        WHY soft instead of hard:
        An out-of-bounds rate can be clamped to [0, 1] by the executor without
        causing harm.  The warning alerts operators to a potential policy bug.
        """
        if action.rate_multiplier < 0.0 or action.rate_multiplier > 1.0:
            return ConstraintViolation(
                "rate_out_of_bounds",
                f"Rate multiplier {action.rate_multiplier} outside [0.0, 1.0]",
                severity="soft",  # Advisory — can be corrected by clamping
            )
        return None

    def get_constraint_cost(self, state: CMDPState, action: CMDPAction,
                            next_state: CMDPState) -> float:
        """
        Compute the constraint cost c(s, a, s') for a state transition.

        This is the 'c' in the CMDP constraint:
            E[Sigma_t gamma^t * c(s_t, a_t, s_{t+1})] <= d

        where d is the constraint threshold (DRLPolicy.constraint_threshold).

        The constraint cost measures TARGET IMPACT — how much the action
        harmed or stressed the target device.  It is distinct from the reward
        function because:
        - Reward is what we MAXIMIZE (net benefit of probing).
        - Constraint cost is what we BOUND (total acceptable harm).

        The DRL policy uses this cost to update the Lagrangian multiplier:
        - If cumulative cost > d: lambda increases, biasing toward safe actions.
        - If cumulative cost < d: lambda decreases, allowing more aggressive actions.

        Cost components and their weights:

        1. Budget consumption (weight: 1.0 per 100% consumed):
           Each percentage point of budget consumed adds 0.01 to the cost.
           WHY: Budget consumption is a proxy for engagement resource usage.
           It's weighted lower per unit because it's an expected part of probing.

        2. RTT degradation (weight: 0.3 per unit RTT ratio increase):
           Each unit increase in RTT ratio adds 0.3 to the cost.
           WHY: RTT increase indicates the target is becoming sluggish.
           Weighted moderately because RTT can increase due to network
           conditions (not just our probing).

        3. Stress events (weight: 0.5 per event):
           Each new stress event adds 0.5 to the cost.
           WHY: Stress events are direct indicators of target harm
           (service restarts, connection resets, etc.).  Weighted higher
           than RTT because they are more clearly attributable to our probing.

        4. Timeout increase (weight: 0.2 per timeout):
           Each new consecutive timeout adds 0.2 to the cost.
           WHY: Timeouts suggest the target may be overloaded or has crashed.
           Weighted lower than stress events because timeouts can also
           result from network issues unrelated to our probing.
        """
        cost = 0.0

        # Component 1: Budget consumption rate.
        # Measures what fraction of total budget was consumed in this transition.
        # The delta is in percentage points (0-100), divided by 100 to get fraction.
        # max(0, ...) ensures we don't get negative cost if budget somehow increases
        # (which shouldn't happen but is defensive programming).
        if state.budget_total > 0:
            budget_consumed = (
                (state.budget_remaining_pct - next_state.budget_remaining_pct) / 100.0
            )
            cost += max(0, budget_consumed)

        # Component 2: RTT impact.
        # Measures how much the target's response time worsened.
        # max(0, ...) ensures we only count RTT INCREASES (degradation),
        # not improvements (which would be a good thing, not a cost).
        # Weight 0.3: moderate because RTT can fluctuate due to network conditions.
        rtt_increase = max(0, next_state.rtt_ratio - state.rtt_ratio)
        cost += rtt_increase * 0.3

        # Component 3: New stress events.
        # Each new stress event is a direct indicator of target harm.
        # max(0, ...) ensures we only count NEW events, not decreases
        # (stress_events is cumulative and should only increase).
        # Weight 0.5: higher than RTT because stress events are more clearly
        # caused by our probing.
        new_stress = max(0, next_state.stress_events - state.stress_events)
        cost += new_stress * 0.5

        # Component 4: Timeout increase.
        # New consecutive timeouts suggest the target is becoming unresponsive.
        # max(0, ...) ensures we only count increases (note: consecutive_timeouts
        # can decrease if a probe succeeds, breaking the timeout streak).
        # Weight 0.2: lower than stress events because timeouts are less
        # definitively caused by our probing (could be network issues).
        new_timeouts = max(0, next_state.consecutive_timeouts - state.consecutive_timeouts)
        cost += new_timeouts * 0.2

        return cost
