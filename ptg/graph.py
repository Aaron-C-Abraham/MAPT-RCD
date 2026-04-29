import logging
from typing import Dict, List, Optional

from ptg.models import PTGNode, PTGNodeStatus, StopCondition
# CircuitBreakerStatus is from the TIB-PCF (Per-Connection Firewall) layer.
# It represents whether the circuit breaker for a target is ACTIVE (normal)
# or TRIPPED (all testing must stop immediately).
from TIB_and_PCF.TIB.TIB_structures import CircuitBreakerStatus

logger = logging.getLogger(__name__)


class PTGGraph:
    """
    Runtime engine for a TIB-aware Penetration Task Graph.

    One PTGGraph per target device. Manages the DAG of pentest actions,
    resolves dependencies, and supports budget-aware pruning.

    The graph structure:
      - Nodes: PTGNode instances, each representing one pentest action
      - Edges: Defined implicitly via each node's `dependencies` list (forward
        edges) and `children` list (reverse edges, maintained automatically).
        An edge from A to B means "A must complete before B can start."
      - Fallback edges: A special edge type where node A has a fallback_node_id
        pointing to node B. If A cannot execute (budget, failure), B is
        activated as a cheaper/safer alternative.

    Execution model:
      The consuming engine uses a loop:
        1. Call get_ready_nodes() to find nodes whose deps are all met
        2. Pick the highest-priority ready node
        3. Call mark_running() to record it as active
        4. Execute the tool
        5. Call mark_completed() or mark_failed()
        6. Optionally call mark_validated() after validation oracle checks
        7. Repeat until is_complete() returns True
    """

    def __init__(self, target_ip: str, total_budget: float = 0.0):
        """
        Initialize a PTG for a single target device.

        Args:
            target_ip: The IP address of the target device this graph covers.
            total_budget: Total budget points allocated for testing this target.
                          Budget comes from the TIB configuration (TIER_TIB_DEFAULTS).
                          A value of 0.0 means unlimited budget.
        """
        self.target_ip = target_ip
        self.total_budget = total_budget
        # _nodes: internal dictionary mapping node_id -> PTGNode for O(1) lookup
        self._nodes: Dict[str, PTGNode] = {}
        # _execution_order: records the order in which nodes were actually executed
        # (appended to in mark_running), useful for post-hoc analysis and reporting
        self._execution_order: List[str] = []

    # ── Node management ────────────────────────────────────────────────────────

    def add_node(self, node: PTGNode) -> str:
        """
        Add a node to the graph and wire up parent-child relationships.

        This method does two things:
          1. Stores the node in the internal dictionary
          2. For each dependency listed in node.dependencies, finds the parent
             node and adds this node's ID to the parent's children list. This
             maintains the reverse edge so parents know who depends on them.

        The node's target_ip is also overwritten with this graph's target_ip
        to ensure consistency (all nodes in a graph target the same device).

        Args:
            node: The PTGNode to add to this graph.

        Returns:
            The node_id of the added node (for convenience in chaining).
        """
        # Ensure the node is tagged with this graph's target IP
        node.target_ip = self.target_ip
        # Store the node for O(1) lookup by ID
        self._nodes[node.node_id] = node

        # Maintain reverse edges: for each dependency (parent), register this
        # node as a child so the parent knows who depends on it. This is used
        # for cascade operations (e.g., blocking children when a parent fails).
        for dep_id in node.dependencies:
            parent = self._nodes.get(dep_id)
            if parent and node.node_id not in parent.children:
                parent.children.append(node.node_id)

        return node.node_id

    def get_node(self, node_id: str) -> Optional[PTGNode]:
        """Look up a node by its unique ID. Returns None if not found."""
        return self._nodes.get(node_id)

    def get_all_nodes(self) -> List[PTGNode]:
        """Return all nodes in the graph as a list (order is insertion order)."""
        return list(self._nodes.values())

    # ── Dependency resolution ──────────────────────────────────────────────────

    def get_ready_nodes(self) -> List[PTGNode]:
        """
        Return nodes whose dependencies are all met and that are eligible
        for execution. These are nodes currently in PENDING status whose
        every dependency is in a terminal state (COMPLETED, VALIDATED,
        SKIPPED, or FALLBACK).

        Side effect: transitions matching nodes from PENDING to READY status.

        The returned list is sorted by priority descending (highest priority
        first), so the caller can simply pick the first node to execute next.

        Returns:
            List of PTGNode instances now in READY status, sorted by
            descending priority.
        """
        ready = []
        for node in self._nodes.values():
            # Only consider nodes that haven't been processed yet
            if node.status != PTGNodeStatus.PENDING:
                continue
            # Check if all prerequisite nodes have reached a terminal state
            if self._dependencies_met(node):
                # Transition from PENDING -> READY (node is now eligible)
                node.status = PTGNodeStatus.READY
                ready.append(node)

        # Sort by priority descending so the most important nodes are first
        ready.sort(key=lambda n: n.priority, reverse=True)
        return ready

    def _dependencies_met(self, node: PTGNode) -> bool:
        """
        Check if all of a node's dependencies are in a terminal state.

        Terminal states are those where the dependency has finished and will
        not change further: COMPLETED, VALIDATED, SKIPPED, or FALLBACK.
        Note that FAILED is NOT terminal for dependency purposes — a failed
        dependency blocks its children (they cannot proceed).

        If a dependency node_id does not exist in the graph (perhaps it was
        removed or never added), it is treated as met. This is a permissive
        default that allows the graph to function even with missing nodes.

        Args:
            node: The node whose dependencies to check.

        Returns:
            True if all dependencies are in a terminal state (or missing).
        """
        # These statuses mean the dependency has concluded and dependents can proceed
        terminal = {PTGNodeStatus.COMPLETED, PTGNodeStatus.VALIDATED,
                    PTGNodeStatus.SKIPPED, PTGNodeStatus.FALLBACK}
        for dep_id in node.dependencies:
            dep = self._nodes.get(dep_id)
            if dep is None:
                continue  # Missing dependency is treated as met (permissive default)
            if dep.status not in terminal:
                return False  # At least one dependency is not yet resolved
        return True

    # ── Status updates ─────────────────────────────────────────────────────────
    # These methods transition nodes through their lifecycle. The pentest
    # execution engine calls them as actions progress.

    def mark_running(self, node_id: str) -> None:
        """
        Transition a node to RUNNING status and record it in execution order.

        Called by the engine right before executing the node's tool. The node
        is appended to _execution_order for post-hoc analysis.
        """
        node = self._nodes.get(node_id)
        if node:
            node.status = PTGNodeStatus.RUNNING
            # Record the execution order for reporting and replay
            self._execution_order.append(node_id)

    def mark_completed(self, node_id: str, result: dict = None,
                       actual_cost: float = 0.0) -> None:
        """
        Transition a node to COMPLETED status after successful execution.

        Stores the tool's output and the actual budget cost consumed. The
        actual cost may differ from the estimate (e.g., if fewer packets
        were needed than predicted).

        Args:
            node_id: ID of the node that completed.
            result: Dictionary of tool output (findings, data collected).
            actual_cost: Real budget points consumed during execution.
        """
        node = self._nodes.get(node_id)
        if node:
            node.status = PTGNodeStatus.COMPLETED
            node.result = result               # Store tool output for later analysis
            node.actual_budget_cost = actual_cost  # Record real cost for budget tracking

    def mark_validated(self, node_id: str) -> None:
        """
        Transition a COMPLETED node to VALIDATED status after its findings
        have been confirmed by validation oracles.

        Only nodes in COMPLETED status can be validated — this prevents
        accidentally validating failed or skipped nodes.
        """
        node = self._nodes.get(node_id)
        # Guard: only transition from COMPLETED to prevent invalid state changes
        if node and node.status == PTGNodeStatus.COMPLETED:
            node.status = PTGNodeStatus.VALIDATED

    def mark_failed(self, node_id: str, error: str = "") -> None:
        """
        Transition a node to FAILED status when execution encounters an error.

        The error string is stored for diagnostics. Note: FAILED is NOT a
        terminal state for dependency resolution — children of a failed node
        will remain blocked unless the fallback mechanism is used.

        Args:
            node_id: ID of the failed node.
            error: Human-readable error description.
        """
        node = self._nodes.get(node_id)
        if node:
            node.status = PTGNodeStatus.FAILED
            node.error = error  # Store error message for diagnostics/reporting

    def mark_skipped(self, node_id: str, reason: str = "") -> None:
        """
        Transition a node to SKIPPED status. Used when a node is pruned
        due to budget constraints or deemed unnecessary.

        SKIPPED is a terminal state that allows dependent nodes to proceed
        (unlike FAILED, which blocks dependents).

        Args:
            node_id: ID of the node to skip.
            reason: Why this node was skipped (e.g., budget insufficient).
        """
        node = self._nodes.get(node_id)
        if node:
            node.status = PTGNodeStatus.SKIPPED
            node.error = reason  # Reuse error field to store the skip reason

    def activate_fallback(self, node_id: str) -> Optional[PTGNode]:
        """
        Mark a node as FALLBACK and activate its fallback alternative.

        When a node cannot execute (too expensive, failed, stop condition
        triggered), this method:
          1. Sets the original node to FALLBACK status
          2. Finds the fallback node pointed to by fallback_node_id
          3. Promotes the fallback node from PENDING to READY

        The fallback node is typically a cheaper or less aggressive alternative
        (e.g., a TCP connect scan instead of a SYN scan, or passive OS ID
        instead of active OS probing).

        Args:
            node_id: ID of the node being abandoned in favor of its fallback.

        Returns:
            The fallback PTGNode (now in READY status) if one exists and was
            successfully activated, or None if no fallback is available.
        """
        node = self._nodes.get(node_id)
        # Guard: node must exist and must have a fallback configured
        if not node and not node.fallback_node_id:
            return None

        # Mark the original node as abandoned
        node.status = PTGNodeStatus.FALLBACK
        # Look up the fallback node and promote it to READY if it's still PENDING
        fallback = self._nodes.get(node.fallback_node_id)
        if fallback and fallback.status == PTGNodeStatus.PENDING:
            fallback.status = PTGNodeStatus.READY
            return fallback
        return None

    # ── Budget-aware operations ────────────────────────────────────────────────
    # Budget tracking is central to the TIB framework. Each action has an
    # estimated impact cost, and the graph ensures total spending stays
    # within the allocated budget for the target device.

    def estimate_remaining_cost(self) -> float:
        """
        Sum of estimated costs of all nodes that have not yet executed
        (PENDING or READY status). This represents the projected budget
        needed to complete the remaining graph.

        Returns:
            Total estimated budget points for unexecuted nodes.
        """
        return sum(
            n.estimated_budget_cost
            for n in self._nodes.values()
            if n.status in (PTGNodeStatus.PENDING, PTGNodeStatus.READY)
        )

    def total_spent(self) -> float:
        """
        Sum of actual costs of all nodes that have executed, including
        failed nodes (they still consumed budget even though they failed).

        Returns:
            Total actual budget points consumed so far.
        """
        return sum(
            n.actual_budget_cost
            for n in self._nodes.values()
            # Include FAILED because failed actions still consumed real budget
            if n.status in (PTGNodeStatus.COMPLETED, PTGNodeStatus.VALIDATED,
                            PTGNodeStatus.FAILED)
        )

    def prune_by_budget(self, remaining_budget: float) -> List[str]:
        """
        Mark nodes as SKIPPED if they cannot fit within the remaining budget.

        Budget pruning algorithm:
          1. Collect all unexecuted nodes (PENDING or READY status)
          2. Sort by priority ASCENDING (lowest priority first) — this ensures
             the least important nodes are pruned first
          3. Walk through the sorted list, subtracting each node's estimated
             cost from the remaining budget
          4. If a node's cost exceeds the remaining budget:
             a. Try its fallback node first — if the fallback is cheaper and
                fits within budget, activate it instead (FALLBACK status)
             b. If no fallback fits, skip the node entirely (SKIPPED status)

        This greedy approach ensures that the most important (highest priority)
        nodes are preserved while lower-priority nodes are sacrificed to stay
        within budget.

        Args:
            remaining_budget: Budget points still available for this target.

        Returns:
            List of node IDs that were skipped (pruned).
        """
        # Collect all nodes that haven't been executed yet
        pending = [
            n for n in self._nodes.values()
            if n.status in (PTGNodeStatus.PENDING, PTGNodeStatus.READY)
        ]
        # Sort by priority ascending — prune lowest priority first, so that
        # high-priority nodes (like discovery and fingerprinting) are preserved
        pending.sort(key=lambda n: n.priority)

        skipped = []
        budget_left = remaining_budget

        # Walk through nodes from lowest to highest priority
        for node in pending:
            if node.estimated_budget_cost > budget_left:
                # This node is too expensive for the remaining budget.
                # Try to activate a cheaper fallback node instead.
                if node.fallback_node_id:
                    fb = self._nodes.get(node.fallback_node_id)
                    # Only use fallback if it exists AND fits within budget
                    if fb and fb.estimated_budget_cost <= budget_left:
                        # Abandon this node in favor of the cheaper fallback
                        node.status = PTGNodeStatus.FALLBACK
                        fb.status = PTGNodeStatus.READY
                        budget_left -= fb.estimated_budget_cost
                        continue  # Fallback activated successfully, move on

                # No fallback available or fallback also too expensive — skip
                node.status = PTGNodeStatus.SKIPPED
                node.error = f"Budget insufficient ({node.estimated_budget_cost:.1f} > {budget_left:.1f})"
                skipped.append(node.node_id)
            else:
                # Node fits within budget — reserve its cost
                budget_left -= node.estimated_budget_cost

        # Log a summary if any nodes were pruned
        if skipped:
            logger.info(
                f"[PTG {self.target_ip}] Pruned {len(skipped)} nodes "
                f"due to budget constraints"
            )
        return skipped

    # ── Stop condition checking ────────────────────────────────────────────────

    def check_stop_conditions(self, node: PTGNode,
                              budget_remaining_pct: float = 100.0,
                              rtt_ratio: float = 1.0,
                              consecutive_timeouts: int = 0,
                              breaker_status: CircuitBreakerStatus = CircuitBreakerStatus.ACTIVE
                              ) -> Optional[StopCondition]:
        """
        Check if any stop condition is triggered for a node given current
        runtime metrics.

        This method iterates through the node's stop conditions and compares
        each against the current runtime state. The first triggered condition
        is returned (short-circuit evaluation). If no condition is triggered,
        returns None.

        The runtime metrics come from the TIB-PCF layer and the pentest
        execution engine:
          - budget_remaining_pct: How much budget is left as a percentage (0-100)
          - rtt_ratio: Current RTT divided by baseline RTT (1.0 = normal)
          - consecutive_timeouts: How many probes in a row timed out
          - breaker_status: Whether the circuit breaker has tripped

        Args:
            node: The PTGNode whose stop conditions to evaluate.
            budget_remaining_pct: Remaining budget as a percentage (0-100).
            rtt_ratio: Ratio of current RTT to baseline RTT.
            consecutive_timeouts: Number of consecutive probe timeouts.
            breaker_status: Circuit breaker state (ACTIVE or TRIPPED).

        Returns:
            The first StopCondition that fired, or None if all conditions pass.
        """
        for sc in node.stop_conditions:
            # Budget check: stop if remaining budget percentage is below threshold
            if sc.check_type == "budget" and budget_remaining_pct < sc.threshold:
                return sc
            # RTT check: stop if RTT has spiked above the multiplier threshold
            elif sc.check_type == "rtt" and rtt_ratio > sc.threshold:
                return sc
            # Timeout check: stop after N consecutive timeouts
            elif sc.check_type == "timeout" and consecutive_timeouts >= sc.threshold:
                return sc
            # Breaker check: stop immediately if circuit breaker has tripped
            elif sc.check_type == "breaker" and breaker_status == CircuitBreakerStatus.TRIPPED:
                return sc
        return None  # No stop condition triggered — safe to continue

    # ── Graph queries ──────────────────────────────────────────────────────────

    def get_nodes_by_phase(self, phase: str) -> List[PTGNode]:
        """Return all nodes belonging to a specific pentest phase (e.g., 'HOST_DISCOVERY')."""
        return [n for n in self._nodes.values() if n.phase == phase]

    def get_nodes_by_status(self, status: PTGNodeStatus) -> List[PTGNode]:
        """Return all nodes currently in the given status (e.g., PTGNodeStatus.FAILED)."""
        return [n for n in self._nodes.values() if n.status == status]

    def is_complete(self) -> bool:
        """
        Check whether the graph has finished executing.

        Returns True if ALL nodes are in a terminal state, meaning no more
        actions can be taken. Terminal states include completed, validated,
        skipped, failed, fallback, and blocked.

        The execution engine uses this to know when to stop its main loop.
        """
        terminal = {PTGNodeStatus.COMPLETED, PTGNodeStatus.VALIDATED,
                    PTGNodeStatus.SKIPPED, PTGNodeStatus.FAILED,
                    PTGNodeStatus.FALLBACK, PTGNodeStatus.BLOCKED}
        return all(n.status in terminal for n in self._nodes.values())

    def get_execution_order(self) -> List[str]:
        """
        Return the list of node IDs in the order they were actually executed.
        Useful for post-hoc analysis, reporting, and replaying the pentest.
        """
        return list(self._execution_order)

    # ── Summary ────────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """
        Generate a summary of the graph's current state for reporting.

        Returns a dictionary with:
          - target_ip: Which device this graph covers
          - total_nodes: How many nodes are in the graph
          - total_budget: The allocated budget
          - total_spent: How much budget has been consumed
          - estimated_remaining: How much more budget the remaining nodes need
          - by_status: Count of nodes in each status (for progress tracking)
          - is_complete: Whether all nodes have reached terminal states
        """
        # Count nodes in each status for a quick progress overview
        status_counts = {}
        for n in self._nodes.values():
            s = n.status.value  # Use the string value of the enum as the key
            status_counts[s] = status_counts.get(s, 0) + 1

        return {
            "target_ip": self.target_ip,
            "total_nodes": len(self._nodes),
            "total_budget": self.total_budget,
            "total_spent": self.total_spent(),
            "estimated_remaining": self.estimate_remaining_cost(),
            "by_status": status_counts,
            "is_complete": self.is_complete(),
        }

    def to_dict(self) -> dict:
        """
        Serialize the entire graph to a dictionary for JSON export.

        Includes the target IP, budget, and all nodes (each serialized
        via PTGNode.to_dict()). Used for persistence, API responses,
        and inter-process communication.
        """
        return {
            "target_ip": self.target_ip,
            "total_budget": self.total_budget,
            "nodes": [n.to_dict() for n in self._nodes.values()],
        }
