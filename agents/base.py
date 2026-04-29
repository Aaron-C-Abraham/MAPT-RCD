"""
agents/base.py — Base agent class and inter-agent messaging.

PURPOSE:
    Defines the foundational abstractions for the TRUCE-PT multi-agent system:

    1. AgentRole enum     — enumerates all 9 specialist agents + coordinator.
    2. MessageType enum   — categorizes inter-agent messages (request, result,
                            alert, veto, status, query).
    3. AgentMessage       — typed envelope for inter-agent communication.
    4. AgentResult        — standardized return type from every agent's execute().
    5. MessageBus         — simple in-process pub/sub bus with per-role queues.
    6. BaseAgent          — abstract base class that all agents inherit from.

ARCHITECTURE:
    All TRUCE-PT agents inherit from BaseAgent and communicate through a shared
    MessageBus stored in the SessionContext. The bus uses a "mailbox" pattern:
    each AgentRole has its own queue. Agents push messages into a recipient's
    queue and the recipient pulls them when it is ready.

    Communication flows (key patterns):
      Discovery  ──RESULT──>  TargetProfiling   (devices found)
      Profiling  ──RESULT──>  Planner           (tier summary)
      Profiling  ──ALERT───>  SafetyOfficer     (OT devices detected)
      Profiling  ──RESULT──>  FleetReasoner     (device count)
      Planner    ──RESULT──>  ToolOrchestrator  (PTGs built)
      ToolOrch   ──RESULT──>  Evidence          (per-action results)
      ToolOrch   ──REQUEST─>  Validator         (validation needed)
      ImpactMon  ──ALERT───>  ToolOrchestrator  (breaker/RTT/budget)
      ImpactMon  ──VETO────>  ToolOrchestrator  (block stressed CRITICAL)
      SafetyOff  ──VETO────>  ToolOrchestrator  (block unsafe actions)
      FleetReas  ──RESULT──>  Planner           (clusters ready)
      ImpactMon  ──ALERT───>  Coordinator       (subnet stress)
      Validator  ──RESULT──>  ToolOrchestrator  (validation outcomes)

Paper reference: Section VI-B (Agent Roles)
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from agents.session_context import SessionContext

# Module-level logger; child loggers are created per-agent in BaseAgent.__init__.
logger = logging.getLogger(__name__)


# ── AgentRole ──────────────────────────────────────────────────────────────────
# Enumerates every distinct role in the TRUCE-PT multi-agent system.
# Each role maps 1-to-1 to an agent class AND to a dedicated queue in the
# MessageBus, so messages can be addressed by role rather than by object ref.
class AgentRole(Enum):
    DISCOVERY = "discovery"                # Phase 0-1: passive recon + active host discovery
    TARGET_PROFILING = "target_profiling"  # Phase 2-3: fingerprinting + TIB tier assignment
    PLANNER = "planner"                    # Builds Per-Target Graphs (PTGs) from TIB data
    TOOL_ORCHESTRATOR = "tool_orchestrator"  # Executes PTG nodes via IC-ToolSpec contracts
    IMPACT_MONITOR = "impact_monitor"      # Watches RTT / circuit-breaker / budget stress
    VALIDATOR = "validator"                # Validates findings with oracle recipes
    SAFETY_OFFICER = "safety_officer"      # OT safety gating — can veto any action
    EVIDENCE = "evidence"                  # Manages PCF DAG, builds proof bundles
    FLEET_REASONER = "fleet_reasoner"      # Clusters devices; propagates hypotheses
    POST_EXPLOITATION = "post_exploitation"  # Reverse shell, lateral movement, attack graph
    COORDINATOR = "coordinator"            # Top-level orchestrator (not a BaseAgent itself)


# ── MessageType ────────────────────────────────────────────────────────────────
# Classifies the intent of an inter-agent message so that recipients can filter
# or dispatch without inspecting the payload. The VETO type is particularly
# important: it is the mechanism through which SafetyOfficer and ImpactMonitor
# can unilaterally block actions on critical or stressed devices.
class MessageType(Enum):
    REQUEST = "request"  # "Please do something" (e.g., validate a finding)
    RESULT = "result"    # "Here are my outputs" (e.g., discovered hosts)
    ALERT = "alert"      # "Something needs attention" (e.g., RTT spike)
    VETO = "veto"        # "I am blocking this action" (safety / impact gate)
    STATUS = "status"    # Informational status update (e.g., execution complete)
    QUERY = "query"      # Ad-hoc data request between agents


# ── AgentMessage ───────────────────────────────────────────────────────────────
@dataclass
class AgentMessage:
    """
    Inter-agent message envelope.

    Every message travels through the MessageBus and has:
      - sender / recipient : which agent sent it and which should receive it.
      - message_type       : REQUEST, RESULT, ALERT, VETO, STATUS, or QUERY.
      - payload            : arbitrary dict carrying the actual data.
      - timestamp          : auto-populated creation time (epoch seconds).
      - message_id         : unique id assigned by the bus if left empty.
      - in_reply_to        : links a reply back to the original message for
                             correlation (e.g., Validator replying to a
                             validation REQUEST from ToolOrchestrator).
    """
    sender: AgentRole           # Which agent created this message
    recipient: AgentRole        # Which agent should receive this message
    message_type: MessageType   # Semantic category (request / result / alert / veto / …)
    payload: Dict               # Free-form data dictionary specific to the message
    timestamp: float = field(default_factory=time.time)  # Auto-set to current epoch time
    message_id: str = ""        # Unique ID — auto-assigned by MessageBus.send() if empty
    in_reply_to: str = ""       # ID of the message this is responding to (for correlation)

    def to_dict(self) -> dict:
        """
        Serialize the message to a plain dict for logging, persistence, or
        JSON export. Used by the Evidence Agent when recording the message
        history into the engagement ledger.
        """
        return {
            "sender": self.sender.value,           # Store enum as string value
            "recipient": self.recipient.value,
            "message_type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
        }


# ── AgentResult ────────────────────────────────────────────────────────────────
@dataclass
class AgentResult:
    """
    Standardized result returned by every agent's execute() method.

    The Coordinator inspects these to decide whether to proceed to the next
    pipeline step. For example, if DiscoveryAgent returns success=False (no
    devices found), the Coordinator aborts the session early.

    Fields:
      success        — True if the agent completed its primary task.
      data           — Key metrics / outputs (varies per agent).
      errors         — Non-fatal error descriptions collected during execution.
      messages_sent  — How many messages the agent pushed onto the bus.
      actions_taken  — How many concrete actions (scans, probes, etc.) ran.
    """
    success: bool                                    # Did the agent achieve its goal?
    data: Dict = field(default_factory=dict)         # Agent-specific output data
    errors: List[str] = field(default_factory=list)  # Accumulated non-fatal errors
    messages_sent: int = 0                           # Count of messages sent during execute()
    actions_taken: int = 0                           # Count of concrete actions performed


# ── MessageBus ─────────────────────────────────────────────────────────────────
class MessageBus:
    """
    Simple in-process message bus for inter-agent communication.

    ARCHITECTURE:
        - One FIFO queue per AgentRole, lazily created at init for all roles.
        - Agents *send* messages into a recipient's queue.
        - Agents *receive* (destructively) or *peek* (non-destructively) their
          own queue.
        - A global _history list keeps every message ever sent, enabling
          post-hoc analysis, auditing, and the Evidence Agent's ledger export.

    WHY in-process instead of a real broker (Redis, RabbitMQ, etc.)?
        The TRUCE-PT pipeline is inherently sequential (discovery before profiling
        before planning, etc.), so a simple list-based bus avoids external
        dependencies while still decoupling agents via message passing.
    """

    def __init__(self):
        # Create an empty queue (list) for every possible agent role so that
        # send() never needs to check if the key exists.
        self._queues: Dict[AgentRole, List[AgentMessage]] = {
            role: [] for role in AgentRole
        }
        # Append-only log of every message sent through the bus. Used for
        # auditing, debugging, and engagement ledger construction.
        self._history: List[AgentMessage] = []

    def send(self, message: AgentMessage) -> None:
        """
        Deliver a message to the recipient's queue.

        If the message has no message_id yet, one is auto-assigned using the
        history length as a monotonically increasing counter (e.g., "msg-0",
        "msg-1", …). This keeps IDs unique and ordered.
        """
        if not message.message_id:
            # Auto-generate a sequential message ID based on total messages sent
            message.message_id = f"msg-{len(self._history)}"
        # Append to the recipient's per-role queue for later retrieval
        self._queues[message.recipient].append(message)
        # Also record in the global history for auditing / evidence
        self._history.append(message)
        # Debug-level trace so operators can follow inter-agent traffic
        logger.debug(
            f"[MessageBus] {message.sender.value} -> {message.recipient.value}: "
            f"{message.message_type.value}"
        )

    def receive(self, role: AgentRole) -> List[AgentMessage]:
        """
        Get and clear all pending messages for a role.

        This is the primary consumption method. After calling receive(), the
        queue is empty — messages are delivered exactly once. This prevents
        agents from accidentally re-processing old messages on subsequent
        execute() calls.
        """
        # Copy the list so we can clear the queue and still return the messages
        messages = list(self._queues[role])
        self._queues[role].clear()  # Destructive read — messages consumed
        return messages

    def peek(self, role: AgentRole) -> List[AgentMessage]:
        """
        View pending messages without clearing them.

        Used by ToolOrchestrator to check for VETO messages from SafetyOfficer
        or ImpactMonitor *before* executing an action, without consuming the
        messages (so they can be re-checked later if needed).
        """
        return list(self._queues[role])  # Non-destructive — queue unchanged

    def has_messages(self, role: AgentRole) -> bool:
        """Check whether the given role has any pending messages."""
        return len(self._queues[role]) > 0

    def get_history(self, sender: AgentRole = None,
                    recipient: AgentRole = None) -> List[AgentMessage]:
        """
        Query the global message history, optionally filtering by sender
        and/or recipient. Used for post-session auditing, debugging, and
        by the Evidence Agent when constructing the engagement ledger.
        """
        msgs = self._history
        if sender:
            # Filter to only messages from this sender
            msgs = [m for m in msgs if m.sender == sender]
        if recipient:
            # Further filter to only messages to this recipient
            msgs = [m for m in msgs if m.recipient == recipient]
        return msgs


# ── BaseAgent ──────────────────────────────────────────────────────────────────
class BaseAgent(ABC):
    """
    Abstract base class for all TRUCE-PT agents.

    WHY a base class?
        Every agent shares three responsibilities:
          1. Hold a reference to the shared SessionContext (devices, PCF DAG, etc.).
          2. Send and receive messages through the MessageBus.
          3. Implement an execute() method that performs the agent's main work.

        BaseAgent provides default implementations for messaging (send_message,
        send_alert, send_veto, process_inbox) so subclasses only need to
        implement execute() and optionally override handle_message().

    LIFECYCLE:
        1. The Coordinator instantiates each agent, passing the shared context.
        2. The Coordinator calls agent.execute() at the appropriate pipeline step.
        3. During execute(), the agent may send messages to other agents.
        4. Some agents (Validator, Evidence) process their inbox inside execute()
           because they are downstream consumers that act on messages from
           earlier pipeline stages.

    Each agent has:
      - A role (from AgentRole enum) — determines its message queue address.
      - Access to the shared SessionContext — single source of truth.
      - A message bus for inter-agent communication (via context.message_bus).
      - An execute() method that performs the agent's main work.
      - A handle_message() method for responding to individual messages.
    """

    def __init__(self, role: AgentRole, context: "SessionContext"):
        # Store the role so the bus knows which queue this agent owns
        self.role = role
        # Shared session state — every agent reads/writes this context
        self.context = context
        # Per-agent logger with a descriptive name like "agent.discovery"
        self.logger = logging.getLogger(f"agent.{role.value}")

    @abstractmethod
    def execute(self) -> AgentResult:
        """
        Perform the agent's main work.

        This is the primary entry point called by the Coordinator during the
        9-step pipeline. Each subclass implements its own logic here.

        Returns:
            AgentResult with success status, output data, and any errors.
        """
        pass

    def handle_message(self, msg: AgentMessage) -> Optional[AgentMessage]:
        """
        Handle an incoming message. Override in subclasses that need to
        respond to individual messages (e.g., Validator responding to a
        validation REQUEST).

        Returns a reply AgentMessage, or None if no reply is needed.
        Default implementation does nothing — subclasses opt in.
        """
        return None

    def send_message(self, recipient: AgentRole, message_type: MessageType,
                     payload: dict, in_reply_to: str = "") -> None:
        """
        Send a message to another agent via the shared message bus.

        This is the primary inter-agent communication primitive. The message
        is enqueued in the recipient's mailbox and will be consumed when the
        recipient calls receive() or process_inbox().

        Args:
            recipient    — Target agent role (determines which queue).
            message_type — Semantic type (REQUEST, RESULT, ALERT, VETO, etc.).
            payload      — Arbitrary data dict (content depends on context).
            in_reply_to  — Optional message_id of the original message this
                           responds to, enabling request-reply correlation.
        """
        # Construct the message envelope with sender auto-set to this agent's role
        msg = AgentMessage(
            sender=self.role,
            recipient=recipient,
            message_type=message_type,
            payload=payload,
            in_reply_to=in_reply_to,
        )
        # Deliver via the session's shared message bus
        self.context.message_bus.send(msg)

    def process_inbox(self) -> List[AgentMessage]:
        """
        Process all pending messages in this agent's queue.

        Iterates over every queued message, calling handle_message() for each.
        If handle_message() returns a reply, the reply is automatically sent
        back through the bus and collected in the returned list.

        Returns:
            List of reply messages that were sent.
        """
        # receive() is destructive — messages are consumed and won't appear again
        messages = self.context.message_bus.receive(self.role)
        replies = []
        for msg in messages:
            # Delegate to the subclass's handler (default returns None)
            reply = self.handle_message(msg)
            if reply:
                # Auto-send the reply through the bus
                self.context.message_bus.send(reply)
                replies.append(reply)
        return replies

    def send_alert(self, recipient: AgentRole, alert_type: str,
                   details: dict) -> None:
        """
        Send an alert message (e.g., safety concern, budget warning, RTT spike).

        Alerts are INFORMATIONAL — they notify the recipient of a condition
        but do not block actions (unlike vetoes). The alert_type string lets
        the recipient dispatch on the kind of alert without parsing the payload.

        Args:
            recipient  — Which agent should receive the alert.
            alert_type — Short identifier like "breaker_tripped", "rtt_stress".
            details    — Extra data merged into the payload alongside alert_type.
        """
        # Merge alert_type into the details dict so the payload is self-describing
        self.send_message(
            recipient, MessageType.ALERT,
            {"alert_type": alert_type, **details},
        )

    def send_veto(self, recipient: AgentRole, reason: str,
                  action_id: str = "") -> None:
        """
        Send a veto to BLOCK an action on a device.

        VETO MECHANISM:
            Only SafetyOfficerAgent and ImpactMonitorAgent send vetoes. When
            ToolOrchestratorAgent peeks its queue and finds a VETO message
            targeting a specific device_ip or action_id, it skips that action
            entirely. This is the primary safety enforcement mechanism in
            TRUCE-PT, ensuring that no unsafe probe reaches a CRITICAL or
            stressed device.

        Args:
            recipient — Typically TOOL_ORCHESTRATOR (the action executor).
            reason    — Human-readable explanation of why the action is blocked.
            action_id — Optional identifier of the specific action being vetoed.
        """
        self.send_message(
            recipient, MessageType.VETO,
            {"reason": reason, "action_id": action_id},
        )
