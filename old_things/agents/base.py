import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from agents.session_context import SessionContext

logger = logging.getLogger(__name__)

class AgentRole(Enum):
    DISCOVERY = "discovery"                
    TARGET_PROFILING = "target_profiling"  
    PLANNER = "planner"                    
    TOOL_ORCHESTRATOR = "tool_orchestrator"
    IMPACT_MONITOR = "impact_monitor"      
    VALIDATOR = "validator"                
    SAFETY_OFFICER = "safety_officer"      
    EVIDENCE = "evidence"                  
    FLEET_REASONER = "fleet_reasoner"      
    COORDINATOR = "coordinator"            

class MessageType(Enum):
    REQUEST = "request"  
    RESULT = "result"    
    ALERT = "alert"      
    VETO = "veto"        
    STATUS = "status"    
    QUERY = "query"      

@dataclass
class AgentMessage:
    """
    Inter-agent message envelope
    """
    sender: AgentRole           
    recipient: AgentRole        
    message_type: MessageType   
    payload: Dict               
    timestamp: float = field(default_factory=time.time) 
    message_id: str = ""        
    in_reply_to: str = ""       

    def to_dict(self) -> dict:
        return {
            "sender": self.sender.value,           
            "recipient": self.recipient.value,
            "message_type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
        }

@dataclass
class AgentResult:
    """
    Standardized result returned by every agent's execute() method.
    """
    success: bool                                    
    data: Dict = field(default_factory=dict)         
    errors: List[str] = field(default_factory=list)  
    messages_sent: int = 0                          
    actions_taken: int = 0                         


class MessageBus:
    """
    Simple in-process message bus for inter-agent communication
    """

    def __init__(self):
        self._queues: Dict[AgentRole, List[AgentMessage]] = {
            role: [] for role in AgentRole
        }
        self._history: List[AgentMessage] = []

    def send(self, message: AgentMessage) -> None:
        """
        Deliver a message to the recipient's queue
        """
        if not message.message_id:
            message.message_id = f"msg-{len(self._history)}"
        self._queues[message.recipient].append(message)
        self._history.append(message)
        logger.debug(
            f"[MessageBus] {message.sender.value} -> {message.recipient.value}: "
            f"{message.message_type.value}"
        )

    def receive(self, role: AgentRole) -> List[AgentMessage]:
        """
        Get and clear all pending messages for a role
        """
        messages = list(self._queues[role])
        self._queues[role].clear()
        return messages

    def peek(self, role: AgentRole) -> List[AgentMessage]:
        """
        View pending messages without clearing them
        """
        return list(self._queues[role])  # Non-destructive — queue unchanged

    def has_messages(self, role: AgentRole) -> bool:
        """Check whether the given role has any pending messages."""
        return len(self._queues[role]) > 0

    def get_history(self, sender: AgentRole = None,
                    recipient: AgentRole = None) -> List[AgentMessage]:
        """
        Query the global message history, optionally filtering by sender
        and/or recipient. 
        """
        msgs = self._history
        if sender:
            # Filter to only messages from this sender
            msgs = [m for m in msgs if m.sender == sender]
        if recipient:
            # Further filter to only messages to this recipient
            msgs = [m for m in msgs if m.recipient == recipient]
        return msgs

class BaseAgent(ABC):
    """
    Abstract base class for all agents.
    """

    def __init__(self, role: AgentRole, context: "SessionContext"):
        self.role = role
        self.context = context
        self.logger = logging.getLogger(f"agent.{role.value}")

    @abstractmethod
    def execute(self) -> AgentResult:
        """
        Perform the agent's main work.
        """
        pass

    def handle_message(self, msg: AgentMessage) -> Optional[AgentMessage]:
        """
        Handle an incoming message. Override in subclasses that need to
        respond to individual messages
        """
        return None

    def send_message(self, recipient: AgentRole, message_type: MessageType,
                     payload: dict, in_reply_to: str = "") -> None:
        """
        Send a message to another agent via the shared message bus.
        """
        msg = AgentMessage(
            sender=self.role,
            recipient=recipient,
            message_type=message_type,
            payload=payload,
            in_reply_to=in_reply_to,
        )
        self.context.message_bus.send(msg)

    def process_inbox(self) -> List[AgentMessage]:
        messages = self.context.message_bus.receive(self.role)
        replies = []
        for msg in messages:
            reply = self.handle_message(msg)
            if reply:
                self.context.message_bus.send(reply)
                replies.append(reply)
        return replies

    def send_alert(self, recipient: AgentRole, alert_type: str,
                   details: dict) -> None:
        self.send_message(
            recipient, MessageType.ALERT,
            {"alert_type": alert_type, **details},
        )

    def send_veto(self, recipient: AgentRole, reason: str,
                  action_id: str = "") -> None:
        self.send_message(
            recipient, MessageType.VETO,
            {"reason": reason, "action_id": action_id},
        )
