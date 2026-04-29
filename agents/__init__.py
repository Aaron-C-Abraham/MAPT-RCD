"""
agents/__init__.py — Package initializer for the TRUCE-PT multi-agent system.

PURPOSE:
    This module exposes the core building blocks that external code (e.g., the CLI
    entry point or tests) needs to bootstrap a TRUCE-PT engagement session.

    By re-exporting from here, callers can write:
        from agents import BaseAgent, SessionContext
    instead of reaching into submodules directly.

EXPORTED SYMBOLS:
    BaseAgent      — Abstract base class every agent inherits from.
    AgentRole      — Enum listing all nine agent roles + the coordinator.
    AgentMessage   — Dataclass for inter-agent messages on the message bus.
    AgentResult    — Dataclass returned by every agent's execute() method.
    SessionContext — Shared mutable state that all agents read/write during a session.
"""

# Import the foundational types from the base module so they are available
# at the package level (e.g., `from agents import BaseAgent`).
from agents.base import BaseAgent, AgentRole, AgentMessage, AgentResult

# Import the shared session state container that every agent receives at
# construction time. It holds references to the PCF DAG, TIB managers,
# PTG graphs, tool registry, fleet clusters, and the message bus.
from agents.session_context import SessionContext

# __all__ controls what `from agents import *` exposes. Kept intentionally
# narrow to avoid leaking implementation details like MessageBus or MessageType.
__all__ = ["BaseAgent", "AgentRole", "AgentMessage", "AgentResult", "SessionContext"]
