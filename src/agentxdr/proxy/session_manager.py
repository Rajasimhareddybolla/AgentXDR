"""Thread-safe in-memory session manager for the AgentXDR LLM Gateway Proxy."""

from __future__ import annotations

import threading
from typing import Dict, Optional

from agentxdr.proxy.models import SessionContext


class SessionManager:
    """Thread-safe, in-memory store for per-trace session contexts."""

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionContext] = {}
        self._lock = threading.RLock()
        self._requests_total: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_or_create(self, trace_id: str, agent_id: str) -> SessionContext:
        """Return the existing session or create a new one."""
        with self._lock:
            if trace_id not in self._sessions:
                self._sessions[trace_id] = SessionContext(
                    trace_id=trace_id,
                    agent_id=agent_id,
                )
            return self._sessions[trace_id]

    def increment_turn(self, trace_id: str) -> SessionContext:
        """Increment the turn counter for an existing (or auto-created) session."""
        with self._lock:
            ctx = self._sessions.get(trace_id)
            if ctx is None:
                # Auto-create with a placeholder agent_id so the gateway can
                # call increment_turn before get_or_create.
                ctx = SessionContext(trace_id=trace_id, agent_id="")
                self._sessions[trace_id] = ctx
            ctx.turn_count += 1
            self._requests_total += 1
            return ctx

    def increment_tool_call(self, trace_id: str) -> SessionContext:
        """Increment the tool-call counter for a session."""
        with self._lock:
            ctx = self._sessions.get(trace_id)
            if ctx is None:
                ctx = SessionContext(trace_id=trace_id, agent_id="")
                self._sessions[trace_id] = ctx
            ctx.tool_call_count += 1
            return ctx

    def add_taint(self, trace_id: str, label: str) -> SessionContext:
        """Add a taint label to a session."""
        with self._lock:
            ctx = self._sessions.get(trace_id)
            if ctx is None:
                ctx = SessionContext(trace_id=trace_id, agent_id="")
                self._sessions[trace_id] = ctx
            ctx.taint_labels.add(label)
            return ctx

    def get(self, trace_id: str) -> Optional[SessionContext]:
        """Return the session context, or *None* if it does not exist."""
        with self._lock:
            return self._sessions.get(trace_id)

    def clear(self, trace_id: str) -> None:
        """Remove a session from the store."""
        with self._lock:
            self._sessions.pop(trace_id, None)

    # ------------------------------------------------------------------
    # Metrics helpers
    # ------------------------------------------------------------------

    @property
    def sessions_active(self) -> int:
        """Number of live sessions currently tracked."""
        with self._lock:
            return len(self._sessions)

    @property
    def requests_total(self) -> int:
        """Cumulative number of turns recorded across all sessions."""
        with self._lock:
            return self._requests_total
