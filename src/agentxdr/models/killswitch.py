"""Hierarchical multi-granularity kill-switch model for AgentXDR."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field


class KillSwitchScope(str, Enum):
    """Granularity scopes for emergency termination."""

    GLOBAL = "GLOBAL"
    AGENT = "AGENT"
    SESSION = "SESSION"
    TOOL = "TOOL"
    MCP_SERVER = "MCP_SERVER"


class KillSwitchRecord(BaseModel):
    """Audit record for an activated kill switch."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: KillSwitchScope
    target_id: str
    reason: str
    triggered_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_seconds: Optional[int] = Field(default=None, gt=0)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Evaluate if the record has exceeded its time-to-live."""
        if self.ttl_seconds is None:
            return False
        current_time = now or datetime.now(timezone.utc)
        elapsed = (current_time - self.created_at).total_seconds()
        return elapsed >= self.ttl_seconds


class KillSwitchState:
    """Multi-granularity hierarchical kill-switch state machine.

    Evaluation hierarchy:
    GLOBAL > AGENT > SESSION > (TOOL / MCP_SERVER)
    """

    def __init__(self) -> None:
        self._records: Dict[Tuple[KillSwitchScope, str], KillSwitchRecord] = {}
        self._lock = threading.RLock()

    def activate(
        self,
        scope: KillSwitchScope,
        target_id: str,
        reason: str,
        triggered_by: str,
        ttl_seconds: Optional[int] = None,
    ) -> KillSwitchRecord:
        """Activate a kill switch at the specified scope and target."""
        cleaned_target = (target_id.strip() if target_id else "*") if scope == KillSwitchScope.GLOBAL else target_id.strip()
        if not cleaned_target:
            raise ValueError("target_id must be a non-empty string")
        if not reason or not reason.strip():
            raise ValueError("reason must be a non-empty string")
        if not triggered_by or not triggered_by.strip():
            raise ValueError("triggered_by must be a non-empty string")

        record = KillSwitchRecord(
            scope=scope,
            target_id=cleaned_target,
            reason=reason.strip(),
            triggered_by=triggered_by.strip(),
            ttl_seconds=ttl_seconds,
        )
        with self._lock:
            self._records[(scope, cleaned_target)] = record
        return record

    def deactivate(self, scope: KillSwitchScope, target_id: str) -> bool:
        """Deactivate a kill switch at the specified scope and target."""
        cleaned_target = (target_id.strip() if target_id else "*") if scope == KillSwitchScope.GLOBAL else target_id.strip()
        key = (scope, cleaned_target)
        with self._lock:
            if key in self._records:
                del self._records[key]
                return True
            return False

    def is_killed(
        self,
        agent_id: str,
        trace_id: str,
        tool_name: Optional[str] = None,
        mcp_server: Optional[str] = None,
    ) -> bool:
        """Evaluate hierarchical kill status for a specific execution context.

        Order of precedence:
        1. GLOBAL (target matches '*' or any global switch)
        2. AGENT (target matches agent_id or '*')
        3. SESSION (target matches trace_id or '*')
        4. TOOL (target matches tool_name)
        5. MCP_SERVER (target matches mcp_server)
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            # 1. Scope: GLOBAL
            for (scope, _target), record in list(self._records.items()):
                if scope == KillSwitchScope.GLOBAL:
                    if record.is_expired(now):
                        del self._records[(scope, _target)]
                    else:
                        return True

            # 2. Scope: AGENT
            if agent_id:
                for target in (agent_id.strip(), "*"):
                    key = (KillSwitchScope.AGENT, target)
                    if key in self._records:
                        record = self._records[key]
                        if record.is_expired(now):
                            del self._records[key]
                        else:
                            return True

            # 3. Scope: SESSION
            if trace_id:
                for target in (trace_id.strip(), "*"):
                    key = (KillSwitchScope.SESSION, target)
                    if key in self._records:
                        record = self._records[key]
                        if record.is_expired(now):
                            del self._records[key]
                        else:
                            return True

            # 4. Scope: TOOL
            if tool_name:
                key = (KillSwitchScope.TOOL, tool_name.strip())
                if key in self._records:
                    record = self._records[key]
                    if record.is_expired(now):
                        del self._records[key]
                    else:
                        return True

            # 5. Scope: MCP_SERVER
            if mcp_server:
                key = (KillSwitchScope.MCP_SERVER, mcp_server.strip())
                if key in self._records:
                    record = self._records[key]
                    if record.is_expired(now):
                        del self._records[key]
                    else:
                        return True

            return False

    def get_active_records(self) -> List[KillSwitchRecord]:
        """Return all active, unexpired kill switch records."""
        now = datetime.now(timezone.utc)
        active: List[KillSwitchRecord] = []
        with self._lock:
            for key, record in list(self._records.items()):
                if record.is_expired(now):
                    del self._records[key]
                else:
                    active.append(record)
        return active

    def clear(self) -> None:
        """Clear all active records."""
        with self._lock:
            self._records.clear()
