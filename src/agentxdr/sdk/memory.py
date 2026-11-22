"""Memory Guard — prevents poisoned writes and maintains a write-ahead snapshot log."""

from __future__ import annotations

import datetime
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agentxdr.sdk.context import AgentXDRContext


@dataclass
class MemoryWriteResult:
    """Result of an attempted memory persistence operation."""

    key: str
    value_hash: str
    allowed: bool
    blocked_reason: Optional[str] = None
    snapshot_id: str = ""


class MemoryGuard:
    """Guards stateful agent memory stores with write-ahead commit logging and taint gating."""

    def __init__(self, ctx: AgentXDRContext) -> None:
        self.ctx = ctx
        self._snapshots: List[Dict[str, Any]] = []

    def write(self, store: Any, key: str, value: Any) -> MemoryWriteResult:
        """Attempt to persist a key-value pair to memory store.

        If the current session carries the ``SUSPECTED_INJECTION`` taint label,
        the write is blocked deterministically to prevent persistent memory poisoning (ASI08).
        """
        # 1. Gating against poisoned / injected turns
        if self.ctx.has_taint("SUSPECTED_INJECTION"):
            return MemoryWriteResult(
                key=key,
                value_hash="",
                allowed=False,
                blocked_reason="TAINTED_WRITE_BLOCKED",
                snapshot_id="",
            )

        # 2. Cryptographic digest of persisted value
        val_bytes = str(value).encode("utf-8")
        val_hash = hashlib.sha256(val_bytes).hexdigest()
        snapshot_id = str(uuid.uuid4())

        # 3. Append commit record to Write-Ahead Log (WAL)
        commit_record = {
            "snapshot_id": snapshot_id,
            "trace_id": self.ctx.trace_id,
            "agent_id": self.ctx.agent_id,
            "key": key,
            "value_hash": val_hash,
            "taint_labels": list(self.ctx.get_taint_snapshot()),
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._snapshots.append(commit_record)

        # 4. Write to persistent store (duck-typed: .set(k, v))
        store.set(key, value)

        return MemoryWriteResult(
            key=key,
            value_hash=val_hash,
            allowed=True,
            snapshot_id=snapshot_id,
        )

    def get_snapshots(self) -> List[Dict[str, Any]]:
        """Return a copy of the Write-Ahead Log snapshots for this session."""
        return list(self._snapshots)
