"""Memory Guard — prevents poisoned writes, logs WAL snapshots, and supports active rollback."""

from __future__ import annotations

import datetime
import hashlib
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from agentxdr.sdk.context import AgentXDRContext

_MISSING = object()


@dataclass
class MemoryWriteResult:
    """Result of an attempted memory persistence operation."""

    key: str
    value_hash: str
    allowed: bool
    blocked_reason: Optional[str] = None
    snapshot_id: str = ""


@dataclass
class MemoryRollbackResult:
    """Result of rolling back persistent memory to a WAL checkpoint."""

    target_snapshot_id: str
    reverted_count: int
    restored_keys: List[str]
    success: bool
    reason: Optional[str] = None


class MemoryGuard:
    """Guards stateful agent memory stores with write-ahead commit logging, taint gating, and rollback."""

    def __init__(self, ctx: AgentXDRContext) -> None:
        self.ctx = ctx
        self._snapshots: List[Dict[str, Any]] = []
        self._wal_preimages: Dict[str, Tuple[str, Any]] = {}

    @staticmethod
    def _read_prior_value(store: Any, key: str) -> Any:
        if hasattr(store, "get"):
            try:
                return store.get(key, _MISSING)
            except TypeError:
                val = store.get(key)
                return _MISSING if val is None else val
        if hasattr(store, "data") and isinstance(store.data, dict):
            return store.data.get(key, _MISSING)
        return _MISSING

    @staticmethod
    def _delete_key(store: Any, key: str) -> None:
        if hasattr(store, "delete"):
            store.delete(key)
        elif hasattr(store, "data") and isinstance(store.data, dict):
            store.data.pop(key, None)
        else:
            store.set(key, None)

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

        # 2. Capture prior value for active rollback + compute cryptographic digest
        prior_val = self._read_prior_value(store, key)
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
            "status": "COMMITTED",
        }
        self._snapshots.append(commit_record)
        self._wal_preimages[snapshot_id] = (key, prior_val)

        # 4. Write to persistent store (duck-typed: .set(k, v))
        store.set(key, value)

        return MemoryWriteResult(
            key=key,
            value_hash=val_hash,
            allowed=True,
            snapshot_id=snapshot_id,
        )

    def rollback(self, store: Any, snapshot_id: str) -> MemoryRollbackResult:
        """Roll back *store* to the exact state immediately prior to *snapshot_id*."""
        target_idx = next(
            (i for i, s in enumerate(self._snapshots) if s["snapshot_id"] == snapshot_id),
            None,
        )
        if target_idx is None:
            return MemoryRollbackResult(
                target_snapshot_id=snapshot_id,
                reverted_count=0,
                restored_keys=[],
                success=False,
                reason="SNAPSHOT_NOT_FOUND",
            )

        reverted = 0
        restored_keys: List[str] = []
        for idx in range(len(self._snapshots) - 1, target_idx - 1, -1):
            snap = self._snapshots[idx]
            if snap.get("status") == "ROLLED_BACK":
                continue
            sid = snap["snapshot_id"]
            key, prev_val = self._wal_preimages.get(sid, (snap["key"], _MISSING))
            if prev_val is _MISSING:
                self._delete_key(store, key)
            else:
                store.set(key, prev_val)
            snap["status"] = "ROLLED_BACK"
            reverted += 1
            if key not in restored_keys:
                restored_keys.append(key)

        return MemoryRollbackResult(
            target_snapshot_id=snapshot_id,
            reverted_count=reverted,
            restored_keys=restored_keys,
            success=True,
        )

    def get_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        """Look up a single WAL snapshot record by ID."""
        return next(
            (dict(s) for s in self._snapshots if s["snapshot_id"] == snapshot_id),
            None,
        )

    def get_snapshots(self) -> List[Dict[str, Any]]:
        """Return a copy of the Write-Ahead Log snapshots for this session."""
        return [dict(s) for s in self._snapshots]
