"""Monotonic session taint accumulation state machine for AgentXDR."""

from __future__ import annotations

import threading
from typing import Iterable, List, Optional, Set


class TaintState:
    """Monotonic taint accumulation state machine tracking active taints per trace_id.

    Invariants:
    1. Taints can only be added, never removed (strictly monotonic).
    2. Taint additions are idempotent.
    3. Rule matching evaluates whether all required taints are present (subset check).
    """

    def __init__(self, trace_id: str, initial_taints: Optional[Iterable[str]] = None) -> None:
        if not trace_id or not trace_id.strip():
            raise ValueError("trace_id must be a non-empty string")
        self._trace_id: str = trace_id.strip()
        self._taints: Set[str] = set()
        self._lock = threading.RLock()

        if initial_taints:
            self.add_taints(initial_taints)

    @property
    def trace_id(self) -> str:
        """Trace identifier associated with this taint state."""
        return self._trace_id

    def add_taint(self, label: str) -> None:
        """Add a single taint label monotonically and idempotently."""
        if not label or not label.strip():
            raise ValueError("Taint label must be a non-empty string")
        cleaned = label.strip()
        with self._lock:
            self._taints.add(cleaned)

    def add_taints(self, labels: Iterable[str]) -> None:
        """Add multiple taint labels monotonically and idempotently."""
        for label in labels:
            self.add_taint(label)

    def has_taint(self, label: str) -> bool:
        """Check if a specific taint label is currently active."""
        if not label:
            return False
        with self._lock:
            return label.strip() in self._taints

    def matches_rule(self, match_taints: Iterable[str]) -> bool:
        """Evaluate if all match_taints are present in the active taints (subset check).

        Returns True if match_taints is non-empty and every label in match_taints
        is present in active taints. If match_taints is empty, returns False.
        """
        required = {t.strip() for t in match_taints if t and t.strip()}
        if not required:
            return False
        with self._lock:
            return required.issubset(self._taints)

    def to_list(self) -> List[str]:
        """Return a sorted list of active taints."""
        with self._lock:
            return sorted(self._taints)

    def __contains__(self, label: str) -> bool:
        return self.has_taint(label)

    def __len__(self) -> int:
        with self._lock:
            return len(self._taints)

    def __repr__(self) -> str:
        with self._lock:
            return f"TaintState(trace_id={self._trace_id!r}, taints={sorted(self._taints)!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintState):
            return False
        if self is other:
            return True
        with self._lock:
            s_trace, s_taints = self._trace_id, set(self._taints)
        with other._lock:
            o_trace, o_taints = other._trace_id, set(other._taints)
        return s_trace == o_trace and s_taints == o_taints
