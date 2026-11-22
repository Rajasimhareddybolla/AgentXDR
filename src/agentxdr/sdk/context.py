"""AgentXDR Python In-Process SDK context carrier."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Set


@dataclass
class AgentXDRContext:
    """Thread-safe context carrier for agent identity, tracing, and taints."""

    user_id: str
    user_roles: List[str]
    agent_id: str
    trace_id: str
    policy_version: str = "1.0.0"
    taint_labels: Set[str] = field(default_factory=set)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def add_taint(self, label: str) -> None:
        """Add a taint label thread-safely."""
        with self._lock:
            self.taint_labels.add(label)

    def has_taint(self, label: str) -> bool:
        """Check if a taint label is present."""
        with self._lock:
            return label in self.taint_labels

    def get_taint_snapshot(self) -> FrozenSet[str]:
        """Return an immutable snapshot of active taint labels."""
        with self._lock:
            return frozenset(self.taint_labels)

    def to_headers(self) -> Dict[str, str]:
        """Generate HTTP headers for transparent gateway and MCP proxy context propagation."""
        with self._lock:
            return {
                "X-AgentXDR-Agent-ID": self.agent_id,
                "X-AgentXDR-Trace-ID": self.trace_id,
                "X-AgentXDR-Policy-Version": self.policy_version,
                "X-AgentXDR-User-ID": self.user_id,
                "X-AgentXDR-Roles": ",".join(self.user_roles),
            }
