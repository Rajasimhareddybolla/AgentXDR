"""Pydantic models for the AgentXDR LLM Gateway Proxy (M4)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Literal, Optional, Set

from pydantic import BaseModel, ConfigDict, Field

from agentxdr.models.killswitch import KillSwitchState
from agentxdr.models.policy import PolicySchema


class GatewayConfig(BaseModel):
    """Configuration for the LLM Gateway Proxy."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    upstream_url: str
    agent_id: str
    policy: PolicySchema
    api_key: Optional[str] = None
    kill_switch: Optional[KillSwitchState] = None
    max_response_tokens: int = 4096


class SecurityRefusal(BaseModel):
    """Structured security refusal model."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    owasp_id: str
    trace_id: str
    verdict: str
    http_status: int

    def to_response(self) -> dict:
        """Return a dict suitable for a JSON HTTP response body."""
        return {
            "error": {
                "type": "security_refusal",
                "rule_id": self.rule_id,
                "owasp_id": self.owasp_id,
                "trace_id": self.trace_id,
                "verdict": self.verdict,
                "message": "Request blocked by AgentXDR inline security policy.",
            }
        }


class InspectionResult(BaseModel):
    """Result of a request or response inspection pass."""

    action: Literal["allow", "block", "mask"]
    rule_ids: List[str] = Field(default_factory=list)
    owasp_ids: List[str] = Field(default_factory=list)
    masked_content: Optional[str] = None


@dataclass
class SessionContext:
    """In-memory mutable session context for a single trace."""

    trace_id: str
    agent_id: str
    turn_count: int = 0
    tool_call_count: int = 0
    taint_labels: Set[str] = field(default_factory=set)
    start_time: float = field(default_factory=time.monotonic)
