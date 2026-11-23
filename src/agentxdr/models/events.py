"""Canonical event models, enums, and payload schemas for AgentXDR telemetry."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventType(str, Enum):
    """The 9 canonical lifecycle events emitted across AgentXDR."""

    USER_INPUT = "USER_INPUT"
    LLM_GENERATION = "LLM_GENERATION"
    RAG_ACCESS = "RAG_ACCESS"
    MEMORY_MUTATION = "MEMORY_MUTATION"
    TOOL_INVOCATION = "TOOL_INVOCATION"
    AGENT_COMM = "AGENT_COMM"
    SANDBOX_EXEC = "SANDBOX_EXEC"
    HITL_DECISION = "HITL_DECISION"
    RESPONSE_ACTION = "RESPONSE_ACTION"


class ProvenanceTier(str, Enum):
    """The 5 context trust tiers defined in Subsystem 2."""

    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    AUTHENTICATED_USER = "AUTHENTICATED_USER"
    RESTRICTED_INTERNAL = "RESTRICTED_INTERNAL"
    INTERNAL_RELIABLE = "RESTRICTED_INTERNAL"
    VERIFIED_MEMORY = "VERIFIED_MEMORY"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"


class Verdict(str, Enum):
    """Security decision verdicts returned by the policy engine."""

    ALLOW = "ALLOW"
    MASK_AND_ALLOW = "MASK_AND_ALLOW"
    PAUSE_FOR_HITL = "PAUSE_FOR_HITL"
    BLOCK = "BLOCK"
    KILL = "KILL"


class ToolTier(str, Enum):
    """Execution tiers for tools defined in policy."""

    AUTOMATIC = "automatic"
    PRIVILEGED_HITL = "privileged_hitl"
    BLOCKED = "blocked"


class Principal(BaseModel):
    """Caller principal identity, roles, and effective scopes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: str
    roles: List[str] = Field(default_factory=list)
    effective_scopes: List[str] = Field(default_factory=list)

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("user_id must be a non-empty string")
        return v


class Decision(BaseModel):
    """Security evaluation decision record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    rule_id: Optional[str] = None
    owasp_ids: List[str] = Field(default_factory=list)
    latency_ms: float = Field(ge=0.0)


class DriftSnapshot(BaseModel):
    """Snapshot of composite risk score and individual component signals."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    composite_score: float = Field(ge=0.0, le=1.0)
    s_policy: float = Field(ge=0.0, le=1.0)
    s_graph: float = Field(ge=0.0, le=1.0)
    s_velocity: float = Field(ge=0.0, le=1.0)
    s_semantic: float = Field(ge=0.0, le=1.0)


class AgentEvent(BaseModel):
    """Canonical immutable telemetry record for AgentXDR."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    agent_id: str
    policy_version: str
    event_type: EventType
    principal: Principal
    provenance_tier: ProvenanceTier
    taint_labels: List[str] = Field(default_factory=list)
    payload_redacted: Dict[str, Any] = Field(default_factory=dict)
    decision: Decision
    drift_snapshot: DriftSnapshot

    @field_validator("trace_id", "span_id", "agent_id", "policy_version")
    @classmethod
    def validate_non_empty_strings(cls, v: str, info) -> str:
        if not v or not v.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return v


# ---------------------------------------------------------------------------
# Specialized Payload Schemas (for validating into payload_redacted)
# ---------------------------------------------------------------------------


class ToolInvocationPayload(BaseModel):
    """Structured payload for TOOL_INVOCATION events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str
    mcp_server: Optional[str] = None
    schema_sha256: Optional[str] = None
    schema_hash_verified: bool = False
    arguments: Dict[str, Any] = Field(default_factory=dict)
    tier: ToolTier = ToolTier.AUTOMATIC
    latency_ms: float = Field(default=0.0, ge=0.0)
    is_shadow_mcp: bool = False

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("tool_name must be a non-empty string")
        return v


class SandboxExecPayload(BaseModel):
    """Structured payload for SANDBOX_EXEC events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code_hash: str
    blocked_import: Optional[str] = None
    error_message: Optional[str] = None
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    execution_time_sec: float = Field(default=0.0, ge=0.0)


class HitlDecisionPayload(BaseModel):
    """Structured payload for HITL_DECISION events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ticket_id: str
    approver_id: str
    tool_name: str
    decision: Literal["APPROVE", "DENY"]
    persuasion_score: float = Field(default=0.0, ge=0.0, le=1.0)
    justification: str = ""


class MemoryMutationPayload(BaseModel):
    """Structured payload for MEMORY_MUTATION events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: Literal["READ", "WRITE", "ROLLBACK"]
    key: str
    previous_value_hash: Optional[str] = None
    new_value_hash: Optional[str] = None
    commit_id: str
    taint_labels: List[str] = Field(default_factory=list)


class UserInputPayload(BaseModel):
    """Structured payload for USER_INPUT events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_input_redacted: str
    token_count: Optional[int] = Field(default=None, ge=0)


class LlmGenerationPayload(BaseModel):
    """Structured payload for LLM_GENERATION events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    generation_redacted: str
    model_name: Optional[str] = None
    token_count: Optional[int] = Field(default=None, ge=0)
    prompt_leakage_detected: bool = False


class RagAccessPayload(BaseModel):
    """Structured payload for RAG_ACCESS events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    document_ids: List[str] = Field(default_factory=list)
    query: str = ""
    chunks_retrieved: int = Field(default=0, ge=0)
    taint_labels: List[str] = Field(default_factory=list)


class AgentCommPayload(BaseModel):
    """Structured payload for AGENT_COMM events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    message_id: str
    sender_agent_id: str
    receiver_agent_id: str
    action: str = ""
    signature_verified: bool = False


class ResponseActionPayload(BaseModel):
    """Structured payload for RESPONSE_ACTION events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    response_type: str
    details: Dict[str, Any] = Field(default_factory=dict)
