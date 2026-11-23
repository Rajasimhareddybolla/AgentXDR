"""Graph data models, enums, node, edge, and motif violation schemas for AgentXDR."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from agentxdr.models.events import DriftSnapshot, EventType, ProvenanceTier, Verdict


class GraphNodeType(str, Enum):
    """Canonical node categories in the execution action-graph."""

    USER = "USER"
    AGENT = "AGENT"
    RAG_DOC = "RAG_DOC"
    LLM_STEP = "LLM_STEP"
    TOOL_CALL = "TOOL_CALL"
    MEMORY_STORE = "MEMORY_STORE"
    SANDBOX = "SANDBOX"
    PEER_AGENT = "PEER_AGENT"
    CONTEXT_SOURCE = "CONTEXT_SOURCE"


class GraphEdgeType(str, Enum):
    """Semantic relationship types between action-graph nodes."""

    READS_FROM = "READS_FROM"
    INVOKES = "INVOKES"
    WRITES_TO = "WRITES_TO"
    DELEGATES_TO = "DELEGATES_TO"
    RETURNS_TO = "RETURNS_TO"
    CAUSAL_FLOW = "CAUSAL_FLOW"


class GraphNode(BaseModel):
    """Execution DAG node representation in AgentXDR."""

    model_config = ConfigDict(extra="ignore")

    id: str
    node_type: GraphNodeType
    label: str
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    agent_id: Optional[str] = None
    event_type: Optional[EventType] = None
    timestamp: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = False
    provenance_tier: Optional[ProvenanceTier] = None
    taint_labels: List[str] = Field(default_factory=list)
    drift_score: Optional[float] = None
    drift_snapshot: Optional[DriftSnapshot] = None
    verdict: Optional[Verdict] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Execution DAG edge representation connecting two nodes."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    target: str
    edge_type: GraphEdgeType = GraphEdgeType.CAUSAL_FLOW
    taint_badges: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MotifType(str, Enum):
    """The 5 core attack and anomaly graph motifs."""

    FORBIDDEN_TAINT_SUBGRAPH = "FORBIDDEN_TAINT_SUBGRAPH"
    EXECUTION_LOOP = "EXECUTION_LOOP"
    UNAUTHORIZED_TOOL_JUMPING = "UNAUTHORIZED_TOOL_JUMPING"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    FAN_OUT_BURST = "FAN_OUT_BURST"


class MotifSeverity(str, Enum):
    """Severity tier for detected graph motif anomalies."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MotifViolation(BaseModel):
    """Structured report of a detected motif anomaly in the action-graph."""

    model_config = ConfigDict(extra="ignore")

    violation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    motif_type: MotifType
    severity: MotifSeverity
    description: str
    trace_id: Optional[str] = None
    affected_nodes: List[str] = Field(default_factory=list)
    affected_edges: List[str] = Field(default_factory=list)
    owasp_id: Optional[str] = None
    mitigation: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
