"""Data models and enums for semantic drift detection and trajectory tracking."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from agentxdr.models.events import DriftSnapshot


class DriftClassification(str, Enum):
    """Calibrated security classification tiers for behavioral drift risk."""

    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class TrajectoryPoint(BaseModel):
    """Immutable point along an agent trace trajectory."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trace_id: str
    step_index: int = Field(ge=0)
    text: str
    drift_score: float = Field(ge=0.0, le=1.0)
    classification: DriftClassification
    composite_risk: float = Field(ge=0.0, le=1.0)
    sliding_window_drift: float = Field(ge=0.0, le=1.0)
    s_policy: float = Field(default=0.0, ge=0.0, le=1.0)
    s_graph: float = Field(default=0.0, ge=0.0, le=1.0)
    s_velocity: float = Field(default=0.0, ge=0.0, le=1.0)
    s_semantic: float = Field(default=0.0, ge=0.0, le=1.0)
    embedding: Optional[List[float]] = None


class SemanticDriftResult(BaseModel):
    """Result of semantic drift calculation for a single execution step."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    trace_id: str
    step_index: int = Field(ge=0)
    drift_score: float = Field(ge=0.0, le=1.0)
    classification: DriftClassification
    composite_risk: float = Field(ge=0.0, le=1.0)
    sliding_window_drift: float = Field(ge=0.0, le=1.0)
    trajectory: List[TrajectoryPoint] = Field(default_factory=list)
    s_policy: float = Field(default=0.0, ge=0.0, le=1.0)
    s_graph: float = Field(default=0.0, ge=0.0, le=1.0)
    s_velocity: float = Field(default=0.0, ge=0.0, le=1.0)
    s_semantic: float = Field(default=0.0, ge=0.0, le=1.0)
    drift_snapshot: Optional[DriftSnapshot] = None

    def to_drift_snapshot(self) -> DriftSnapshot:
        """Convert result into standard AgentXDR DriftSnapshot telemetry record."""
        return DriftSnapshot(
            composite_score=self.composite_risk,
            s_policy=self.s_policy,
            s_graph=self.s_graph,
            s_velocity=self.s_velocity,
            s_semantic=self.s_semantic,
        )
