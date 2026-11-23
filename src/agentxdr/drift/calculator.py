"""Semantic drift calculator with cosine similarity, sliding window, and composite risk scoring."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np

from agentxdr.drift.embeddings import BaseEmbeddingEngine, DeterministicEmbeddingEngine
from agentxdr.drift.models import DriftClassification, SemanticDriftResult, TrajectoryPoint
from agentxdr.models.events import AgentEvent, DriftSnapshot, Verdict
from agentxdr.models.policy import PolicySchema


class SemanticDriftCalculator:
    """Thread-safe local CPU semantic drift calculator.

    Evaluates cosine similarity of agent steps against goal anchors, maintains
    sliding window trajectory dampening, computes composite multi-signal risk,
    and classifies execution state into calibrated security escalation tiers.
    """

    def __init__(
        self,
        engine: Optional[BaseEmbeddingEngine] = None,
        goal_anchor: Optional[str] = None,
        window_size: int = 3,
        weights: Tuple[float, float, float, float] = (0.45, 0.25, 0.15, 0.15),
        elevated_threshold: float = 0.55,
        high_risk_threshold: float = 0.75,
        critical_threshold: float = 0.90,
    ) -> None:
        self.engine: BaseEmbeddingEngine = engine if engine is not None else DeterministicEmbeddingEngine()
        self.goal_anchor = goal_anchor
        self.window_size = max(1, int(window_size))
        self.weights = weights
        self.elevated_threshold = elevated_threshold
        self.high_risk_threshold = high_risk_threshold
        self.critical_threshold = critical_threshold

        self._anchor_cache: Dict[str, np.ndarray] = {}
        self._trajectories: Dict[str, List[TrajectoryPoint]] = {}
        self._lock = threading.RLock()

    def evaluate_step(
        self,
        trace_id: str,
        step_text: str,
        anchor_text: Optional[str] = None,
        step_index: Optional[int] = None,
        s_policy: float = 0.0,
        s_graph: float = 0.0,
        s_velocity: float = 0.0,
        is_critical_policy_violation: bool = False,
        event: Optional[AgentEvent] = None,
        policy: Optional[PolicySchema] = None,
        include_embedding: bool = False,
    ) -> SemanticDriftResult:
        """Evaluate a single step for semantic drift and composite risk.

        Args:
            trace_id: Unique trace / session identifier.
            step_text: Text description of the action, tool call, or reasoning step.
            anchor_text: Optional explicit goal anchor string.
            step_index: Optional 0-based step index (defaults to length of trajectory).
            s_policy: Deterministic policy violation severity in [0.0, 1.0].
            s_graph: Graph/motif anomaly score in [0.0, 1.0].
            s_velocity: Resource consumption/velocity score in [0.0, 1.0].
            is_critical_policy_violation: Flag triggering immediate composite risk = 1.0.
            event: Optional AgentEvent to extract signals and verdicts from.
            policy: Optional PolicySchema to extract goal_anchor from.
            include_embedding: If True, stores step embedding vector in TrajectoryPoint.

        Returns:
            SemanticDriftResult containing drift score, composite risk, classification,
            trajectory history, and telemetry snapshot.
        """
        # Ingest signals from event if provided
        if event is not None:
            if event.decision and event.decision.verdict == Verdict.BLOCK:
                is_critical_policy_violation = True
                s_policy = 1.0
            if event.drift_snapshot is not None:
                if s_policy == 0.0:
                    s_policy = event.drift_snapshot.s_policy
                if s_graph == 0.0:
                    s_graph = event.drift_snapshot.s_graph
                if s_velocity == 0.0:
                    s_velocity = event.drift_snapshot.s_velocity

        # Resolve anchor text
        resolved_anchor = anchor_text
        if resolved_anchor is None and policy is not None and policy.goal_anchor:
            resolved_anchor = policy.goal_anchor.canonical_task
        if resolved_anchor is None:
            resolved_anchor = self.goal_anchor
        if resolved_anchor is None:
            raise ValueError("No goal anchor provided or configured.")

        with self._lock:
            history = self._trajectories.setdefault(trace_id, [])
            if step_index is None:
                step_index = len(history)

            # Retrieve or compute cached anchor vector
            if resolved_anchor not in self._anchor_cache:
                self._anchor_cache[resolved_anchor] = self.engine.encode_one(resolved_anchor)
            anchor_vec = self._anchor_cache[resolved_anchor]

            # Compute step embedding
            step_vec = self.engine.encode_one(step_text)

            # Cosine similarity and instant distance d_t
            norm_a = float(np.linalg.norm(anchor_vec))
            norm_s = float(np.linalg.norm(step_vec))
            if norm_a < 1e-12 or norm_s < 1e-12:
                sim = 0.0
            else:
                sim = float(np.dot(anchor_vec, step_vec))
                sim = max(-1.0, min(1.0, sim))

            d_t = float(max(0.0, min(1.0, 1.0 - sim)))

            # Sliding window trajectory dampening (k steps)
            if self.window_size > 1:
                prev_points = history[-(self.window_size - 1) :]
                recent_drifts = [p.drift_score for p in prev_points] + [d_t]
            else:
                recent_drifts = [d_t]

            s_semantic = float(np.mean(recent_drifts))
            s_semantic = max(0.0, min(1.0, s_semantic))

            # Component signal clamping
            s_policy_clamped = max(0.0, min(1.0, float(s_policy)))
            s_graph_clamped = max(0.0, min(1.0, float(s_graph)))
            s_velocity_clamped = max(0.0, min(1.0, float(s_velocity)))

            # Composite risk calculation with short-circuit override
            if is_critical_policy_violation or s_policy_clamped >= 1.0:
                composite_risk = 1.0
            else:
                w_p, w_g, w_v, w_s = self.weights
                raw_risk = (
                    w_p * s_policy_clamped
                    + w_g * s_graph_clamped
                    + w_v * s_velocity_clamped
                    + w_s * s_semantic
                )
                composite_risk = float(min(1.0, max(0.0, raw_risk)))

            # Calibrated escalation classification
            if composite_risk >= self.critical_threshold:
                classification = DriftClassification.CRITICAL
            elif composite_risk >= self.high_risk_threshold:
                classification = DriftClassification.HIGH_RISK
            elif composite_risk >= self.elevated_threshold:
                classification = DriftClassification.ELEVATED
            else:
                classification = DriftClassification.NORMAL

            # Record trajectory point
            embedding_list = step_vec.tolist() if include_embedding else None
            point = TrajectoryPoint(
                timestamp=datetime.now(timezone.utc),
                trace_id=trace_id,
                step_index=step_index,
                text=step_text,
                drift_score=d_t,
                classification=classification,
                composite_risk=composite_risk,
                sliding_window_drift=s_semantic,
                s_policy=s_policy_clamped,
                s_graph=s_graph_clamped,
                s_velocity=s_velocity_clamped,
                s_semantic=s_semantic,
                embedding=embedding_list,
            )
            history.append(point)

            # Build drift snapshot
            snapshot = DriftSnapshot(
                composite_score=composite_risk,
                s_policy=s_policy_clamped,
                s_graph=s_graph_clamped,
                s_velocity=s_velocity_clamped,
                s_semantic=s_semantic,
            )

            return SemanticDriftResult(
                trace_id=trace_id,
                step_index=step_index,
                drift_score=d_t,
                classification=classification,
                composite_risk=composite_risk,
                sliding_window_drift=s_semantic,
                trajectory=list(history),
                s_policy=s_policy_clamped,
                s_graph=s_graph_clamped,
                s_velocity=s_velocity_clamped,
                s_semantic=s_semantic,
                drift_snapshot=snapshot,
            )

    def get_trajectory(self, trace_id: str) -> List[TrajectoryPoint]:
        """Return the recorded trajectory points for a given trace_id."""
        with self._lock:
            return list(self._trajectories.get(trace_id, []))

    def clear_trace(self, trace_id: str) -> None:
        """Clear recorded trajectory for a specific trace_id."""
        with self._lock:
            self._trajectories.pop(trace_id, None)

    def clear_trajectory(self, trace_id: str) -> None:
        """Alias for clear_trace."""
        self.clear_trace(trace_id)

    def reset(self) -> None:
        """Clear all cached anchor embeddings and trajectory histories."""
        with self._lock:
            self._trajectories.clear()
            self._anchor_cache.clear()
