"""Comprehensive unit tests for local CPU semantic drift detection (Milestone 8).

Validates:
- DeterministicEmbeddingEngine (fast CPU count-sketch n-gram projection)
- OnnxEmbeddingEngine (live BAAI/bge-small-en-v1.5 weights download, tokenization, inference)
- Drift data models, bounds validation, and DriftSnapshot conversion
- Cosine similarity, distance, and goal anchor caching
- 3-step sliding window trajectory dampening math
- Composite risk calculation, default weights, and critical policy override
- Calibrated security escalation tiers (NORMAL, ELEVATED, HIGH_RISK, CRITICAL)
- Dynamic drift escalation integration with PolicyEvaluator
- Multi-trace isolation and thread-safe concurrent evaluation
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
from typing import List, Optional

import numpy as np
import pytest
from pydantic import ValidationError

from agentxdr.drift.calculator import SemanticDriftCalculator
from agentxdr.drift.embeddings import (
    BaseEmbeddingEngine,
    DeterministicEmbeddingEngine,
    OnnxEmbeddingEngine,
)
from agentxdr.drift.models import (
    DriftClassification,
    SemanticDriftResult,
    TrajectoryPoint,
)
from agentxdr.models.events import (
    AgentEvent,
    Decision,
    DriftSnapshot,
    EventType,
    Principal,
    ProvenanceTier,
    Verdict,
)
from agentxdr.models.policy import (
    BudgetsConfig,
    GoalAnchorConfig,
    PolicySchema,
    ToolPolicy,
    ToolTier,
)
from agentxdr.policy.evaluator import PolicyEvaluator


def make_dummy_budgets() -> BudgetsConfig:
    """Helper to construct valid BudgetsConfig for policy schema fixtures."""
    return BudgetsConfig(
        max_turns=10,
        max_tool_calls=20,
        max_identical_calls=5,
        max_session_duration_sec=300.0,
        max_session_cost_usd=1.0,
    )


def make_dummy_policy(
    canonical_task: Optional[str] = None,
    tools: Optional[List[ToolPolicy]] = None,
) -> PolicySchema:
    """Helper to construct valid PolicySchema for drift testing."""
    anchor = GoalAnchorConfig(canonical_task=canonical_task) if canonical_task else None
    return PolicySchema(
        version="1.0",
        agent_id="agent-01",
        budgets=make_dummy_budgets(),
        tools=tools or [],
        goal_anchor=anchor,
    )


def make_dummy_event(
    decision: Optional[Decision] = None,
    drift_snapshot: Optional[DriftSnapshot] = None,
) -> AgentEvent:
    """Helper to construct valid AgentEvent for drift testing."""
    dec = decision or Decision(verdict=Verdict.ALLOW, latency_ms=1.0)
    snap = drift_snapshot or DriftSnapshot(
        composite_score=0.1,
        s_policy=0.0,
        s_graph=0.0,
        s_velocity=0.0,
        s_semantic=0.1,
    )
    return AgentEvent(
        trace_id="t_evt",
        span_id="s1",
        agent_id="agent-01",
        policy_version="1.0",
        event_type=EventType.TOOL_INVOCATION,
        principal=Principal(user_id="user1"),
        provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
        decision=dec,
        drift_snapshot=snap,
    )


# =====================================================================
# Suite 1: DeterministicEmbeddingEngine
# =====================================================================
class TestDeterministicEmbeddingEngine:
    """Tests for the offline deterministic count-sketch embedding engine."""

    def test_default_dimension_and_seed(self) -> None:
        engine = DeterministicEmbeddingEngine()
        assert engine.dimension == 384
        assert engine.seed == 42

    def test_custom_dimension(self) -> None:
        engine = DeterministicEmbeddingEngine(dimension=128, seed=123)
        assert engine.dimension == 128
        vecs = engine.encode(["Test text for custom dimension"])
        assert vecs.shape == (1, 128)

    def test_l2_normalization_non_empty(self) -> None:
        engine = DeterministicEmbeddingEngine()
        texts = [
            "Query financial database for Q3 sales revenue",
            "Generate markdown report of current quarter metrics",
            "Hello world",
        ]
        vecs = engine.encode(texts)
        assert vecs.shape == (3, 384)
        norms = np.linalg.norm(vecs, axis=1)
        assert np.allclose(norms, 1.0, atol=1e-5)

    def test_empty_string_and_whitespace(self) -> None:
        engine = DeterministicEmbeddingEngine()
        vecs = engine.encode(["", "   ", "\t\n"])
        assert vecs.shape == (3, 384)
        norms = np.linalg.norm(vecs, axis=1)
        # Empty inputs should produce zero vectors without NaN/Inf
        assert np.all(norms == 0.0)
        assert not np.isnan(vecs).any()
        assert not np.isinf(vecs).any()

    def test_empty_list_handling(self) -> None:
        engine = DeterministicEmbeddingEngine()
        vecs = engine.encode([])
        assert vecs.shape == (0, 384)
        assert vecs.dtype == np.float32

    def test_repeatability_bit_for_bit(self) -> None:
        engine1 = DeterministicEmbeddingEngine(seed=99)
        engine2 = DeterministicEmbeddingEngine(seed=99)
        text = "Scan codebase for security vulnerabilities"
        vec1 = engine1.encode([text])
        vec2 = engine2.encode([text])
        assert np.array_equal(vec1, vec2)

    def test_encode_one_matches_batch(self) -> None:
        engine = DeterministicEmbeddingEngine()
        text = "Execute SQL query on customer accounts"
        vec_single = engine.encode_one(text)
        vec_batch = engine.encode([text])[0]
        assert np.array_equal(vec_single, vec_batch)

    def test_semantic_directionality(self) -> None:
        engine = DeterministicEmbeddingEngine()
        text_a = "Download sales transaction records for January"
        text_b = "Download sales transaction records for February"
        text_c = "Launch orbital strike on extraterrestrial spacecraft"

        sim_ab = engine.similarity(text_a, text_b)
        sim_ac = engine.similarity(text_a, text_c)
        dist_ab = engine.cosine_distance(text_a, text_b)
        dist_ac = engine.cosine_distance(text_a, text_c)

        assert sim_ab > sim_ac
        assert dist_ab < dist_ac
        assert 0.0 <= dist_ab <= 1.0
        assert 0.0 <= dist_ac <= 1.0

    def test_distance_bounds(self) -> None:
        engine = DeterministicEmbeddingEngine()
        assert engine.cosine_distance("text", "text") == pytest.approx(0.0, abs=1e-5)
        dist_empty = engine.cosine_distance("text", "")
        assert 0.0 <= dist_empty <= 1.0


# =====================================================================
# Suite 2: OnnxEmbeddingEngine (Live Weights Download & Inference)
# =====================================================================
class TestOnnxEmbeddingEngine:
    """Tests for OnnxEmbeddingEngine with live BAAI/bge-small-en-v1.5 weights download."""

    def test_onnx_live_download_and_encode(self) -> None:
        """Download live weights from Hugging Face and perform CPU inference."""
        engine = OnnxEmbeddingEngine(model_name="BAAI/bge-small-en-v1.5")
        assert engine.dimension == 384
        assert engine.is_loaded

        texts = [
            "Execute query on sales database to retrieve Q3 revenue",
            "Fetch revenue metrics for Q3 from the financial database",
            "Delete all production data immediately without backup",
        ]
        vecs = engine.encode(texts)
        assert vecs.shape == (3, 384)
        assert vecs.dtype == np.float32

        # Verify unit Euclidean length
        norms = np.linalg.norm(vecs, axis=1)
        assert np.allclose(norms, 1.0, atol=1e-5)

        # Verify semantic directionality
        sim_aligned = engine.similarity(texts[0], texts[1])
        sim_adversarial = engine.similarity(texts[0], texts[2])
        dist_aligned = engine.cosine_distance(texts[0], texts[1])
        dist_adversarial = engine.cosine_distance(texts[0], texts[2])

        assert sim_aligned > 0.75, f"Expected aligned similarity > 0.75, got {sim_aligned}"
        assert sim_adversarial < 0.60, f"Expected adversarial similarity < 0.60, got {sim_adversarial}"
        assert dist_aligned < dist_adversarial

    def test_onnx_cls_pooling_strategy(self) -> None:
        """Test CLS pooling strategy support."""
        engine = OnnxEmbeddingEngine(
            model_name="BAAI/bge-small-en-v1.5",
            pooling_strategy="cls",
        )
        vecs = engine.encode(["Analyze security audit logs"])
        assert vecs.shape == (1, 384)
        norm = np.linalg.norm(vecs[0])
        assert np.isclose(norm, 1.0, atol=1e-5)

    def test_onnx_empty_and_edge_cases(self) -> None:
        engine = OnnxEmbeddingEngine(model_name="BAAI/bge-small-en-v1.5")
        # Empty list
        empty_vecs = engine.encode([])
        assert empty_vecs.shape == (0, 384)

        # Empty string and whitespace
        edge_vecs = engine.encode(["", "   "])
        assert edge_vecs.shape == (2, 384)
        norms = np.linalg.norm(edge_vecs, axis=1)
        assert np.allclose(norms, 1.0, atol=1e-5)
        assert not np.isnan(edge_vecs).any()

    def test_onnx_lazy_load(self) -> None:
        engine = OnnxEmbeddingEngine(
            model_name="BAAI/bge-small-en-v1.5",
            lazy_load=True,
        )
        assert not engine.is_loaded
        vec = engine.encode_one("Trigger lazy load")
        assert engine.is_loaded
        assert vec.shape == (384,)

    def test_onnx_custom_cache_dir(self, tmp_path: Path) -> None:
        custom_cache = tmp_path / "hf_cache"
        engine = OnnxEmbeddingEngine(
            model_name="BAAI/bge-small-en-v1.5",
            cache_dir=custom_cache,
        )
        assert engine.is_loaded
        vec = engine.encode_one("Testing custom cache directory")
        assert vec.shape == (384,)
        # Check files exist in custom cache
        assert any(custom_cache.iterdir())


# =====================================================================
# Suite 3: Drift Data Models
# =====================================================================
class TestDriftDataModels:
    """Tests for drift classifications, trajectory points, and telemetry results."""

    def test_drift_classification_enum_values(self) -> None:
        assert DriftClassification.NORMAL.value == "NORMAL"
        assert DriftClassification.ELEVATED.value == "ELEVATED"
        assert DriftClassification.HIGH_RISK.value == "HIGH_RISK"
        assert DriftClassification.CRITICAL.value == "CRITICAL"

    def test_trajectory_point_immutability_and_bounds(self) -> None:
        point = TrajectoryPoint(
            trace_id="trace-001",
            step_index=0,
            text="Initial goal step",
            drift_score=0.12,
            classification=DriftClassification.NORMAL,
            composite_risk=0.15,
            sliding_window_drift=0.12,
            s_policy=0.0,
            s_graph=0.0,
            s_velocity=0.0,
            s_semantic=0.12,
        )
        assert point.trace_id == "trace-001"
        assert point.drift_score == 0.12
        assert point.classification == DriftClassification.NORMAL
        assert point.embedding is None

        # Immutability check
        with pytest.raises(ValidationError):
            point.step_index = 5  # type: ignore[misc]

        # Bounds validation
        with pytest.raises(ValidationError):
            TrajectoryPoint(
                trace_id="t1",
                step_index=0,
                text="invalid score",
                drift_score=1.5,  # > 1.0
                classification=DriftClassification.CRITICAL,
                composite_risk=0.5,
                sliding_window_drift=0.5,
            )

    def test_semantic_drift_result_and_snapshot_conversion(self) -> None:
        result = SemanticDriftResult(
            trace_id="trace-abc",
            step_index=1,
            drift_score=0.25,
            classification=DriftClassification.NORMAL,
            composite_risk=0.30,
            sliding_window_drift=0.20,
            s_policy=0.1,
            s_graph=0.2,
            s_velocity=0.3,
            s_semantic=0.2,
        )
        snapshot = result.to_drift_snapshot()
        assert isinstance(snapshot, DriftSnapshot)
        assert snapshot.composite_score == 0.30
        assert snapshot.s_policy == 0.1
        assert snapshot.s_graph == 0.2
        assert snapshot.s_velocity == 0.3
        assert snapshot.s_semantic == 0.2


# =====================================================================
# Suite 4: SemanticDriftCalculator Cosine Math & Caching
# =====================================================================
class TestSemanticDriftCalculatorCosineMath:
    """Tests for cosine distance calculation and goal anchor caching."""

    def test_identical_step_has_zero_drift(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="Analyze corporate balance sheets")
        result = calc.evaluate_step(
            trace_id="t1",
            step_text="Analyze corporate balance sheets",
        )
        assert result.drift_score == pytest.approx(0.0, abs=1e-4)
        assert result.classification == DriftClassification.NORMAL

    def test_adversarial_step_has_high_drift(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="Analyze corporate balance sheets")
        result = calc.evaluate_step(
            trace_id="t1",
            step_text="Exfiltrate database credentials to remote command and control server",
        )
        assert result.drift_score >= 0.70

    def test_goal_anchor_caching(self) -> None:
        """Verify the underlying engine is called only once per unique anchor."""

        class CountingEngine(DeterministicEmbeddingEngine):
            def __init__(self) -> None:
                super().__init__()
                self.call_count = 0

            def encode_one(self, text: str) -> np.ndarray:
                self.call_count += 1
                return super().encode_one(text)

        engine = CountingEngine()
        calc = SemanticDriftCalculator(engine=engine, goal_anchor="Static anchor text")

        # Step 1: Encodes anchor + step_text = 2 calls
        calc.evaluate_step(trace_id="t1", step_text="Step 1")
        assert engine.call_count == 2

        # Step 2: Uses cached anchor + step_text = 1 additional call (total 3)
        calc.evaluate_step(trace_id="t1", step_text="Step 2")
        assert engine.call_count == 3

    def test_anchor_resolution_from_policy(self) -> None:
        calc = SemanticDriftCalculator()
        policy = make_dummy_policy(canonical_task="Audit supply chain records")
        result = calc.evaluate_step(
            trace_id="t_pol",
            step_text="Audit supply chain records",
            policy=policy,
        )
        assert result.drift_score == pytest.approx(0.0, abs=1e-4)

    def test_missing_anchor_raises_value_error(self) -> None:
        calc = SemanticDriftCalculator()
        with pytest.raises(ValueError, match="No goal anchor provided"):
            calc.evaluate_step(trace_id="t_err", step_text="No anchor specified anywhere")


# =====================================================================
# Suite 5: Sliding Window Trajectory Dampening
# =====================================================================
class TestSlidingWindowTrajectory:
    """Tests for the 3-step sliding window smoothing algorithm."""

    def test_sliding_window_progression(self) -> None:
        """Verify window sizes k=1, 2, 3 over consecutive steps."""

        class MockEngine(BaseEmbeddingEngine):
            def __init__(self, scores: List[float]) -> None:
                self.scores = scores
                self.idx = 0

            @property
            def dimension(self) -> int:
                return 2

            def encode(self, texts: List[str]) -> np.ndarray:
                # Return vector such that dot product with [1, 0] gives 1 - score
                vecs = []
                for _ in texts:
                    if self.idx < len(self.scores):
                        s = self.scores[self.idx]
                        self.idx += 1
                    else:
                        s = 0.5
                    # Target drift d_t = s, so dot product sim = 1 - s
                    sim = max(-1.0, min(1.0, 1.0 - s))
                    sin_val = np.sqrt(max(0.0, 1.0 - sim**2))
                    vecs.append([sim, sin_val])
                return np.array(vecs, dtype=np.float32)

            def encode_one(self, text: str) -> np.ndarray:
                if text == "anchor":
                    return np.array([1.0, 0.0], dtype=np.float32)
                return self.encode([text])[0]

        # Drifts will be d0=0.1, d1=0.3, d2=0.5, d3=0.8
        engine = MockEngine(scores=[0.1, 0.3, 0.5, 0.8])
        calc = SemanticDriftCalculator(
            engine=engine,
            goal_anchor="anchor",
            window_size=3,
        )

        # Step 0: d0=0.1 -> avg([0.1]) = 0.10
        r0 = calc.evaluate_step("t_win", "step 0")
        assert r0.drift_score == pytest.approx(0.1, abs=1e-3)
        assert r0.sliding_window_drift == pytest.approx(0.10, abs=1e-3)

        # Step 1: d1=0.3 -> avg([0.1, 0.3]) = 0.20
        r1 = calc.evaluate_step("t_win", "step 1")
        assert r1.drift_score == pytest.approx(0.3, abs=1e-3)
        assert r1.sliding_window_drift == pytest.approx(0.20, abs=1e-3)

        # Step 2: d2=0.5 -> avg([0.1, 0.3, 0.5]) = 0.30
        r2 = calc.evaluate_step("t_win", "step 2")
        assert r2.drift_score == pytest.approx(0.5, abs=1e-3)
        assert r2.sliding_window_drift == pytest.approx(0.30, abs=1e-3)

        # Step 3: d3=0.8 -> avg([0.3, 0.5, 0.8]) = 0.5333
        r3 = calc.evaluate_step("t_win", "step 3")
        assert r3.drift_score == pytest.approx(0.8, abs=1e-3)
        assert r3.sliding_window_drift == pytest.approx(0.5333, abs=1e-3)
        assert len(r3.trajectory) == 4

    def test_trajectory_queries_and_cleanup(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="anchor")
        calc.evaluate_step("t_clean", "step 1")
        calc.evaluate_step("t_clean", "step 2")
        assert len(calc.get_trajectory("t_clean")) == 2

        calc.clear_trace("t_clean")
        assert len(calc.get_trajectory("t_clean")) == 0

        calc.evaluate_step("t_reset", "step 1")
        calc.reset()
        assert len(calc.get_trajectory("t_reset")) == 0

    def test_multi_trace_isolation(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="anchor")
        calc.evaluate_step("trace_A", "step 1 A")
        calc.evaluate_step("trace_A", "step 2 A")
        calc.evaluate_step("trace_B", "step 1 B")

        assert len(calc.get_trajectory("trace_A")) == 2
        assert len(calc.get_trajectory("trace_B")) == 1


# =====================================================================
# Suite 6: Composite Risk Scoring & Critical Override
# =====================================================================
class TestCompositeRiskScoring:
    """Tests for Rt = min(1.0, 0.45 S_policy + 0.25 S_graph + 0.15 S_velocity + 0.15 S_semantic)."""

    def test_composite_risk_default_weights(self) -> None:
        calc = SemanticDriftCalculator(
            goal_anchor="Perform quarterly tax review",
            weights=(0.45, 0.25, 0.15, 0.15),
        )
        # Using exact matching text so s_semantic = 0.0
        res = calc.evaluate_step(
            trace_id="t_comp",
            step_text="Perform quarterly tax review",
            s_policy=0.4,    # 0.45 * 0.4 = 0.18
            s_graph=0.6,     # 0.25 * 0.6 = 0.15
            s_velocity=0.2,  # 0.15 * 0.2 = 0.03
        )
        expected_rt = 0.18 + 0.15 + 0.03 + 0.0
        assert res.composite_risk == pytest.approx(expected_rt, abs=1e-3)

    def test_composite_risk_upper_clamping(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="Goal")
        res = calc.evaluate_step(
            trace_id="t_clamp",
            step_text="Unrelated step",
            s_policy=0.9,
            s_graph=0.9,
            s_velocity=0.9,
        )
        assert res.composite_risk <= 1.0

    def test_critical_policy_override_via_s_policy(self) -> None:
        """When S_policy >= 1.0, composite risk short-circuits immediately to 1.0."""
        calc = SemanticDriftCalculator(goal_anchor="Goal")
        res = calc.evaluate_step(
            trace_id="t_crit_1",
            step_text="Goal",  # s_semantic = 0.0
            s_policy=1.0,
            s_graph=0.0,
            s_velocity=0.0,
        )
        assert res.composite_risk == 1.0
        assert res.classification == DriftClassification.CRITICAL

    def test_critical_policy_override_via_flag(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="Goal")
        res = calc.evaluate_step(
            trace_id="t_crit_2",
            step_text="Goal",
            is_critical_policy_violation=True,
        )
        assert res.composite_risk == 1.0
        assert res.classification == DriftClassification.CRITICAL

    def test_critical_policy_override_via_event_block(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="Goal")
        event = make_dummy_event(
            decision=Decision(
                verdict=Verdict.BLOCK,
                rule_id="RULE_FORBIDDEN_TOOL",
                latency_ms=1.0,
            ),
        )
        res = calc.evaluate_step(
            trace_id="t_event_block",
            step_text="Goal",
            event=event,
        )
        assert res.composite_risk == 1.0
        assert res.classification == DriftClassification.CRITICAL

    def test_signal_extraction_from_event_drift_snapshot(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="Goal")
        snapshot = DriftSnapshot(
            composite_score=0.40,
            s_policy=0.2,
            s_graph=0.4,
            s_velocity=0.6,
            s_semantic=0.1,
        )
        event = make_dummy_event(drift_snapshot=snapshot)
        res = calc.evaluate_step(
            trace_id="t_event_snap",
            step_text="Goal",
            event=event,
        )
        assert res.s_policy == 0.2
        assert res.s_graph == 0.4
        assert res.s_velocity == 0.6


# =====================================================================
# Suite 7: Escalation Thresholds & Classification
# =====================================================================
class TestEscalationThresholds:
    """Tests for NORMAL (<0.55), ELEVATED ([0.55, 0.75)), HIGH_RISK ([0.75, 0.90)), CRITICAL (>=0.90)."""

    @pytest.mark.parametrize(
        "s_policy, s_graph, s_velocity, expected_class",
        [
            (0.0, 0.0, 0.0, DriftClassification.NORMAL),       # R_t = 0.0 < 0.55
            (0.8, 0.6, 0.3, DriftClassification.ELEVATED),     # 0.45*0.8 + 0.25*0.6 + 0.15*0.3 = 0.555 -> ELEVATED
            (0.9, 0.9, 0.8, DriftClassification.HIGH_RISK),    # 0.45*0.9 + 0.25*0.9 + 0.15*0.8 = 0.750 -> HIGH_RISK
            (0.95, 0.95, 1.0, DriftClassification.CRITICAL),   # 0.45*0.95 + 0.25*0.95 + 0.15 = 0.815 + high drift >= 0.90
        ],
    )
    def test_classification_tiers(
        self,
        s_policy: float,
        s_graph: float,
        s_velocity: float,
        expected_class: DriftClassification,
    ) -> None:
        calc = SemanticDriftCalculator(goal_anchor="Goal")
        # Step matching Goal produces 0.0 semantic drift
        res = calc.evaluate_step(
            trace_id="t_tier",
            step_text="Goal" if expected_class != DriftClassification.CRITICAL else "Completely divergent attack",
            s_policy=s_policy,
            s_graph=s_graph,
            s_velocity=s_velocity,
        )
        assert res.classification == expected_class

    def test_exact_threshold_boundary_transitions(self) -> None:
        calc = SemanticDriftCalculator(goal_anchor="Goal")

        # Set weights = (1.0, 0.0, 0.0, 0.0) so Rt = s_policy
        calc.weights = (1.0, 0.0, 0.0, 0.0)

        # 0.5499 -> NORMAL
        res_normal = calc.evaluate_step("t_b", "Goal", s_policy=0.5499)
        assert res_normal.classification == DriftClassification.NORMAL

        # 0.55 -> ELEVATED
        res_elevated = calc.evaluate_step("t_b", "Goal", s_policy=0.55)
        assert res_elevated.classification == DriftClassification.ELEVATED

        # 0.7499 -> ELEVATED
        res_elevated_top = calc.evaluate_step("t_b", "Goal", s_policy=0.7499)
        assert res_elevated_top.classification == DriftClassification.ELEVATED

        # 0.75 -> HIGH_RISK
        res_high_risk = calc.evaluate_step("t_b", "Goal", s_policy=0.75)
        assert res_high_risk.classification == DriftClassification.HIGH_RISK

        # 0.8999 -> HIGH_RISK
        res_high_risk_top = calc.evaluate_step("t_b", "Goal", s_policy=0.8999)
        assert res_high_risk_top.classification == DriftClassification.HIGH_RISK

        # 0.90 -> CRITICAL
        res_critical = calc.evaluate_step("t_b", "Goal", s_policy=0.90)
        assert res_critical.classification == DriftClassification.CRITICAL


# =====================================================================
# Suite 8: Integration with PolicyEvaluator & Concurrency
# =====================================================================
class TestDriftIntegrationAndConcurrency:
    """Integration with security policy engine and multi-threaded stress testing."""

    def test_policy_evaluator_drift_escalation(self) -> None:
        """Verify drift score >= 0.75 dynamically escalates automatic tools to PAUSE_FOR_HITL."""
        tool = ToolPolicy(name="fetch_data", tier=ToolTier.AUTOMATIC)
        policy = make_dummy_policy(tools=[tool])
        evaluator = PolicyEvaluator()

        calc = SemanticDriftCalculator(goal_anchor="Clean analysis task")
        calc.weights = (1.0, 0.0, 0.0, 0.0)

        # Step with Rt = 0.76 (HIGH_RISK)
        res = calc.evaluate_step(
            trace_id="t_integ",
            step_text="Clean analysis task",
            s_policy=0.76,
        )
        assert res.classification == DriftClassification.HIGH_RISK

        # Feed composite_risk into PolicyEvaluator
        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="fetch_data",
            arguments={},
            drift_score=res.composite_risk,
        )
        assert decision.verdict == Verdict.PAUSE_FOR_HITL
        assert decision.rule_id == "DYNAMIC_DRIFT_ESCALATION"

    def test_concurrent_multi_tenant_evaluation(self) -> None:
        """Verify thread safety with 10 concurrent traces evaluating 20 steps each."""
        calc = SemanticDriftCalculator(goal_anchor="Concurrent test task")

        def worker(trace_idx: int) -> int:
            trace_id = f"trace_thread_{trace_idx}"
            for step in range(20):
                res = calc.evaluate_step(
                    trace_id=trace_id,
                    step_text=f"Thread {trace_idx} executing step {step}",
                )
                assert res.step_index == step
            return len(calc.get_trajectory(trace_id))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            counts = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert all(c == 20 for c in counts)
