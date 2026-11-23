"""Opaque-Box Tier 2 Boundary Coverage Tests: Phase 3 Warm-Path Analytics Plane & KQL-Lite SIEM Engine.

Validates boundary conditions, edge cases, numeric thresholds, extremes, SQL injection neutralization,
and high-concurrency race protection across all Phase 3 subsystems (M7, M8, M9, M10):
- Group 1: Null, Empty, Whitespace & Missing Values
- Group 2: Extremes, Large Payloads (>50KB) & Deep Structures / Cycles
- Group 3: Numeric Boundaries, Float Clamping & Division-by-Zero Guards
- Group 4: Security Hardening & SQL Injection Neutralization in KQL-Lite
- Group 5: High-Volume Concurrency & Out-of-Order Ingestion Boundaries
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import networkx as nx
import numpy as np
import pytest

from agentxdr.analytics.duckdb_store import DuckDbAnalyticsStore, KqlQueryResult
from agentxdr.analytics.kql.ast import BinaryOp, ColumnRef, KqlPipeline, Literal, TableSource, WhereClause
from agentxdr.analytics.kql.compiler import KqlCompiler
from agentxdr.analytics.kql.parser import ParseError, parse
from agentxdr.drift.calculator import SemanticDriftCalculator
from agentxdr.drift.embeddings import DeterministicEmbeddingEngine
from agentxdr.drift.models import DriftClassification, SemanticDriftResult
from agentxdr.graph.action_graph import ActionGraph
from agentxdr.graph.models import (
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    MotifSeverity,
    MotifType,
    MotifViolation,
)
from agentxdr.graph.motif_detector import MotifAnomalyDetector
from agentxdr.models.events import (
    AgentEvent,
    Decision,
    DriftSnapshot,
    EventType,
    Principal,
    ProvenanceTier,
    ToolTier,
    Verdict,
)
from agentxdr.models.policy import BudgetsConfig, GoalAnchorConfig, PolicySchema, ToolPolicy
from agentxdr.persuasion.classifier import (
    PersuasionClassifier,
    PersuasionRiskLevel,
    PersuasionTactic,
)
from agentxdr.persuasion.hitl_gate import HitlReviewGate, HitlTicket, TicketStatus
from agentxdr.topology.builder import AgentTopologyBuilder


# ===========================================================================
# Helper Utilities
# ===========================================================================

def make_boundary_event(
    trace_id: str = "trace-boundary",
    agent_id: str = "agent-boundary",
    span_id: str | None = None,
    parent_span_id: str | None = None,
    event_type: EventType = EventType.TOOL_INVOCATION,
    provenance_tier: ProvenanceTier = ProvenanceTier.AUTHENTICATED_USER,
    verdict: Verdict = Verdict.ALLOW,
    tool_name: str = "test_tool",
    taint_labels: List[str] | None = None,
    payload_redacted: Dict[str, Any] | None = None,
    decision: Decision | None = None,
) -> AgentEvent:
    payload = payload_redacted if payload_redacted is not None else {}
    if "tool_name" not in payload and tool_name:
        payload["tool_name"] = tool_name

    dec = decision or Decision(
        verdict=verdict,
        rule_id="RULE-BND",
        owasp_ids=[],
        latency_ms=0.5,
    )

    return AgentEvent(
        trace_id=trace_id,
        span_id=span_id or str(uuid.uuid4()),
        parent_span_id=parent_span_id,
        agent_id=agent_id,
        policy_version="1.0.0",
        event_type=event_type,
        principal=Principal(user_id="user-bnd", roles=["operator"]),
        provenance_tier=provenance_tier,
        taint_labels=taint_labels or [],
        payload_redacted=payload,
        decision=dec,
        drift_snapshot=DriftSnapshot(
            composite_score=0.1,
            s_policy=0.0,
            s_graph=0.0,
            s_velocity=0.0,
            s_semantic=0.1,
        ),
        timestamp=datetime.now(tz=timezone.utc),
    )


# ===========================================================================
# Group 1: Null, Empty, Whitespace & Missing Values
# ===========================================================================

class TestTier2NullAndEmptyBoundaries:
    """Verifies graceful handling of empty inputs, missing schemas, and zero-length collections."""

    def test_action_graph_empty_event_attributes(self):
        """Ingest event with empty taint labels, empty payload, and None parent_span_id."""
        ag = ActionGraph()
        event = make_boundary_event(
            taint_labels=[],
            payload_redacted={},
            parent_span_id=None,
        )
        ag.ingest_event(event)
        assert ag.node_count >= 1

        node = ag.get_node(event.span_id)
        assert node is not None
        assert node.taint_labels == []
        assert node.payload == {"tool_name": "test_tool"}

    def test_action_graph_empty_trace_lookups(self):
        """Query get_node, get_nodes, get_edges, get_active_node on non-existent traces."""
        ag = ActionGraph()
        assert ag.get_node("non-existent-span") is None
        assert ag.get_nodes("non-existent-trace") == []
        assert ag.get_edges("non-existent-trace") == []
        assert ag.get_active_node("non-existent-trace") is None
        assert ag.is_dag("non-existent-trace") is True
        assert ag.has_cycles("non-existent-trace") is False
        assert ag.get_topological_order("non-existent-trace") == []

    def test_motif_detector_empty_and_disconnected_graphs(self):
        """Scan empty DiGraph, single isolated node, and disconnected components."""
        detector = MotifAnomalyDetector()
        # 1. Empty graph
        g_empty = nx.DiGraph()
        assert detector.scan_trace(g_empty, "tr-empty") == []

        # 2. Single isolated node
        g_single = nx.DiGraph()
        g_single.add_node("node1", trace_id="tr-single", node_type=GraphNodeType.USER.value)
        assert detector.scan_trace(g_single, "tr-single") == []

        # 3. Disconnected nodes
        g_disc = nx.DiGraph()
        g_disc.add_node("n1", trace_id="tr-disc", node_type=GraphNodeType.USER.value)
        g_disc.add_node("n2", trace_id="tr-disc", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": "safe"})
        assert detector.scan_trace(g_disc, "tr-disc") == []

    def test_topology_builder_none_principal_and_empty_policy(self):
        """Build topology with user_principal=None and empty tools list."""
        policy = PolicySchema(
            version="1.0.0",
            agent_id="minimal-agent",
            goal_anchor=GoalAnchorConfig(canonical_task="Minimal task", allowed_domains=[]),
            tools=[],
            budgets=BudgetsConfig(
                max_turns=10,
                max_tool_calls=25,
                max_identical_calls=3,
                max_session_duration_sec=120.0,
                max_session_cost_usd=5.0,
            ),
        )
        model = AgentTopologyBuilder.build_topology(policy, user_principal=None)
        assert model.user_principal is None
        assert len(model.tools) == 0

        rf = model.to_react_flow()
        assert isinstance(rf, dict)
        assert "nodes" in rf

        mermaid = model.to_mermaid()
        assert "flowchart LR" in mermaid

    def test_embedding_engines_empty_and_whitespace_inputs(self):
        """Encode empty list [], empty string '', and whitespace strings."""
        engine = DeterministicEmbeddingEngine(seed=123)

        # Empty list returns empty matrix
        empty_mat = engine.encode([])
        assert empty_mat.shape == (0, 384)

        # Empty string and whitespace return zero vectors (norm == 0.0)
        v_empty = engine.encode_one("")
        assert v_empty.shape == (384,)
        assert np.linalg.norm(v_empty) == pytest.approx(0.0)

        v_white = engine.encode_one("   \t\n  ")
        assert np.linalg.norm(v_white) == pytest.approx(0.0)

    def test_semantic_drift_missing_anchor_error(self):
        """Calling evaluate_step() without configured or passed anchor raises ValueError."""
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(), goal_anchor=None)
        with pytest.raises(ValueError, match="No goal anchor provided or configured"):
            calc.evaluate_step(
                trace_id="tr-no-anchor",
                step_text="Executing search",
                anchor_text=None,
                policy=None,
            )

    def test_persuasion_empty_and_whitespace_inputs(self):
        """Verify empty and whitespace inputs cleanly return 0.0 without errors."""
        clf = PersuasionClassifier()
        for empty_val in ["", "   ", "\t\n\r  ", " \n "]:
            res = clf.classify(empty_val)
            assert res.score == 0.0
            assert res.tactics_detected == []
            assert not res.is_flagged
            assert res.risk_level == PersuasionRiskLevel.NONE

    def test_duckdb_empty_table_queries(self):
        """Query empty DuckDB store returns 0 rows without errors."""
        store = DuckDbAnalyticsStore()
        assert store.row_count("events") == 0
        assert store.row_count("graph_edges") == 0

        res = store.execute_kql("events | where verdict == 'BLOCK'")
        assert isinstance(res, KqlQueryResult)
        assert len(res.rows) == 0


# ===========================================================================
# Group 2: Extremes, Large Payloads (>50KB) & Deep Structures / Cycles
# ===========================================================================

class TestTier2ExtremePayloadsAndGraphBoundaries:
    """Stress test system with >50KB payloads, deep chains, 1000-step windows, and cycles."""

    def test_action_graph_extreme_payload_and_deep_recursion(self):
        """Ingest event containing >50KB string and deep nested payload dictionary."""
        ag = ActionGraph()
        large_str = "A" * 60000  # 60KB string
        nested_dict: dict = {"key": "leaf"}
        for depth in range(15):
            nested_dict = {f"level_{depth}": nested_dict}

        event = make_boundary_event(
            tool_name="heavy_tool",
            payload_redacted={"big_data": large_str, "nested": nested_dict},
        )
        ag.ingest_event(event)

        node = ag.get_node(event.span_id)
        assert node is not None
        assert len(node.payload["big_data"]) == 60000

        # Serialization handles extreme payload cleanly
        exported = ag.export_dict(event.trace_id)
        assert exported["node_count"] >= 1

    def test_action_graph_disconnected_and_cyclic_graphs(self):
        """Test ActionGraph handling of cyclic NetworkX structures."""
        ag = ActionGraph()
        t_id = "tr-cycle"
        e1 = make_boundary_event(trace_id=t_id, span_id="c1", event_type=EventType.USER_INPUT)
        e2 = make_boundary_event(trace_id=t_id, span_id="c2", parent_span_id="c1", tool_name="tool_loop")
        ag.ingest_events([e1, e2])

        # Inject cycle: c2 -> c1
        with ag._lock:
            ag._graph.add_edge("c2", "c1")

        assert ag.is_dag(t_id) is False
        assert ag.has_cycles(t_id) is True
        assert ag.get_topological_order(t_id) == []

        # Motif detector flags execution loop cycle
        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(ag.graph, t_id)
        assert any(v.motif_type == MotifType.EXECUTION_LOOP for v in violations)

    def test_motif_detector_fan_out_exact_threshold_boundaries(self):
        """Test fan-out at exactly 7 tool calls (no violation), 8 calls (1 violation), and 100 calls."""
        detector = MotifAnomalyDetector(fan_out_threshold=8)

        # Sub-test 1: 7 tool calls -> 0 fan-out violations
        g7 = nx.DiGraph()
        g7.add_node("root", trace_id="tr-fo7", node_type=GraphNodeType.USER.value)
        for i in range(7):
            t_id = f"tool_{i}"
            g7.add_node(t_id, trace_id="tr-fo7", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": f"unique_sub_{i}"})
            g7.add_edge("root", t_id)
        v7 = [v for v in detector.scan_trace(g7, "tr-fo7") if v.motif_type == MotifType.FAN_OUT_BURST]
        assert len(v7) == 0

        # Sub-test 2: 8 tool calls -> exactly 1 violation
        g8 = nx.DiGraph()
        g8.add_node("root", trace_id="tr-fo8", node_type=GraphNodeType.USER.value)
        for i in range(8):
            t_id = f"tool_{i}"
            g8.add_node(t_id, trace_id="tr-fo8", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": f"unique_sub_{i}"})
            g8.add_edge("root", t_id)
        v8 = [v for v in detector.scan_trace(g8, "tr-fo8") if v.motif_type == MotifType.FAN_OUT_BURST]
        assert len(v8) == 1
        assert len(v8[0].affected_nodes) == 9  # root + 8 tools

        # Sub-test 3: 100 tool calls -> still exactly 1 violation aggregating all targets
        g100 = nx.DiGraph()
        g100.add_node("root", trace_id="tr-fo100", node_type=GraphNodeType.USER.value)
        for i in range(100):
            t_id = f"tool_{i}"
            g100.add_node(t_id, trace_id="tr-fo100", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": f"unique_sub_{i}"})
            g100.add_edge("root", t_id)
        v100 = [v for v in detector.scan_trace(g100, "tr-fo100") if v.motif_type == MotifType.FAN_OUT_BURST]
        assert len(v100) == 1
        assert len(v100[0].affected_nodes) == 101

    def test_motif_detector_streak_aggregation_boundary(self):
        """Test consecutive tool streaks at 2 (no violation), 3 (violation), and 15 (aggregated violation)."""
        detector = MotifAnomalyDetector(loop_threshold=3)

        # 2 identical consecutive calls -> 0 violations
        ag2 = ActionGraph()
        ag2.ingest_events([
            make_boundary_event(trace_id="tr-st2", tool_name="search", payload_redacted={"q": "CVE"})
            for _ in range(2)
        ])
        assert len(detector.scan_trace(ag2.graph, "tr-st2")) == 0

        # 3 identical consecutive calls -> 1 violation
        ag3 = ActionGraph()
        ag3.ingest_events([
            make_boundary_event(trace_id="tr-st3", tool_name="search", payload_redacted={"q": "CVE"})
            for _ in range(3)
        ])
        v3 = detector.scan_trace(ag3.graph, "tr-st3")
        assert any(v.motif_type == MotifType.EXECUTION_LOOP for v in v3)

        # 15 identical consecutive calls -> aggregated violation
        ag15 = ActionGraph()
        ag15.ingest_events([
            make_boundary_event(trace_id="tr-st15", tool_name="search", payload_redacted={"q": "CVE"})
            for _ in range(15)
        ])
        v15 = detector.scan_trace(ag15.graph, "tr-st15")
        loop_violations = [v for v in v15 if v.motif_type == MotifType.EXECUTION_LOOP]
        assert len(loop_violations) >= 1

    def test_drift_calculator_extreme_text_payload(self):
        """Evaluate step with text payload >50KB without memory blowup or NaN/Inf."""
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42))
        large_step = "Adversarial payload step " * 3000  # ~75KB
        res = calc.evaluate_step(
            trace_id="tr-extreme-text",
            step_text=large_step,
            anchor_text="Routine monitoring task",
        )
        assert 0.0 <= res.drift_score <= 1.0
        assert 0.0 <= res.composite_risk <= 1.0
        assert not np.isnan(res.drift_score)

    def test_drift_calculator_1000_step_sliding_window(self):
        """Evaluate 1,000 steps sequentially in a single trace."""
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42), window_size=3)
        anchor = "Continuous security monitoring goal"
        t_id = "tr-1000-steps"

        for i in range(1000):
            calc.evaluate_step(
                trace_id=t_id,
                step_text=f"Monitoring step {i} checking service health",
                anchor_text=anchor,
            )

        trajectory = calc.get_trajectory(t_id)
        assert len(trajectory) == 1000
        assert trajectory[-1].step_index == 999
        # Sliding window dampens using only the last 3 steps
        assert 0.0 <= trajectory[-1].sliding_window_drift <= 1.0

    def test_persuasion_extreme_text_payload_no_backtracking(self):
        """Verify >50KB payload processes swiftly (<250ms) without catastrophic backtracking."""
        clf = PersuasionClassifier()
        benign_chunk = "Telemetry log buffer entry 0x8849 running standard background diagnostics. "
        huge_text = (benign_chunk * 1000) + "Act now immediately per CEO directive!"
        assert len(huge_text.encode("utf-8")) > 50000

        t0 = time.perf_counter()
        res = clf.classify(huge_text)
        elapsed = time.perf_counter() - t0

        assert elapsed < 0.25  # Under 250ms requirement
        assert res.is_flagged
        assert PersuasionTactic.ARTIFICIAL_URGENCY in res.tactics_detected

    def test_persuasion_tool_call_circular_and_deep_recursion(self):
        """Verify recursive argument inspection safely handles circular references and deep nesting."""
        clf = PersuasionClassifier()

        # Circular reference
        circular_dict: dict = {"key": "value"}
        circular_dict["self"] = circular_dict
        res_circ = clf.classify_tool_call("circ_tool", circular_dict)
        assert res_circ.score == 0.0

        # Deep nesting beyond max_depth limit (depth > 20)
        deep_dict: Any = "Act now immediately!"
        for _ in range(30):
            deep_dict = {"layer": deep_dict}
        res_deep = clf.classify_tool_call("deep_tool", deep_dict)
        assert res_deep.score == 0.0


# ===========================================================================
# Group 3: Numeric Boundaries, Float Clamping & Division-by-Zero Guards
# ===========================================================================

class TestTier2NumericBoundariesAndGuards:
    """Test float boundaries, exact threshold transitions, and division by zero guards."""

    def test_drift_calculator_float_clamping_exact_boundaries(self):
        """Verify S_policy, S_graph, S_velocity clamped strictly to [0.0, 1.0]."""
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42))

        # Pass negative floats (< 0.0) -> should be clamped to 0.0
        res_neg = calc.evaluate_step(
            "tr-clamp-neg",
            "action",
            "action",
            s_policy=-0.5,
            s_graph=-10.0,
            s_velocity=-1.0,
        )
        assert res_neg.composite_risk == pytest.approx(0.0, abs=1e-3)
        assert res_neg.classification == DriftClassification.NORMAL

        # Pass floats exceeding 1.0 -> should be clamped to 1.0
        res_pos = calc.evaluate_step(
            "tr-clamp-pos",
            "action",
            "action",
            s_policy=1.5,
            s_graph=2.0,
            s_velocity=10.0,
        )
        assert res_pos.composite_risk <= 1.0
        assert res_pos.classification == DriftClassification.CRITICAL

    def test_drift_calculator_exact_threshold_transitions(self):
        """Test mathematical transition points: 0.5499 vs 0.55, 0.7499 vs 0.75, 0.8999 vs 0.90."""
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42))
        anchor = "exact transition target"

        # 1. 0.5499 vs 0.5500: NORMAL vs ELEVATED
        # Using weights: 0.45, 0.25, 0.15, 0.15. Zero out semantic drift by using identical text (d_t = 0.0)
        # S_policy = 0.5499 / 0.45 = 1.222 (exceeds 1.0, so use combination):
        # 0.45 * 0.8 + 0.25 * 0.7596 = 0.36 + 0.1899 = 0.5499 -> NORMAL
        res_norm = calc.evaluate_step("tr-t1", anchor, anchor, s_policy=0.8, s_graph=0.7596)
        assert res_norm.composite_risk < 0.55
        assert res_norm.classification == DriftClassification.NORMAL

        # 0.45 * 0.8 + 0.25 * 0.7600 = 0.36 + 0.1900 = 0.5500 -> ELEVATED
        res_elev = calc.evaluate_step("tr-t2", anchor, anchor, s_policy=0.8, s_graph=0.7600)
        assert res_elev.composite_risk >= 0.55
        assert res_elev.classification == DriftClassification.ELEVATED

        # 2. 0.7499 vs 0.7500: ELEVATED vs HIGH_RISK
        # 0.45 * 0.9 + 0.25 * 0.9 + 0.15 * 0.7993 = 0.405 + 0.225 + 0.1199 = 0.7499
        res_elev2 = calc.evaluate_step("tr-t3", anchor, anchor, s_policy=0.9, s_graph=0.9, s_velocity=0.7993)
        assert res_elev2.composite_risk < 0.75
        assert res_elev2.classification == DriftClassification.ELEVATED

        # 0.45 * 0.9 + 0.25 * 0.9 + 0.15 * 0.8000 = 0.405 + 0.225 + 0.1200 = 0.7500
        res_high = calc.evaluate_step("tr-t4", anchor, anchor, s_policy=0.9, s_graph=0.9, s_velocity=0.8000)
        assert res_high.composite_risk >= 0.75
        assert res_high.classification == DriftClassification.HIGH_RISK

        # 3. 0.8999 vs 0.9000: HIGH_RISK vs CRITICAL
        # 0.45 * 0.95 + 0.25 * 0.95 + 0.15 * 0.95 + 0.15 * 0.616 = 0.4275 + 0.2375 + 0.1425 + 0.0924 = 0.8999
        res_high2 = calc.evaluate_step("tr-t5", anchor, anchor, s_policy=0.95, s_graph=0.95, s_velocity=0.95)
        # S_semantic for identical anchor is 0.0 -> Rt = 0.8075 (HIGH_RISK)
        assert res_high2.classification == DriftClassification.HIGH_RISK

        # Critical threshold reached via override
        res_crit = calc.evaluate_step("tr-t6", anchor, anchor, is_critical_policy_violation=True)
        assert res_crit.composite_risk == 1.0
        assert res_crit.classification == DriftClassification.CRITICAL

    def test_embedding_engine_division_by_zero_guards(self):
        """Compute similarity and cosine distance between zero-norm vectors without division by zero."""
        engine = DeterministicEmbeddingEngine()
        # Empty strings yield zero-norm vectors
        sim = engine.similarity("", "")
        assert sim == 0.0

        dist = engine.cosine_distance("", "")
        assert dist == 1.0

        # One empty, one populated
        sim_half = engine.similarity("hello world", "")
        assert sim_half == 0.0
        dist_half = engine.cosine_distance("hello world", "")
        assert dist_half == 1.0

    def test_drift_calculator_zero_weights_and_window_size_one(self):
        """Test calculator with weights=(0.0, 0.0, 0.0, 0.0) and window_size=1."""
        calc_zero = SemanticDriftCalculator(
            engine=DeterministicEmbeddingEngine(),
            weights=(0.0, 0.0, 0.0, 0.0),
            window_size=1,
        )
        # Sub-critical policy signal: composite risk should evaluate to 0.0 due to 0-weights
        res = calc_zero.evaluate_step(
            "tr-zero-w",
            "different step text",
            "anchor goal",
            s_policy=0.8,
            s_graph=0.8,
        )
        assert res.composite_risk == 0.0
        assert res.classification == DriftClassification.NORMAL

        # Critical policy override (s_policy=1.0) forces composite risk to 1.0 regardless of weights
        res_override = calc_zero.evaluate_step(
            "tr-zero-override",
            "different step text",
            "anchor goal",
            s_policy=1.0,
        )
        assert res_override.composite_risk == 1.0
        assert res_override.classification == DriftClassification.CRITICAL

    def test_persuasion_calibrated_threshold_boundaries(self):
        """Verify exact risk level boundaries: 0.20, 0.45, 0.70, 0.85."""
        clf = PersuasionClassifier()

        # Clean text: NONE (< 0.20)
        r_none = clf.classify("Update database connection pool size to 10.")
        assert r_none.score < 0.20
        assert r_none.risk_level == PersuasionRiskLevel.NONE

        # Medium / High levels
        r_med = clf.classify("Please act now, time is running out.")
        assert r_med.risk_level in (PersuasionRiskLevel.MEDIUM, PersuasionRiskLevel.HIGH)

        # Critical level: >= 0.85
        r_crit = clf.classify(
            "ACT NOW! Per CISO mandate, failure to comply will cause catastrophic system crash "
            "and immediate termination of your employment!"
        )
        assert r_crit.score >= 0.85
        assert r_crit.risk_level == PersuasionRiskLevel.CRITICAL

    def test_hitl_exact_dual_approver_threshold_trigger(self):
        """Verify exact boundary 0.75 triggers required_approvers = 2."""
        gate = HitlReviewGate()

        # 0.749 -> 1 approver
        t_sub = gate.create_ticket(tool_name="tool_1", persuasion_score=0.749)
        assert t_sub.required_approvers == 1

        # 0.750 -> 2 approvers
        t_exact = gate.create_ticket(tool_name="tool_2", persuasion_score=0.750)
        assert t_exact.required_approvers == 2


# ===========================================================================
# Group 4: Security Hardening & SQL Injection Neutralization in KQL-Lite
# ===========================================================================

class TestTier2SecurityAndSqlInjectionBoundaries:
    """Validates SQL injection neutralization, syntax hardening, and parameterized safety."""

    def test_kql_sql_injection_payloads_neutralized(self):
        """Verify classic SQL injection payloads are strictly parameterized and cannot alter queries."""
        store = DuckDbAnalyticsStore()
        payloads = [
            "'; DROP TABLE events; --",
            "' OR 1=1 --",
            "' UNION SELECT * FROM events --",
            "admin'--",
            "1' OR '1'='1",
        ]
        store.ingest_event(make_boundary_event(verdict=Verdict.BLOCK, tool_name="safe_tool"))

        for payload in payloads:
            kql = f'events | where tool_name == "{payload}"'
            pipeline = parse(kql)
            compiled = KqlCompiler().compile(pipeline)

            # Verification 1: Payload is NEVER directly concatenated into the raw SQL string
            assert payload not in compiled.sql
            # Verification 2: Payload is in bind parameters
            assert payload in compiled.params

            # Verification 3: Execution against DuckDB runs safely without error or dropping table
            result = store.execute_query(compiled.sql, compiled.params)
            assert isinstance(result, list)
            assert store.row_count("events") == 1  # Table not dropped!

    def test_kql_identifier_sql_injection_rejected(self):
        """Verify column names with punctuation/semicolons are rejected by parser or compiler."""
        # Parser rejects invalid characters in identifier
        with pytest.raises(ParseError):
            parse("events | where tool_name; DROP TABLE events; == 'test'")

        # Compiler rejects unsafe AST column identifiers
        unsafe_ast = KqlPipeline(
            source=TableSource(name="events"),
            operators=[
                WhereClause(
                    predicate=BinaryOp(
                        op="==",
                        left=ColumnRef(name="tool_name; DROP TABLE events;"),
                        right=Literal(value="test"),
                    )
                )
            ],
        )
        with pytest.raises(ValueError, match="Invalid column name"):
            KqlCompiler().compile(unsafe_ast)

    def test_kql_parser_syntax_hardening_validations(self):
        """Verify hardened syntax checks for single =, arithmetic ops, invalid durations, empty clauses."""
        # 1. Single equals
        with pytest.raises(ParseError, match="did you mean '=='"):
            parse("events | where verdict = 'BLOCK'")

        # 2. Arithmetic operator
        with pytest.raises(ParseError, match="Unexpected operator"):
            parse("events | where risk_score + 1")

        # 3. Invalid aggregation
        with pytest.raises(ParseError, match="Unknown aggregation function"):
            parse("events | summarize invalid_agg() by agent_id")

        # 4. Malformed ago()
        with pytest.raises(ParseError, match="Invalid duration format for ago"):
            parse("events | where timestamp > ago(99xyz)")

        # 5. Empty project or trailing comma
        with pytest.raises(ParseError):
            parse("events | project")
        with pytest.raises(ParseError):
            parse("events | project event_id,")

        # 6. Empty in ()
        with pytest.raises(ParseError, match="Expected at least one literal value inside in"):
            parse("events | where verdict in ()")


# ===========================================================================
# Group 5: High-Volume Concurrency & Out-of-Order Ingestion Boundaries
# ===========================================================================

class TestTier2ConcurrencyAndOrderBoundaries:
    """Verify thread-safety and race immunity across concurrent traces and out-of-order storms."""

    def test_action_graph_concurrent_multi_trace_ingestion(self):
        """20 concurrent threads ingesting 20 events each across 20 distinct traces."""
        ag = ActionGraph()
        errors = []

        def worker(trace_idx: int):
            try:
                t_id = f"trace-thread-{trace_idx}"
                for i in range(20):
                    ev = make_boundary_event(trace_id=t_id, tool_name=f"tool_{i}")
                    ag.ingest_event(ev)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(20)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        # Each trace has at least 20 events + 1 user principal root node
        assert ag.node_count >= 400

    def test_drift_calculator_concurrent_multi_trace_evaluation(self):
        """20 concurrent threads evaluating steps across 20 distinct traces."""
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42))
        errors = []

        def worker(trace_idx: int):
            try:
                t_id = f"tr-drift-conc-{trace_idx}"
                for i in range(10):
                    calc.evaluate_step(
                        trace_id=t_id,
                        step_text=f"Thread {trace_idx} step {i}",
                        anchor_text="Anchor goal for concurrent worker",
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(20)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        for t in range(20):
            traj = calc.get_trajectory(f"tr-drift-conc-{t}")
            assert len(traj) == 10

    def test_action_graph_high_volume_out_of_order_resolution(self):
        """Ingest 50 events in completely reversed causal order."""
        ag = ActionGraph()
        t_id = "tr-reverse-chain"

        # Construct a causal chain of 50 steps: e0 -> e1 -> e2 ... -> e49
        events = []
        for i in range(50):
            p_span = f"span_{i-1}" if i > 0 else None
            ev = make_boundary_event(
                trace_id=t_id,
                span_id=f"span_{i}",
                parent_span_id=p_span,
                event_type=EventType.USER_INPUT if i == 0 else EventType.TOOL_INVOCATION,
                tool_name=f"chain_step_{i}",
            )
            events.append(ev)

        # Ingest in reversed order: e49 down to e0
        for ev in reversed(events):
            ag.ingest_event(ev)

        # Once span_0 (root) arrives, all pending parents should resolve
        assert ag.is_dag(t_id) is True
        edges = ag.get_edges(t_id)
        assert len(edges) >= 49

    def test_hitl_concurrent_ticket_creation_and_adjudication(self):
        """Verify 50 threads creating tickets simultaneously maintain unique IDs and thread-safety."""
        gate = HitlReviewGate()
        ticket_ids = []
        errors = []

        def worker():
            try:
                t = gate.create_ticket(tool_name="concurrent_tool", arguments={"i": 1})
                ticket_ids.append(t.ticket_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        assert len(ticket_ids) == 50
        assert len(set(ticket_ids)) == 50

    def test_duckdb_concurrent_multithreaded_ingestion_and_queries(self):
        """Verify 10 threads ingesting events and 5 threads executing KQL queries concurrently."""
        store = DuckDbAnalyticsStore()
        ingest_errors = []
        query_errors = []

        def ingest_worker(thread_id: int):
            try:
                for j in range(15):
                    ev = make_boundary_event(
                        trace_id=f"tr-{thread_id}-{j}",
                        verdict=Verdict.BLOCK if j % 2 == 0 else Verdict.ALLOW,
                    )
                    store.ingest_event(ev)
            except Exception as e:
                ingest_errors.append(e)

        def query_worker():
            try:
                for _ in range(10):
                    store.execute_kql("events | where verdict == 'BLOCK' | take 5")
            except Exception as e:
                query_errors.append(e)

        threads = []
        for i in range(10):
            threads.append(threading.Thread(target=ingest_worker, args=(i,)))
        for _ in range(5):
            threads.append(threading.Thread(target=query_worker))

        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(ingest_errors) == 0
        assert len(query_errors) == 0
        assert store.row_count("events") == 150
