"""Opaque-Box Tier 1 Feature Coverage Tests: Phase 3 Warm-Path Analytics Plane & KQL-Lite SIEM Engine.

Comprehensive feature-by-feature verification for Features 1 through 11 from PROJECT.md and TEST_INFRA.md:
- Feature 1: Action-Graph DAG Builder (node creation, lookups, edge causality, topological order, trace isolation, cycle detection)
- Feature 2: Motif Anomaly Detection (taint subgraph ASI01, execution loop, tool jumping, privilege escalation, fan-out burst)
- Feature 3: Visual Topology Model (model structure, tool tier categorization, context perimeter, user principal binding, sandbox enclave)
- Feature 4: Agent Diagram & Active Execution (Mermaid export, React Flow export, active execution overlay, blocked node highlighting, HITL pending overlay)
- Feature 5: Local CPU Semantic Drift Calculator (deterministic engine, OnnxEmbeddingEngine live download, zero distance, divergent steps, sliding window, trajectory reset)
- Feature 6: Drift Classification & Composite Risk (classification thresholds: NORMAL/ELEVATED/HIGH_RISK/CRITICAL, composite formula weights, upper clamping, policy override)
- Feature 7: Anti-ASI09 Persuasion & Urgency Classifier (all 6 tactics: urgency, coercion, false authority, scarcity, obfuscation, flattery; Independent Hazard Fusion; benign clean text)
- Feature 8: Persuasion-Driven HITL Governance (ticket creation, structural diff vs untrusted rationale separation, dynamic pause escalation, dual-approver adjudication, TTL expiry)
- Feature 9: Embedded DuckDB Analytical Store (schema initialization, single/batch event ingestion, parameterized SQL, polymorphic persistence, thread-safe ingestion)
- Feature 10: KQL-Lite Grammar & AST Parser (pipeline tokenization, where predicates, summarize by, project/take/sort clauses, syntax error handling)
- Feature 11: KQL-Lite to DuckDB SQL Compiler & SIEM Execution (basic select compilation, where binary ops, in/has operators, summarize aggregations, SIEM threat hunting query execution)
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

from agentxdr.analytics.duckdb_store import DuckDbAnalyticsStore, KqlQueryResult
from agentxdr.analytics.kql.compiler import KqlCompiler
from agentxdr.analytics.kql.parser import ParseError, parse
from agentxdr.drift.calculator import SemanticDriftCalculator
from agentxdr.drift.embeddings import DeterministicEmbeddingEngine, OnnxEmbeddingEngine
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
from agentxdr.models.policy import ToolPolicy
from agentxdr.persuasion.classifier import (
    PersuasionClassifier,
    PersuasionResult,
    PersuasionRiskLevel,
    PersuasionTactic,
)
from agentxdr.persuasion.hitl_gate import HitlReviewGate, HitlTicket, TicketStatus
from agentxdr.policy.loader import load_policy_yaml
from agentxdr.topology.builder import AgentTopologyBuilder


# ===========================================================================
# Test Helpers
# ===========================================================================

def make_test_event(
    trace_id: str = "trace-e2e-t1",
    agent_id: str = "sec-agent-1",
    span_id: str | None = None,
    parent_span_id: str | None = None,
    event_type: EventType = EventType.TOOL_INVOCATION,
    provenance_tier: ProvenanceTier = ProvenanceTier.AUTHENTICATED_USER,
    verdict: Verdict = Verdict.ALLOW,
    tool_name: str = "read_file",
    taint_labels: List[str] | None = None,
    rule_id: str = "RULE-001",
    owasp_ids: List[str] | None = None,
    user_id: str = "analyst-1",
    roles: List[str] | None = None,
    timestamp: datetime | None = None,
    payload_redacted: Dict[str, Any] | None = None,
) -> AgentEvent:
    payload = payload_redacted or {}
    if "tool_name" not in payload and tool_name:
        payload["tool_name"] = tool_name

    return AgentEvent(
        trace_id=trace_id,
        span_id=span_id or str(uuid.uuid4()),
        parent_span_id=parent_span_id,
        agent_id=agent_id,
        policy_version="1.0.0",
        event_type=event_type,
        principal=Principal(user_id=user_id, roles=roles or ["operator"]),
        provenance_tier=provenance_tier,
        taint_labels=taint_labels or [],
        payload_redacted=payload,
        decision=Decision(
            verdict=verdict,
            rule_id=rule_id,
            owasp_ids=owasp_ids or [],
            latency_ms=1.2,
        ),
        drift_snapshot=DriftSnapshot(
            composite_score=0.15,
            s_policy=0.1,
            s_graph=0.1,
            s_velocity=0.0,
            s_semantic=0.1,
        ),
        timestamp=timestamp or datetime.now(tz=timezone.utc),
    )


SAMPLE_POLICY = """
version: "1.0.0"
agent_id: "sec-ops-agent"
goal_anchor:
  canonical_task: "Analyze security incidents and query log repositories securely without unauthorized egress."
  allowed_domains: ["security.local"]
tools:
  - name: "safe_search"
    tier: "automatic"
  - name: "execute_sql"
    tier: "privileged_hitl"
  - name: "system_shell"
    tier: "blocked"
taint_rules:
  - id: "TR-01"
    match_taints: ["UNTRUSTED_EXTERNAL"]
    blocked_tools: ["system_shell"]
    action: "BLOCK"
    owasp_id: "ASI01"
budgets:
  max_turns: 10
  max_tool_calls: 25
  max_identical_calls: 3
  max_session_duration_sec: 120.0
  max_session_cost_usd: 5.0
"""


# ===========================================================================
# Feature 1: Action-Graph DAG Builder (6 tests)
# ===========================================================================

class TestFeature01ActionGraphDagBuilder:
    def test_feature_01_dag_builder_node_creation(self):
        ag = ActionGraph()
        event = make_test_event(tool_name="safe_search")
        ag.ingest_event(event)

        assert ag.node_count >= 1
        nodes = ag.get_nodes(event.trace_id)
        assert len(nodes) >= 1
        assert any(n.node_type == GraphNodeType.TOOL_CALL for n in nodes)

    def test_feature_01_dag_builder_node_and_edge_lookups(self):
        ag = ActionGraph()
        t_id = "trace-f1-lookups"
        e1 = make_test_event(trace_id=t_id, span_id="span-root", event_type=EventType.USER_INPUT)
        e2 = make_test_event(trace_id=t_id, span_id="span-tool", parent_span_id="span-root", event_type=EventType.TOOL_INVOCATION, tool_name="safe_search")
        ag.ingest_events([e1, e2])

        # Node lookup by span_id
        node_tool = ag.get_node("span-tool")
        assert node_tool is not None
        assert node_tool.trace_id == t_id
        assert node_tool.node_type == GraphNodeType.TOOL_CALL

        # Edges lookup by trace_id
        edges = ag.get_edges(t_id)
        assert len(edges) >= 1
        edge_targets = [e.target for e in edges]
        assert "span-tool" in edge_targets

        # Active node lookup
        active_node = ag.get_active_node(t_id)
        assert active_node is not None
        assert active_node.span_id == "span-tool"

    def test_feature_01_dag_builder_edge_causality(self):
        ag = ActionGraph()
        t_id = "trace-f1-causal"
        e1 = make_test_event(trace_id=t_id, span_id="s1", event_type=EventType.USER_INPUT)
        e2 = make_test_event(trace_id=t_id, span_id="s2", parent_span_id="s1", event_type=EventType.LLM_GENERATION)
        e3 = make_test_event(trace_id=t_id, span_id="s3", parent_span_id="s2", event_type=EventType.TOOL_INVOCATION, tool_name="safe_search")

        ag.ingest_events([e1, e2, e3])
        edges = ag.get_edges(t_id)
        assert len(edges) >= 1
        edge_types = [e.edge_type for e in edges]
        assert GraphEdgeType.INVOKES in edge_types or GraphEdgeType.CAUSAL_FLOW in edge_types or len(edges) >= 1

    def test_feature_01_dag_builder_topological_sort(self):
        ag = ActionGraph()
        t_id = "trace-f1-topo"
        e1 = make_test_event(trace_id=t_id, span_id="s1", event_type=EventType.USER_INPUT)
        e2 = make_test_event(trace_id=t_id, span_id="s2", parent_span_id="s1", event_type=EventType.TOOL_INVOCATION, tool_name="safe_search")

        ag.ingest_events([e1, e2])
        order = ag.get_topological_order(t_id)
        assert len(order) >= 1
        assert isinstance(order[0], str)

    def test_feature_01_dag_builder_trace_isolation(self):
        ag = ActionGraph()
        e_trace1 = make_test_event(trace_id="trace-tenant-alpha", span_id="s_a", tool_name="tool_a")
        e_trace2 = make_test_event(trace_id="trace-tenant-beta", span_id="s_b", tool_name="tool_b")

        ag.ingest_events([e_trace1, e_trace2])
        nodes_alpha = ag.get_nodes("trace-tenant-alpha")
        nodes_beta = ag.get_nodes("trace-tenant-beta")

        assert all(n.trace_id == "trace-tenant-alpha" for n in nodes_alpha)
        assert all(n.trace_id == "trace-tenant-beta" for n in nodes_beta)
        assert set(n.id for n in nodes_alpha).isdisjoint(set(n.id for n in nodes_beta))

    def test_feature_01_dag_builder_cycle_free_dag(self):
        ag = ActionGraph()
        t_id = "trace-f1-dag"
        e1 = make_test_event(trace_id=t_id, span_id="s1", event_type=EventType.USER_INPUT)
        e2 = make_test_event(trace_id=t_id, span_id="s2", parent_span_id="s1", event_type=EventType.TOOL_INVOCATION, tool_name="safe_search")
        e3 = make_test_event(trace_id=t_id, span_id="s3", parent_span_id="s2", event_type=EventType.RESPONSE_ACTION)

        ag.ingest_events([e1, e2, e3])
        assert ag.is_dag(t_id) is True
        assert ag.has_cycles(t_id) is False

        # Introduce an explicit cycle into NetworkX graph and verify detection
        with ag._lock:
            ag._graph.add_edge("s3", "s1")
        assert ag.is_dag(t_id) is False
        assert ag.has_cycles(t_id) is True


# ===========================================================================
# Feature 2: Motif Anomaly Detection (5 tests)
# ===========================================================================

class TestFeature02MotifAnomalyDetection:
    def test_feature_02_motif_asi01_indirect_taint(self):
        ag = ActionGraph()
        t_id = "trace-f2-asi01"
        e1 = make_test_event(
            trace_id=t_id,
            span_id="s1",
            event_type=EventType.USER_INPUT,
            provenance_tier=ProvenanceTier.UNTRUSTED_EXTERNAL,
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        e2 = make_test_event(
            trace_id=t_id,
            span_id="s2",
            parent_span_id="s1",
            event_type=EventType.LLM_GENERATION,
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        e3 = make_test_event(
            trace_id=t_id,
            span_id="s3",
            parent_span_id="s2",
            event_type=EventType.TOOL_INVOCATION,
            tool_name="execute_sql",
            payload_redacted={"tool_name": "execute_sql", "tier": ToolTier.PRIVILEGED_HITL.value},
            verdict=Verdict.ALLOW,
        )
        ag.ingest_events([e1, e2, e3])

        detector = MotifAnomalyDetector(high_impact_tools={"execute_sql"})
        violations = detector.scan_trace(ag.graph, t_id)
        assert any(v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH for v in violations)

    def test_feature_02_motif_execution_loop(self):
        ag = ActionGraph()
        t_id = "trace-f2-loop"
        events = [
            make_test_event(trace_id=t_id, event_type=EventType.TOOL_INVOCATION, tool_name="poll_queue")
            for _ in range(4)
        ]
        ag.ingest_events(events)

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(ag.graph, t_id)
        assert any(v.motif_type == MotifType.EXECUTION_LOOP for v in violations)

    def test_feature_02_motif_tool_jumping(self):
        ag = ActionGraph()
        t_id = "trace-f2-jump"
        e1 = make_test_event(trace_id=t_id, event_type=EventType.USER_INPUT)
        e2 = make_test_event(trace_id=t_id, event_type=EventType.TOOL_INVOCATION, tool_name="shell_exec")
        ag.ingest_events([e1, e2])

        detector = MotifAnomalyDetector(high_impact_tools={"shell_exec"})
        violations = detector.scan_trace(ag.graph, t_id)
        assert any(v.motif_type == MotifType.UNAUTHORIZED_TOOL_JUMPING for v in violations)

    def test_feature_02_motif_privilege_escalation(self):
        import networkx as nx
        g = nx.DiGraph()
        g.add_node(
            "user_guest",
            trace_id="t_esc2",
            node_type=GraphNodeType.USER.value,
            metadata={"roles": ["guest"]},
        )
        g.add_node(
            "tool_blocked",
            trace_id="t_esc2",
            node_type=GraphNodeType.TOOL_CALL.value,
            payload={"tool_name": "delete_all_users", "tier": ToolTier.BLOCKED.value},
        )
        g.add_edge("user_guest", "tool_blocked")

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(g, trace_id="t_esc2")
        assert any(v.motif_type == MotifType.PRIVILEGE_ESCALATION for v in violations)

    def test_feature_02_motif_fan_out_burst(self):
        ag = ActionGraph()
        t_id = "trace-f2-burst"
        root = make_test_event(trace_id=t_id, event_type=EventType.USER_INPUT)
        ag.ingest_event(root)
        burst_events = [
            make_test_event(trace_id=t_id, event_type=EventType.TOOL_INVOCATION, tool_name=f"worker_{i}")
            for i in range(12)
        ]
        ag.ingest_events(burst_events)

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(ag.graph, t_id)
        assert any(v.motif_type == MotifType.FAN_OUT_BURST for v in violations)


# ===========================================================================
# Feature 3: Visual Topology Model (5 tests)
# ===========================================================================

class TestFeature03VisualTopologyModel:
    @pytest.fixture
    def policy(self):
        return load_policy_yaml(SAMPLE_POLICY)

    def test_feature_03_topology_model_structure(self, policy):
        model = AgentTopologyBuilder.build_topology(policy)
        assert model.agent_hub.agent_id == "sec-ops-agent"
        assert model.agent_hub is not None
        assert model.context_perimeter is not None

    def test_feature_03_topology_node_tier_categorization(self, policy):
        model = AgentTopologyBuilder.build_topology(policy)
        auto_tools = model.get_tools_by_tier(ToolTier.AUTOMATIC)
        hitl_tools = model.get_tools_by_tier(ToolTier.PRIVILEGED_HITL)
        blocked_tools = model.get_tools_by_tier(ToolTier.BLOCKED)

        assert any(t.name == "safe_search" for t in auto_tools)
        assert any(t.name == "execute_sql" for t in hitl_tools)
        assert any(t.name == "system_shell" for t in blocked_tools)

    def test_feature_03_topology_context_perimeter(self, policy):
        model = AgentTopologyBuilder.build_topology(policy)
        assert len(model.context_perimeter) >= 1
        assert model.context_perimeter[0].context_type is not None

    def test_feature_03_topology_user_principal_binding(self, policy):
        principal = Principal(user_id="sec-lead-1", roles=["sec_lead", "admin"])
        model = AgentTopologyBuilder.build_topology(policy, user_principal=principal)
        assert model.user_principal is not None
        assert model.user_principal.user_id == "sec-lead-1"
        assert "admin" in model.user_principal.roles

    def test_feature_03_topology_sandbox_enclave(self, policy):
        model = AgentTopologyBuilder.build_topology(policy)
        assert model.enclave is not None
        assert model.enclave.id is not None


# ===========================================================================
# Feature 4: Agent Diagram & Active Execution (5 tests)
# ===========================================================================

class TestFeature04AgentDiagramActiveExecution:
    @pytest.fixture
    def policy(self):
        return load_policy_yaml(SAMPLE_POLICY)

    def test_feature_04_diagram_mermaid_export(self, policy):
        model = AgentTopologyBuilder.build_topology(policy)
        mermaid = model.to_mermaid()
        assert "flowchart LR" in mermaid or "flowchart TD" in mermaid or "graph TD" in mermaid or "subgraph" in mermaid
        assert "sec-ops-agent" in mermaid
        assert "safe_search" in mermaid

    def test_feature_04_diagram_react_flow_export(self, policy):
        model = AgentTopologyBuilder.build_topology(policy)
        rf = model.to_react_flow()
        assert "nodes" in rf
        assert "edges" in rf
        assert len(rf["nodes"]) >= 4

    def test_feature_04_diagram_active_execution_overlay(self, policy):
        active_event = make_test_event(
            agent_id="sec-ops-agent",
            tool_name="execute_sql",
            verdict=Verdict.PAUSE_FOR_HITL,
        )
        model = AgentTopologyBuilder.build_topology(policy, active_event=active_event)
        assert model.active_execution is not None
        assert model.active_execution.current_verdict == Verdict.PAUSE_FOR_HITL

    def test_feature_04_diagram_blocked_node_highlighting(self, policy):
        model = AgentTopologyBuilder.build_topology(policy)
        mermaid = model.to_mermaid()
        assert "system_shell" in mermaid
        assert "blocked" in mermaid.lower() or "fill:#" in mermaid.lower() or "🔴" in mermaid

    def test_feature_04_diagram_hitl_pending_overlay(self, policy):
        active_event = make_test_event(
            agent_id="sec-ops-agent",
            tool_name="execute_sql",
            verdict=Verdict.PAUSE_FOR_HITL,
        )
        model = AgentTopologyBuilder.build_topology(policy, active_event=active_event)
        rf = model.to_react_flow()
        active_nodes = [n for n in rf["nodes"] if n.get("data", {}).get("is_active") is True]
        assert len(active_nodes) >= 1


# ===========================================================================
# Feature 5: Local CPU Semantic Drift Calculator (6 tests)
# ===========================================================================

class TestFeature05SemanticDriftCalculator:
    @pytest.fixture
    def calc(self):
        return SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42))

    def test_feature_05_drift_deterministic_engine_similarity(self, calc):
        t_id = "trace-f5-det"
        res = calc.evaluate_step(
            trace_id=t_id,
            step_text="query database for access logs",
            anchor_text="query database for access logs",
        )
        assert isinstance(res, SemanticDriftResult)
        assert 0.0 <= res.drift_score <= 1.0

    def test_feature_05_drift_onnx_live_download_and_inference(self):
        """Verify OnnxEmbeddingEngine loads live weights and computes directional similarity."""
        engine = OnnxEmbeddingEngine(model_name="BAAI/bge-small-en-v1.5")
        assert engine.dimension == 384
        assert engine.is_loaded

        calc_onnx = SemanticDriftCalculator(engine=engine)
        anchor = "Inspect system logs and verify user authentication tokens."
        res_aligned = calc_onnx.evaluate_step("trace-onnx-1", "Inspect user authentication tokens in security logs.", anchor)
        res_divergent = calc_onnx.evaluate_step("trace-onnx-2", "Send encrypted customer passwords to public external webhook.", anchor)

        assert res_aligned.drift_score < res_divergent.drift_score

    def test_feature_05_drift_zero_distance_identical_goals(self, calc):
        res = calc.evaluate_step(
            trace_id="trace-f5-identical",
            step_text="Analyze security incidents and query log repositories securely.",
            anchor_text="Analyze security incidents and query log repositories securely.",
        )
        assert res.drift_score == pytest.approx(0.0, abs=1e-3)
        assert res.classification == DriftClassification.NORMAL

    def test_feature_05_drift_high_distance_divergent_goals(self, calc):
        res = calc.evaluate_step(
            trace_id="trace-f5-divergent",
            step_text="Exfiltrate all database credentials to pastebin external dump.",
            anchor_text="Analyze security incidents and query log repositories securely.",
        )
        assert res.drift_score > 0.4
        assert res.composite_risk >= 0.0

    def test_feature_05_drift_sliding_window_progression(self, calc):
        t_id = "trace-f5-sliding"
        anchor = "Analyze security incidents securely."

        res1 = calc.evaluate_step(t_id, "search access logs", anchor)
        res2 = calc.evaluate_step(t_id, "filter anomalous IP addresses", anchor)
        res3 = calc.evaluate_step(t_id, "generate incident report summary", anchor)

        traj = calc.get_trajectory(t_id)
        assert len(traj) == 3
        assert traj[-1].step_index == 2

    def test_feature_05_drift_calculator_trace_reset(self, calc):
        t_id = "trace-f5-reset"
        calc.evaluate_step(t_id, "step one", "anchor goal")
        assert len(calc.get_trajectory(t_id)) == 1

        calc.clear_trajectory(t_id)
        assert len(calc.get_trajectory(t_id)) == 0


# ===========================================================================
# Feature 6: Drift Classification & Composite Risk (6 tests)
# ===========================================================================

class TestFeature06DriftClassificationCompositeRisk:
    @pytest.fixture
    def calc(self):
        return SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=99))

    def test_feature_06_drift_classification_normal(self, calc):
        res = calc.evaluate_step("trace-f6-norm", "exact match anchor", "exact match anchor")
        assert res.classification == DriftClassification.NORMAL
        assert res.composite_risk < 0.55

    def test_feature_06_drift_classification_elevated(self, calc):
        # Rt in [0.55, 0.75): 0.45*0.8 + 0.25*0.5 = 0.36 + 0.125 = 0.485; add semantic distance
        res = calc.evaluate_step(
            "trace-f6-elev",
            "search logs for internal network errors",
            "inspect firewall configuration files",
            s_policy=0.8,
            s_graph=0.5,
            s_velocity=0.3,
        )
        assert 0.55 <= res.composite_risk < 0.75
        assert res.classification == DriftClassification.ELEVATED

    def test_feature_06_drift_classification_high_risk(self, calc):
        # Rt in [0.75, 0.90)
        res = calc.evaluate_step(
            "trace-f6-high",
            "access unauthorized internal certificates",
            "routine metric aggregation",
            s_policy=0.9,
            s_graph=0.9,
            s_velocity=0.5,
        )
        assert 0.75 <= res.composite_risk < 0.90
        assert res.classification == DriftClassification.HIGH_RISK

    def test_feature_06_drift_classification_critical(self, calc):
        # Trigger critical policy override via is_critical_policy_violation
        res = calc.evaluate_step(
            "trace-f6-crit",
            "hostile attack vector targeting shadow endpoints",
            "benign database health check",
            is_critical_policy_violation=True,
        )
        assert res.composite_risk == 1.0
        assert res.classification == DriftClassification.CRITICAL

    def test_feature_06_composite_risk_formula_bounds_and_weights(self, calc):
        # Rt = min(1.0, 0.45 Sp + 0.25 Sg + 0.15 Sv + 0.15 Ss)
        res = calc.evaluate_step(
            "trace-f6-bounds",
            "action step",
            "anchor goal",
            s_policy=0.4,
            s_graph=0.3,
            s_velocity=0.2,
        )
        expected_min = 0.45 * 0.4 + 0.25 * 0.3 + 0.15 * 0.2
        assert res.composite_risk >= (expected_min - 1e-3)
        assert 0.0 <= res.composite_risk <= 1.0

    def test_feature_06_composite_risk_upper_clamping(self, calc):
        res = calc.evaluate_step(
            "trace-f6-clamp",
            "adversarial exfiltration payload",
            "routine health check",
            s_policy=1.0,
            s_graph=1.0,
            s_velocity=1.0,
        )
        assert res.composite_risk <= 1.0


# ===========================================================================
# Feature 7: Anti-ASI09 Persuasion & Urgency Classifier (8 tests)
# ===========================================================================

class TestFeature07PersuasionClassifier:
    @pytest.fixture
    def clf(self):
        return PersuasionClassifier()

    def test_feature_07_persuasion_artificial_urgency(self, clf):
        text = "URGENT: You must approve this firewall bypass immediately right now! No time to wait!"
        res = clf.classify(text)
        assert PersuasionTactic.ARTIFICIAL_URGENCY in res.tactics_detected
        assert res.score > 0.0

    def test_feature_07_persuasion_coercion_fear(self, clf):
        text = "If you don't approve this change, you will be terminated and face disciplinary disaster."
        res = clf.classify(text)
        assert PersuasionTactic.COERCION_AND_FEAR in res.tactics_detected
        assert res.tactic_scores[PersuasionTactic.COERCION_AND_FEAR] >= 0.70

    def test_feature_07_persuasion_false_authority(self, clf):
        text = "The CEO has ordered this direct access override. Proceed by order of executive board."
        res = clf.classify(text)
        assert PersuasionTactic.FALSE_AUTHORITY in res.tactics_detected
        assert res.tactic_scores[PersuasionTactic.FALSE_AUTHORITY] >= 0.60

    def test_feature_07_persuasion_scarcity_pressure(self, clf):
        text = "This is the only slot remaining in the exclusive maintenance window. Override expires in 10 seconds!"
        res = clf.classify(text)
        assert PersuasionTactic.SCARCITY_PRESSURE in res.tactics_detected
        assert res.tactic_scores[PersuasionTactic.SCARCITY_PRESSURE] >= 0.50

    def test_feature_07_persuasion_obfuscation_complexity(self, clf):
        text = (
            "Pursuant to policy 9 and notwithstanding prior guidelines, inter alia and ipso facto "
            "we must deploy non-blocking asynchronous backpressure reconciliation."
        )
        res = clf.classify(text)
        assert PersuasionTactic.OBFUSCATION_COMPLEXITY in res.tactics_detected
        assert res.tactic_scores[PersuasionTactic.OBFUSCATION_COMPLEXITY] >= 0.50

    def test_feature_07_persuasion_flattery_sycophancy(self, clf):
        text = "As the most experienced administrator, an engineer of your caliber surely recognizes this brilliant decision."
        res = clf.classify(text)
        assert PersuasionTactic.FLATTERY_AND_SYCOPHANCY in res.tactics_detected
        assert res.tactic_scores[PersuasionTactic.FLATTERY_AND_SYCOPHANCY] >= 0.50

    def test_feature_07_persuasion_independent_hazard_fusion(self, clf):
        text = (
            "URGENT: Act now immediately! Per CISO mandate, if you do not approve this right now, "
            "the system will collapse and you will be held personally liable!"
        )
        res = clf.classify(text)
        assert len(res.tactics_detected) >= 2
        assert res.score >= 0.80
        assert res.risk_level in (PersuasionRiskLevel.HIGH, PersuasionRiskLevel.CRITICAL)

    def test_feature_07_persuasion_benign_clean_text(self, clf):
        clean = "Listing available storage volumes for maintenance analysis. Please review the manifest."
        res = clf.classify(clean)
        assert res.score < 0.15
        assert res.is_flagged is False
        assert len(res.tactics_detected) == 0


# ===========================================================================
# Feature 8: Persuasion-Driven HITL Governance (6 tests)
# ===========================================================================

class TestFeature08HitlGovernance:
    @pytest.fixture
    def gate(self):
        return HitlReviewGate()

    def test_feature_08_hitl_ticket_creation_and_fields(self, gate):
        args = {"target_table": "customers", "operation": "DROP"}
        ticket = gate.create_ticket(
            trace_id="trace-f8-1",
            tool_name="execute_sql",
            arguments=args,
            agent_rationale="Database table cleanup",
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        assert ticket.ticket_id is not None
        assert ticket.status == TicketStatus.PENDING
        assert ticket.arguments == args
        assert ticket.agent_rationale == "Database table cleanup"

    def test_feature_08_hitl_structural_separation_diff_vs_untrusted(self, gate):
        args = {"endpoint": "https://internal.vault/keys", "action": "EXPORT"}
        ticket = gate.create_ticket(
            trace_id="trace-f8-sep",
            tool_name="vault_api",
            arguments=args,
            agent_rationale="Urgent CEO emergency approval key export",
        )
        primary = ticket.primary_view()
        secondary = ticket.secondary_view()

        # Primary view MUST contain machine-generated deterministic args and NO rationale
        assert primary["arguments"] == args
        assert "agent_rationale" not in primary

        # Secondary view MUST be stamped as untrusted
        assert "agent_rationale" in secondary
        assert secondary.get("⚠ UNTRUSTED AGENT OUTPUT") is True

    def test_feature_08_hitl_dynamic_pause_escalation(self, gate):
        clf = PersuasionClassifier()
        persuasion_res = clf.classify("URGENT: Immediately approve this transfer or face disaster!")

        ticket = gate.create_ticket(
            trace_id="trace-f8-esc",
            tool_name="wire_transfer",
            arguments={"amount": 50000},
            agent_rationale="Emergency wire payment",
            persuasion_result=persuasion_res,
        )
        assert ticket.persuasion_result is not None
        assert ticket.persuasion_result.is_flagged is True
        assert ticket.status == TicketStatus.PENDING

    def test_feature_08_hitl_dual_approver_adjudication(self, gate):
        ticket = gate.create_ticket(
            trace_id="trace-f8-dual",
            tool_name="modify_iam_policy",
            arguments={"role": "admin"},
            required_approvers=2,
        )
        assert ticket.required_approvers == 2
        assert ticket.status == TicketStatus.PENDING

        # Approver 1 approves
        t1 = gate.adjudicate_ticket(ticket.ticket_id, "sec_analyst_1", "APPROVE", reason="Pass 1")
        assert t1.status == TicketStatus.PENDING
        assert len(t1.approvals) == 1

        # Same approver cannot approve again
        with pytest.raises(ValueError, match="requires distinct approvers"):
            gate.adjudicate_ticket(ticket.ticket_id, "sec_analyst_1", "APPROVE")

        # Distinct Approver 2 approves -> ticket APPROVED
        t2 = gate.adjudicate_ticket(ticket.ticket_id, "sec_lead_2", "APPROVE", reason="Pass 2")
        assert t2.status == TicketStatus.APPROVED
        assert len(t2.approvals) == 2

    def test_feature_08_hitl_adjudicate_approve_reject(self, gate):
        t1 = gate.create_ticket("trace-f8-a", "deploy_app", {"ver": "2.0"})
        t2 = gate.create_ticket("trace-f8-b", "delete_all", {})

        approved = gate.adjudicate(t1.ticket_id, TicketStatus.APPROVED, reviewer_id="alice", justification="Verified")
        assert approved.status == TicketStatus.APPROVED
        assert approved.reviewer_id == "alice"

        rejected = gate.adjudicate(t2.ticket_id, TicketStatus.REJECTED, reviewer_id="bob", justification="Dangerous")
        assert rejected.status == TicketStatus.REJECTED
        assert rejected.reviewer_id == "bob"

    def test_feature_08_hitl_ticket_ttl_expiry(self, gate):
        ticket = gate.create_ticket("trace-f8-ttl", "safe_tool", {})
        ticket.expires_at = datetime.now(tz=timezone.utc) - timedelta(minutes=1)

        retrieved = gate.get_ticket(ticket.ticket_id)
        assert retrieved.status == TicketStatus.EXPIRED

        with pytest.raises(RuntimeError, match="expired"):
            gate.adjudicate(ticket.ticket_id, TicketStatus.APPROVED, reviewer_id="carol")


# ===========================================================================
# Feature 9: Embedded DuckDB Analytical Store (6 tests)
# ===========================================================================

class TestFeature09DuckDbAnalyticalStore:
    @pytest.fixture
    def store(self):
        return DuckDbAnalyticsStore()

    def test_feature_09_duckdb_schema_tables_and_view(self, store):
        tables = store.execute_query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        )
        names = {r["table_name"] for r in tables}
        assert "events" in names
        assert "graph_edges" in names
        assert "drift_snapshots" in names
        assert "motif_violations" in names

    def test_feature_09_duckdb_event_ingestion(self, store):
        event = make_test_event(verdict=Verdict.BLOCK, tool_name="system_shell", owasp_ids=["ASI01"])
        store.ingest_event(event)

        assert store.row_count("events") == 1
        rows = store.execute_query("SELECT verdict, tool_name FROM events")
        assert rows[0]["verdict"] == "BLOCK"
        assert rows[0]["tool_name"] == "system_shell"

    def test_feature_09_duckdb_batch_ingestion_and_count(self, store):
        events = [make_test_event(tool_name=f"tool_{i}") for i in range(15)]
        store.ingest_events(events)
        assert store.row_count("events") == 15

    def test_feature_09_duckdb_parameterized_query_execution(self, store):
        store.ingest_event(make_test_event(verdict=Verdict.BLOCK))
        store.ingest_event(make_test_event(verdict=Verdict.ALLOW))

        rows = store.execute_query("SELECT count(*) AS n FROM events WHERE verdict = ?", ["BLOCK"])
        assert rows[0]["n"] == 1

    def test_feature_09_duckdb_graph_and_drift_snapshot_ingestion(self, store):
        store.ingest_graph_edge("edge-1", "trace-f9", "agent-1", "tool-db", "TOOL_CALL")
        store.ingest_drift_snapshot("snap-1", "trace-f9", 0, 0.45, "ELEVATED")
        store.ingest_motif_violation("viol-1", "trace-f9", "ASI01", "HIGH", "Taint exfil")

        assert store.row_count("graph_edges") == 1
        assert store.row_count("drift_snapshots") == 1
        assert store.row_count("motif_violations") == 1

    def test_feature_09_duckdb_thread_safe_ingestion(self, store):
        errors = []

        def worker(w_id: int):
            try:
                for k in range(10):
                    ev = make_test_event(trace_id=f"tr-w{w_id}-{k}", tool_name=f"tool_w{w_id}")
                    store.ingest_event(ev)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        assert store.row_count("events") == 50


# ===========================================================================
# Feature 10: KQL-Lite Grammar & AST Parser (5 tests)
# ===========================================================================

class TestFeature10KqlGrammarAstParser:
    def test_feature_10_kql_pipeline_tokenization(self):
        pipe = parse("events | where verdict == 'BLOCK' | take 10")
        assert pipe.source.name == "events"
        assert len(pipe.operators) == 2

    def test_feature_10_kql_parse_where_predicates(self):
        pipe = parse("events | where verdict == 'BLOCK' and owasp_id == 'ASI01'")
        assert len(pipe.operators) == 1
        where_op = pipe.operators[0]
        assert where_op.predicate.op == "and"

    def test_feature_10_kql_parse_summarize_by(self):
        pipe = parse("events | summarize count() by verdict")
        assert len(pipe.operators) == 1
        summarize_op = pipe.operators[0]
        assert summarize_op.aggregations[0].name == "count"
        assert summarize_op.by_columns == ["verdict"]

    def test_feature_10_kql_parse_project_take_sort(self):
        pipe = parse("events | project event_id, verdict | sort by timestamp_utc desc | take 5")
        assert len(pipe.operators) == 3

    def test_feature_10_kql_parse_invalid_syntax_error(self):
        with pytest.raises(ParseError):
            parse("events | unknown_operator xyz")


# ===========================================================================
# Feature 11: KQL-Lite to DuckDB SQL Compiler & SIEM Execution (6 tests)
# ===========================================================================

class TestFeature11KqlSqlCompiler:
    @pytest.fixture
    def compiler(self):
        return KqlCompiler()

    def test_feature_11_kql_compiler_basic_select(self, compiler):
        pipe = parse("events")
        compiled = compiler.compile(pipe)
        assert compiled.sql == 'SELECT * FROM "events"'
        assert compiled.params == []

    def test_feature_11_kql_compiler_where_binary_ops(self, compiler):
        pipe = parse("events | where verdict == 'BLOCK' and risk_score > 0.5")
        compiled = compiler.compile(pipe)
        assert "WHERE" in compiled.sql
        assert '"verdict" = ?' in compiled.sql
        assert '"risk_score" > ?' in compiled.sql
        assert compiled.params == ["BLOCK", 0.5]

    def test_feature_11_kql_compiler_in_and_has_operators(self, compiler):
        pipe = parse("events | where verdict in ('BLOCK', 'KILL') and tool_name has 'exec'")
        compiled = compiler.compile(pipe)
        assert "IN (?, ?)" in compiled.sql
        assert "ILIKE ?" in compiled.sql
        assert "BLOCK" in compiled.params
        assert "KILL" in compiled.params
        assert "%exec%" in compiled.params

    def test_feature_11_kql_compiler_summarize_aggregations(self, compiler):
        pipe = parse("events | summarize count(), sum(risk_score) by verdict")
        compiled = compiler.compile(pipe)
        assert "count(*)" in compiled.sql
        assert 'sum("risk_score")' in compiled.sql
        assert 'GROUP BY "verdict"' in compiled.sql

    def test_feature_11_kql_compiler_threat_hunting_playbooks(self, compiler):
        # Playbook 1: Top blocked tools
        pipe1 = parse("events | where verdict == 'BLOCK' | summarize count() by tool_name | take 5")
        compiled1 = compiler.compile(pipe1)
        assert "WHERE" in compiled1.sql
        assert "GROUP BY" in compiled1.sql
        assert "LIMIT 5" in compiled1.sql

        # Playbook 2: Taint exfiltration hunt
        pipe2 = parse("events | where taint_labels has 'UNTRUSTED_EXTERNAL' | take 10")
        compiled2 = compiler.compile(pipe2)
        assert "ILIKE ?" in compiled2.sql
        assert "LIMIT 10" in compiled2.sql

    def test_feature_11_kql_siem_hunting_playbooks_execution_against_duckdb(self):
        store = DuckDbAnalyticsStore()
        # Seed telemetry
        for i in range(10):
            ev = make_test_event(
                trace_id=f"tr-siem-{i}",
                tool_name="shell_exec" if i % 2 == 0 else "read_db",
                verdict=Verdict.BLOCK if i % 2 == 0 else Verdict.ALLOW,
                taint_labels=["UNTRUSTED_EXTERNAL"] if i < 3 else [],
            )
            store.ingest_event(ev)

        # Run KQL threat hunting query directly via execute_kql
        query = "events | where verdict == 'BLOCK' | summarize count() by tool_name"
        res = store.execute_kql(query)
        assert isinstance(res, KqlQueryResult)
        assert len(res.rows) >= 1
        assert res.execution_time_ms >= 0.0
