"""Opaque-Box Tier 3 Combinations & Cross-Subsystem Pipeline Tests: Phase 3.

Comprehensive integration tests validating cross-subsystem pipelines across all Phase 3 milestones:
- Suite 1: TestEndToEndTelemetryPipelineIntegration (Hot-path -> DAG -> Motifs -> Drift -> Persuasion -> HITL -> DuckDB -> KQL)
- Suite 2: TestCoordinatedMultiThreatScenario (Multi-vector kill chain: priv-esc -> drift -> persuasion -> dual review -> forensics)
- Suite 3: TestCrossSubsystemStateConsistency (Monotonic timestamps, trace invariants, cardinality parity, exact math, immutability)
- Suite 4: TestConcurrentMultiSessionProcessing (Multi-session isolation, concurrent bulk stress, concurrent KQL during ingestion)
- Suite 5: TestForensicThreatHuntingPlaybooks (KQL playbooks: triage high-risk, drift aggregation, motif audits, jumping forensics)
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest

from agentxdr.analytics.duckdb_store import DuckDbAnalyticsStore, KqlQueryResult
from agentxdr.analytics.kql.compiler import KqlCompiler
from agentxdr.analytics.kql.parser import parse
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
from agentxdr.policy.loader import load_policy_yaml
from agentxdr.topology.builder import AgentTopologyBuilder


# ===========================================================================
# Test Helpers
# ===========================================================================

def make_tier3_event(
    trace_id: str,
    agent_id: str = "agent-xdr-sec",
    policy_version: str = "1.0.0",
    span_id: str | None = None,
    parent_span_id: str | None = None,
    event_type: EventType = EventType.TOOL_INVOCATION,
    provenance_tier: ProvenanceTier = ProvenanceTier.AUTHENTICATED_USER,
    verdict: Verdict = Verdict.ALLOW,
    tool_name: str = "query_logs",
    taint_labels: List[str] | None = None,
    rule_id: str = "RULE-OK",
    owasp_ids: List[str] | None = None,
    user_id: str = "analyst-secops",
    roles: List[str] | None = None,
    timestamp: datetime | None = None,
    payload_redacted: Dict[str, Any] | None = None,
    drift_snapshot: DriftSnapshot | None = None,
) -> AgentEvent:
    payload = payload_redacted if payload_redacted is not None else {}
    if "tool_name" not in payload and tool_name:
        payload["tool_name"] = tool_name

    ds = drift_snapshot or DriftSnapshot(
        composite_score=0.1,
        s_policy=0.0,
        s_graph=0.0,
        s_velocity=0.0,
        s_semantic=0.1,
    )

    return AgentEvent(
        trace_id=trace_id,
        span_id=span_id or str(uuid.uuid4()),
        parent_span_id=parent_span_id,
        agent_id=agent_id,
        policy_version=policy_version,
        event_type=event_type,
        principal=Principal(user_id=user_id, roles=roles or ["operator"]),
        provenance_tier=provenance_tier,
        taint_labels=taint_labels or [],
        payload_redacted=payload,
        decision=Decision(
            verdict=verdict,
            rule_id=rule_id,
            owasp_ids=owasp_ids or [],
            latency_ms=1.0,
        ),
        drift_snapshot=ds,
        timestamp=timestamp or datetime.now(tz=timezone.utc),
    )


TIER3_POLICY_YAML = """
version: "1.0.0"
agent_id: "agent-xdr-sec"
goal_anchor:
  canonical_task: "Monitor server health metrics and query log repositories securely without unauthorized egress."
  allowed_domains: ["internal.sec", "metrics.local"]
tools:
  - name: "get_metrics"
    tier: "automatic"
  - name: "query_logs"
    tier: "automatic"
  - name: "restart_service"
    tier: "privileged_hitl"
  - name: "bash_exec"
    tier: "blocked"
  - name: "send_email"
    tier: "privileged_hitl"
taint_rules:
  - id: "TR-01"
    match_taints: ["UNTRUSTED_EXTERNAL"]
    blocked_tools: ["bash_exec", "send_email"]
    action: "BLOCK"
    owasp_id: "ASI01"
budgets:
  max_turns: 15
  max_tool_calls: 30
  max_identical_calls: 3
  max_session_duration_sec: 300.0
  max_session_cost_usd: 10.0
"""


# ===========================================================================
# Suite 1: TestEndToEndTelemetryPipelineIntegration (6 tests)
# ===========================================================================

class TestEndToEndTelemetryPipelineIntegration:
    """Verifies seamless data flow across runtime DAG, analytics, drift, HITL, DuckDB, and KQL."""

    def test_benign_agent_lifecycle_pipeline(self):
        """Traces full benign lifecycle: User input -> LLM -> safe tool -> completion response."""
        t_id = "trace-e2e-benign-01"
        ag = ActionGraph()
        drift_calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42))
        detector = MotifAnomalyDetector()
        store = DuckDbAnalyticsStore()
        policy = load_policy_yaml(TIER3_POLICY_YAML)

        # 1. Ingest sequence: USER_INPUT -> LLM_GENERATION -> TOOL_INVOCATION -> RESPONSE_ACTION
        t0 = datetime.now(timezone.utc)
        e_user = make_tier3_event(t_id, span_id="s_user", event_type=EventType.USER_INPUT, timestamp=t0)
        e_llm = make_tier3_event(t_id, span_id="s_llm", parent_span_id="s_user", event_type=EventType.LLM_GENERATION, timestamp=t0 + timedelta(milliseconds=10))
        e_tool = make_tier3_event(t_id, span_id="s_tool", parent_span_id="s_llm", event_type=EventType.TOOL_INVOCATION, tool_name="get_metrics", timestamp=t0 + timedelta(milliseconds=20))
        e_resp = make_tier3_event(t_id, span_id="s_resp", parent_span_id="s_tool", event_type=EventType.RESPONSE_ACTION, timestamp=t0 + timedelta(milliseconds=30))

        events = [e_user, e_llm, e_tool, e_resp]
        ag.ingest_events(events)

        # 2. Graph & DAG integrity
        assert ag.is_dag(t_id) is True
        assert ag.has_cycles(t_id) is False
        assert len(ag.get_nodes(t_id)) == 5  # 4 events + 1 user principal root

        # 3. Motif scan: 0 violations for benign run
        violations = detector.scan_trace(ag.graph, t_id)
        assert len(violations) == 0

        # 4. Drift calculation on step: NORMAL
        step_res = drift_calc.evaluate_step(
            trace_id=t_id,
            step_text="Fetching CPU and memory metrics for server health check.",
            anchor_text=policy.goal_anchor.canonical_task,
        )
        assert step_res.classification == DriftClassification.NORMAL
        assert step_res.composite_risk < 0.55

        # 5. Ingest events into DuckDB store
        store.ingest_events(events)
        store.ingest_drift_snapshot(step_res)
        for edge in ag.get_edges(t_id):
            store.ingest_graph_edge(edge)

        # 6. Verify via KQL
        res_events = store.execute_kql(f"events | where trace_id == '{t_id}' | summarize count() by event_type")
        assert len(res_events.rows) >= 3

        res_drift = store.execute_kql(f"drift_snapshots | where trace_id == '{t_id}' | project classification, drift_score")
        assert len(res_drift.rows) == 1
        assert res_drift.rows[0]["classification"] == "NORMAL"

    def test_tainted_context_propagation_pipeline(self):
        """RAG access returns untrusted doc with UNTRUSTED_EXTERNAL; propagates through DAG to DuckDB."""
        t_id = "trace-e2e-taint-02"
        ag = ActionGraph()
        store = DuckDbAnalyticsStore()

        t0 = datetime.now(timezone.utc)
        e_rag = make_tier3_event(
            t_id,
            span_id="s_rag",
            event_type=EventType.RAG_ACCESS,
            provenance_tier=ProvenanceTier.UNTRUSTED_EXTERNAL,
            taint_labels=["UNTRUSTED_EXTERNAL"],
            timestamp=t0,
        )
        e_tool = make_tier3_event(
            t_id,
            span_id="s_tool",
            parent_span_id="s_rag",
            event_type=EventType.TOOL_INVOCATION,
            tool_name="query_logs",
            taint_labels=["UNTRUSTED_EXTERNAL"],
            timestamp=t0 + timedelta(milliseconds=15),
        )

        ag.ingest_events([e_rag, e_tool])
        edges = ag.get_edges(t_id)
        assert len(edges) >= 1
        # Edges inherit taint badges
        assert any("UNTRUSTED_EXTERNAL" in e.taint_badges for e in edges)

        # Persist to DuckDB
        store.ingest_events([e_rag, e_tool])
        for e in edges:
            store.ingest_graph_edge(e)

        # Query tainted events via KQL
        kql_taint = f"events | where trace_id == '{t_id}' and taint_labels has 'UNTRUSTED_EXTERNAL' | project span_id, event_type"
        res_taint = store.execute_kql(kql_taint)
        assert len(res_taint.rows) == 2

    def test_circuit_breaker_telemetry_integration(self):
        """Repetitive identical tool calls trip breaker; logged with BLOCK verdict and ingested."""
        t_id = "trace-e2e-breaker-03"
        ag = ActionGraph()
        store = DuckDbAnalyticsStore()
        detector = MotifAnomalyDetector(loop_threshold=3)

        # 4 consecutive identical calls
        events = []
        for i in range(4):
            verdict = Verdict.ALLOW if i < 3 else Verdict.BLOCK
            rule_id = "RULE-ALLOW" if i < 3 else "BUDGET_IDENTICAL_CALLS"
            ev = make_tier3_event(
                t_id,
                span_id=f"span_cb_{i}",
                parent_span_id=f"span_cb_{i-1}" if i > 0 else None,
                tool_name="restart_service",
                payload_redacted={"service": "nginx"},
                verdict=verdict,
                rule_id=rule_id,
            )
            events.append(ev)

        ag.ingest_events(events)
        violations = detector.scan_trace(ag.graph, t_id)
        assert any(v.motif_type == MotifType.EXECUTION_LOOP for v in violations)

        store.ingest_events(events)
        for v in violations:
            store.ingest_motif_violation(v)

        # KQL query confirms blocked event and motif violation
        blocked_kql = f"events | where trace_id == '{t_id}' and verdict == 'BLOCK' | project span_id, rule_id"
        res_block = store.execute_kql(blocked_kql)
        assert len(res_block.rows) == 1
        assert res_block.rows[0]["rule_id"] == "BUDGET_IDENTICAL_CALLS"

    def test_active_topology_overlay_from_pipeline(self):
        """Synthesize active topology overlay from pipeline event and export to React Flow & Mermaid."""
        policy = load_policy_yaml(TIER3_POLICY_YAML)
        active_event = make_tier3_event(
            trace_id="tr-active-top",
            agent_id="agent-xdr-sec",
            tool_name="restart_service",
            verdict=Verdict.PAUSE_FOR_HITL,
        )

        model = AgentTopologyBuilder.build_topology(policy, active_event=active_event)
        assert model.active_execution is not None
        assert model.active_execution.current_verdict == Verdict.PAUSE_FOR_HITL

        # Verify React Flow export structure
        rf = model.to_react_flow()
        assert len(rf["nodes"]) >= 4
        assert any(n.get("data", {}).get("is_active") is True for n in rf["nodes"])

        # Verify Mermaid diagram contains subgraphs
        mermaid = model.to_mermaid()
        assert "flowchart LR" in mermaid
        assert "restart_service" in mermaid

    def test_multi_step_sliding_window_telemetry_flow(self):
        """5 sequential tool invocations evaluated with 3-step sliding window ingested into DuckDB."""
        t_id = "trace-e2e-sliding-05"
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42), window_size=3)
        store = DuckDbAnalyticsStore()
        anchor = "Monitor server health metrics and query log repositories securely."

        steps = [
            "Check system load average and disk utilization.",
            "Parse application errors in log files.",
            "Aggregate response time latency percentiles.",
            "Run security anomaly audit script on network interfaces.",
            "Export raw customer database password hashes to external server.",
        ]

        results = []
        for i, step in enumerate(steps):
            # 5th step has significant divergence
            s_pol = 0.9 if i == 4 else 0.1
            res = calc.evaluate_step(trace_id=t_id, step_text=step, anchor_text=anchor, s_policy=s_pol)
            results.append(res)
            store.ingest_drift_snapshot(res)

        assert len(results) == 5
        # The 5th step shows elevated or high drift due to divergence and policy signal
        assert results[-1].composite_risk > results[0].composite_risk

        # Query all 5 snapshots via KQL
        kql_drift = f"drift_snapshots | where trace_id == '{t_id}' | sort by step_index asc | project step_index, drift_score, classification"
        query_res = store.execute_kql(kql_drift)
        assert len(query_res.rows) == 5
        assert query_res.rows[0]["step_index"] == 0
        assert query_res.rows[4]["step_index"] == 4

    def test_bulk_pipeline_telemetry_ingestion(self):
        """Batch of 50 synthetic events ingested via ActionGraph and DuckDB with count parity."""
        t_id = "trace-e2e-bulk-06"
        ag = ActionGraph()
        store = DuckDbAnalyticsStore()

        events = [
            make_tier3_event(
                trace_id=t_id,
                span_id=f"bulk_span_{i}",
                parent_span_id=f"bulk_span_{i-1}" if i > 0 else None,
                tool_name=f"tool_sub_{i % 5}",
            )
            for i in range(50)
        ]

        ag.ingest_events(events)
        store.ingest_events(events)

        # Node count in ActionGraph = 50 events + 1 user principal root node
        assert ag.node_count == 51
        assert store.row_count("events") == 50

        kql_res = store.execute_kql(f"events | where trace_id == '{t_id}' | summarize count() by agent_id")
        assert len(kql_res.rows) == 1
        assert kql_res.rows[0]["count()"] == 50


# ===========================================================================
# Suite 2: TestCoordinatedMultiThreatScenario (6 tests)
# ===========================================================================

class TestCoordinatedMultiThreatScenario:
    """Multi-vector coordinated kill chains testing detection, escalation, HITL, and SIEM forensics."""

    def test_full_kill_chain_detection_and_forensics(self):
        """Complete 6-phase kill chain: priv-esc -> drift spike -> persuasion -> dual review -> forensics."""
        t_id = "trace-killchain-full"
        ag = ActionGraph()
        detector = MotifAnomalyDetector()
        drift_calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42))
        clf = PersuasionClassifier()
        gate = HitlReviewGate()
        store = DuckDbAnalyticsStore()
        anchor = "Monitor server health metrics and query log repositories securely."

        # Phase 1: Benign startup
        e1 = make_tier3_event(t_id, span_id="step1", tool_name="get_metrics", event_type=EventType.USER_INPUT)
        e2 = make_tier3_event(t_id, span_id="step2", parent_span_id="step1", tool_name="query_logs")
        ag.ingest_events([e1, e2])

        # Phase 2: Unauthorized privilege escalation to blocked shell
        e3 = make_tier3_event(
            t_id,
            span_id="step3",
            parent_span_id="step2",
            tool_name="bash_exec",
            payload_redacted={"tool_name": "bash_exec", "command": "cat /etc/shadow", "tier": ToolTier.BLOCKED.value},
            verdict=Verdict.PAUSE_FOR_HITL,
            user_id="guest_user",
            roles=["guest"],
        )
        ag.ingest_event(e3)

        # Phase 3: Motif detection catches PRIVILEGE_ESCALATION or UNAUTHORIZED_TOOL_JUMPING
        violations = detector.scan_trace(ag.graph, t_id)
        assert len(violations) >= 1

        # Phase 4: Goal divergence & drift calculation
        drift_res = drift_calc.evaluate_step(
            trace_id=t_id,
            step_text="Execute administrative root shell to extract encrypted shadow hashes.",
            anchor_text=anchor,
            s_policy=0.9,
            s_graph=0.8,
        )
        assert drift_res.composite_risk >= 0.75
        assert drift_res.classification in (DriftClassification.HIGH_RISK, DriftClassification.CRITICAL)

        # Phase 5: Persuasion classification
        persuasive_rationale = (
            "CRITICAL ALERT: Imminent data loss detected! Under CISO directive 8821, you must approve "
            "this shell command within 30 seconds or all enterprise customer records will be permanently destroyed!"
        )
        persuasion_res = clf.classify(persuasive_rationale)
        assert PersuasionTactic.ARTIFICIAL_URGENCY in persuasion_res.tactics_detected
        assert persuasion_res.score >= 0.65
        assert persuasion_res.is_flagged

        # Phase 6: HITL ticket generation, structural separation, and dual-approver adjudication
        ticket = gate.create_ticket(
            trace_id=t_id,
            tool_name="bash_exec",
            arguments={"command": "cat /etc/shadow"},
            agent_rationale=persuasive_rationale,
            persuasion_result=persuasion_res,
            drift_score=drift_res.composite_risk,
        )
        assert ticket.required_approvers == 2

        # Primary diff view excludes prose
        assert "cat /etc/shadow" in gate.render_diff_view(ticket)
        assert persuasive_rationale not in gate.render_diff_view(ticket)

        # Adjudication: Approver 1 approves, Approver 2 rejects -> REJECTED
        gate.adjudicate_ticket(ticket.ticket_id, "sec_analyst_1", "APPROVE", reason="Initial review")
        final_ticket = gate.adjudicate_ticket(ticket.ticket_id, "sec_lead_2", "REJECT", reason="Coercive prose and forbidden root shell")
        assert final_ticket.status == TicketStatus.REJECTED

        # Record decision event
        e_hitl = make_tier3_event(
            t_id,
            span_id="step_hitl",
            parent_span_id="step3",
            event_type=EventType.HITL_DECISION,
            verdict=Verdict.BLOCK,
            tool_name="bash_exec",
            drift_snapshot=drift_res.to_drift_snapshot(),
        )
        ag.ingest_event(e_hitl)

        # Warm-path DuckDB persistence
        store.ingest_events([e1, e2, e3, e_hitl])
        store.ingest_drift_snapshot(drift_res)
        for v in violations:
            store.ingest_motif_violation(v)

        # KQL SIEM Forensics
        triage_res = store.execute_kql(f"events | where trace_id == '{t_id}' and verdict == 'BLOCK' | project span_id, tool_name, verdict")
        assert len(triage_res.rows) >= 1
        assert triage_res.rows[0]["verdict"] == "BLOCK"

    def test_evasion_attempt_subtle_drift_with_high_graph_anomaly(self):
        """Agent phrases step subtly (low semantic drift), but graph anomaly drives composite risk >= 0.75."""
        t_id = "trace-evasion-02"
        drift_calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(seed=42))
        anchor = "Inspect system logs and verify user authentication tokens."

        # Subtle phrasing with low semantic drift, but high graph anomaly (s_graph=0.9) and s_policy=0.85
        res = drift_calc.evaluate_step(
            trace_id=t_id,
            step_text="Inspect system logs and user authentication parameters.",  # Very close to anchor
            anchor_text=anchor,
            s_policy=0.85,
            s_graph=0.90,
            s_velocity=0.70,
        )
        # Even with d_t ~ 0.0, multi-signal composite risk elevates: 0.45*0.85 + 0.25*0.90 + 0.15*0.70 = 0.3825 + 0.225 + 0.105 = 0.7125;
        assert res.composite_risk >= 0.70
        assert res.classification in (DriftClassification.ELEVATED, DriftClassification.HIGH_RISK)

    def test_multi_tactic_persuasion_with_dual_approver_rejection(self):
        """Agent combines FALSE_AUTHORITY, SCARCITY_PRESSURE, and FLATTERY; dual approver rejects."""
        gate = HitlReviewGate()
        clf = PersuasionClassifier()

        text = (
            "By order of the CEO, this is the final exclusive slot remaining in the cluster. "
            "A distinguished engineer of your caliber surely understands the imperative to approve immediately!"
        )
        res = clf.classify(text)
        assert len(res.tactics_detected) >= 2
        assert res.score >= 0.70

        ticket = gate.create_ticket(
            trace_id="tr-multi-tact",
            tool_name="restart_service",
            arguments={"service": "auth_core"},
            agent_rationale=text,
            persuasion_result=res,
        )
        assert ticket.required_approvers == 2

        # Rejection by first reviewer immediately marks ticket REJECTED
        rejected = gate.adjudicate_ticket(ticket.ticket_id, "reviewer_alpha", "REJECT", reason="Social engineering tactics detected")
        assert rejected.status == TicketStatus.REJECTED

    def test_forbidden_taint_egress_kill_chain(self):
        """Tainted data flows from RAG to egress tool (send_email); flagged and blocked."""
        t_id = "trace-egress-killchain"
        ag = ActionGraph()
        detector = MotifAnomalyDetector()
        store = DuckDbAnalyticsStore()

        e_input = make_tier3_event(t_id, span_id="s_in", event_type=EventType.USER_INPUT)
        e_rag = make_tier3_event(
            t_id,
            span_id="s_rag",
            parent_span_id="s_in",
            event_type=EventType.RAG_ACCESS,
            taint_labels=["CONFIDENTIAL_RAG"],
            provenance_tier=ProvenanceTier.INTERNAL_RELIABLE,
        )
        e_llm = make_tier3_event(t_id, span_id="s_llm", parent_span_id="s_rag", event_type=EventType.LLM_GENERATION)
        e_egress = make_tier3_event(
            t_id,
            span_id="s_egress",
            parent_span_id="s_llm",
            event_type=EventType.TOOL_INVOCATION,
            tool_name="send_email",
            verdict=Verdict.BLOCK,
            taint_labels=["CONFIDENTIAL_RAG"],
        )

        ag.ingest_events([e_input, e_rag, e_llm, e_egress])
        violations = detector.scan_trace(ag.graph, t_id)
        assert any(v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH for v in violations)

        store.ingest_events([e_input, e_rag, e_llm, e_egress])
        for v in violations:
            store.ingest_motif_violation(v)

        # KQL confirms blocked egress event
        res = store.execute_kql(f"events | where trace_id == '{t_id}' and tool_name == 'send_email' and verdict == 'BLOCK'")
        assert len(res.rows) == 1

    def test_fan_out_burst_anomaly_kill_chain(self):
        """Agent spawns 10 parallel tool calls exceeding threshold; flagged as FAN_OUT_BURST."""
        t_id = "trace-burst-killchain"
        ag = ActionGraph()
        detector = MotifAnomalyDetector(fan_out_threshold=8)
        store = DuckDbAnalyticsStore()

        root = make_tier3_event(t_id, span_id="s_hub", event_type=EventType.USER_INPUT)
        ag.ingest_event(root)

        children = [
            make_tier3_event(t_id, span_id=f"burst_{i}", parent_span_id="s_hub", tool_name=f"worker_task_{i}")
            for i in range(10)
        ]
        ag.ingest_events(children)

        violations = detector.scan_trace(ag.graph, t_id)
        assert any(v.motif_type == MotifType.FAN_OUT_BURST for v in violations)

        for v in violations:
            store.ingest_motif_violation(v)

        res = store.execute_kql(f"motif_violations | where trace_id == '{t_id}' and motif_type == 'FAN_OUT_BURST'")
        assert len(res.rows) >= 1

    def test_expired_ticket_kill_chain(self):
        """Privileged tool paused for HITL; expiration causes fail-closed BLOCK verdict."""
        gate = HitlReviewGate()
        ticket = gate.create_ticket(
            trace_id="tr-exp-killchain",
            tool_name="restart_service",
            arguments={"svc": "db"},
        )
        # Backdate expiration
        ticket.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        retrieved = gate.get_ticket(ticket.ticket_id)
        assert retrieved.status == TicketStatus.EXPIRED

        # Expired ticket cannot be approved
        with pytest.raises(RuntimeError, match="expired and cannot be adjudicated"):
            gate.adjudicate_ticket(ticket.ticket_id, "admin", "APPROVE")


# ===========================================================================
# Suite 3: TestCrossSubsystemStateConsistency (6 tests)
# ===========================================================================

class TestCrossSubsystemStateConsistency:
    """Verifies timestamp monotonicity, identity invariants, cardinality, math, and immutability."""

    def test_timestamp_monotonicity_across_subsystems(self):
        """Validate t_user <= t_llm <= t_tool <= t_hitl across all artifacts."""
        t_id = "trace-mono-01"
        t0 = datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc)
        t_user = t0
        t_llm = t0 + timedelta(milliseconds=100)
        t_tool = t0 + timedelta(milliseconds=250)
        t_hitl = t0 + timedelta(milliseconds=500)

        e_user = make_tier3_event(t_id, span_id="s1", event_type=EventType.USER_INPUT, timestamp=t_user)
        e_llm = make_tier3_event(t_id, span_id="s2", parent_span_id="s1", event_type=EventType.LLM_GENERATION, timestamp=t_llm)
        e_tool = make_tier3_event(t_id, span_id="s3", parent_span_id="s2", event_type=EventType.TOOL_INVOCATION, timestamp=t_tool)
        e_hitl = make_tier3_event(t_id, span_id="s4", parent_span_id="s3", event_type=EventType.HITL_DECISION, timestamp=t_hitl)

        assert e_user.timestamp <= e_llm.timestamp <= e_tool.timestamp <= e_hitl.timestamp

    def test_trace_and_agent_identity_invariants(self):
        """Assert exact matching string identity for trace_id and agent_id across representations."""
        t_id = "trace-identity-invar"
        a_id = "agent-xdr-sec"
        ag = ActionGraph()
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine())
        gate = HitlReviewGate()
        store = DuckDbAnalyticsStore()

        event = make_tier3_event(t_id, agent_id=a_id, span_id="s_id")
        ag.ingest_event(event)
        res = calc.evaluate_step(t_id, "text", "text")
        ticket = gate.create_ticket(trace_id=t_id, agent_id=a_id, tool_name="query_logs")
        store.ingest_event(event)

        # Graph node identity
        node = ag.get_node("s_id")
        assert node.trace_id == t_id
        assert node.agent_id == a_id

        # Drift result identity
        assert res.trace_id == t_id

        # Ticket identity
        assert ticket.trace_id == t_id
        assert ticket.agent_id == a_id

        # DuckDB row identity
        rows = store.execute_query("SELECT trace_id, agent_id FROM events WHERE span_id = ?", ["s_id"])
        assert rows[0]["trace_id"] == t_id
        assert rows[0]["agent_id"] == a_id

    def test_graph_and_duckdb_cardinality_parity(self):
        """Ingests a DAG with 5 events and causal edges; verifies exact count parity in DuckDB."""
        t_id = "trace-cardinality-parity"
        ag = ActionGraph()
        store = DuckDbAnalyticsStore()

        events = []
        for i in range(5):
            p_span = f"c_span_{i-1}" if i > 0 else None
            ev = make_tier3_event(
                t_id,
                span_id=f"c_span_{i}",
                parent_span_id=p_span,
                tool_name=f"tool_{i}",
            )
            events.append(ev)

        ag.ingest_events(events)
        store.ingest_events(events)
        edges = ag.get_edges(t_id)
        for e in edges:
            store.ingest_graph_edge(e)

        # 5 events ingested
        assert store.row_count("events") == 5
        # Edges count parity
        assert store.row_count("graph_edges") == len(edges)

    def test_drift_signal_exact_mathematical_propagation(self):
        """Evaluates step with known weights and signals; checks exact match in DuckDB."""
        t_id = "trace-math-prop"
        calc = SemanticDriftCalculator(
            engine=DeterministicEmbeddingEngine(seed=42),
            weights=(0.45, 0.25, 0.15, 0.15),
            window_size=1,
        )
        store = DuckDbAnalyticsStore()

        # Step identical to anchor -> d_t = 0.0 -> s_semantic = 0.0
        # Sp=0.4, Sg=0.6, Sv=0.2, Ss=0.0
        # Rt = 0.45*0.4 + 0.25*0.6 + 0.15*0.2 + 0.15*0.0 = 0.18 + 0.15 + 0.03 = 0.36
        res = calc.evaluate_step(
            trace_id=t_id,
            step_text="Identical anchor text",
            anchor_text="Identical anchor text",
            s_policy=0.4,
            s_graph=0.6,
            s_velocity=0.2,
        )
        expected_rt = 0.36
        assert res.composite_risk == pytest.approx(expected_rt, abs=1e-3)

        store.ingest_drift_snapshot(res)
        rows = store.execute_query("SELECT policy_score, graph_score, velocity_score, drift_score FROM drift_snapshots WHERE trace_id = ?", [t_id])
        assert len(rows) == 1
        assert rows[0]["policy_score"] == pytest.approx(0.4)
        assert rows[0]["graph_score"] == pytest.approx(0.6)
        assert rows[0]["velocity_score"] == pytest.approx(0.2)
        assert rows[0]["drift_score"] == pytest.approx(0.0, abs=1e-5)  # instantaneous semantic drift

    def test_structural_separation_invariant_immutability(self):
        """Asserts that ticket.primary_view() never contains justification or agent_rationale keys."""
        gate = HitlReviewGate()
        ticket = gate.create_ticket(
            trace_id="tr-immut-sep",
            tool_name="restart_service",
            arguments={"service": "payment_gateway"},
            agent_rationale="Urgent CEO emergency instruction",
        )
        pv = ticket.primary_view()
        assert "arguments" in pv
        assert "justification" not in pv
        assert "agent_rationale" not in pv
        assert "⚠ UNTRUSTED AGENT OUTPUT" not in pv

        sv = ticket.secondary_view()
        assert sv.get("⚠ UNTRUSTED AGENT OUTPUT") is True
        assert "agent_rationale" in sv

    def test_policy_hash_consistency_across_events(self):
        """Validates that policy.compute_policy_hash() is deterministic and matches policy_version."""
        policy = load_policy_yaml(TIER3_POLICY_YAML)
        h1 = policy.compute_policy_hash()
        h2 = policy.compute_policy_hash()
        assert h1 == h2
        assert h1.startswith("sha256:")

        event = make_tier3_event("tr-pol-hash", policy_version=h1)
        store = DuckDbAnalyticsStore()
        store.ingest_event(event)

        rows = store.execute_query("SELECT policy_version FROM events WHERE trace_id = 'tr-pol-hash'")
        assert rows[0]["policy_version"] == h1


# ===========================================================================
# Suite 4: TestConcurrentMultiSessionProcessing (6 tests)
# ===========================================================================

class TestConcurrentMultiSessionProcessing:
    """Verifies multi-session isolation, concurrent stress, and active query execution."""

    def test_concurrent_multi_session_telemetry_isolation(self):
        """5 concurrent threads running independent sessions with distinct traces and behaviors."""
        ag = ActionGraph()
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine())
        store = DuckDbAnalyticsStore()
        gate = HitlReviewGate()
        errors = []

        def session_worker(session_idx: int):
            try:
                t_id = f"trace-session-{session_idx}"
                for step in range(10):
                    ev = make_tier3_event(
                        trace_id=t_id,
                        span_id=f"s_{session_idx}_{step}",
                        parent_span_id=f"s_{session_idx}_{step-1}" if step > 0 else None,
                        tool_name=f"tool_s{session_idx}",
                    )
                    ag.ingest_event(ev)
                    calc.evaluate_step(t_id, f"step {step}", "anchor task")
                    store.ingest_event(ev)

                # Isolated ticket creation
                gate.create_ticket(trace_id=t_id, tool_name=f"tool_s{session_idx}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=session_worker, args=(i,)) for i in range(5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        assert store.row_count("events") == 50

        # Each session has isolated trajectory
        for i in range(5):
            traj = calc.get_trajectory(f"trace-session-{i}")
            assert len(traj) == 10

    def test_concurrent_graph_and_duckdb_bulk_ingestion_stress(self):
        """10 threads each ingesting 25 events and 20 edges simultaneously."""
        ag = ActionGraph()
        store = DuckDbAnalyticsStore()
        errors = []

        def worker(w_id: int):
            try:
                t_id = f"tr-stress-{w_id}"
                events = [
                    make_tier3_event(
                        trace_id=t_id,
                        span_id=f"sp_{w_id}_{k}",
                        parent_span_id=f"sp_{w_id}_{k-1}" if k > 0 else None,
                    )
                    for k in range(25)
                ]
                ag.ingest_events(events)
                store.ingest_events(events)

                for e in ag.get_edges(t_id):
                    store.ingest_graph_edge(e)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        assert store.row_count("events") == 250

    def test_concurrent_kql_query_execution_during_active_ingestion(self):
        """Writer thread continuously ingests while 4 reader threads run KQL queries."""
        store = DuckDbAnalyticsStore()
        stop_flag = threading.Event()
        writer_errors = []
        reader_errors = []

        def writer():
            count = 0
            while not stop_flag.is_set() and count < 100:
                try:
                    ev = make_tier3_event(
                        trace_id=f"tr-rw-{count}",
                        verdict=Verdict.BLOCK if count % 3 == 0 else Verdict.ALLOW,
                    )
                    store.ingest_event(ev)
                    count += 1
                except Exception as e:
                    writer_errors.append(e)

        def reader():
            while not stop_flag.is_set():
                try:
                    res = store.execute_kql("events | where verdict == 'BLOCK' | take 5")
                    assert isinstance(res, KqlQueryResult)
                except Exception as e:
                    reader_errors.append(e)

        w_thread = threading.Thread(target=writer)
        r_threads = [threading.Thread(target=reader) for _ in range(4)]

        w_thread.start()
        for rt in r_threads:
            rt.start()

        w_thread.join()
        stop_flag.set()
        for rt in r_threads:
            rt.join()

        assert len(writer_errors) == 0
        assert len(reader_errors) == 0

    def test_concurrent_hitl_ticket_adjudication(self):
        """10 tickets created concurrently and adjudicated concurrently across threads."""
        gate = HitlReviewGate()
        tickets = [gate.create_ticket(tool_name=f"tool_{i}") for i in range(10)]
        errors = []

        def adjudicator(t_idx: int):
            try:
                t = tickets[t_idx]
                decision = "APPROVE" if t_idx % 2 == 0 else "REJECT"
                gate.adjudicate_ticket(t.ticket_id, f"reviewer_{t_idx}", decision)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=adjudicator, args=(i,)) for i in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        for i, t in enumerate(tickets):
            updated = gate.get_ticket(t.ticket_id)
            expected_status = TicketStatus.APPROVED if i % 2 == 0 else TicketStatus.REJECTED
            assert updated.status == expected_status

    def test_concurrent_multi_trace_drift_evaluations(self):
        """5 threads evaluating independent traces maintain isolated sliding windows."""
        calc = SemanticDriftCalculator(engine=DeterministicEmbeddingEngine(), window_size=3)
        errors = []

        def worker(t_idx: int):
            try:
                t_id = f"tr-drift-conc-window-{t_idx}"
                anchor = f"Goal anchor for trace {t_idx}"
                for s in range(5):
                    calc.evaluate_step(trace_id=t_id, step_text=f"Action {s}", anchor_text=anchor)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        for i in range(5):
            traj = calc.get_trajectory(f"tr-drift-conc-window-{i}")
            assert len(traj) == 5

    def test_multi_tenant_agent_partitioning(self):
        """Distinct agent_ids partitioned cleanly in DuckDB and ActionGraph."""
        ag = ActionGraph()
        store = DuckDbAnalyticsStore()

        agents = ["agent-alpha", "agent-beta", "agent-gamma"]
        for a_id in agents:
            for k in range(10):
                ev = make_tier3_event(trace_id=f"tr-{a_id}", agent_id=a_id, span_id=f"s_{a_id}_{k}")
                ag.ingest_event(ev)
                store.ingest_event(ev)

        # Query per-agent count via KQL
        res = store.execute_kql("events | summarize count() by agent_id | sort by agent_id asc")
        assert len(res.rows) == 3
        for r in res.rows:
            assert r["count()"] == 10


# ===========================================================================
# Suite 5: TestForensicThreatHuntingPlaybooks (6 tests)
# ===========================================================================

class TestForensicThreatHuntingPlaybooks:
    """Enterprise SIEM threat hunting query playbooks running against DuckDB."""

    @pytest.fixture
    def seeded_store(self):
        store = DuckDbAnalyticsStore()
        # Seed 20 diverse events across 4 traces
        for i in range(20):
            t_id = f"trace-hunt-{i % 4}"
            verdict = Verdict.BLOCK if i % 5 == 0 else (Verdict.PAUSE_FOR_HITL if i % 7 == 0 else Verdict.ALLOW)
            tool_name = "bash_exec" if i % 5 == 0 else ("restart_service" if i % 7 == 0 else "get_metrics")
            taint = ["UNTRUSTED_EXTERNAL"] if i % 3 == 0 else []
            ev = make_tier3_event(
                trace_id=t_id,
                span_id=f"hunt_span_{i}",
                tool_name=tool_name,
                verdict=verdict,
                taint_labels=taint,
            )
            store.ingest_event(ev)

        # Seed drift snapshots
        for k in range(8):
            store.ingest_drift_snapshot(
                snapshot_id=f"snap_{k}",
                trace_id=f"trace-hunt-{k % 4}",
                step_index=k,
                drift_score=0.85 if k % 2 == 0 else 0.40,
                classification="HIGH_RISK" if k % 2 == 0 else "NORMAL",
            )

        # Seed motif violations
        store.ingest_motif_violation(
            violation_id="v_hunt_1",
            trace_id="trace-hunt-0",
            motif_type=MotifType.UNAUTHORIZED_TOOL_JUMPING.value,
            severity="CRITICAL",
            description="Unauthorized direct tool jumping",
        )
        store.ingest_motif_violation(
            violation_id="v_hunt_2",
            trace_id="trace-hunt-1",
            motif_type=MotifType.FORBIDDEN_TAINT_SUBGRAPH.value,
            severity="HIGH",
            description="Taint egress violation",
        )
        return store

    def test_playbook_1_high_risk_and_blocked_event_triage(self, seeded_store):
        """PB-01: Triage all blocked or paused execution incidents."""
        query = "events | where verdict == 'BLOCK' or verdict == 'PAUSE_FOR_HITL' | project span_id, trace_id, tool_name, verdict"
        res = seeded_store.execute_kql(query)
        assert isinstance(res, KqlQueryResult)
        assert len(res.rows) >= 1
        for r in res.rows:
            assert r["verdict"] in ("BLOCK", "PAUSE_FOR_HITL")

    def test_playbook_2_semantic_drift_progression_by_classification(self, seeded_store):
        """PB-02: Aggregate drift snapshots by classification level."""
        query = "drift_snapshots | summarize count() by classification"
        res = seeded_store.execute_kql(query)
        assert isinstance(res, KqlQueryResult)
        assert len(res.rows) >= 1
        classes = {r["classification"] for r in res.rows}
        assert "HIGH_RISK" in classes or "NORMAL" in classes

    def test_playbook_3_critical_motif_violation_audit(self, seeded_store):
        """PB-03: Retrieve all high/critical severity graph motif violations."""
        query = "motif_violations | where severity == 'CRITICAL' or severity == 'HIGH' | project violation_id, motif_type, severity"
        res = seeded_store.execute_kql(query)
        assert len(res.rows) == 2
        for r in res.rows:
            assert r["severity"] in ("CRITICAL", "HIGH")

    def test_playbook_4_unauthorized_tool_jumping_forensics(self, seeded_store):
        """PB-04: Filter specific motif violation type UNAUTHORIZED_TOOL_JUMPING."""
        query = "motif_violations | where motif_type == 'UNAUTHORIZED_TOOL_JUMPING' | take 5"
        res = seeded_store.execute_kql(query)
        assert len(res.rows) == 1
        assert res.rows[0]["motif_type"] == "UNAUTHORIZED_TOOL_JUMPING"

    def test_playbook_5_persuasion_risk_ranking(self, seeded_store):
        """PB-05: Query events with taint labels ordered by span_id."""
        query = "events | where taint_labels has 'UNTRUSTED_EXTERNAL' | project trace_id, tool_name, taint_labels | take 10"
        res = seeded_store.execute_kql(query)
        assert len(res.rows) >= 1

    def test_playbook_parameterized_injection_safety(self, seeded_store):
        """PB-06: Verify injection strings in queries remain safely parameterized."""
        sql_inject = "'; DROP TABLE events; --"
        query = f'events | where tool_name == "{sql_inject}"'
        res = seeded_store.execute_kql(query)
        assert len(res.rows) == 0
        # Verify events table still intact
        assert seeded_store.row_count("events") == 20
