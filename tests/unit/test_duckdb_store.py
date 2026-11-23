"""
tests/unit/test_duckdb_store.py

Unit tests for the embedded DuckDB Analytics Store.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

import pytest

from agentxdr.analytics.duckdb_store import DuckDbAnalyticsStore
from agentxdr.models.events import (
    AgentEvent,
    Decision,
    DriftSnapshot,
    EventType,
    Principal,
    ProvenanceTier,
    Verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRINCIPAL = Principal(user_id="user-test", roles=["analyst"])
_DRIFT = DriftSnapshot(
    composite_score=0.1,
    s_policy=0.1,
    s_graph=0.1,
    s_velocity=0.0,
    s_semantic=0.0,
)


def _make_event(
    verdict: str = "ALLOW",
    owasp_id: str | None = None,
    rule_id: str | None = None,
    tool_name: str = "read_file",
) -> AgentEvent:
    owasp_ids = [owasp_id] if owasp_id else []
    decision = Decision(
        verdict=Verdict[verdict],
        rule_id=rule_id or f"rule-{verdict.lower()}",
        owasp_ids=owasp_ids,
        latency_ms=1.0,
    )
    return AgentEvent(
        trace_id="trace-001",
        span_id=str(uuid.uuid4()),
        agent_id="agent-A",
        policy_version="1.0",
        event_type=EventType.TOOL_INVOCATION,
        principal=_PRINCIPAL,
        provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
        decision=decision,
        drift_snapshot=_DRIFT,
        payload_redacted={"tool_name": tool_name},
    )


@pytest.fixture
def store() -> DuckDbAnalyticsStore:
    return DuckDbAnalyticsStore()   # in-memory


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------


class TestSchemaInit:
    def test_tables_exist(self, store):
        tables = store.execute_query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        )
        names = {r["table_name"] for r in tables}
        assert "events" in names
        assert "graph_edges" in names
        assert "drift_snapshots" in names
        assert "motif_violations" in names

    def test_initial_row_counts_zero(self, store):
        for table in ("events", "graph_edges", "drift_snapshots", "motif_violations"):
            assert store.row_count(table) == 0


# ---------------------------------------------------------------------------
# Event ingestion
# ---------------------------------------------------------------------------


class TestEventIngestion:
    def test_ingest_single_event(self, store):
        store.ingest_event(_make_event())
        assert store.row_count("events") == 1

    def test_ingest_multiple_events(self, store):
        events = [_make_event() for _ in range(10)]
        store.ingest_events(events)
        assert store.row_count("events") == 10

    def test_verdict_stored_correctly(self, store):
        store.ingest_event(_make_event(verdict="BLOCK"))
        rows = store.execute_query("SELECT verdict FROM events")
        assert rows[0]["verdict"] == "BLOCK"

    def test_tool_name_stored(self, store):
        store.ingest_event(_make_event(tool_name="write_file"))
        rows = store.execute_query("SELECT tool_name FROM events")
        assert rows[0]["tool_name"] == "write_file"

    def test_owasp_id_stored(self, store):
        store.ingest_event(_make_event(owasp_id="ASI01"))
        rows = store.execute_query("SELECT owasp_id FROM events")
        assert rows[0]["owasp_id"] == "ASI01"

    def test_rule_id_stored(self, store):
        store.ingest_event(_make_event(rule_id="R-100"))
        rows = store.execute_query("SELECT rule_id FROM events")
        assert rows[0]["rule_id"] == "R-100"

    def test_mixed_verdicts_filtered(self, store):
        store.ingest_event(_make_event(verdict="BLOCK"))
        store.ingest_event(_make_event(verdict="ALLOW"))
        store.ingest_event(_make_event(verdict="BLOCK"))
        rows = store.execute_query("SELECT * FROM events WHERE verdict = ?", ["BLOCK"])
        assert len(rows) == 2


# ---------------------------------------------------------------------------
# Graph edge ingestion
# ---------------------------------------------------------------------------


class TestGraphEdgeIngestion:
    def test_ingest_graph_edge(self, store):
        store.ingest_graph_edge("e1", "t1", "agent-A", "tool-read", "TOOL_CALL")
        assert store.row_count("graph_edges") == 1

    def test_edge_fields_stored(self, store):
        store.ingest_graph_edge("e2", "t2", "agent-B", "tool-write", "TOOL_RESPONSE", "PII,SECRET")
        rows = store.execute_query("SELECT * FROM graph_edges")
        r = rows[0]
        assert r["source_node"] == "agent-B"
        assert r["target_node"] == "tool-write"
        assert r["taint_labels"] == "PII,SECRET"


# ---------------------------------------------------------------------------
# Drift snapshot ingestion
# ---------------------------------------------------------------------------


class TestDriftSnapshotIngestion:
    def test_ingest_drift_snapshot(self, store):
        store.ingest_drift_snapshot("s1", "t1", 0, 0.75, "DRIFT_CRITICAL")
        assert store.row_count("drift_snapshots") == 1

    def test_drift_scores_stored(self, store):
        store.ingest_drift_snapshot("s2", "t2", 1, 0.42, "DRIFT_WARNING",
                                    policy_score=0.3, graph_score=0.1)
        rows = store.execute_query("SELECT * FROM drift_snapshots")
        r = rows[0]
        assert r["drift_score"] == pytest.approx(0.42)
        assert r["classification"] == "DRIFT_WARNING"
        assert r["policy_score"] == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# Motif violation ingestion
# ---------------------------------------------------------------------------


class TestMotifViolationIngestion:
    def test_ingest_motif_violation(self, store):
        store.ingest_motif_violation("v1", "t1", "ASI01", "HIGH", "Indirect taint")
        assert store.row_count("motif_violations") == 1

    def test_violation_fields_stored(self, store):
        store.ingest_motif_violation("v2", "t2", "ASI03", "MEDIUM", "Meta tamper",
                                     involved_nodes="agent-A,agent-B")
        rows = store.execute_query("SELECT * FROM motif_violations")
        r = rows[0]
        assert r["motif_type"] == "ASI03"
        assert r["involved_nodes"] == "agent-A,agent-B"


# ---------------------------------------------------------------------------
# Raw SQL execution
# ---------------------------------------------------------------------------


class TestRawSqlExecution:
    def test_execute_query_returns_dicts(self, store):
        store.ingest_event(_make_event(verdict="BLOCK", owasp_id="ASI01"))
        rows = store.execute_query("SELECT event_id, verdict FROM events")
        assert isinstance(rows, list)
        assert isinstance(rows[0], dict)
        assert "verdict" in rows[0]

    def test_parameterised_query(self, store):
        store.ingest_event(_make_event(verdict="BLOCK"))
        store.ingest_event(_make_event(verdict="ALLOW"))
        rows = store.execute_query("SELECT count(*) AS n FROM events WHERE verdict = ?", ["BLOCK"])
        assert rows[0]["n"] == 1


# ---------------------------------------------------------------------------
# KQL execution (high-level)
# ---------------------------------------------------------------------------


class TestKqlExecution:
    def test_simple_kql_query(self, store):
        store.ingest_events([_make_event(verdict="BLOCK") for _ in range(3)])
        store.ingest_events([_make_event(verdict="ALLOW") for _ in range(5)])
        result = store.execute_kql("events | where verdict == 'BLOCK'")
        assert len(result.rows) == 3

    def test_kql_take(self, store):
        store.ingest_events([_make_event() for _ in range(20)])
        result = store.execute_kql("events | take 5")
        assert len(result.rows) == 5

    def test_kql_project(self, store):
        store.ingest_event(_make_event())
        result = store.execute_kql("events | project event_id, verdict")
        assert result.columns == ["event_id", "verdict"]

    def test_kql_summarize(self, store):
        store.ingest_event(_make_event(verdict="BLOCK"))
        store.ingest_event(_make_event(verdict="BLOCK"))
        store.ingest_event(_make_event(verdict="ALLOW"))
        result = store.execute_kql("events | summarize count() by verdict")
        # Should have 2 groups
        assert len(result.rows) == 2

    def test_kql_execution_time_reported(self, store):
        store.ingest_event(_make_event())
        result = store.execute_kql("events | take 1")
        assert result.execution_time_ms >= 0.0

    def test_kql_no_results_returns_empty(self, store):
        result = store.execute_kql("events | where verdict == 'NONEXISTENT'")
        assert result.rows == []
        assert result.columns == []


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_ingestion(self, store):
        errors = []

        def insert_batch():
            try:
                for _ in range(20):
                    store.ingest_event(_make_event())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=insert_batch) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert store.row_count("events") == 200


# ---------------------------------------------------------------------------
# Interface contracts & Polymorphic ingestion
# ---------------------------------------------------------------------------


class TestInterfaceContractsAndPolymorphism:
    def test_ingest_events_returns_count(self, store):
        events = [_make_event() for _ in range(7)]
        count = store.ingest_events(events)
        assert count == 7
        assert store.row_count("events") == 7

    def test_query_sql_and_query_kql(self, store):
        store.ingest_event(_make_event(verdict="BLOCK"))
        rows_sql = store.query_sql("SELECT verdict FROM events WHERE verdict = ?", ["BLOCK"])
        assert len(rows_sql) == 1
        assert rows_sql[0]["verdict"] == "BLOCK"

        rows_kql = store.query_kql("events | where verdict == 'BLOCK'")
        assert len(rows_kql) == 1
        assert rows_kql[0]["verdict"] == "BLOCK"

    def test_agent_events_view_and_timestamp(self, store):
        store.ingest_event(_make_event(tool_name="test_tool"))
        rows = store.execute_query('SELECT "timestamp", "tool_name" FROM "AgentEvents"')
        assert len(rows) == 1
        assert rows[0]["tool_name"] == "test_tool"
        assert rows[0]["timestamp"] is not None

    def test_ingest_graph_edge_model(self, store):
        from agentxdr.graph.models import GraphEdge, GraphEdgeType
        edge = GraphEdge(
            id=str(uuid.uuid4()),
            source="agent-1",
            target="tool-1",
            edge_type=GraphEdgeType.INVOKES,
            taint_badges=["CONFIDENTIAL"],
            metadata={"trace_id": "tr-100"},
        )
        store.ingest_graph_edge(edge)
        assert store.row_count("graph_edges") == 1
        rows = store.execute_query("SELECT source_node, target_node, taint_labels FROM graph_edges")
        assert rows[0]["source_node"] == "agent-1"
        assert rows[0]["target_node"] == "tool-1"
        assert rows[0]["taint_labels"] == "CONFIDENTIAL"

    def test_ingest_semantic_drift_result_model(self, store):
        from agentxdr.drift.models import DriftClassification, SemanticDriftResult
        drift = SemanticDriftResult(
            trace_id="tr-200",
            step_index=2,
            drift_score=0.82,
            classification=DriftClassification.HIGH_RISK,
            composite_risk=0.85,
            sliding_window_drift=0.82,
            s_policy=0.5,
            s_graph=0.4,
            s_velocity=0.3,
            s_semantic=0.8,
        )
        store.ingest_drift_snapshot(drift)
        assert store.row_count("drift_snapshots") == 1
        rows = store.execute_query("SELECT trace_id, drift_score, classification FROM drift_snapshots")
        assert rows[0]["trace_id"] == "tr-200"
        assert rows[0]["classification"] == "HIGH_RISK"
        assert rows[0]["drift_score"] == pytest.approx(0.82)

    def test_ingest_motif_violation_model(self, store):
        from agentxdr.graph.models import MotifSeverity, MotifType, MotifViolation
        violation = MotifViolation(
            violation_id=str(uuid.uuid4()),
            motif_type=MotifType.EXECUTION_LOOP,
            severity=MotifSeverity.CRITICAL,
            description="Runaway loop detected",
            trace_id="tr-300",
            affected_nodes=["nodeA", "nodeB"],
            affected_edges=["edge1"],
        )
        store.ingest_motif_violation(violation)
        assert store.row_count("motif_violations") == 1
        rows = store.execute_query("SELECT motif_type, severity, description FROM motif_violations")
        assert rows[0]["motif_type"] == "EXECUTION_LOOP"
        assert rows[0]["severity"] == "CRITICAL"

    def test_readonly_memory_raises_error(self):
        with pytest.raises(ValueError, match="Cannot launch in-memory database in read-only mode"):
            DuckDbAnalyticsStore(database_path=":memory:", read_only=True)

    def test_context_manager(self):
        with DuckDbAnalyticsStore() as s:
            s.ingest_event(_make_event())
            assert s.row_count("events") == 1

