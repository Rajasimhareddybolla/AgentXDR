"""
Embedded DuckDB Analytics Store for AgentXDR SIEM.

Provides a thread-safe columnar store with four purpose-built tables:

    events            — AgentEvent audit log
    graph_edges       — ActionGraph edge records
    drift_snapshots   — SemanticDrift window snapshots
    motif_violations  — MotifAnomalyDetector hits

Usage::

    store = DuckDbAnalyticsStore()               # in-memory
    store = DuckDbAnalyticsStore("/tmp/xdr.db")  # persisted

    store.ingest_event(event)
    result = store.execute_kql("events | where verdict == 'BLOCK' | take 5")
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union

import duckdb

from agentxdr.analytics.kql.compiler import KqlCompiler, KqlQueryResult
from agentxdr.analytics.kql.parser import parse
from agentxdr.drift.models import SemanticDriftResult
from agentxdr.graph.models import GraphEdge, MotifViolation
from agentxdr.models.events import AgentEvent, DriftSnapshot


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_DDL_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    event_id        VARCHAR NOT NULL,
    trace_id        VARCHAR,
    agent_id        VARCHAR,
    event_type      VARCHAR,
    tool_name       VARCHAR,
    verdict         VARCHAR,
    owasp_id        VARCHAR,
    rule_id         VARCHAR,
    risk_score      DOUBLE,
    taint_labels    VARCHAR,
    timestamp_utc   TIMESTAMP,
    metadata_json   VARCHAR,
    payload_redacted VARCHAR,
    decision        VARCHAR,
    drift_snapshot  VARCHAR,
    principal       VARCHAR,
    timestamp       TIMESTAMP GENERATED ALWAYS AS (timestamp_utc)
)
"""

_DDL_EVENTS_VIEW = """
CREATE VIEW IF NOT EXISTS "AgentEvents" AS SELECT * FROM events;
"""

_DDL_GRAPH_EDGES = """
CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id         VARCHAR NOT NULL,
    trace_id        VARCHAR,
    source_node     VARCHAR,
    target_node     VARCHAR,
    edge_type       VARCHAR,
    taint_labels    VARCHAR,
    timestamp_utc   TIMESTAMP
)
"""

_DDL_DRIFT_SNAPSHOTS = """
CREATE TABLE IF NOT EXISTS drift_snapshots (
    snapshot_id     VARCHAR NOT NULL,
    trace_id        VARCHAR,
    step_index      INTEGER,
    drift_score     DOUBLE,
    classification  VARCHAR,
    policy_score    DOUBLE,
    graph_score     DOUBLE,
    velocity_score  DOUBLE,
    semantic_score  DOUBLE,
    timestamp_utc   TIMESTAMP
)
"""

_DDL_MOTIF_VIOLATIONS = """
CREATE TABLE IF NOT EXISTS motif_violations (
    violation_id    VARCHAR NOT NULL,
    trace_id        VARCHAR,
    motif_type      VARCHAR,
    severity        VARCHAR,
    description     VARCHAR,
    involved_nodes  VARCHAR,
    timestamp_utc   TIMESTAMP
)
"""


class DuckDbAnalyticsStore:
    """
    Thread-safe embedded DuckDB store for AgentXDR SIEM telemetry.

    Parameters
    ----------
    database_path : str
        DuckDB database path. Defaults to ":memory:".
    read_only : bool
        Whether to open in read-only mode. Note that in-memory databases
        cannot be opened in read-only mode.
    db_path : Optional[str]
        Alias for database_path for backward compatibility.
    """

    def __init__(
        self,
        database_path: str = ":memory:",
        read_only: bool = False,
        db_path: Optional[str] = None,
    ) -> None:
        self._db_path = db_path if db_path is not None else database_path
        self._read_only = read_only
        self._lock = threading.RLock()

        if self._read_only and self._db_path == ":memory:":
            raise ValueError("Cannot launch in-memory database in read-only mode")

        if not self._read_only and self._db_path != ":memory:":
            parent_dir = os.path.dirname(os.path.abspath(self._db_path))
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

        self._conn = duckdb.connect(self._db_path, read_only=self._read_only)
        if not self._read_only:
            self._init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock:
            for ddl in (
                _DDL_EVENTS,
                _DDL_EVENTS_VIEW,
                _DDL_GRAPH_EDGES,
                _DDL_DRIFT_SNAPSHOTS,
                _DDL_MOTIF_VIOLATIONS,
            ):
                self._conn.execute(ddl)

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def ingest_event(self, event: AgentEvent) -> None:
        """Persist a single :class:`AgentEvent` to the ``events`` table."""
        self._ingest_one(event)

    def ingest_events(self, events: Sequence[AgentEvent]) -> int:
        """Bulk-persist a list of :class:`AgentEvent` objects and return ingested count."""
        with self._lock:
            for event in events:
                self._ingest_one(event)
            return len(events)

    def _ingest_one(self, event: AgentEvent) -> None:
        # Extract tool_name from top-level or payload_redacted
        tool_name = getattr(event, "tool_name", None) or ""
        if not tool_name and hasattr(event, "payload_redacted") and isinstance(event.payload_redacted, dict):
            tool_name = event.payload_redacted.get("tool_name", "") or ""

        # Extract decision details
        verdict_str: Optional[str] = None
        rule_id: Optional[str] = None
        owasp_id: Optional[str] = None
        risk_score: Optional[float] = None

        if hasattr(event, "decision") and event.decision is not None:
            d = event.decision
            if hasattr(d, "verdict"):
                verdict_str = d.verdict.value if hasattr(d.verdict, "value") else str(d.verdict)
            rule_id = getattr(d, "rule_id", None)
            owasp_id = getattr(d, "owasp_id", None)
            if not owasp_id and hasattr(d, "owasp_ids") and d.owasp_ids:
                owasp_id = d.owasp_ids[0]
            risk_score = getattr(d, "risk_score", None)

        if risk_score is None and hasattr(event, "drift_snapshot") and event.drift_snapshot is not None:
            risk_score = getattr(event.drift_snapshot, "composite_score", None)

        # Extract taint labels
        taint_labels_str: Optional[str] = None
        if hasattr(event, "taint_labels") and event.taint_labels:
            taint_labels_str = ",".join(sorted(str(l) for l in event.taint_labels))
        elif hasattr(event, "taint") and event.taint is not None:
            labels = getattr(event.taint, "labels", set())
            taint_labels_str = ",".join(sorted(str(l) for l in labels))

        # Metadata
        metadata: dict = getattr(event, "metadata", {}) or {}
        if hasattr(event, "payload_redacted") and event.payload_redacted:
            metadata["payload_redacted"] = event.payload_redacted

        ts = getattr(event, "timestamp", None)
        if ts is not None and hasattr(ts, "astimezone"):
            ts_utc = ts.astimezone(timezone.utc)
        else:
            ts_utc = ts or datetime.now(timezone.utc)

        # Extract nested structures as JSON strings for DuckDB JSON querying
        payload_json = json.dumps(getattr(event, "payload_redacted", {}) or {})

        decision_data: Dict[str, Any] = {}
        if hasattr(event, "decision") and event.decision is not None:
            if hasattr(event.decision, "model_dump"):
                decision_data = event.decision.model_dump()
            elif hasattr(event.decision, "__dict__"):
                decision_data = event.decision.__dict__
        decision_json = json.dumps(decision_data, default=str)

        drift_data: Dict[str, Any] = {}
        if hasattr(event, "drift_snapshot") and event.drift_snapshot is not None:
            if hasattr(event.drift_snapshot, "model_dump"):
                drift_data = event.drift_snapshot.model_dump()
            elif hasattr(event.drift_snapshot, "__dict__"):
                drift_data = event.drift_snapshot.__dict__
        drift_json = json.dumps(drift_data, default=str)

        principal_data: Dict[str, Any] = {}
        if hasattr(event, "principal") and event.principal is not None:
            if hasattr(event.principal, "model_dump"):
                principal_data = event.principal.model_dump()
            elif hasattr(event.principal, "__dict__"):
                principal_data = event.principal.__dict__
        principal_json = json.dumps(principal_data, default=str)

        event_type_val = getattr(getattr(event, "event_type", getattr(event, "type", "")), "value", getattr(event, "event_type", ""))

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO events (
                    event_id, trace_id, agent_id, event_type,
                    tool_name, verdict, owasp_id, rule_id,
                    risk_score, taint_labels, timestamp_utc, metadata_json,
                    payload_redacted, decision, drift_snapshot, principal
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    str(getattr(event, "event_id", "")),
                    str(getattr(event, "trace_id", "")),
                    str(getattr(event, "agent_id", "")),
                    str(event_type_val),
                    str(tool_name),
                    verdict_str,
                    owasp_id,
                    rule_id,
                    risk_score,
                    taint_labels_str,
                    ts_utc,
                    json.dumps(metadata),
                    payload_json,
                    decision_json,
                    drift_json,
                    principal_json,
                ],
            )

    # ------------------------------------------------------------------
    # Graph edge ingestion
    # ------------------------------------------------------------------

    def ingest_graph_edge(
        self,
        edge: Union[Dict[str, Any], GraphEdge, str] = None,
        trace_id: Optional[str] = None,
        source_node: Optional[str] = None,
        target_node: Optional[str] = None,
        edge_type: Optional[str] = None,
        taint_labels: Optional[Union[str, List[str]]] = None,
        timestamp_utc: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        """Polymorphic ingestion of graph edges from GraphEdge, dict, or individual params."""
        edge_id = str(uuid.uuid4())
        if isinstance(edge, str):
            edge_id = edge
        elif hasattr(edge, "id") and hasattr(edge, "source") and hasattr(edge, "target"):
            edge_id = str(edge.id)
            source_node = str(edge.source)
            target_node = str(edge.target)
            edge_type = edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type)
            taint_labels = ",".join(edge.taint_badges) if getattr(edge, "taint_badges", None) else None
            meta = getattr(edge, "metadata", {}) or {}
            trace_id = trace_id or meta.get("trace_id", "")
            timestamp_utc = timestamp_utc or meta.get("timestamp_utc", meta.get("timestamp"))
        elif isinstance(edge, dict):
            edge_id = str(edge.get("edge_id") or edge.get("id") or uuid.uuid4())
            source_node = str(edge.get("source_node") or edge.get("source") or "")
            target_node = str(edge.get("target_node") or edge.get("target") or "")
            et = edge.get("edge_type", "CAUSAL_FLOW")
            edge_type = et.value if hasattr(et, "value") else str(et)
            tl = edge.get("taint_labels") or edge.get("taint_badges")
            taint_labels = ",".join(tl) if isinstance(tl, list) else (str(tl) if tl else None)
            trace_id = trace_id or str(edge.get("trace_id") or "")
            timestamp_utc = timestamp_utc or edge.get("timestamp_utc") or edge.get("timestamp")
        else:
            edge_id = kwargs.get("edge_id") or str(uuid.uuid4())

        if isinstance(taint_labels, list):
            taint_labels = ",".join(str(x) for x in taint_labels)
        if timestamp_utc is None:
            timestamp_utc = datetime.now(timezone.utc)

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO graph_edges (
                    edge_id, trace_id, source_node, target_node,
                    edge_type, taint_labels, timestamp_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    str(edge_id),
                    str(trace_id or ""),
                    str(source_node or ""),
                    str(target_node or ""),
                    str(edge_type or "CAUSAL_FLOW"),
                    taint_labels,
                    timestamp_utc,
                ],
            )

    # ------------------------------------------------------------------
    # Drift snapshot ingestion
    # ------------------------------------------------------------------

    def ingest_drift_snapshot(
        self,
        snapshot: Union[DriftSnapshot, SemanticDriftResult, Dict[str, Any], str] = None,
        trace_id: Optional[str] = None,
        step_index: Optional[int] = None,
        drift_score: Optional[float] = None,
        classification: Optional[str] = None,
        policy_score: float = 0.0,
        graph_score: float = 0.0,
        velocity_score: float = 0.0,
        semantic_score: float = 0.0,
        timestamp_utc: Optional[Any] = None,
        snapshot_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Polymorphic ingestion of drift snapshots from models, dicts, or params."""
        if isinstance(snapshot, str):
            snapshot_id = snapshot
        elif isinstance(snapshot, SemanticDriftResult):
            snapshot_id = str(uuid.uuid4())
            trace_id = snapshot.trace_id
            step_index = snapshot.step_index
            drift_score = snapshot.drift_score
            classification = snapshot.classification.value if hasattr(snapshot.classification, "value") else str(snapshot.classification)
            policy_score = snapshot.s_policy
            graph_score = snapshot.s_graph
            velocity_score = snapshot.s_velocity
            semantic_score = snapshot.s_semantic
        elif isinstance(snapshot, DriftSnapshot):
            snapshot_id = snapshot_id or kwargs.get("snapshot_id") or str(uuid.uuid4())
            trace_id = trace_id or kwargs.get("trace_id", "")
            step_index = step_index if step_index is not None else kwargs.get("step_index", 0)
            drift_score = snapshot.composite_score
            classification = classification or kwargs.get("classification", "NORMAL")
            policy_score = snapshot.s_policy
            graph_score = snapshot.s_graph
            velocity_score = snapshot.s_velocity
            semantic_score = snapshot.s_semantic
        elif isinstance(snapshot, dict):
            snapshot_id = str(snapshot.get("snapshot_id") or uuid.uuid4())
            trace_id = str(snapshot.get("trace_id") or trace_id or "")
            step_index = int(snapshot.get("step_index", step_index or 0))
            drift_score = float(snapshot.get("drift_score", snapshot.get("composite_score", 0.0)))
            c = snapshot.get("classification", classification or "NORMAL")
            classification = c.value if hasattr(c, "value") else str(c)
            policy_score = float(snapshot.get("policy_score", snapshot.get("s_policy", 0.0)))
            graph_score = float(snapshot.get("graph_score", snapshot.get("s_graph", 0.0)))
            velocity_score = float(snapshot.get("velocity_score", snapshot.get("s_velocity", 0.0)))
            semantic_score = float(snapshot.get("semantic_score", snapshot.get("s_semantic", 0.0)))
            timestamp_utc = timestamp_utc or snapshot.get("timestamp_utc")

        snapshot_id = snapshot_id or kwargs.get("snapshot_id") or str(uuid.uuid4())
        trace_id = trace_id or kwargs.get("trace_id", "")
        step_index = step_index if step_index is not None else kwargs.get("step_index", 0)
        drift_score = drift_score if drift_score is not None else kwargs.get("drift_score", 0.0)
        classification = classification or kwargs.get("classification", "NORMAL")
        if timestamp_utc is None:
            timestamp_utc = datetime.now(timezone.utc)

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO drift_snapshots (
                    snapshot_id, trace_id, step_index, drift_score,
                    classification, policy_score, graph_score,
                    velocity_score, semantic_score, timestamp_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    str(snapshot_id),
                    str(trace_id),
                    int(step_index),
                    float(drift_score),
                    str(classification),
                    float(policy_score),
                    float(graph_score),
                    float(velocity_score),
                    float(semantic_score),
                    timestamp_utc,
                ],
            )

    # ------------------------------------------------------------------
    # Motif violation ingestion
    # ------------------------------------------------------------------

    def ingest_motif_violation(
        self,
        violation: Union[MotifViolation, Dict[str, Any], str] = None,
        trace_id: Optional[str] = None,
        motif_type: Optional[str] = None,
        severity: Optional[str] = None,
        description: Optional[str] = None,
        involved_nodes: Optional[Union[str, List[str]]] = None,
        timestamp_utc: Optional[Any] = None,
        violation_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Polymorphic ingestion of motif violations from models, dicts, or params."""
        if isinstance(violation, str):
            violation_id = violation
        elif isinstance(violation, MotifViolation):
            violation_id = str(violation.violation_id)
            trace_id = violation.trace_id or ""
            mt = violation.motif_type
            motif_type = mt.value if hasattr(mt, "value") else str(mt)
            sev = violation.severity
            severity = sev.value if hasattr(sev, "value") else str(sev)
            description = violation.description
            involved_nodes = ",".join(violation.affected_nodes) if violation.affected_nodes else ""
            timestamp_utc = datetime.now(timezone.utc)
        elif isinstance(violation, dict):
            violation_id = str(violation.get("violation_id") or uuid.uuid4())
            trace_id = str(violation.get("trace_id") or trace_id or "")
            mt = violation.get("motif_type", motif_type or "ANOMALY")
            motif_type = mt.value if hasattr(mt, "value") else str(mt)
            sev = violation.get("severity", severity or "MEDIUM")
            severity = sev.value if hasattr(sev, "value") else str(sev)
            description = str(violation.get("description", description or ""))
            nodes = violation.get("involved_nodes") or violation.get("affected_nodes")
            involved_nodes = ",".join(nodes) if isinstance(nodes, list) else (str(nodes) if nodes else "")
            timestamp_utc = timestamp_utc or violation.get("timestamp_utc")

        violation_id = violation_id or kwargs.get("violation_id") or str(uuid.uuid4())
        trace_id = trace_id or kwargs.get("trace_id", "")
        motif_type = motif_type or kwargs.get("motif_type", "ANOMALY")
        severity = severity or kwargs.get("severity", "MEDIUM")
        description = description or kwargs.get("description", "")
        if isinstance(involved_nodes, list):
            involved_nodes = ",".join(str(x) for x in involved_nodes)
        if timestamp_utc is None:
            timestamp_utc = datetime.now(timezone.utc)

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO motif_violations (
                    violation_id, trace_id, motif_type, severity,
                    description, involved_nodes, timestamp_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    str(violation_id),
                    str(trace_id),
                    str(motif_type),
                    str(severity),
                    str(description),
                    involved_nodes,
                    timestamp_utc,
                ],
            )

    # ------------------------------------------------------------------
    # Raw SQL execution
    # ------------------------------------------------------------------

    def execute_query(self, sql: str, params: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute a raw parameterized SQL query and return rows as dicts.

        Parameters
        ----------
        sql    : SQL query with ? placeholders
        params : bind parameters matching ? placeholders in order
        """
        with self._lock:
            rel = self._conn.execute(sql, list(params) if params else [])
            columns = [desc[0] for desc in rel.description]
            rows = rel.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    def query_sql(self, sql: str, params: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]:
        """Execute a raw SQL query per SCOPE.md interface contract."""
        return self.execute_query(sql, params)

    # ------------------------------------------------------------------
    # KQL execution (high-level)
    # ------------------------------------------------------------------

    def execute_kql(self, kql_query: str) -> KqlQueryResult:
        """
        Parse a KQL-Lite query, compile it to SQL, execute it, and return
        a :class:`KqlQueryResult`.
        """
        t0 = time.perf_counter()
        pipeline = parse(kql_query)
        compiler = KqlCompiler()
        compiled = compiler.compile(pipeline)
        rows_raw = self.execute_query(compiled.sql, compiled.params)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        columns = list(rows_raw[0].keys()) if rows_raw else []
        return KqlQueryResult(
            columns=columns,
            rows=rows_raw,
            execution_time_ms=elapsed_ms,
        )

    def query_kql(self, kql: str) -> List[Dict[str, Any]]:
        """Execute a KQL query and return rows as dicts per SCOPE.md contract."""
        return self.execute_kql(kql).rows

    # ------------------------------------------------------------------
    # Convenience & Lifecycle
    # ------------------------------------------------------------------

    def row_count(self, table: str) -> int:
        """Return the number of rows in *table*."""
        rows = self.execute_query(f'SELECT count(*) AS n FROM "{table}"')
        return int(rows[0]["n"])

    def close(self) -> None:
        """Close the DuckDB connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> DuckDbAnalyticsStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
