"""AgentXDR Unified Runtime Control Plane Server.

Integrates the hot-path inline gateways (LLM proxy, MCP proxy) with the warm-path
analytics plane (DuckDB, KQL-Lite SIEM, ActionGraph DAG, Motif Detector,
Semantic Drift, Anti-ASI09 Persuasion, and HITL Review Gate).
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agentxdr.analytics.duckdb_store import DuckDbAnalyticsStore
from agentxdr.analytics.kql.compiler import KqlQueryResult
from agentxdr.drift.calculator import SemanticDriftCalculator
from agentxdr.drift.embeddings import DeterministicEmbeddingEngine
from agentxdr.graph.action_graph import ActionGraph
from agentxdr.graph.motif_detector import MotifAnomalyDetector
from agentxdr.mcp.proxy import create_fastapi_mcp_app
from agentxdr.models.events import AgentEvent, EventType, ToolTier, Verdict
from agentxdr.models.killswitch import KillSwitchRecord, KillSwitchScope, KillSwitchState
from agentxdr.models.policy import PolicySchema
from agentxdr.persuasion.classifier import PersuasionClassifier, PersuasionResult
from agentxdr.persuasion.hitl_gate import HitlReviewGate, TicketStatus
from agentxdr.policy.evaluator import PolicyEvaluator
from agentxdr.policy.loader import load_policy_yaml
from agentxdr.proxy.gateway import GatewayConfig, LlmGateway
from agentxdr.topology.builder import AgentTopologyBuilder

logger = logging.getLogger("agentxdr.server")


# ===========================================================================
# Request & Response Schemas
# ===========================================================================

class KqlRequest(BaseModel):
    query: str = Field(..., description="KQL-Lite pipeline query string, e.g. 'events | where verdict == \"BLOCK\" | take 10'")


class KqlResponse(BaseModel):
    columns: List[str]
    rows: List[Dict[str, Any]]
    execution_time_ms: float
    row_count: int


class DriftEvaluateRequest(BaseModel):
    trace_id: str
    step_text: str
    anchor_text: Optional[str] = None
    s_policy: float = 0.0
    s_graph: float = 0.0
    s_velocity: float = 0.0
    is_critical_policy_violation: bool = False


class PersuasionClassifyRequest(BaseModel):
    text: str


class HitlAdjudicateRequest(BaseModel):
    decision: TicketStatus
    reviewer_id: str
    justification: str = ""


class KillSwitchTripRequest(BaseModel):
    scope: KillSwitchScope
    target_id: str
    reason: str
    triggered_by: str = "security-admin"


class KillSwitchResetRequest(BaseModel):
    scope: KillSwitchScope
    target_id: str


# ===========================================================================
# Server Factory
# ===========================================================================

def create_agentxdr_app(
    policy_path: Optional[str] = None,
    policy_yaml: Optional[str] = None,
    db_path: str = ":memory:",
    upstream_llm_url: str = "https://api.openai.com/v1",
) -> FastAPI:
    """Create and configure the unified AgentXDR FastAPI application."""

    app = FastAPI(
        title="AgentXDR Unified Runtime Control Plane",
        version="0.1.0",
        description="Enterprise Security Control Plane & Inline Runtime Protection for Agentic AI",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 1. Policy & Evaluator
    policy: Optional[PolicySchema] = None
    if policy_yaml:
        policy = load_policy_yaml(policy_yaml)
    elif policy_path:
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = load_policy_yaml(f.read())
    else:
        # Default minimal permissive policy
        default_yaml = """
version: "1.0.0"
agent_id: "agentxdr-fleet"
goal_anchor:
  canonical_task: "Assist authenticated operators securely and report operational anomalies."
  allowed_domains: ["*"]
tools:
  - name: "safe_search"
    tier: "automatic"
  - name: "execute_sql"
    tier: "privileged_hitl"
  - name: "system_shell"
    tier: "blocked"
budgets:
  max_turns: 50
  max_tool_calls: 100
  max_identical_calls: 5
  max_session_duration_sec: 3600.0
  max_session_cost_usd: 50.0
"""
        policy = load_policy_yaml(default_yaml)

    kill_switch = KillSwitchState()
    evaluator = PolicyEvaluator(kill_switch=kill_switch)

    # 2. Analytics Plane
    analytics_store = DuckDbAnalyticsStore(db_path=db_path)
    action_graph = ActionGraph()
    motif_detector = MotifAnomalyDetector()
    embedding_engine = DeterministicEmbeddingEngine()
    drift_calc = SemanticDriftCalculator(
        engine=embedding_engine,
        goal_anchor=policy.goal_anchor.canonical_task if policy.goal_anchor else "Execute safe tasks",
    )
    persuasion_clf = PersuasionClassifier()
    hitl_gate = HitlReviewGate()

    # 3. Mount Hot-Path Gateways
    gateway_config = GatewayConfig(
        upstream_url=upstream_llm_url,
        agent_id=policy.agent_id,
        policy=policy,
        kill_switch=kill_switch,
    )
    llm_gateway = LlmGateway(config=gateway_config)

    # Wire MCP Proxy
    from agentxdr.guardrails.dlp import DlpMasker
    from agentxdr.mcp.call_enforcer import McpCallEnforcer
    from agentxdr.mcp.injection_scanner import McpInjectionScanner
    from agentxdr.mcp.proxy import McpProxy
    from agentxdr.mcp.schema_registry import McpSchemaRegistry
    from agentxdr.mcp.tool_filter import McpToolFilter

    dlp_masker = DlpMasker()
    mcp_registry = McpSchemaRegistry()
    mcp_scanner = McpInjectionScanner()
    mcp_filter = McpToolFilter(policy=policy, registry=mcp_registry, scanner=mcp_scanner)
    mcp_enforcer = McpCallEnforcer(
        evaluator=evaluator,
        dlp=dlp_masker,
        scanner=mcp_scanner,
    )
    mcp_proxy = McpProxy(
        policy=policy,
        registry=mcp_registry,
        filter=mcp_filter,
        enforcer=mcp_enforcer,
    )
    mcp_app = create_fastapi_mcp_app(proxy=mcp_proxy)

    app.mount("/mcp", mcp_app)

    # State injection
    app.state.policy = policy
    app.state.evaluator = evaluator
    app.state.analytics_store = analytics_store
    app.state.action_graph = action_graph
    app.state.motif_detector = motif_detector
    app.state.drift_calc = drift_calc
    app.state.persuasion_clf = persuasion_clf
    app.state.hitl_gate = hitl_gate
    app.state.kill_switch = kill_switch
    app.state.llm_gateway = llm_gateway

    # -----------------------------------------------------------------------
    # System Info & Health
    # -----------------------------------------------------------------------

    @app.get("/health", tags=["System"])
    def health_check():
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy_id": policy.agent_id if policy else "none",
            "events_ingested": analytics_store.row_count("events"),
        }

    @app.get("/api/v1/info", tags=["System"])
    def get_info():
        return {
            "app": "AgentXDR Unified Runtime Control Plane",
            "version": "0.1.0",
            "active_policy": policy.agent_id if policy else None,
            "tools_count": len(policy.tools) if policy else 0,
            "kill_switch_active_count": len(kill_switch.get_active_records()),
            "pending_hitl_tickets": len(hitl_gate.list_pending()),
        }

    # -----------------------------------------------------------------------
    # Hot-Path Proxy Routes
    # -----------------------------------------------------------------------

    @app.post("/v1/chat/completions", tags=["Hot-Path LLM Gateway"])
    async def chat_completions(req: Dict[str, Any]):
        return await llm_gateway.process_request(req)

    # -----------------------------------------------------------------------
    # Warm-Path Analytics & KQL-Lite SIEM
    # -----------------------------------------------------------------------

    @app.post("/api/v1/analytics/events", tags=["Warm-Path Analytics"])
    def ingest_event(event: AgentEvent):
        # 1. Ingest into DuckDB
        analytics_store.ingest_event(event)

        # 2. Ingest into ActionGraph
        action_graph.ingest_event(event)

        # 3. Check for motif violations
        violations = motif_detector.scan_trace(action_graph.graph, trace_id=event.trace_id)
        for v in violations:
            analytics_store.ingest_motif_violation(
                violation_id=str(v.violation_id),
                trace_id=event.trace_id,
                motif_type=v.motif_type.value,
                severity=v.severity.value,
                description=v.description,
                involved_nodes=",".join(v.involved_nodes),
                timestamp_utc=datetime.now(timezone.utc),
            )

        return {"status": "ingested", "event_id": event.event_id, "violations_detected": len(violations)}

    @app.post("/api/v1/analytics/kql", response_model=KqlResponse, tags=["Warm-Path SIEM Engine"])
    def query_kql(req: KqlRequest):
        try:
            result = analytics_store.execute_kql(req.query)
            return KqlResponse(
                columns=result.columns,
                rows=result.rows,
                execution_time_ms=result.execution_time_ms,
                row_count=len(result.rows),
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"KQL Query Error: {e}")

    @app.get("/api/v1/analytics/stats", tags=["Warm-Path Analytics"])
    def get_analytics_stats():
        return {
            "events_count": analytics_store.row_count("events"),
            "graph_edges_count": analytics_store.row_count("graph_edges"),
            "drift_snapshots_count": analytics_store.row_count("drift_snapshots"),
            "motif_violations_count": analytics_store.row_count("motif_violations"),
        }

    # -----------------------------------------------------------------------
    # Visual Topology & ActionGraph
    # -----------------------------------------------------------------------

    @app.get("/api/v1/topology/mermaid", tags=["Visual Topology"])
    def get_mermaid_topology():
        model = AgentTopologyBuilder.build_topology(policy)
        return {"mermaid": model.to_mermaid()}

    @app.get("/api/v1/topology/react-flow", tags=["Visual Topology"])
    def get_react_flow_topology():
        model = AgentTopologyBuilder.build_topology(policy)
        return model.to_react_flow()

    @app.get("/api/v1/graph/{trace_id}", tags=["Visual Topology"])
    def get_trace_graph(trace_id: str):
        nodes = [n.model_dump() for n in action_graph.get_nodes(trace_id)]
        edges = [e.model_dump() for e in action_graph.get_edges(trace_id)]
        return {
            "trace_id": trace_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "is_dag": action_graph.is_dag(trace_id),
        }

    @app.get("/api/v1/graph/{trace_id}/motifs", tags=["Visual Topology"])
    def get_trace_motifs(trace_id: str):
        violations = motif_detector.scan_trace(action_graph.graph, trace_id=trace_id)
        return {
            "trace_id": trace_id,
            "violation_count": len(violations),
            "violations": [v.model_dump() for v in violations],
        }

    # -----------------------------------------------------------------------
    # Semantic Drift
    # -----------------------------------------------------------------------

    @app.post("/api/v1/drift/evaluate", tags=["Semantic Drift"])
    def evaluate_semantic_drift(req: DriftEvaluateRequest):
        res = drift_calc.evaluate_step(
            trace_id=req.trace_id,
            step_text=req.step_text,
            anchor_text=req.anchor_text,
            s_policy=req.s_policy,
            s_graph=req.s_graph,
            s_velocity=req.s_velocity,
            is_critical_policy_violation=req.is_critical_policy_violation,
        )
        # Ingest snapshot into DuckDB
        analytics_store.ingest_drift_snapshot(
            snapshot_id=f"drift-{req.trace_id}-{res.step_index}",
            trace_id=req.trace_id,
            step_index=res.step_index,
            drift_score=res.drift_score,
            classification=res.classification.value,
            policy_score=req.s_policy,
            graph_score=req.s_graph,
            velocity_score=req.s_velocity,
            semantic_score=res.drift_score,
            timestamp_utc=datetime.now(timezone.utc),
        )
        return res.model_dump()

    @app.get("/api/v1/drift/{trace_id}/trajectory", tags=["Semantic Drift"])
    def get_drift_trajectory(trace_id: str):
        points = drift_calc.get_trajectory(trace_id)
        return {
            "trace_id": trace_id,
            "step_count": len(points),
            "trajectory": [p.model_dump() for p in points],
        }

    # -----------------------------------------------------------------------
    # Anti-ASI09 Persuasion & HITL Review Gate
    # -----------------------------------------------------------------------

    @app.post("/api/v1/persuasion/classify", tags=["Anti-ASI09 Persuasion"])
    def classify_persuasion(req: PersuasionClassifyRequest):
        res = persuasion_clf.classify(req.text)
        return {
            "score": res.score,
            "is_flagged": res.is_flagged,
            "tactics": [t.value for t in res.tactics_detected],
            "spans": res.spans,
        }

    @app.get("/api/v1/hitl/tickets", tags=["HITL Governance"])
    def list_hitl_tickets():
        tickets = hitl_gate.list_pending()
        return {
            "pending_count": len(tickets),
            "tickets": [t.primary_view() for t in tickets],
        }

    @app.get("/api/v1/hitl/tickets/{ticket_id}", tags=["HITL Governance"])
    def get_hitl_ticket(ticket_id: str):
        ticket = hitl_gate.get_ticket(ticket_id)
        if ticket is None:
            raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found")
        return {
            "primary_deterministic_diff": ticket.primary_view(),
            "secondary_untrusted_rationale": ticket.secondary_view(),
        }

    @app.post("/api/v1/hitl/tickets/{ticket_id}/adjudicate", tags=["HITL Governance"])
    def adjudicate_hitl_ticket(ticket_id: str, req: HitlAdjudicateRequest):
        try:
            ticket = hitl_gate.adjudicate(
                ticket_id=ticket_id,
                decision=req.decision,
                reviewer_id=req.reviewer_id,
                justification=req.justification,
            )
            return {
                "status": "adjudicated",
                "ticket_id": ticket.ticket_id,
                "verdict": ticket.status.value,
                "reviewer_id": ticket.reviewer_id,
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    # -----------------------------------------------------------------------
    # Active Response & Kill Switches
    # -----------------------------------------------------------------------

    @app.get("/api/v1/response/kill-switch/status", tags=["Active Response"])
    def get_kill_switch_status():
        records = kill_switch.get_active_records()
        return {
            "active_count": len(records),
            "records": [r.model_dump() for r in records],
        }

    @app.post("/api/v1/response/kill-switch/trip", tags=["Active Response"])
    def trip_kill_switch(req: KillSwitchTripRequest):
        record = kill_switch.activate(
            scope=req.scope,
            target_id=req.target_id,
            reason=req.reason,
            triggered_by=req.triggered_by,
        )
        return {"status": "tripped", "record": record.model_dump()}

    @app.post("/api/v1/response/kill-switch/reset", tags=["Active Response"])
    def reset_kill_switch(req: KillSwitchResetRequest):
        deactivated = kill_switch.deactivate(scope=req.scope, target_id=req.target_id)
        return {"status": "reset", "deactivated": deactivated}

    return app
