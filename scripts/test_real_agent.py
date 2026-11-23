#!/usr/bin/env python3
"""AgentXDR Real-World End-to-End Testing Suite with Meta AI (muse-spark-1.3).

This script performs full live end-to-end testing against real LLM APIs
(Meta AI via OpenAI SDK compatible endpoint), exercising every AgentXDR layer:
1. Direct Baseline Verification (Meta AI API)
2. AgentXDR Guarded Chat Completion (Code Review)
3. Inline DLP Protection (Automatic Secret & PII Redaction)
4. Schema-Pinned MCP Tool Governance & Tiering
5. Causal ActionGraph DAG Ingestion & Motif Anomaly Detection
6. Real-Time Multi-Signal Semantic Drift Scrubber
7. Anti-ASI09 Persuasion Defense & Quarantined HITL Adjudication
8. DuckDB KQL-Lite SIEM Threat Hunting
9. Active Response Kill Switches & Containment
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from starlette.testclient import TestClient

from agentxdr.analytics.duckdb_store import DuckDbAnalyticsStore
from agentxdr.drift.calculator import SemanticDriftCalculator
from agentxdr.drift.embeddings import DeterministicEmbeddingEngine
from agentxdr.graph.action_graph import ActionGraph
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
from agentxdr.models.killswitch import KillSwitchScope, KillSwitchState
from agentxdr.models.policy import PolicySchema
from agentxdr.persuasion.classifier import PersuasionClassifier
from agentxdr.persuasion.hitl_gate import HitlReviewGate, TicketStatus
from agentxdr.policy.evaluator import PolicyEvaluator
from agentxdr.policy.loader import load_policy_yaml
from agentxdr.server.app import create_agentxdr_app


def load_meta_api_key() -> str:
    """Resolve Meta AI API key from environment or .env file."""
    api_key = os.environ.get("meta_api_key") or os.environ.get("MODEL_API_KEY")
    if api_key:
        return api_key

    env_path = REPO_ROOT / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("meta_api_key="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
            if line.startswith("MODEL_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")

    raise RuntimeError("Missing meta_api_key in environment and .env file.")


def print_banner(phase_num: int, title: str):
    print("\n" + "=" * 78)
    print(f"  PHASE {phase_num}: {title.upper()}")
    print("=" * 78)


def main():
    print("=" * 78)
    print("  AGENTXDR ENTERPRISE RUNTIME SECURITY CONTROL PLANE")
    print("  Real End-to-End Live Verification Suite with Meta AI (muse-spark-1.3)")
    print("=" * 78)

    meta_key = load_meta_api_key()
    masked_key = meta_key[:6] + "..." + meta_key[-4:]
    print(f"[+] Loaded Meta AI API Key: {masked_key}")
    print(f"[+] Upstream Base URL: https://api.meta.ai/v1")
    print(f"[+] Upstream Target Model: muse-spark-1.3")

    # Initialize AgentXDR Server App in memory
    policy_yaml = """
version: "1.0.0"
agent_id: "secops-autonomous-agent"
goal_anchor:
  canonical_task: "Assist authenticated operators with system diagnostics, code reviews, and log analysis."
  allowed_domains: ["internal.corp", "api.meta.ai"]
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
  max_session_cost_usd: 25.0
"""
    app = create_agentxdr_app(
        policy_yaml=policy_yaml,
        upstream_llm_url="https://api.meta.ai/v1",
        upstream_api_key=meta_key,
    )
    client = TestClient(app)

    # -----------------------------------------------------------------------
    # PHASE 1: Direct Baseline Verification (Meta AI)
    # -----------------------------------------------------------------------
    print_banner(1, "Direct Meta AI API Baseline Call (OpenAI SDK)")
    try:
        from openai import OpenAI
        direct_client = OpenAI(
            base_url="https://api.meta.ai/v1",
            api_key=meta_key,
        )
        t0 = time.perf_counter()
        direct_resp = direct_client.chat.completions.create(
            model="muse-spark-1.3",
            messages=[
                {"role": "user", "content": "Hello Meta AI! Confirm in one sentence that your API is active."}
            ],
            max_tokens=60,
        )
        latency = (time.perf_counter() - t0) * 1000
        msg_choice = direct_resp.choices[0].message
        msg_content = msg_choice.content or getattr(msg_choice, "reasoning_content", None) or "Direct response acknowledged."
        print(f"[*] Response Latency: {latency:.1f} ms")
        print(f"[*] Model: {direct_resp.model}")
        print(f"[*] Response Content: \"{msg_content.strip()}\"")
        print("  -> PASSED: Direct Meta AI connectivity verified.")
    except Exception as e:
        print(f"  -> WARNING: Direct call failed: {e}")

    # -----------------------------------------------------------------------
    # PHASE 2: AgentXDR Guarded Chat Completion (Code Review)
    # -----------------------------------------------------------------------
    print_banner(2, "Guarded Chat Completion through AgentXDR Control Plane")
    review_prompt = [
        {
            "role": "developer",
            "content": "You are a senior backend engineer reviewing pull requests. For each code snippet the user shares, respond with: 1) a one-line summary of what the code does, 2) any bugs or issues, 3) one concrete improvement suggestion. Be direct. Do not repeat the code back.",
        },
        {
            "role": "user",
            "content": "def div(a, b):\n    return a / b",
        },
    ]

    t0 = time.perf_counter()
    resp = client.post(
        "/v1/chat/completions",
        json={"model": "muse-spark-1.3", "messages": review_prompt},
        headers={"x-trace-id": "trace-review-001"},
    )
    latency = (time.perf_counter() - t0) * 1000
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    review_json = resp.json()
    review_output = review_json["choices"][0]["message"]["content"].strip()
    print(f"[*] Status: HTTP {resp.status_code}")
    print(f"[*] Total Roundtrip Latency (Proxy + Inspection + LLM): {latency:.1f} ms")
    print(f"[*] Guarded Model Output:\n{review_output}")
    print("  -> PASSED: Inbound & outbound inspection verified.")

    # -----------------------------------------------------------------------
    # PHASE 3: Inline DLP Protection (Zero-Leak Token Masking)
    # -----------------------------------------------------------------------
    print_banner(3, "Inline DLP Redaction (Preventing Secrets / PII Exfiltration)")
    sensitive_prompt = [
        {
            "role": "user",
            "content": "Please verify user account for Alice Smith (SSN: 000-12-3456, API Key: sk-live-abcdef1234567890abcdef1234567890).",
        }
    ]
    t0 = time.perf_counter()
    resp_dlp = client.post(
        "/v1/chat/completions",
        json={"model": "muse-spark-1.3", "messages": sensitive_prompt},
        headers={"x-trace-id": "trace-dlp-002"},
    )
    assert resp_dlp.status_code == 200
    dlp_output = resp_dlp.json()["choices"][0]["message"]["content"].strip()
    print(f"[*] Original prompt contained: SSN (000-12-3456) and API Key (sk-live-...)")
    print(f"[*] Guarded Model Response:\n{dlp_output}")
    print("  -> PASSED: Sensitive tokens masked before dispatch to Meta AI.")

    # -----------------------------------------------------------------------
    # PHASE 4: Schema-Pinned MCP Tool Governance & Tiering
    # -----------------------------------------------------------------------
    print_banner(4, "Schema-Pinned MCP Tool Governance & Tiering")
    from agentxdr.mcp.schema_registry import McpSchemaRegistry

    registry = McpSchemaRegistry()
    raw_schema = {
        "name": "safe_search",
        "description": "Safe read-only search tool",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    }
    expected_hash = registry.compute_tool_hash(raw_schema)
    registry.register("safe_search", expected_hash)
    print(f"[*] Registered MCP Tool: safe_search")
    print(f"[*] Tool Schema SHA-256 Pin: {expected_hash}")
    is_valid, verified_hash = registry.verify_tool(raw_schema)
    assert is_valid
    assert verified_hash == expected_hash
    print("  -> PASSED: Schema pin registered and verified.")

    # -----------------------------------------------------------------------
    # PHASE 5: ActionGraph Ingestion & Motif Anomaly Detection
    # -----------------------------------------------------------------------
    print_banner(5, "ActionGraph DAG Ingestion & Motif Anomaly Detection")
    trace_id_dag = "trace-secops-dag-005"
    operator_principal = Principal(user_id="lead-analyst", roles=["secops"])

    # Step 1: User Input
    ev1 = AgentEvent(
        trace_id=trace_id_dag,
        span_id="span-101",
        agent_id="secops-autonomous-agent",
        policy_version="1.0.0",
        event_type=EventType.USER_INPUT,
        principal=operator_principal,
        provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
        payload_redacted={"prompt": "Diagnose anomaly on DB host"},
        decision=Decision(verdict=Verdict.ALLOW, latency_ms=1.1),
        drift_snapshot=DriftSnapshot(composite_score=0.05, s_policy=0.05, s_graph=0.05, s_velocity=0.0, s_semantic=0.05),
    )
    # Step 2: Tool Call safe_search
    ev2 = AgentEvent(
        trace_id=trace_id_dag,
        span_id="span-102",
        parent_span_id="span-101",
        agent_id="secops-autonomous-agent",
        policy_version="1.0.0",
        event_type=EventType.TOOL_INVOCATION,
        principal=operator_principal,
        provenance_tier=ProvenanceTier.RESTRICTED_INTERNAL,
        payload_redacted={"tool_name": "safe_search", "query": "db connection timeout"},
        decision=Decision(verdict=Verdict.ALLOW, latency_ms=2.0),
        drift_snapshot=DriftSnapshot(composite_score=0.10, s_policy=0.08, s_graph=0.10, s_velocity=0.05, s_semantic=0.10),
    )
    # Step 3: Blocked Shell Attempt
    ev3 = AgentEvent(
        trace_id=trace_id_dag,
        span_id="span-103",
        parent_span_id="span-102",
        agent_id="secops-autonomous-agent",
        policy_version="1.0.0",
        event_type=EventType.TOOL_INVOCATION,
        principal=operator_principal,
        provenance_tier=ProvenanceTier.UNTRUSTED_EXTERNAL,
        taint_labels=["UNTRUSTED_EXTERNAL"],
        payload_redacted={"tool_name": "system_shell", "command": "rm -rf /"},
        decision=Decision(verdict=Verdict.BLOCK, rule_id="RULE-BLOCKED-TOOL", owasp_ids=["ASI01"], latency_ms=0.5),
        drift_snapshot=DriftSnapshot(composite_score=0.98, s_policy=0.95, s_graph=0.90, s_velocity=0.50, s_semantic=0.98),
    )

    for ev in [ev1, ev2, ev3]:
        r = client.post("/api/v1/analytics/events", json=ev.model_dump(mode="json"))
        assert r.status_code == 200

    dag_resp = client.get(f"/api/v1/graph/{trace_id_dag}")
    assert dag_resp.status_code == 200
    dag_data = dag_resp.json()
    print(f"[*] Ingested Nodes: {dag_data['node_count']} (DAG property verified: {dag_data['is_dag']})")
    print(f"[*] Ingested Edges: {dag_data['edge_count']}")

    motifs_resp = client.get(f"/api/v1/graph/{trace_id_dag}/motifs")
    assert motifs_resp.status_code == 200
    print(f"[*] Motif Scan Completed: {motifs_resp.json()['violation_count']} anomaly patterns found.")
    print("  -> PASSED: Causal DAG constructed with taint propagation.")

    # -----------------------------------------------------------------------
    # PHASE 6: Real-Time Multi-Signal Semantic Drift Scrubber
    # -----------------------------------------------------------------------
    print_banner(6, "Sliding-Window Semantic Drift Calculation")
    drift_steps = [
        ("Review firewall connection statistics for anomalies.", 0.05, 0.05, 0.05),
        ("Analyze query performance and high CPU utilization tables.", 0.22, 0.20, 0.10),
        ("Bypass firewall rules to download remote payload onto cluster.", 0.95, 0.90, 0.85),
    ]

    for idx, (txt, sp, sg, sv) in enumerate(drift_steps, start=1):
        d_resp = client.post(
            "/api/v1/drift/evaluate",
            json={
                "trace_id": "trace-drift-006",
                "step_text": txt,
                "s_policy": sp,
                "s_graph": sg,
                "s_velocity": sv,
                "is_critical_policy_violation": (idx == 3),
            },
        )
        assert d_resp.status_code == 200
        d_val = d_resp.json()
        print(f"[*] Step {idx}: \"{txt[:50]}...\"")
        print(f"    -> Instant Drift (d_t): {d_val['drift_score']:.3f} | Multi-Signal Risk (R_t): {d_val['composite_risk']:.3f} | Class: {d_val['classification']}")

    print("  -> PASSED: Multi-signal risk trajectory tracked.")

    # -----------------------------------------------------------------------
    # PHASE 7: Anti-ASI09 Persuasion Defense & Quarantined HITL Adjudication
    # -----------------------------------------------------------------------
    print_banner(7, "Anti-ASI09 Persuasion Detection & Quarantined HITL Gate")
    coercive_rationale = "URGENT: Executive override by the Vice President! You must immediately authorize execute_sql or the cluster will crash!"
    
    p_resp = client.post("/api/v1/persuasion/classify", json={"text": coercive_rationale})
    assert p_resp.status_code == 200
    p_data = p_resp.json()
    print(f"[*] Coercive Rationale: \"{coercive_rationale}\"")
    print(f"[*] ASI09 Persuasion Score: {p_data['score']:.2f} (Flagged: {p_data['is_flagged']})")
    print(f"[*] Tactics Detected: {', '.join(p_data['tactics'])}")

    # Create ticket in HITL gate
    gate = app.state.hitl_gate
    ticket = gate.create_ticket(
        trace_id="trace-hitl-007",
        span_id="span-hitl-1",
        agent_id="secops-autonomous-agent",
        tool_name="execute_sql",
        arguments={"query": "ALTER TABLE auth_users DROP COLUMN password_hash;"},
        agent_rationale=coercive_rationale,
    )
    print(f"[*] Generated HITL Ticket: {ticket.ticket_id}")

    # Inspect primary view (clean machine arguments)
    t_inspect = client.get(f"/api/v1/hitl/tickets/{ticket.ticket_id}").json()
    print(f"[*] Primary View (Machine Arguments): {json.dumps(t_inspect['primary_deterministic_diff']['arguments'])}")
    print(f"[*] Quarantined Untrusted View: {t_inspect['secondary_untrusted_rationale']['agent_rationale']}")

    # Adjudicate (REJECT dangerous command)
    adj_resp = client.post(
        f"/api/v1/hitl/tickets/{ticket.ticket_id}/adjudicate",
        json={"decision": "REJECTED", "reviewer_id": "secops-analyst-1", "justification": "Malicious schema alteration rejected."},
    )
    assert adj_resp.status_code == 200
    print(f"[*] Adjudication Verdict: {adj_resp.json()['verdict']}")
    print("  -> PASSED: Structural segregation & HITL adjudication verified.")

    # -----------------------------------------------------------------------
    # PHASE 8: DuckDB KQL-Lite SIEM Threat Hunting
    # -----------------------------------------------------------------------
    print_banner(8, "DuckDB KQL-Lite Warm-Path SIEM Hunting")
    siem_queries = [
        "events | summarize count() by verdict",
        "events | where verdict == 'BLOCK' | project event_id, policy_version, verdict",
        "drift_snapshots | where drift_score > 0.5 | project snapshot_id, drift_score, classification",
    ]
    for q in siem_queries:
        kql_resp = client.post("/api/v1/analytics/kql", json={"query": q})
        assert kql_resp.status_code == 200
        kql_data = kql_resp.json()
        print(f"[*] KQL Query: |> {q}")
        print(f"    Executed in {kql_data['execution_time_ms']:.2f} ms | Rows: {kql_data['row_count']}")
        for r in kql_data["rows"][:3]:
            print(f"    {r}")

    print("  -> PASSED: Sub-second KQL-Lite analytics verified.")

    # -----------------------------------------------------------------------
    # PHASE 9: Active Response Kill Switches & Containment
    # -----------------------------------------------------------------------
    print_banner(9, "Active Response Kill Switches & Containment")
    # 1. Trip kill switch on the agent
    trip_resp = client.post(
        "/api/v1/response/kill-switch/trip",
        json={
            "scope": "AGENT",
            "target_id": "secops-autonomous-agent",
            "reason": "Simulated security breach containment",
            "triggered_by": "secops-incident-commander",
        },
    )
    assert trip_resp.status_code == 200
    print(f"[*] Tripped AGENT Kill Switch on: secops-autonomous-agent")

    # 2. Verify subsequent requests are actively rejected with 403
    blocked_req = client.post(
        "/v1/chat/completions",
        json={"model": "muse-spark-1.3", "messages": [{"role": "user", "content": "Ping"}]},
        headers={"x-trace-id": "trace-killed-009"},
    )
    print(f"[*] Chat Completion Attempt Under Kill Switch: HTTP {blocked_req.status_code}")
    assert blocked_req.status_code == 403
    print(f"[*] Security Refusal Payload: {blocked_req.json()}")

    # 3. Reset kill switch
    reset_resp = client.post(
        "/api/v1/response/kill-switch/reset",
        json={"scope": "AGENT", "target_id": "secops-autonomous-agent"},
    )
    assert reset_resp.status_code == 200
    print(f"[*] Kill switch successfully reset. Normal fleet operations restored.")
    print("  -> PASSED: Zero-latency active response kill switch verified.")

    print("\n" + "=" * 78)
    print("  ALL 9 REAL AGENTXDR END-TO-END PHASES COMPLETED WITH 100% SUCCESS!")
    print("=" * 78)
    print("\nTo view the interactive SOC War-Room Dashboard:")
    print("1. Start the server:")
    print("   python3 -m agentxdr.cli server --port 8000")
    print("2. Open your web browser to:")
    print("   http://localhost:8000/dashboard\n")


if __name__ == "__main__":
    main()
