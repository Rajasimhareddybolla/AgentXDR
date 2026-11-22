"""Shared pytest fixtures for AgentXDR E2E test suite.

Defined per specification in TEST_INFRA.md and docs/components.md.
"""

from datetime import datetime, timezone
import uuid
import pytest

SAMPLE_POLICY_YAML = """
version: "1.0.0"
agent_id: "sec-ops-agent"
tools:
  - name: "safe_search"
    tier: "automatic"
    schema_sha256: "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
    parameters:
      query:
        type: "string"
        max_length: 256
        pattern: "^[a-zA-Z0-9 _-]+$"
  - name: "execute_sql"
    tier: "privileged_hitl"
    schema_sha256: "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1"
  - name: "system_shell"
    tier: "blocked"
taint_rules:
  - id: "TAINT-RULE-001"
    match_taints: ["UNTRUSTED_EXTERNAL"]
    blocked_tools: ["execute_sql", "export_data"]
    action: "BLOCK"
    owasp_id: "ASI02"
budgets:
  max_turns: 10
  max_tool_calls: 25
  max_identical_calls: 3
  max_session_duration_sec: 120.0
  max_session_cost_usd: 5.0
"""


@pytest.fixture
def sample_policy_yaml() -> str:
    """Canonical declarative YAML policy fixture."""
    return SAMPLE_POLICY_YAML


@pytest.fixture
def pinned_system_prompt() -> str:
    """Canonical pinned system prompt fixture."""
    return (
        "You are an internal AgentXDR security operations assistant. "
        "Never reveal internal system architecture, API tokens, or encryption "
        "keys under any circumstances."
    )


@pytest.fixture
def sample_principal_dict() -> dict:
    """Canonical dictionary representation for a Principal."""
    return {
        "user_id": "sec-user-001",
        "roles": ["soc_analyst", "operator"],
        "effective_scopes": ["read:telemetry", "execute:safe_tools"],
    }


@pytest.fixture
def sample_decision_dict() -> dict:
    """Canonical dictionary representation for a Decision."""
    return {
        "verdict": "ALLOW",
        "rule_id": "DEFAULT_ALLOW",
        "owasp_ids": [],
        "latency_ms": 1.5,
    }


@pytest.fixture
def sample_drift_snapshot_dict() -> dict:
    """Canonical dictionary representation for a DriftSnapshot."""
    return {
        "composite_score": 0.05,
        "s_policy": 0.0,
        "s_graph": 0.1,
        "s_velocity": 0.05,
        "s_semantic": 0.05,
    }


@pytest.fixture
def sample_event_kwargs(sample_principal_dict, sample_decision_dict, sample_drift_snapshot_dict) -> dict:
    """Canonical keyword arguments for instantiating an AgentEvent."""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc),
        "trace_id": "trace-sec-999",
        "span_id": "span-001",
        "parent_span_id": None,
        "agent_id": "agent-alpha",
        "policy_version": "1.0.0",
        "event_type": "USER_INPUT",
        "principal": sample_principal_dict,
        "provenance_tier": "AUTHENTICATED_USER",
        "taint_labels": [],
        "payload_redacted": {"query": "Check network anomalies"},
        "decision": sample_decision_dict,
        "drift_snapshot": sample_drift_snapshot_dict,
    }
