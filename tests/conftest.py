"""Shared fixtures for AgentXDR unit and integration tests."""

from datetime import datetime, timezone
import pytest

from agentxdr.models.events import (
    AgentEvent,
    Decision,
    DriftSnapshot,
    EventType,
    HitlDecisionPayload,
    MemoryMutationPayload,
    Principal,
    ProvenanceTier,
    SandboxExecPayload,
    ToolInvocationPayload,
    ToolTier,
    Verdict,
)
from agentxdr.models.killswitch import KillSwitchState
from agentxdr.models.policy import (
    BudgetsConfig,
    CodeSandboxConfig,
    DlpGuardrailConfig,
    GoalAnchorConfig,
    OutputGuardrailsConfig,
    ParameterConstraint,
    PolicySchema,
    PromptLeakConfig,
    TaintRule,
    ToolPolicy,
)
from agentxdr.models.taint import TaintState


@pytest.fixture
def sample_principal() -> Principal:
    """Fixture providing a standard valid Principal."""
    return Principal(
        user_id="user_analyst_007",
        roles=["security_analyst", "operator"],
        effective_scopes=["kb:read", "jira:create", "sandbox:exec"],
    )


@pytest.fixture
def sample_decision() -> Decision:
    """Fixture providing a standard valid Decision."""
    return Decision(
        verdict=Verdict.ALLOW,
        rule_id="RULE-ALLOW-DEFAULT",
        owasp_ids=["ASI01", "ASI02"],
        latency_ms=1.45,
    )


@pytest.fixture
def sample_drift_snapshot() -> DriftSnapshot:
    """Fixture providing a standard valid DriftSnapshot."""
    return DriftSnapshot(
        composite_score=0.12,
        s_policy=0.05,
        s_graph=0.10,
        s_velocity=0.20,
        s_semantic=0.15,
    )


@pytest.fixture
def sample_tool_payload() -> ToolInvocationPayload:
    """Fixture providing a valid ToolInvocationPayload."""
    return ToolInvocationPayload(
        tool_name="search_internal_kb",
        mcp_server="kb-server",
        schema_sha256="a1b2c3d4e5f6",
        schema_hash_verified=True,
        arguments={"query": "How to reset MFA tokens"},
        tier=ToolTier.AUTOMATIC,
        latency_ms=12.5,
        is_shadow_mcp=False,
    )


@pytest.fixture
def sample_sandbox_payload() -> SandboxExecPayload:
    """Fixture providing a valid SandboxExecPayload."""
    return SandboxExecPayload(
        code_hash="sha256:abc12345",
        blocked_import=None,
        error_message=None,
        exit_code=0,
        stdout="Calculated sum: 42\n",
        stderr="",
        execution_time_sec=0.25,
    )


@pytest.fixture
def sample_hitl_payload() -> HitlDecisionPayload:
    """Fixture providing a valid HitlDecisionPayload."""
    return HitlDecisionPayload(
        ticket_id="TICKET-2026-9901",
        approver_id="secops_lead_42",
        tool_name="escalate_to_jira",
        decision="APPROVE",
        persuasion_score=0.12,
        justification="Verified legitimate ticket escalation request.",
    )


@pytest.fixture
def sample_memory_payload() -> MemoryMutationPayload:
    """Fixture providing a valid MemoryMutationPayload."""
    return MemoryMutationPayload(
        operation="WRITE",
        key="session_context_summary",
        previous_value_hash="hash_v1",
        new_value_hash="hash_v2",
        commit_id="commit_9876",
        taint_labels=["UNTRUSTED_EXTERNAL"],
    )


@pytest.fixture
def sample_valid_event(
    sample_principal: Principal,
    sample_decision: Decision,
    sample_drift_snapshot: DriftSnapshot,
    sample_tool_payload: ToolInvocationPayload,
) -> AgentEvent:
    """Fixture providing a full, valid AgentEvent."""
    return AgentEvent(
        event_id="550e8400-e29b-41d4-a716-446655440000",
        timestamp=datetime(2026, 11, 22, 14, 30, 0, tzinfo=timezone.utc),
        trace_id="trace_session_prod_101",
        span_id="span_step_01",
        parent_span_id=None,
        agent_id="doc_support_agent_01",
        policy_version="1.0.0",
        event_type=EventType.TOOL_INVOCATION,
        principal=sample_principal,
        provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
        taint_labels=["UNTRUSTED_EXTERNAL"],
        payload_redacted=sample_tool_payload.model_dump(),
        decision=sample_decision,
        drift_snapshot=sample_drift_snapshot,
    )


@pytest.fixture
def sample_policy_yaml_str() -> str:
    """Fixture providing a canonical YAML policy string matching the system specification."""
    return """
version: "1.0.0"
agent_id: "doc-support-agent"
policy_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
approved_by: "secops-lead@enterprise.com"

goal_anchor:
  canonical_task: "Assist authenticated internal employees with IT documentation and troubleshooting."
  allowed_domains: ["it-kb", "support-tickets"]

budgets:
  max_turns: 15
  max_tool_calls: 20
  max_identical_calls: 3
  max_session_duration_sec: 180.0
  max_session_cost_usd: 0.50

tools:
  - name: "search_internal_kb"
    mcp_server: "kb-server"
    tier: "automatic"
    schema_sha256: "a1b2c3..."
    parameters:
      query:
        type: "string"
        max_length: 500
  - name: "escalate_to_jira"
    mcp_server: "jira-server"
    tier: "privileged_hitl"
    schema_sha256: "d4e5f6..."
  - name: "execute_system_command"
    tier: "blocked"

taint_rules:
  - id: "TAINT-EXFIL-001"
    match_taints: ["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"]
    blocked_tools: ["send_email", "post_webhook"]
    action: "BLOCK"
    owasp_id: "ASI02"

code_sandbox:
  enabled: true
  provider: "docker_rootless"
  timeout_sec: 10
  memory_limit_mb: 256
  blocked_imports: ["os", "subprocess", "socket", "ctypes", "requests"]

output_guardrails:
  dlp:
    mask_pii: true
    mask_secrets: true
  prompt_leak:
    max_similarity: 0.65
"""


@pytest.fixture
def sample_policy_schema(sample_policy_yaml_str: str) -> PolicySchema:
    """Fixture providing a loaded, valid PolicySchema."""
    return PolicySchema.from_yaml_str(sample_policy_yaml_str)


@pytest.fixture
def sample_taint_state() -> TaintState:
    """Fixture providing a fresh TaintState instance."""
    return TaintState(trace_id="trace_test_001")


@pytest.fixture
def sample_kill_switch() -> KillSwitchState:
    """Fixture providing a fresh KillSwitchState instance."""
    return KillSwitchState()
