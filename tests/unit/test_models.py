"""Comprehensive unit tests for AgentXDR core models, event schemas, policy, taint, and kill switch."""

import concurrent.futures
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from pydantic import ValidationError

from agentxdr.models.events import (
    AgentCommPayload,
    AgentEvent,
    Decision,
    DriftSnapshot,
    EventType,
    HitlDecisionPayload,
    LlmGenerationPayload,
    MemoryMutationPayload,
    Principal,
    ProvenanceTier,
    RagAccessPayload,
    ResponseActionPayload,
    SandboxExecPayload,
    ToolInvocationPayload,
    ToolTier,
    UserInputPayload,
    Verdict,
)
from agentxdr.models.killswitch import (
    KillSwitchRecord,
    KillSwitchScope,
    KillSwitchState,
)
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


# ===========================================================================
# 1. Enum Tests
# ===========================================================================


class TestEnums:
    """Verify all canonical enumerations match the specification."""

    def test_all_event_types(self) -> None:
        expected = {
            "USER_INPUT",
            "LLM_GENERATION",
            "RAG_ACCESS",
            "MEMORY_MUTATION",
            "TOOL_INVOCATION",
            "AGENT_COMM",
            "SANDBOX_EXEC",
            "HITL_DECISION",
            "RESPONSE_ACTION",
        }
        actual = {e.value for e in EventType}
        assert actual == expected
        assert len(EventType) == 9

    def test_all_provenance_tiers(self) -> None:
        expected = {
            "TRUSTED_SYSTEM",
            "AUTHENTICATED_USER",
            "RESTRICTED_INTERNAL",
            "VERIFIED_MEMORY",
            "UNTRUSTED_EXTERNAL",
        }
        actual = {p.value for p in ProvenanceTier}
        assert actual == expected
        assert len(ProvenanceTier) == 5

    def test_all_verdicts(self) -> None:
        expected = {
            "ALLOW",
            "MASK_AND_ALLOW",
            "PAUSE_FOR_HITL",
            "BLOCK",
            "KILL",
        }
        actual = {v.value for v in Verdict}
        assert actual == expected
        assert len(Verdict) == 5

    def test_all_tool_tiers(self) -> None:
        expected = {
            "automatic",
            "privileged_hitl",
            "blocked",
        }
        actual = {t.value for t in ToolTier}
        assert actual == expected
        assert len(ToolTier) == 3

    def test_all_killswitch_scopes(self) -> None:
        expected = {
            "GLOBAL",
            "AGENT",
            "SESSION",
            "TOOL",
            "MCP_SERVER",
        }
        actual = {s.value for s in KillSwitchScope}
        assert actual == expected
        assert len(KillSwitchScope) == 5


# ===========================================================================
# 2. Principal Model Tests
# ===========================================================================


class TestPrincipal:
    """Verify Principal sub-model constraints and immutability."""

    def test_valid_principal(self) -> None:
        p = Principal(
            user_id="user_123",
            roles=["analyst"],
            effective_scopes=["read:data"],
        )
        assert p.user_id == "user_123"
        assert p.roles == ["analyst"]
        assert p.effective_scopes == ["read:data"]

    def test_principal_defaults(self) -> None:
        p = Principal(user_id="user_simple")
        assert p.roles == []
        assert p.effective_scopes == []

    def test_principal_empty_user_id_rejected(self) -> None:
        with pytest.raises(ValidationError, match="user_id must be a non-empty string"):
            Principal(user_id="")

        with pytest.raises(ValidationError, match="user_id must be a non-empty string"):
            Principal(user_id="   ")

    def test_principal_frozen(self, sample_principal: Principal) -> None:
        with pytest.raises(ValidationError):
            sample_principal.user_id = "new_user"  # type: ignore

    def test_principal_extra_forbid(self) -> None:
        with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs are not permitted"):
            Principal(user_id="valid_user", unexpected_field="malicious")  # type: ignore


# ===========================================================================
# 3. Decision Model Tests
# ===========================================================================


class TestDecision:
    """Verify Decision sub-model constraints and validation."""

    def test_valid_decision(self, sample_decision: Decision) -> None:
        assert sample_decision.verdict == Verdict.ALLOW
        assert sample_decision.latency_ms == 1.45
        assert "ASI01" in sample_decision.owasp_ids

    def test_decision_negative_latency_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Decision(verdict=Verdict.ALLOW, latency_ms=-0.1)

    def test_decision_frozen(self, sample_decision: Decision) -> None:
        with pytest.raises(ValidationError):
            sample_decision.verdict = Verdict.BLOCK  # type: ignore

    def test_decision_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            Decision(verdict=Verdict.ALLOW, latency_ms=1.0, extra_prop="forbid_me")  # type: ignore


# ===========================================================================
# 4. DriftSnapshot Model Tests
# ===========================================================================


class TestDriftSnapshot:
    """Verify composite drift risk scoring snapshot validation."""

    def test_valid_drift_snapshot(self, sample_drift_snapshot: DriftSnapshot) -> None:
        assert sample_drift_snapshot.composite_score == 0.12
        assert sample_drift_snapshot.s_policy == 0.05
        assert sample_drift_snapshot.s_graph == 0.10
        assert sample_drift_snapshot.s_velocity == 0.20
        assert sample_drift_snapshot.s_semantic == 0.15

    def test_drift_score_bounds_rejection(self) -> None:
        with pytest.raises(ValidationError):
            DriftSnapshot(
                composite_score=1.5,  # > 1.0
                s_policy=0.1,
                s_graph=0.1,
                s_velocity=0.1,
                s_semantic=0.1,
            )

        with pytest.raises(ValidationError):
            DriftSnapshot(
                composite_score=-0.1,  # < 0.0
                s_policy=0.1,
                s_graph=0.1,
                s_velocity=0.1,
                s_semantic=0.1,
            )

    def test_drift_snapshot_frozen(self, sample_drift_snapshot: DriftSnapshot) -> None:
        with pytest.raises(ValidationError):
            sample_drift_snapshot.composite_score = 0.99  # type: ignore

    def test_drift_snapshot_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            DriftSnapshot(
                composite_score=0.5,
                s_policy=0.5,
                s_graph=0.5,
                s_velocity=0.5,
                s_semantic=0.5,
                anomaly_flag=True,  # type: ignore
            )


# ===========================================================================
# 5. Specialized Payloads Tests
# ===========================================================================


class TestSpecializedPayloads:
    """Verify strongly-typed schemas for event payloads."""

    def test_tool_invocation_payload(self) -> None:
        payload = ToolInvocationPayload(
            tool_name="query_db",
            mcp_server="sql-proxy",
            schema_sha256="abc12345",
            schema_hash_verified=True,
            arguments={"query": "SELECT 1"},
            tier=ToolTier.AUTOMATIC,
            latency_ms=5.2,
            is_shadow_mcp=False,
        )
        assert payload.tool_name == "query_db"
        assert payload.arguments == {"query": "SELECT 1"}

        # Empty tool_name rejected
        with pytest.raises(ValidationError, match="tool_name must be a non-empty string"):
            ToolInvocationPayload(tool_name="")

        # Extra forbidden
        with pytest.raises(ValidationError):
            ToolInvocationPayload(tool_name="q", malicious="yes")  # type: ignore

    def test_sandbox_exec_payload(self) -> None:
        payload = SandboxExecPayload(
            code_hash="sha256:111222",
            blocked_import="os",
            error_message="Import 'os' is blocked",
            exit_code=1,
            stdout="",
            stderr="ImportError",
            execution_time_sec=0.05,
        )
        assert payload.blocked_import == "os"
        assert payload.exit_code == 1

        with pytest.raises(ValidationError):
            SandboxExecPayload(code_hash="c", execution_time_sec=-1.0)

    def test_hitl_decision_payload(self) -> None:
        payload = HitlDecisionPayload(
            ticket_id="TICKET-01",
            approver_id="user_admin",
            tool_name="transfer_funds",
            decision="APPROVE",
            persuasion_score=0.45,
            justification="Pre-approved batch payment",
        )
        assert payload.decision == "APPROVE"

        # Invalid decision literal
        with pytest.raises(ValidationError):
            HitlDecisionPayload(
                ticket_id="T-01",
                approver_id="admin",
                tool_name="t",
                decision="MAYBE",  # type: ignore
            )

        # Invalid persuasion score bounds
        with pytest.raises(ValidationError):
            HitlDecisionPayload(
                ticket_id="T-01",
                approver_id="admin",
                tool_name="t",
                decision="DENY",
                persuasion_score=1.5,
            )

    def test_memory_mutation_payload(self) -> None:
        payload = MemoryMutationPayload(
            operation="ROLLBACK",
            key="user_intent",
            previous_value_hash="hash_a",
            new_value_hash=None,
            commit_id="commit_456",
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        assert payload.operation == "ROLLBACK"
        assert payload.taint_labels == ["UNTRUSTED_EXTERNAL"]

        with pytest.raises(ValidationError):
            MemoryMutationPayload(
                operation="DELETE",  # type: ignore
                key="k",
                commit_id="c",
            )

    def test_user_input_payload(self) -> None:
        payload = UserInputPayload(user_input_redacted="Hello [REDACTED_EMAIL]", token_count=10)
        assert payload.token_count == 10

        with pytest.raises(ValidationError):
            UserInputPayload(user_input_redacted="test", token_count=-5)

    def test_llm_generation_payload(self) -> None:
        payload = LlmGenerationPayload(
            generation_redacted="Response text",
            model_name="gpt-4o",
            token_count=120,
            prompt_leakage_detected=False,
        )
        assert payload.model_name == "gpt-4o"
        assert not payload.prompt_leakage_detected

    def test_rag_access_payload(self) -> None:
        payload = RagAccessPayload(
            document_ids=["doc_1", "doc_2"],
            query="financial reports 2026",
            chunks_retrieved=4,
            taint_labels=["CONFIDENTIAL_RAG"],
        )
        assert payload.chunks_retrieved == 4

    def test_agent_comm_payload(self) -> None:
        payload = AgentCommPayload(
            message_id="msg_001",
            sender_agent_id="agent_a",
            receiver_agent_id="agent_b",
            action="delegate_analysis",
            signature_verified=True,
        )
        assert payload.signature_verified is True

    def test_response_action_payload(self) -> None:
        payload = ResponseActionPayload(
            response_type="FINAL_COMPLETION",
            details={"rendered_markdown": True},
        )
        assert payload.response_type == "FINAL_COMPLETION"


# ===========================================================================
# 6. AgentEvent Model Tests
# ===========================================================================


class TestAgentEvent:
    """Verify canonical AgentEvent envelope immutability, schema strictness, and serialization."""

    def test_agent_event_instantiation(self, sample_valid_event: AgentEvent) -> None:
        assert sample_valid_event.trace_id == "trace_session_prod_101"
        assert sample_valid_event.span_id == "span_step_01"
        assert sample_valid_event.parent_span_id is None
        assert sample_valid_event.event_type == EventType.TOOL_INVOCATION
        assert sample_valid_event.provenance_tier == ProvenanceTier.AUTHENTICATED_USER
        assert sample_valid_event.taint_labels == ["UNTRUSTED_EXTERNAL"]
        assert sample_valid_event.decision.verdict == Verdict.ALLOW

    def test_agent_event_defaults(
        self,
        sample_principal: Principal,
        sample_decision: Decision,
        sample_drift_snapshot: DriftSnapshot,
    ) -> None:
        event = AgentEvent(
            trace_id="trace_auto",
            span_id="span_auto",
            agent_id="agent_auto",
            policy_version="1.0.0",
            event_type=EventType.USER_INPUT,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            decision=sample_decision,
            drift_snapshot=sample_drift_snapshot,
        )
        assert event.event_id is not None
        assert len(event.event_id) > 0
        assert event.timestamp is not None
        assert event.timestamp.tzinfo is not None
        assert event.taint_labels == []
        assert event.payload_redacted == {}

    def test_agent_event_frozen(self, sample_valid_event: AgentEvent) -> None:
        with pytest.raises(ValidationError):
            sample_valid_event.trace_id = "new_trace"  # type: ignore

        with pytest.raises(ValidationError):
            sample_valid_event.taint_labels = ["NEW_TAINT"]  # type: ignore

        with pytest.raises(ValidationError):
            sample_valid_event.decision = Decision(verdict=Verdict.BLOCK, latency_ms=0.0)  # type: ignore

    def test_agent_event_extra_forbid(
        self,
        sample_principal: Principal,
        sample_decision: Decision,
        sample_drift_snapshot: DriftSnapshot,
    ) -> None:
        with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs are not permitted"):
            AgentEvent(
                trace_id="t",
                span_id="s",
                agent_id="a",
                policy_version="1.0",
                event_type=EventType.USER_INPUT,
                principal=sample_principal,
                provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
                decision=sample_decision,
                drift_snapshot=sample_drift_snapshot,
                unexpected_payload_field=123,  # type: ignore
            )

    def test_agent_event_empty_identifiers_rejected(
        self,
        sample_principal: Principal,
        sample_decision: Decision,
        sample_drift_snapshot: DriftSnapshot,
    ) -> None:
        with pytest.raises(ValidationError, match="trace_id must be a non-empty string"):
            AgentEvent(
                trace_id="",
                span_id="s",
                agent_id="a",
                policy_version="1.0",
                event_type=EventType.USER_INPUT,
                principal=sample_principal,
                provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
                decision=sample_decision,
                drift_snapshot=sample_drift_snapshot,
            )

    def test_agent_event_json_serialization_roundtrip(self, sample_valid_event: AgentEvent) -> None:
        json_data = sample_valid_event.model_dump_json()
        assert isinstance(json_data, str)
        assert "trace_session_prod_101" in json_data
        assert "TOOL_INVOCATION" in json_data
        assert "search_internal_kb" in json_data

        restored = AgentEvent.model_validate_json(json_data)
        assert restored == sample_valid_event
        assert restored.event_id == sample_valid_event.event_id
        assert restored.timestamp == sample_valid_event.timestamp
        assert restored.decision.verdict == sample_valid_event.decision.verdict
        assert restored.drift_snapshot.composite_score == sample_valid_event.drift_snapshot.composite_score


# ===========================================================================
# 7. Policy Schema & Validation Tests
# ===========================================================================


class TestPolicySchema:
    """Verify declarative PolicySchema, parameter constraints, budget limits, and hash calculation."""

    def test_policy_loading_from_yaml_str(self, sample_policy_yaml_str: str) -> None:
        policy = PolicySchema.from_yaml_str(sample_policy_yaml_str)
        assert policy.version == "1.0.0"
        assert policy.agent_id == "doc-support-agent"
        assert policy.approved_by == "secops-lead@enterprise.com"
        assert policy.budgets.max_turns == 15
        assert policy.budgets.max_tool_calls == 20
        assert policy.budgets.max_identical_calls == 3
        assert policy.budgets.max_session_duration_sec == 180.0
        assert policy.budgets.max_session_cost_usd == 0.50
        assert len(policy.tools) == 3
        assert len(policy.taint_rules) == 1
        assert policy.code_sandbox is not None
        assert policy.code_sandbox.enabled is True
        assert "os" in policy.code_sandbox.blocked_imports
        assert policy.output_guardrails is not None
        assert policy.output_guardrails.dlp.mask_pii is True
        assert policy.output_guardrails.prompt_leak.max_similarity == 0.65

    def test_policy_loading_from_yaml_file(self, tmp_path: Path, sample_policy_yaml_str: str) -> None:
        policy_file = tmp_path / "test_policy.yaml"
        policy_file.write_text(sample_policy_yaml_str, encoding="utf-8")

        policy = PolicySchema.from_yaml_file(policy_file)
        assert policy.agent_id == "doc-support-agent"
        assert len(policy.tools) == 3

    def test_policy_file_not_found_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            PolicySchema.from_yaml_file("/non/existent/path/policy.yaml")

    def test_policy_invalid_yaml_root_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid YAML policy"):
            PolicySchema.from_yaml_str("- just\n- a\n- list")

    def test_budget_constraints_validation(self) -> None:
        # max_turns <= 0
        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=0,
                max_tool_calls=10,
                max_identical_calls=2,
                max_session_duration_sec=60.0,
                max_session_cost_usd=1.0,
            )

        # max_session_cost_usd <= 0
        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=10,
                max_tool_calls=10,
                max_identical_calls=2,
                max_session_duration_sec=60.0,
                max_session_cost_usd=0.0,
            )

    def test_duplicate_tools_rejected(self) -> None:
        yaml_with_duplicate_tools = """
version: "1.0.0"
agent_id: "test-agent"
budgets:
  max_turns: 5
  max_tool_calls: 5
  max_identical_calls: 2
  max_session_duration_sec: 30
  max_session_cost_usd: 0.10
tools:
  - name: "search_kb"
    tier: "automatic"
  - name: "search_kb"
    tier: "privileged_hitl"
"""
        with pytest.raises(ValidationError, match="Duplicate tool definitions found"):
            PolicySchema.from_yaml_str(yaml_with_duplicate_tools)

    def test_parameter_constraints_validation(self) -> None:
        valid_constraint = ParameterConstraint(type="string", max_length=100, pattern=r"^[A-Z]+$")
        assert valid_constraint.max_length == 100

        with pytest.raises(ValidationError):
            ParameterConstraint(type="string", max_length=-1)

    def test_policy_canonical_sha256_hash_computation(self, sample_policy_yaml_str: str) -> None:
        policy = PolicySchema.from_yaml_str(sample_policy_yaml_str)
        hash_1 = policy.compute_policy_hash()
        hash_2 = policy.compute_policy_hash()

        assert hash_1.startswith("sha256:")
        assert len(hash_1) == 7 + 64
        # Hash is deterministic
        assert hash_1 == hash_2

        # Verify hash match logic
        policy_with_matching_hash = policy.model_copy(update={"policy_hash": hash_1})
        assert policy_with_matching_hash.verify_hash() is True

        policy_with_wrong_hash = policy.model_copy(update={"policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"})
        assert policy_with_wrong_hash.verify_hash() is False

    def test_tool_policy_name_whitespace_normalized(self) -> None:
        tp = ToolPolicy(name="  execute_code  ", tier=ToolTier.AUTOMATIC)
        assert tp.name == "execute_code"


# ===========================================================================
# 8. TaintState Model & State Machine Tests
# ===========================================================================


class TestTaintState:
    """Verify monotonic session taint accumulation and rule matching."""

    def test_taint_initialization(self, sample_taint_state: TaintState) -> None:
        assert sample_taint_state.trace_id == "trace_test_001"
        assert len(sample_taint_state) == 0
        assert sample_taint_state.to_list() == []

    def test_empty_trace_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="trace_id must be a non-empty string"):
            TaintState(trace_id="")

        with pytest.raises(ValueError, match="trace_id must be a non-empty string"):
            TaintState(trace_id="   ")

    def test_monotonic_taint_addition(self, sample_taint_state: TaintState) -> None:
        sample_taint_state.add_taint("UNTRUSTED_EXTERNAL")
        assert sample_taint_state.has_taint("UNTRUSTED_EXTERNAL")
        assert "UNTRUSTED_EXTERNAL" in sample_taint_state
        assert len(sample_taint_state) == 1

        sample_taint_state.add_taint("CONFIDENTIAL_RAG")
        assert len(sample_taint_state) == 2
        assert sample_taint_state.to_list() == ["CONFIDENTIAL_RAG", "UNTRUSTED_EXTERNAL"]

    def test_taint_addition_idempotency(self, sample_taint_state: TaintState) -> None:
        sample_taint_state.add_taint("CONTAINS_PII")
        sample_taint_state.add_taint("CONTAINS_PII")
        sample_taint_state.add_taint("CONTAINS_PII")

        assert len(sample_taint_state) == 1
        assert sample_taint_state.to_list() == ["CONTAINS_PII"]

    def test_bulk_taint_addition(self, sample_taint_state: TaintState) -> None:
        sample_taint_state.add_taints(["UNTRUSTED_EXTERNAL", "SUSPECTED_INJECTION", "UNTRUSTED_EXTERNAL"])
        assert len(sample_taint_state) == 2
        assert sample_taint_state.has_taint("UNTRUSTED_EXTERNAL")
        assert sample_taint_state.has_taint("SUSPECTED_INJECTION")

    def test_empty_taint_label_rejected(self, sample_taint_state: TaintState) -> None:
        with pytest.raises(ValueError, match="Taint label must be a non-empty string"):
            sample_taint_state.add_taint("")

        with pytest.raises(ValueError, match="Taint label must be a non-empty string"):
            sample_taint_state.add_taint("   ")

    def test_taint_rule_matching_subset(self, sample_taint_state: TaintState) -> None:
        rule_taints = ["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"]

        # Initially empty: should not match
        assert sample_taint_state.matches_rule(rule_taints) is False

        # Only one taint present (partial): should not match
        sample_taint_state.add_taint("UNTRUSTED_EXTERNAL")
        assert sample_taint_state.matches_rule(rule_taints) is False

        # Both taints present (exact subset): should match
        sample_taint_state.add_taint("CONFIDENTIAL_RAG")
        assert sample_taint_state.matches_rule(rule_taints) is True

        # Superset of taints present: should still match
        sample_taint_state.add_taint("CONTAINS_PII")
        assert sample_taint_state.matches_rule(rule_taints) is True

    def test_taint_rule_matching_empty_rule(self, sample_taint_state: TaintState) -> None:
        sample_taint_state.add_taint("UNTRUSTED_EXTERNAL")
        assert sample_taint_state.matches_rule([]) is False

    def test_concurrent_taint_addition_thread_safety(self) -> None:
        state = TaintState(trace_id="trace_concurrent")

        def add_batch(prefix: str, count: int) -> None:
            for i in range(count):
                state.add_taint(f"{prefix}_{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(add_batch, f"thread_{t}", 50) for t in range(8)]
            concurrent.futures.wait(futures)

        assert len(state) == 400

    def test_taint_self_equality_no_deadlock(self, sample_taint_state: TaintState) -> None:
        sample_taint_state.add_taint("UNTRUSTED")
        assert sample_taint_state == sample_taint_state
        assert sample_taint_state in [sample_taint_state]
        assert not (sample_taint_state != sample_taint_state)

    def test_taint_concurrent_cross_thread_equality_no_deadlock(self) -> None:
        t1 = TaintState("trace_shared", ["A", "B"])
        t2 = TaintState("trace_shared", ["B", "A"])

        def compare_forward() -> None:
            for _ in range(500):
                assert t1 == t2

        def compare_reverse() -> None:
            for _ in range(500):
                assert t2 == t1

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(compare_forward if i % 2 == 0 else compare_reverse)
                for i in range(8)
            ]
            concurrent.futures.wait(futures, timeout=5.0)
            for f in futures:
                f.result()


# ===========================================================================
# 9. KillSwitch Hierarchy & State Tests
# ===========================================================================


class TestKillSwitch:
    """Verify hierarchical multi-granularity kill switches and TTL expiration."""

    def test_killswitch_record_creation(self) -> None:
        record = KillSwitchRecord(
            scope=KillSwitchScope.TOOL,
            target_id="send_email",
            reason="Exfiltration detected",
            triggered_by="secops_operator",
            ttl_seconds=300,
        )
        assert record.scope == KillSwitchScope.TOOL
        assert record.target_id == "send_email"
        assert record.ttl_seconds == 300
        assert record.is_expired() is False

    def test_killswitch_record_ttl_expiration(self) -> None:
        past_time = datetime.now(timezone.utc) - timedelta(seconds=20)
        record = KillSwitchRecord(
            scope=KillSwitchScope.SESSION,
            target_id="trace_123",
            reason="Malicious loop",
            triggered_by="circuit_breaker",
            created_at=past_time,
            ttl_seconds=10,
        )
        assert record.is_expired() is True

    def test_killswitch_global_scope_hierarchy(self, sample_kill_switch: KillSwitchState) -> None:
        assert sample_kill_switch.is_killed(agent_id="agent_1", trace_id="trace_1", tool_name="tool_1") is False

        # Activate GLOBAL kill switch
        sample_kill_switch.activate(
            scope=KillSwitchScope.GLOBAL,
            target_id="*",
            reason="Enterprise red alert",
            triggered_by="ciso",
        )

        # Everything is killed under GLOBAL
        assert sample_kill_switch.is_killed(agent_id="agent_1", trace_id="trace_1", tool_name="tool_1") is True
        assert sample_kill_switch.is_killed(agent_id="agent_2", trace_id="trace_2") is True

    def test_killswitch_agent_scope_hierarchy(self, sample_kill_switch: KillSwitchState) -> None:
        sample_kill_switch.activate(
            scope=KillSwitchScope.AGENT,
            target_id="agent_compromised",
            reason="Agent jailbroken",
            triggered_by="drift_monitor",
        )

        # Compromised agent is killed across all traces and tools
        assert sample_kill_switch.is_killed(agent_id="agent_compromised", trace_id="trace_any") is True
        assert sample_kill_switch.is_killed(agent_id="agent_compromised", trace_id="trace_any", tool_name="read_kb") is True

        # Unaffected agent is NOT killed
        assert sample_kill_switch.is_killed(agent_id="agent_healthy", trace_id="trace_any") is False

    def test_killswitch_session_scope_hierarchy(self, sample_kill_switch: KillSwitchState) -> None:
        sample_kill_switch.activate(
            scope=KillSwitchScope.SESSION,
            target_id="trace_bad_session",
            reason="Prompt injection payload",
            triggered_by="dlp_engine",
        )

        # That specific session is killed
        assert sample_kill_switch.is_killed(agent_id="agent_1", trace_id="trace_bad_session") is True

        # Other sessions on same agent are NOT killed
        assert sample_kill_switch.is_killed(agent_id="agent_1", trace_id="trace_good_session") is False

    def test_killswitch_tool_scope_hierarchy(self, sample_kill_switch: KillSwitchState) -> None:
        sample_kill_switch.activate(
            scope=KillSwitchScope.TOOL,
            target_id="dangerous_exec",
            reason="CVE in tool dependency",
            triggered_by="supply_chain_monitor",
        )

        # Targeted tool is killed
        assert sample_kill_switch.is_killed(agent_id="agent_1", trace_id="trace_1", tool_name="dangerous_exec") is True

        # Other tools on same agent are NOT killed
        assert sample_kill_switch.is_killed(agent_id="agent_1", trace_id="trace_1", tool_name="safe_read") is False

    def test_killswitch_mcp_server_scope_hierarchy(self, sample_kill_switch: KillSwitchState) -> None:
        sample_kill_switch.activate(
            scope=KillSwitchScope.MCP_SERVER,
            target_id="compromised-mcp-server",
            reason="Server authentication failure",
            triggered_by="mcp_proxy",
        )

        # Targeted MCP server is killed
        assert sample_kill_switch.is_killed(
            agent_id="agent_1",
            trace_id="trace_1",
            mcp_server="compromised-mcp-server",
        ) is True

        # Safe MCP server is NOT killed
        assert sample_kill_switch.is_killed(
            agent_id="agent_1",
            trace_id="trace_1",
            mcp_server="safe-mcp-server",
        ) is False

    def test_killswitch_deactivation(self, sample_kill_switch: KillSwitchState) -> None:
        sample_kill_switch.activate(
            scope=KillSwitchScope.TOOL,
            target_id="temp_tool",
            reason="Maintenance",
            triggered_by="admin",
        )
        assert sample_kill_switch.is_killed(agent_id="a", trace_id="t", tool_name="temp_tool") is True

        deactivated = sample_kill_switch.deactivate(scope=KillSwitchScope.TOOL, target_id="temp_tool")
        assert deactivated is True
        assert sample_kill_switch.is_killed(agent_id="a", trace_id="t", tool_name="temp_tool") is False

        # Deactivating non-existent switch returns False
        assert sample_kill_switch.deactivate(scope=KillSwitchScope.TOOL, target_id="temp_tool") is False

    def test_killswitch_ttl_auto_expiration(self, sample_kill_switch: KillSwitchState) -> None:
        # Activate with 1-second TTL
        sample_kill_switch.activate(
            scope=KillSwitchScope.SESSION,
            target_id="trace_ephemeral",
            reason="Transient anomaly",
            triggered_by="automated_policy",
            ttl_seconds=1,
        )

        # Immediately active
        assert sample_kill_switch.is_killed(agent_id="a", trace_id="trace_ephemeral") is True

        # Manually backdate the record to simulate time passing
        key = (KillSwitchScope.SESSION, "trace_ephemeral")
        old_record = sample_kill_switch._records[key]
        backdated_record = old_record.model_copy(
            update={"created_at": datetime.now(timezone.utc) - timedelta(seconds=2)}
        )
        sample_kill_switch._records[key] = backdated_record

        # Now is_killed should detect expiration and return False
        assert sample_kill_switch.is_killed(agent_id="a", trace_id="trace_ephemeral") is False

    def test_killswitch_get_active_records_and_clear(self, sample_kill_switch: KillSwitchState) -> None:
        sample_kill_switch.activate(
            scope=KillSwitchScope.AGENT,
            target_id="agent_1",
            reason="Test",
            triggered_by="tester",
        )
        sample_kill_switch.activate(
            scope=KillSwitchScope.TOOL,
            target_id="tool_1",
            reason="Test",
            triggered_by="tester",
        )

        active = sample_kill_switch.get_active_records()
        assert len(active) == 2

        sample_kill_switch.clear()
        assert len(sample_kill_switch.get_active_records()) == 0

    def test_killswitch_invalid_inputs(self, sample_kill_switch: KillSwitchState) -> None:
        with pytest.raises(ValueError, match="reason must be a non-empty string"):
            sample_kill_switch.activate(
                scope=KillSwitchScope.TOOL,
                target_id="tool_1",
                reason="",
                triggered_by="operator",
            )

        with pytest.raises(ValueError, match="triggered_by must be a non-empty string"):
            sample_kill_switch.activate(
                scope=KillSwitchScope.TOOL,
                target_id="tool_1",
                reason="emergency",
                triggered_by="  ",
            )

        with pytest.raises(ValueError, match="target_id must be a non-empty string"):
            sample_kill_switch.activate(
                scope=KillSwitchScope.AGENT,
                target_id="  ",
                reason="emergency",
                triggered_by="operator",
            )

    def test_killswitch_global_default_wildcard(self, sample_kill_switch: KillSwitchState) -> None:
        record = sample_kill_switch.activate(
            scope=KillSwitchScope.GLOBAL,
            target_id="",
            reason="Total shutdown",
            triggered_by="ciso",
        )
        assert record.target_id == "*"
        assert sample_kill_switch.is_killed(agent_id="any_agent", trace_id="any_trace") is True

    def test_killswitch_target_validation_and_global_defaults(self, sample_kill_switch: KillSwitchState) -> None:
        # None target for GLOBAL defaults to "*"
        rec1 = sample_kill_switch.activate(
            scope=KillSwitchScope.GLOBAL,
            target_id=None,
            reason="Enterprise lock",
            triggered_by="ciso",
        )
        assert rec1.target_id == "*"
        assert sample_kill_switch.is_killed(agent_id="agent_x", trace_id="trace_y") is True

        # Deactivate GLOBAL with None target
        assert sample_kill_switch.deactivate(scope=KillSwitchScope.GLOBAL, target_id=None) is True
        assert sample_kill_switch.is_killed(agent_id="agent_x", trace_id="trace_y") is False

        # Whitespace-only target for GLOBAL defaults to "*"
        rec2 = sample_kill_switch.activate(
            scope=KillSwitchScope.GLOBAL,
            target_id="   ",
            reason="Total shutdown",
            triggered_by="ciso",
        )
        assert rec2.target_id == "*"
        assert sample_kill_switch.deactivate(scope=KillSwitchScope.GLOBAL, target_id="") is True

        # None or empty target for non-GLOBAL scope must raise ValueError
        with pytest.raises(ValueError, match="target_id must be a non-empty string"):
            sample_kill_switch.activate(
                scope=KillSwitchScope.AGENT,
                target_id=None,
                reason="Compromised agent",
                triggered_by="admin",
            )

        with pytest.raises(ValueError, match="target_id must be a non-empty string"):
            sample_kill_switch.activate(
                scope=KillSwitchScope.TOOL,
                target_id="",
                reason="CVE",
                triggered_by="admin",
            )

        # Deactivating non-GLOBAL with None/empty safely returns False
        assert sample_kill_switch.deactivate(scope=KillSwitchScope.AGENT, target_id=None) is False
        assert sample_kill_switch.deactivate(scope=KillSwitchScope.TOOL, target_id="") is False


# ===========================================================================
# 10. Additional Edge Case Tests
# ===========================================================================


class TestModelEdgeCases:
    """Verify specific boundary and edge case behaviors."""

    def test_taint_initialization_with_initial_taints(self) -> None:
        state = TaintState("trace_init", ["B", "A", "C"])
        assert len(state) == 3
        assert state.to_list() == ["A", "B", "C"]
        assert state.has_taint("") is False

    def test_taint_repr_and_equality(self) -> None:
        s1 = TaintState("trace_eq", ["A", "B"])
        s2 = TaintState("trace_eq", ["B", "A"])
        s3 = TaintState("trace_diff", ["A", "B"])

        assert s1 == s2
        assert s1 != s3
        assert s1 != "not_a_taint_state"
        assert "trace_eq" in repr(s1)

    def test_policy_without_hash_verify(self, sample_policy_yaml_str: str) -> None:
        policy = PolicySchema.from_yaml_str(sample_policy_yaml_str)
        policy_no_hash = policy.model_copy(update={"policy_hash": None})
        assert policy_no_hash.verify_hash() is False

    def test_taint_rule_empty_collections_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TaintRule(
                id="RULE-1",
                match_taints=[],  # min_length=1
                blocked_tools=["tool_a"],
                owasp_id="ASI02",
            )

        with pytest.raises(ValidationError):
            TaintRule(
                id="RULE-1",
                match_taints=["TAINT_A"],
                blocked_tools=[],  # min_length=1
                owasp_id="ASI02",
            )

    def test_agent_event_root_span_serialization(self, sample_valid_event: AgentEvent) -> None:
        json_str = sample_valid_event.model_dump_json()
        assert '"parent_span_id":null' in json_str or '"parent_span_id": null' in json_str

