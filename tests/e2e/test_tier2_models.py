"""Tier 2 Boundary Value Analysis & Corner Case Tests for Models & Scaffolding.

Covers Features 1 through 8 from PROJECT.md and TEST_INFRA.md:
- Feature 1: AgentEvent Envelope Boundaries (>=5 tests)
- Feature 2: Principal, Decision, DriftSnapshot Boundaries (>=5 tests)
- Feature 3: Event Enums Boundaries (>=5 tests)
- Feature 4: PolicySchema Declarative Model Boundaries (>=5 tests)
- Feature 5: TaintState Boundaries (>=5 tests)
- Feature 6: KillSwitchState Hierarchy Boundaries (>=5 tests)
- Feature 7: Supporting Event Payloads Boundaries (>=5 tests)
- Feature 8: Package Scaffolding Boundaries (>=5 tests)
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, get_type_hints
import uuid

import pytest
from pydantic import ValidationError

from agentxdr.models import (
    AgentCommPayload,
    AgentEvent,
    BudgetsConfig,
    CodeSandboxConfig,
    Decision,
    DlpGuardrailConfig,
    DriftSnapshot,
    EventType,
    GoalAnchorConfig,
    HitlDecisionPayload,
    KillSwitchRecord,
    KillSwitchScope,
    KillSwitchState,
    LlmGenerationPayload,
    MemoryMutationPayload,
    OutputGuardrailsConfig,
    ParameterConstraint,
    PolicySchema,
    Principal,
    PromptLeakConfig,
    ProvenanceTier,
    RagAccessPayload,
    ResponseActionPayload,
    SandboxExecPayload,
    TaintRule,
    TaintState,
    ToolInvocationPayload,
    ToolPolicy,
    ToolTier,
    UserInputPayload,
    Verdict,
)


# ===========================================================================
# Helpers & Fixtures
# ===========================================================================


def make_valid_principal(user_id: str = "sec-user-001") -> Principal:
    """Helper to instantiate a valid Principal model."""
    return Principal(
        user_id=user_id,
        roles=["analyst", "operator"],
        effective_scopes=["read:telemetry", "execute:safe_tools"],
    )


def make_valid_decision(verdict: Verdict = Verdict.ALLOW, latency_ms: float = 1.5) -> Decision:
    """Helper to instantiate a valid Decision model."""
    return Decision(
        verdict=verdict,
        rule_id="DEFAULT_ALLOW",
        owasp_ids=["ASI01"],
        latency_ms=latency_ms,
    )


def make_valid_drift_snapshot(score: float = 0.05) -> DriftSnapshot:
    """Helper to instantiate a valid DriftSnapshot model."""
    return DriftSnapshot(
        composite_score=score,
        s_policy=score,
        s_graph=score,
        s_velocity=score,
        s_semantic=score,
    )


def make_valid_event_kwargs() -> Dict[str, Any]:
    """Helper returning a complete dictionary of valid arguments for AgentEvent."""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc),
        "trace_id": "trace-sec-001",
        "span_id": "span-001",
        "parent_span_id": None,
        "agent_id": "agent-alpha",
        "policy_version": "1.0.0",
        "event_type": EventType.USER_INPUT,
        "principal": make_valid_principal(),
        "provenance_tier": ProvenanceTier.AUTHENTICATED_USER,
        "taint_labels": ["UNTRUSTED_EXTERNAL"],
        "payload_redacted": {"query": "status check"},
        "decision": make_valid_decision(),
        "drift_snapshot": make_valid_drift_snapshot(),
    }


def make_valid_budgets() -> BudgetsConfig:
    """Helper to instantiate a valid BudgetsConfig."""
    return BudgetsConfig(
        max_turns=10,
        max_tool_calls=25,
        max_identical_calls=3,
        max_session_duration_sec=120.0,
        max_session_cost_usd=5.0,
    )


# ===========================================================================
# Feature 1: AgentEvent Envelope Boundaries (>=5 tests)
# ===========================================================================


class TestFeature1AgentEventBoundaries:
    """Boundary value analysis and corner cases for AgentEvent envelope."""

    def test_attempting_attribute_mutation_raises_validation_or_frozen_error(self):
        """Mutating attributes on a frozen AgentEvent instance must raise an error."""
        event = AgentEvent(**make_valid_event_kwargs())
        with pytest.raises((ValidationError, TypeError)):
            event.agent_id = "malicious_override"

        with pytest.raises((ValidationError, TypeError)):
            event.trace_id = "hijacked_trace"

        with pytest.raises((ValidationError, TypeError)):
            event.payload_redacted = {"tampered": True}

    def test_injecting_extra_undeclared_fields_raises_validation_error(self):
        """Injecting undeclared fields must be rejected (extra='forbid')."""
        kwargs = make_valid_event_kwargs()
        kwargs["unauthorized_field"] = "injection_attempt"
        kwargs["__shadow_attribute__"] = 12345

        with pytest.raises(ValidationError) as exc_info:
            AgentEvent(**kwargs)
        assert "extra_forbidden" in str(exc_info.value) or "unauthorized_field" in str(exc_info.value)

    @pytest.mark.parametrize("empty_val", ["", "   ", "\t\n  "])
    def test_empty_string_identifiers_raise_validation_error(self, empty_val: str):
        """Empty or whitespace-only trace_id, agent_id, span_id, policy_version must fail."""
        kwargs = make_valid_event_kwargs()

        # Test empty trace_id
        kwargs["trace_id"] = empty_val
        with pytest.raises(ValidationError) as exc_info:
            AgentEvent(**kwargs)
        assert "trace_id" in str(exc_info.value)

        # Test empty agent_id
        kwargs["trace_id"] = "valid-trace"
        kwargs["agent_id"] = empty_val
        with pytest.raises(ValidationError) as exc_info:
            AgentEvent(**kwargs)
        assert "agent_id" in str(exc_info.value)

        # Test empty span_id
        kwargs["agent_id"] = "valid-agent"
        kwargs["span_id"] = empty_val
        with pytest.raises(ValidationError) as exc_info:
            AgentEvent(**kwargs)
        assert "span_id" in str(exc_info.value)

        # Test empty policy_version
        kwargs["span_id"] = "valid-span"
        kwargs["policy_version"] = empty_val
        with pytest.raises(ValidationError) as exc_info:
            AgentEvent(**kwargs)
        assert "policy_version" in str(exc_info.value)

    def test_malformed_datetime_strings_raise_validation_error(self):
        """Passing non-datetime or unparseable datetime strings must be rejected."""
        kwargs = make_valid_event_kwargs()
        kwargs["timestamp"] = "not-a-valid-datetime"

        with pytest.raises(ValidationError) as exc_info:
            AgentEvent(**kwargs)
        assert "timestamp" in str(exc_info.value)

        kwargs["timestamp"] = "2026-13-45T99:99:99Z"
        with pytest.raises(ValidationError):
            AgentEvent(**kwargs)

    def test_gigantic_payload_dictionary_serialization(self):
        """Serialization handles gigantic payload dictionary (10,000 keys) without failure."""
        large_payload = {f"k_{i}": f"val_{i}_{'x' * 10}" for i in range(10_000)}
        kwargs = make_valid_event_kwargs()
        kwargs["payload_redacted"] = large_payload

        event = AgentEvent(**kwargs)
        assert len(event.payload_redacted) == 10_000

        # Verify JSON serialization round-trip
        json_str = event.model_dump_json()
        assert len(json_str) > 100_000
        data = json.loads(json_str)
        assert len(data["payload_redacted"]) == 10_000
        assert data["payload_redacted"]["k_9999"] == "val_9999_xxxxxxxxxx"

    def test_event_id_and_timestamp_default_generation(self):
        """Omitting event_id and timestamp auto-generates valid UUID4 and UTC timestamp."""
        kwargs = make_valid_event_kwargs()
        del kwargs["event_id"]
        del kwargs["timestamp"]

        event = AgentEvent(**kwargs)
        assert event.event_id is not None
        # Must be valid UUID
        parsed_uuid = uuid.UUID(event.event_id)
        assert parsed_uuid.version == 4
        assert event.timestamp.tzinfo is not None

    def test_parent_span_id_optionality_and_validation(self):
        """parent_span_id is optional (can be None) or a valid non-empty string."""
        kwargs = make_valid_event_kwargs()
        kwargs["parent_span_id"] = None
        event_none = AgentEvent(**kwargs)
        assert event_none.parent_span_id is None

        kwargs["parent_span_id"] = "span-parent-000"
        event_with_parent = AgentEvent(**kwargs)
        assert event_with_parent.parent_span_id == "span-parent-000"


# ===========================================================================
# Feature 2: Principal, Decision, DriftSnapshot Boundaries (>=5 tests)
# ===========================================================================


class TestFeature2PrincipalDecisionDriftBoundaries:
    """Boundary value analysis for Principal, Decision, and DriftSnapshot sub-models."""

    def test_negative_latency_ms_rejected_ge_zero(self):
        """latency_ms on Decision must be >= 0.0; negative values must raise ValidationError."""
        # Exact boundary: 0.0 is valid
        decision_zero = Decision(verdict=Verdict.ALLOW, latency_ms=0.0)
        assert decision_zero.latency_ms == 0.0

        # Boundary violation: -0.0001
        with pytest.raises(ValidationError) as exc_info:
            Decision(verdict=Verdict.ALLOW, latency_ms=-0.0001)
        assert "greater than or equal to 0" in str(exc_info.value)

        # Extreme negative
        with pytest.raises(ValidationError):
            Decision(verdict=Verdict.ALLOW, latency_ms=-99999.0)

    @pytest.mark.parametrize("invalid_score", [-0.01, -1.0, 1.0001, 2.5, 100.0])
    def test_drift_score_out_of_bounds_rejected_ge_0_le_1(self, invalid_score: float):
        """All drift score signals must satisfy 0.0 <= score <= 1.0."""
        # Test composite_score boundary
        with pytest.raises(ValidationError):
            DriftSnapshot(
                composite_score=invalid_score,
                s_policy=0.5,
                s_graph=0.5,
                s_velocity=0.5,
                s_semantic=0.5,
            )

        # Test individual signal boundaries
        with pytest.raises(ValidationError):
            DriftSnapshot(
                composite_score=0.5,
                s_policy=invalid_score,
                s_graph=0.5,
                s_velocity=0.5,
                s_semantic=0.5,
            )

    def test_extreme_zero_and_one_drift_scores_accepted(self):
        """Exact extreme boundaries 0.0 and 1.0 are valid for all drift signals."""
        snapshot_min = DriftSnapshot(
            composite_score=0.0,
            s_policy=0.0,
            s_graph=0.0,
            s_velocity=0.0,
            s_semantic=0.0,
        )
        assert snapshot_min.composite_score == 0.0

        snapshot_max = DriftSnapshot(
            composite_score=1.0,
            s_policy=1.0,
            s_graph=1.0,
            s_velocity=1.0,
            s_semantic=1.0,
        )
        assert snapshot_max.composite_score == 1.0

    @pytest.mark.parametrize("empty_user", ["", "   ", "\n\t"])
    def test_empty_user_id_rejected_on_principal(self, empty_user: str):
        """Empty or whitespace-only user_id must raise ValidationError on Principal."""
        with pytest.raises(ValidationError) as exc_info:
            Principal(user_id=empty_user)
        assert "user_id" in str(exc_info.value)

    def test_extra_forbidden_fields_on_principal_decision_drift(self):
        """Injecting undeclared fields on Principal, Decision, or DriftSnapshot raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            Principal(user_id="sec-01", roles=[], effective_scopes=[], malicious_scope="admin:all")
        assert "extra_forbidden" in str(exc_info.value) or "malicious_scope" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info:
            Decision(verdict=Verdict.ALLOW, latency_ms=1.0, override_verdict="KILL")
        assert "extra_forbidden" in str(exc_info.value) or "override_verdict" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info:
            DriftSnapshot(
                composite_score=0.1,
                s_policy=0.1,
                s_graph=0.1,
                s_velocity=0.1,
                s_semantic=0.1,
                extra_metric=0.99,
            )
        assert "extra_forbidden" in str(exc_info.value) or "extra_metric" in str(exc_info.value)

    def test_submodels_attribute_immutability(self):
        """Principal, Decision, and DriftSnapshot instances are frozen and reject mutation."""
        p = make_valid_principal()
        with pytest.raises((ValidationError, TypeError)):
            p.user_id = "attacker"

        d = make_valid_decision()
        with pytest.raises((ValidationError, TypeError)):
            d.verdict = Verdict.KILL

        s = make_valid_drift_snapshot()
        with pytest.raises((ValidationError, TypeError)):
            s.composite_score = 0.99

    def test_principal_special_character_and_length_boundaries(self):
        """Principal accepts valid complex user_id strings with special characters."""
        complex_ids = [
            "service-principal:cluster-alpha/ns-prod/pod-99",
            "user+tag@domain.co.uk",
            "usr_01934e8f-7c1a-7b3b-8f0a-123456789abc",
            "a" * 256,
        ]
        for uid in complex_ids:
            p = Principal(user_id=uid)
            assert p.user_id == uid


# ===========================================================================
# Feature 3: Event Enums Boundaries (>=5 tests)
# ===========================================================================


class TestFeature3EventEnumsBoundaries:
    """Boundary value analysis and corner cases for EventType, Verdict, ToolTier, ProvenanceTier, KillSwitchScope."""

    @pytest.mark.parametrize(
        "enum_cls, invalid_val",
        [
            (EventType, "INVALID_EVENT"),
            (EventType, "user_input"),
            (Verdict, "SUPER_ALLOW"),
            (Verdict, "DENY"),
            (ProvenanceTier, "UNVERIFIED_GUEST"),
            (ToolTier, "SEMI_AUTOMATIC"),
            (KillSwitchScope, "CLUSTER"),
            (KillSwitchScope, "NAMESPACE"),
        ],
    )
    def test_invalid_enum_strings_raise_value_error(self, enum_cls, invalid_val: str):
        """Instantiating enums with invalid strings must raise ValueError."""
        with pytest.raises(ValueError):
            enum_cls(invalid_val)

    def test_enum_case_sensitivity(self):
        """Enums must strictly respect uppercase or lowercase definitions."""
        # Verdict is uppercase
        with pytest.raises(ValueError):
            Verdict("allow")
        assert Verdict("ALLOW") == Verdict.ALLOW

        # ToolTier is lowercase
        with pytest.raises(ValueError):
            ToolTier("AUTOMATIC")
        assert ToolTier("automatic") == ToolTier.AUTOMATIC

        # ProvenanceTier is uppercase
        with pytest.raises(ValueError):
            ProvenanceTier("trusted_system")
        assert ProvenanceTier("TRUSTED_SYSTEM") == ProvenanceTier.TRUSTED_SYSTEM

    def test_enum_comparison_with_raw_strings_and_instances(self):
        """Enums inheriting from str must support equal-to and not-equal comparison with raw strings."""
        assert Verdict.ALLOW == "ALLOW"
        assert Verdict.ALLOW != "BLOCK"
        assert Verdict.ALLOW == Verdict.ALLOW
        assert Verdict.ALLOW != Verdict.KILL
        assert Verdict.ALLOW != "allow"

        assert ToolTier.AUTOMATIC == "automatic"
        assert ToolTier.AUTOMATIC != "AUTOMATIC"
        assert ToolTier.AUTOMATIC == ToolTier.AUTOMATIC

        assert ProvenanceTier.TRUSTED_SYSTEM == "TRUSTED_SYSTEM"
        assert EventType.TOOL_INVOCATION == "TOOL_INVOCATION"
        assert KillSwitchScope.GLOBAL == "GLOBAL"

    def test_exhaustive_mapping_of_all_canonical_enum_values(self):
        """Verify the exact membership and count for all canonical enums from PROJECT.md."""
        # EventType: exactly 9 canonical values
        expected_events = {
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
        actual_events = {e.value for e in EventType}
        assert actual_events == expected_events
        assert len(EventType) == 9

        # ProvenanceTier: exactly 5 values
        expected_tiers = {
            "TRUSTED_SYSTEM",
            "AUTHENTICATED_USER",
            "RESTRICTED_INTERNAL",
            "VERIFIED_MEMORY",
            "UNTRUSTED_EXTERNAL",
        }
        actual_tiers = {t.value for t in ProvenanceTier}
        assert actual_tiers == expected_tiers
        assert len(ProvenanceTier) == 5

        # Verdict: exactly 5 values
        expected_verdicts = {
            "ALLOW",
            "MASK_AND_ALLOW",
            "PAUSE_FOR_HITL",
            "BLOCK",
            "KILL",
        }
        actual_verdicts = {v.value for v in Verdict}
        assert actual_verdicts == expected_verdicts
        assert len(Verdict) == 5

        # ToolTier: exactly 3 values
        expected_tool_tiers = {"automatic", "privileged_hitl", "blocked"}
        actual_tool_tiers = {t.value for t in ToolTier}
        assert actual_tool_tiers == expected_tool_tiers
        assert len(ToolTier) == 3

        # KillSwitchScope: exactly 5 values
        expected_scopes = {"GLOBAL", "AGENT", "SESSION", "TOOL", "MCP_SERVER"}
        actual_scopes = {s.value for s in KillSwitchScope}
        assert actual_scopes == expected_scopes
        assert len(KillSwitchScope) == 5

    def test_non_string_types_rejected_by_enums(self):
        """Passing non-string types such as integers, dicts, or floats raises ValueError."""
        with pytest.raises(ValueError):
            Verdict(123)
        with pytest.raises(ValueError):
            EventType(True)
        with pytest.raises(ValueError):
            ToolTier(["automatic"])


# ===========================================================================
# Feature 4: PolicySchema Declarative Model Boundaries (>=5 tests)
# ===========================================================================


class TestFeature4PolicySchemaBoundaries:
    """Boundary value analysis and corner cases for PolicySchema and declarative sub-models."""

    def test_empty_tools_list_is_valid(self):
        """An agent policy with tools=[] must be valid (e.g. pure conversation agent)."""
        policy = PolicySchema(
            version="1.0.0",
            agent_id="conversational-agent",
            budgets=make_valid_budgets(),
            tools=[],
            taint_rules=[],
        )
        assert policy.tools == []
        assert len(policy.tools) == 0

    def test_duplicate_tool_names_raise_validation_error(self):
        """Declaring duplicate tool names in policy.tools must raise ValidationError."""
        t1 = ToolPolicy(name="database_query", tier=ToolTier.AUTOMATIC)
        t2 = ToolPolicy(name="database_query", tier=ToolTier.BLOCKED)

        with pytest.raises(ValidationError) as exc_info:
            PolicySchema(
                version="1.0.0",
                agent_id="db-agent",
                budgets=make_valid_budgets(),
                tools=[t1, t2],
            )
        assert "Duplicate tool" in str(exc_info.value) or "database_query" in str(exc_info.value)

    @pytest.mark.parametrize("empty_ver", ["", "   ", "\t"])
    def test_missing_or_empty_version_field_rejected(self, empty_ver: str):
        """Missing or whitespace-only version must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            PolicySchema(
                version=empty_ver,
                agent_id="test-agent",
                budgets=make_valid_budgets(),
            )
        assert "version" in str(exc_info.value)

    def test_invalid_tool_tier_string_rejected(self):
        """Specifying an unknown tool tier in ToolPolicy must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            ToolPolicy(name="safe_tool", tier="unrestricted")
        assert "tier" in str(exc_info.value)

    @pytest.mark.parametrize(
        "field_name, invalid_val",
        [
            ("max_turns", 0),
            ("max_turns", -5),
            ("max_tool_calls", 0),
            ("max_tool_calls", -1),
            ("max_identical_calls", 0),
            ("max_identical_calls", -3),
            ("max_session_duration_sec", 0.0),
            ("max_session_duration_sec", -10.0),
            ("max_session_cost_usd", 0.0),
            ("max_session_cost_usd", -0.5),
        ],
    )
    def test_negative_and_zero_budgets_rejected(self, field_name: str, invalid_val: Any):
        """Budget values <= 0 must be rejected according to gt=0 constraints."""
        kwargs = {
            "max_turns": 10,
            "max_tool_calls": 25,
            "max_identical_calls": 3,
            "max_session_duration_sec": 120.0,
            "max_session_cost_usd": 5.0,
        }
        kwargs[field_name] = invalid_val
        with pytest.raises(ValidationError) as exc_info:
            BudgetsConfig(**kwargs)
        assert field_name in str(exc_info.value)

    def test_taint_rule_empty_matching_lists_rejected(self):
        """TaintRule with empty match_taints or blocked_tools must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            TaintRule(
                id="TR-01",
                match_taints=[],
                blocked_tools=["export_data"],
                owasp_id="ASI02",
            )
        assert "match_taints" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info:
            TaintRule(
                id="TR-02",
                match_taints=["UNTRUSTED_EXTERNAL"],
                blocked_tools=[],
                owasp_id="ASI02",
            )
        assert "blocked_tools" in str(exc_info.value)

    def test_policy_hash_computation_and_tamper_detection(self):
        """Modifying any policy content changes the canonical policy hash and fails verification."""
        policy_yaml = """
version: "1.0.0"
agent_id: "sec-ops-agent"
budgets:
  max_turns: 10
  max_tool_calls: 25
  max_identical_calls: 3
  max_session_duration_sec: 120
  max_session_cost_usd: 5.0
tools:
  - name: "safe_search"
    tier: "automatic"
"""
        policy = PolicySchema.from_yaml_str(policy_yaml)
        computed_hash = policy.compute_policy_hash()
        assert computed_hash.startswith("sha256:")

        # Verification with matching hash
        policy_with_hash = policy.model_copy(update={"policy_hash": computed_hash})
        assert policy_with_hash.verify_hash() is True

        # Tampered hash
        tampered_policy = policy.model_copy(update={"policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"})
        assert tampered_policy.verify_hash() is False


# ===========================================================================
# Feature 5: TaintState Boundaries (>=5 tests)
# ===========================================================================


class TestFeature5TaintStateBoundaries:
    """Boundary value analysis and corner cases for TaintState monotonic state machine."""

    def test_empty_initial_taints_behavior(self):
        """Instantiating TaintState with None or empty iterable results in empty state."""
        ts_none = TaintState("trace-empty-1", initial_taints=None)
        assert len(ts_none) == 0
        assert ts_none.to_list() == []
        assert ts_none.has_taint("ANY_LABEL") is False

        ts_empty = TaintState("trace-empty-2", initial_taints=[])
        assert len(ts_empty) == 0
        assert ts_empty.to_list() == []

    def test_duplicate_taint_labels_deduplicated_and_idempotent(self):
        """Adding duplicate taints is idempotent and keeps the state set-based."""
        ts = TaintState("trace-dedup")
        for _ in range(25):
            ts.add_taint("UNTRUSTED_EXTERNAL")
        assert len(ts) == 1
        assert ts.to_list() == ["UNTRUSTED_EXTERNAL"]

        # Batch addition idempotence
        ts.add_taints(["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG", "UNTRUSTED_EXTERNAL"])
        assert len(ts) == 2
        assert ts.to_list() == ["CONFIDENTIAL_RAG", "UNTRUSTED_EXTERNAL"]

    def test_casing_and_whitespace_handling_in_taint_labels(self):
        """Whitespace is stripped, empty labels are rejected, and casing is preserved."""
        ts = TaintState("trace-casing")
        ts.add_taint("  UNTRUSTED_EXTERNAL  ")
        assert ts.has_taint("UNTRUSTED_EXTERNAL") is True
        assert ts.has_taint("  UNTRUSTED_EXTERNAL  ") is True
        assert len(ts) == 1

        # Casing distinction
        ts.add_taint("untrusted_external")
        assert len(ts) == 2
        assert "untrusted_external" in ts
        assert "UNTRUSTED_EXTERNAL" in ts

        # Empty or whitespace taint label raises ValueError
        with pytest.raises(ValueError):
            ts.add_taint("")
        with pytest.raises(ValueError):
            ts.add_taint("   ")

    def test_empty_and_whitespace_rule_matching_list(self):
        """matches_rule returns False when match_taints is empty or contains only whitespace."""
        ts = TaintState("trace-rule-match", initial_taints=["UNTRUSTED_EXTERNAL", "PII"])
        assert ts.matches_rule([]) is False
        assert ts.matches_rule([""]) is False
        assert ts.matches_rule(["   ", "  "]) is False

        # Non-empty subset match
        assert ts.matches_rule(["UNTRUSTED_EXTERNAL"]) is True
        assert ts.matches_rule(["UNTRUSTED_EXTERNAL", "PII"]) is True
        assert ts.matches_rule(["UNTRUSTED_EXTERNAL", "NON_EXISTENT"]) is False

    def test_large_number_of_taint_labels_100_plus(self):
        """Adding 150 unique taint labels behaves efficiently, remains sorted, and matches subsets."""
        ts = TaintState("trace-large-taints")
        labels = [f"TAINT_LABEL_{i:04d}" for i in range(150)]
        ts.add_taints(labels)

        assert len(ts) == 150
        out_list = ts.to_list()
        assert len(out_list) == 150
        assert out_list == sorted(labels)

        # Subset match of 50 labels
        subset = labels[10:60]
        assert ts.matches_rule(subset) is True

        # Subset with 1 non-existent label
        assert ts.matches_rule(subset + ["MISSING_TAINT"]) is False

    @pytest.mark.parametrize("empty_trace", ["", "   ", "\t\n"])
    def test_empty_trace_id_rejected_on_taint_state(self, empty_trace: str):
        """trace_id cannot be empty or whitespace-only."""
        with pytest.raises(ValueError):
            TaintState(trace_id=empty_trace)

    def test_concurrent_taint_addition_thread_safety(self):
        """Concurrent multi-threaded taint addition maintains consistency without corruption."""
        ts = TaintState("trace-concurrent")

        def worker(worker_id: int):
            for i in range(50):
                ts.add_taint(f"THREAD_{worker_id}_TAINT_{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, w) for w in range(8)]
            for f in concurrent.futures.as_completed(futures):
                f.result()

        # 8 workers * 50 unique taints = 400 taints
        assert len(ts) == 400
        assert len(ts.to_list()) == 400


# ===========================================================================
# Feature 6: KillSwitchState Hierarchy Boundaries (>=5 tests)
# ===========================================================================


class TestFeature6KillSwitchHierarchyBoundaries:
    """Boundary value analysis and corner cases for KillSwitchState hierarchy."""

    def test_deactivating_non_activated_scope_gracefully_handled(self):
        """Deactivating a target that was never activated returns False without raising error."""
        ks = KillSwitchState()
        result = ks.deactivate(KillSwitchScope.TOOL, "never_activated_tool")
        assert result is False

        result_global = ks.deactivate(KillSwitchScope.GLOBAL, "*")
        assert result_global is False

    def test_ttl_expiration_simulation(self):
        """Kill switch with TTL expires and auto-deactivates after elapsed time."""
        ks = KillSwitchState()
        # Activate tool kill switch with 1 second TTL
        record = ks.activate(
            scope=KillSwitchScope.TOOL,
            target_id="risky_tool",
            reason="High error rate",
            triggered_by="soc_automated_rule",
            ttl_seconds=1,
        )
        assert record.ttl_seconds == 1

        # Check immediate killed status
        assert ks.is_killed(agent_id="a1", trace_id="t1", tool_name="risky_tool") is True

        # Check expiration logic directly
        future_time = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert record.is_expired(now=future_time) is True

    def test_target_id_with_special_characters(self):
        """Target IDs containing URLs, URI schemes, UUIDs, colons, and punctuation are matched cleanly."""
        ks = KillSwitchState()
        special_targets = [
            "mcp://corp.internal:8443/v1/tools?name=execute#section",
            "urn:uuid:01934e8f-7c1a-7b3b-8f0a-123456789abc",
            "tool_with_spaces and /slashes/ and :colons:",
            "!@#$%^&*()_+-=[]{}|;':,.<>?",
        ]
        for target in special_targets:
            ks.activate(
                scope=KillSwitchScope.TOOL,
                target_id=target,
                reason="Special chars test",
                triggered_by="operator",
            )
            assert ks.is_killed(agent_id="a1", trace_id="t1", tool_name=target) is True
            ks.deactivate(KillSwitchScope.TOOL, target)
            assert ks.is_killed(agent_id="a1", trace_id="t1", tool_name=target) is False

    def test_conflicting_simultaneous_kills_across_scopes_hierarchy(self):
        """GLOBAL scope takes precedence over AGENT, SESSION, TOOL, and MCP_SERVER."""
        ks = KillSwitchState()
        ks.activate(KillSwitchScope.GLOBAL, "*", "Fleetwide lockdown", "admin")
        ks.activate(KillSwitchScope.AGENT, "agent-1", "Compromised agent", "admin")
        ks.activate(KillSwitchScope.SESSION, "trace-100", "Hijacked session", "admin")
        ks.activate(KillSwitchScope.TOOL, "bash_exec", "RCE vulnerability", "admin")

        # Everything is killed due to GLOBAL
        assert ks.is_killed(agent_id="agent-1", trace_id="trace-100", tool_name="bash_exec") is True
        assert ks.is_killed(agent_id="other-agent", trace_id="other-trace", tool_name="other_tool") is True

        # Deactivate GLOBAL: now only targeted entities are killed
        ks.deactivate(KillSwitchScope.GLOBAL, "*")
        assert ks.is_killed(agent_id="agent-1", trace_id="other-trace") is True
        assert ks.is_killed(agent_id="other-agent", trace_id="trace-100") is True
        assert ks.is_killed(agent_id="other-agent", trace_id="other-trace", tool_name="bash_exec") is True
        assert ks.is_killed(agent_id="other-agent", trace_id="other-trace", tool_name="safe_tool") is False

    def test_query_is_killed_with_none_vs_specific_tool_and_mcp_server(self):
        """Querying with tool_name=None or mcp_server=None does not trigger tool/mcp kill switches."""
        ks = KillSwitchState()
        ks.activate(KillSwitchScope.TOOL, "sensitive_db_write", "Maintenance", "dba")
        ks.activate(KillSwitchScope.MCP_SERVER, "finance-mcp", "Audit", "auditor")

        # Without tool_name or mcp_server, returns False
        assert ks.is_killed(agent_id="a1", trace_id="t1", tool_name=None, mcp_server=None) is False
        assert ks.is_killed(agent_id="a1", trace_id="t1") is False

        # With specific tool_name
        assert ks.is_killed(agent_id="a1", trace_id="t1", tool_name="sensitive_db_write") is True
        assert ks.is_killed(agent_id="a1", trace_id="t1", tool_name="other_tool") is False

        # With specific mcp_server
        assert ks.is_killed(agent_id="a1", trace_id="t1", mcp_server="finance-mcp") is True
        assert ks.is_killed(agent_id="a1", trace_id="t1", mcp_server="other-mcp") is False

    def test_clear_removes_all_records(self):
        """ks.clear() purges all active records across all scopes."""
        ks = KillSwitchState()
        ks.activate(KillSwitchScope.GLOBAL, "*", "Shutdown", "admin")
        ks.activate(KillSwitchScope.AGENT, "a1", "Shutdown", "admin")
        assert len(ks.get_active_records()) == 2

        ks.clear()
        assert len(ks.get_active_records()) == 0
        assert ks.is_killed("a1", "t1") is False


# ===========================================================================
# Feature 7: Supporting Event Payloads Boundaries (>=5 tests)
# ===========================================================================


class TestFeature7SupportingEventPayloadsBoundaries:
    """Boundary value analysis and corner cases for specialized payload models."""

    def test_empty_payload_dictionary_on_agent_event(self):
        """AgentEvent with payload_redacted={} is valid and serializes properly."""
        kwargs = make_valid_event_kwargs()
        kwargs["payload_redacted"] = {}

        event = AgentEvent(**kwargs)
        assert event.payload_redacted == {}
        dumped = json.loads(event.model_dump_json())
        assert dumped["payload_redacted"] == {}

    def test_deeply_nested_json_in_payload_redacted(self):
        """payload_redacted handles a 25-level deeply nested JSON hierarchy without recursion error."""
        nested: Dict[str, Any] = {"leaf": "deepest_value", "level": 25}
        for i in range(24, 0, -1):
            nested = {"level": i, "child": nested}

        kwargs = make_valid_event_kwargs()
        kwargs["payload_redacted"] = nested

        event = AgentEvent(**kwargs)
        assert event.payload_redacted["level"] == 1
        serialized = event.model_dump_json()
        restored = json.loads(serialized)
        assert restored["payload_redacted"]["level"] == 1

    def test_unicode_and_emoji_characters_in_payload(self):
        """Payloads preserve international Unicode, Arabic, CJK, and emojis without mangling."""
        unicode_str = (
            "🛡️ AgentXDR Control Plane: 日本語テスト | "
            "مرحبا بالعالم | שלום עולם | 🚀 100% Secure 🔐 | "
            "Math: ∑_{i=1}^n x_i \u2264 \u221e"
        )
        payload = UserInputPayload(user_input_redacted=unicode_str, token_count=42)
        assert payload.user_input_redacted == unicode_str

        # Test within AgentEvent
        kwargs = make_valid_event_kwargs()
        kwargs["payload_redacted"] = {"text": unicode_str}
        event = AgentEvent(**kwargs)

        serialized = event.model_dump_json()
        assert "🛡️" in serialized
        assert "日本語テスト" in serialized
        restored = json.loads(serialized)
        assert restored["payload_redacted"]["text"] == unicode_str

    def test_none_values_in_optional_payload_fields(self):
        """Optional payload fields cleanly accept None without defaulting issues."""
        tool_payload = ToolInvocationPayload(
            tool_name="web_search",
            mcp_server=None,
            schema_sha256=None,
        )
        assert tool_payload.mcp_server is None
        assert tool_payload.schema_sha256 is None

        sandbox_payload = SandboxExecPayload(
            code_hash="sha256:abc123",
            blocked_import=None,
            error_message=None,
        )
        assert sandbox_payload.blocked_import is None
        assert sandbox_payload.error_message is None

        user_payload = UserInputPayload(user_input_redacted="hello", token_count=None)
        assert user_payload.token_count is None

        llm_payload = LlmGenerationPayload(generation_redacted="resp", model_name=None, token_count=None)
        assert llm_payload.model_name is None
        assert llm_payload.token_count is None

    def test_huge_string_values_in_payload(self):
        """Very large string values (1 MB) in sandbox stdout or LLM output serialize cleanly."""
        huge_str = "A" * 1_000_000
        sandbox_payload = SandboxExecPayload(
            code_hash="sha256:fedcba",
            stdout=huge_str,
            stderr="",
        )
        assert len(sandbox_payload.stdout) == 1_000_000
        dumped = sandbox_payload.model_dump_json()
        assert len(dumped) >= 1_000_000

    def test_hitl_decision_payload_persuasion_score_boundaries(self):
        """HitlDecisionPayload persuasion_score must be bounded by ge=0.0 and le=1.0."""
        # 0.0 and 1.0 are valid
        h_min = HitlDecisionPayload(
            ticket_id="TICK-01",
            approver_id="user-sec",
            tool_name="delete_account",
            decision="DENY",
            persuasion_score=0.0,
        )
        assert h_min.persuasion_score == 0.0

        h_max = HitlDecisionPayload(
            ticket_id="TICK-02",
            approver_id="user-sec",
            tool_name="delete_account",
            decision="DENY",
            persuasion_score=1.0,
        )
        assert h_max.persuasion_score == 1.0

        # Out of bounds
        with pytest.raises(ValidationError):
            HitlDecisionPayload(
                ticket_id="TICK-03",
                approver_id="user-sec",
                tool_name="delete_account",
                decision="DENY",
                persuasion_score=-0.01,
            )
        with pytest.raises(ValidationError):
            HitlDecisionPayload(
                ticket_id="TICK-04",
                approver_id="user-sec",
                tool_name="delete_account",
                decision="DENY",
                persuasion_score=1.0001,
            )

    def test_specialized_payloads_reject_extra_fields(self):
        """Injecting extra undeclared fields on specialized payloads raises ValidationError."""
        with pytest.raises(ValidationError):
            ToolInvocationPayload(
                tool_name="test_tool",
                undeclared_param="forbidden",
            )

        with pytest.raises(ValidationError):
            AgentCommPayload(
                message_id="msg-1",
                sender_agent_id="a1",
                receiver_agent_id="a2",
                injected_key="val",
            )


# ===========================================================================
# Feature 8: Package Scaffolding Boundaries (>=5 tests)
# ===========================================================================


class TestFeature8PackageScaffoldingBoundaries:
    """Boundary value analysis and corner cases for package scaffolding and exports."""

    def test_inspect_all_exported_symbols_completeness(self):
        """All canonical models, enums, payloads, and state machines are present in __all__."""
        import agentxdr
        import agentxdr.models

        required_symbols = [
            "AgentEvent",
            "Principal",
            "Decision",
            "DriftSnapshot",
            "EventType",
            "ProvenanceTier",
            "Verdict",
            "ToolTier",
            "PolicySchema",
            "ToolPolicy",
            "BudgetsConfig",
            "TaintState",
            "KillSwitchState",
            "KillSwitchScope",
            "KillSwitchRecord",
        ]

        for sym in required_symbols:
            assert sym in agentxdr.models.__all__, f"{sym} missing from agentxdr.models.__all__"
            assert hasattr(agentxdr.models, sym), f"{sym} not attribute of agentxdr.models"
            assert sym in agentxdr.__all__, f"{sym} missing from agentxdr.__all__"
            assert hasattr(agentxdr, sym), f"{sym} not attribute of agentxdr"

    def test_type_annotations_resolution_via_get_type_hints(self):
        """get_type_hints on core models resolves completely without NameError or unresolvable forward refs."""
        models_to_check = [
            AgentEvent,
            Principal,
            Decision,
            DriftSnapshot,
            PolicySchema,
            ToolPolicy,
            BudgetsConfig,
            TaintRule,
            ToolInvocationPayload,
            SandboxExecPayload,
            HitlDecisionPayload,
            MemoryMutationPayload,
            KillSwitchRecord,
        ]

        for model_cls in models_to_check:
            hints = get_type_hints(model_cls)
            assert isinstance(hints, dict)
            assert len(hints) > 0

    def test_verify_frozen_config_settings_on_all_pydantic_models(self):
        """All telemetry, policy, and payload Pydantic models must have frozen=True."""
        models_to_verify = [
            AgentEvent,
            Principal,
            Decision,
            DriftSnapshot,
            PolicySchema,
            ToolPolicy,
            BudgetsConfig,
            TaintRule,
            CodeSandboxConfig,
            DlpGuardrailConfig,
            PromptLeakConfig,
            OutputGuardrailsConfig,
            GoalAnchorConfig,
            ParameterConstraint,
            ToolInvocationPayload,
            SandboxExecPayload,
            HitlDecisionPayload,
            MemoryMutationPayload,
            UserInputPayload,
            LlmGenerationPayload,
            RagAccessPayload,
            AgentCommPayload,
            ResponseActionPayload,
            KillSwitchRecord,
        ]

        for model_cls in models_to_verify:
            assert model_cls.model_config.get("frozen") is True, f"{model_cls.__name__} is not frozen"

    def test_verify_extra_forbid_config_settings_on_all_pydantic_models(self):
        """All telemetry, policy, and payload Pydantic models must have extra='forbid'."""
        models_to_verify = [
            AgentEvent,
            Principal,
            Decision,
            DriftSnapshot,
            PolicySchema,
            ToolPolicy,
            BudgetsConfig,
            TaintRule,
            CodeSandboxConfig,
            DlpGuardrailConfig,
            PromptLeakConfig,
            OutputGuardrailsConfig,
            GoalAnchorConfig,
            ParameterConstraint,
            ToolInvocationPayload,
            SandboxExecPayload,
            HitlDecisionPayload,
            MemoryMutationPayload,
            UserInputPayload,
            LlmGenerationPayload,
            RagAccessPayload,
            AgentCommPayload,
            ResponseActionPayload,
            KillSwitchRecord,
        ]

        for model_cls in models_to_verify:
            assert model_cls.model_config.get("extra") == "forbid", f"{model_cls.__name__} does not forbid extra fields"

    def test_package_metadata_and_py_typed_marker(self):
        """Package has valid SemVer version and contains PEP 561 py.typed marker."""
        import agentxdr

        # Version check
        assert hasattr(agentxdr, "__version__")
        version_parts = agentxdr.__version__.split(".")
        assert len(version_parts) == 3
        for part in version_parts:
            assert part.isdigit()

        # py.typed marker check
        pkg_dir = Path(agentxdr.__file__).parent
        py_typed = pkg_dir / "py.typed"
        assert py_typed.exists(), "py.typed marker missing from package root"
