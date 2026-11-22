"""Opaque-Box Tier 1 Feature Coverage Tests for AgentXDR Core Models & Scaffolding.

Covers Features 1 through 8 from PROJECT.md and ORIGINAL_REQUEST.md:
- Feature 1: AgentEvent Envelope (>=5 tests)
- Feature 2: Principal, Decision, DriftSnapshot Sub-models (>=5 tests)
- Feature 3: Event Enums (>=5 tests)
- Feature 4: PolicySchema Declarative Model (>=5 tests)
- Feature 5: TaintState State Machine (>=5 tests)
- Feature 6: KillSwitchState Hierarchy (>=5 tests)
- Feature 7: Supporting Event Payloads (>=5 tests)
- Feature 8: Package Scaffolding (>=5 tests)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import re
import time
import uuid
import pytest
from pydantic import ValidationError

from agentxdr.models import (
    AgentCommPayload,
    AgentEvent,
    BudgetsConfig,
    Decision,
    DriftSnapshot,
    EventType,
    HitlDecisionPayload,
    KillSwitchRecord,
    KillSwitchScope,
    KillSwitchState,
    MemoryMutationPayload,
    PolicySchema,
    Principal,
    ProvenanceTier,
    ResponseActionPayload,
    SandboxExecPayload,
    TaintRule,
    TaintState,
    ToolInvocationPayload,
    ToolPolicy,
    ToolTier,
    Verdict,
)


# ===========================================================================
# Feature 1: AgentEvent Envelope
# ===========================================================================


class TestFeature1AgentEventEnvelope:
    """Tests for Feature 1: AgentEvent Envelope."""

    def test_agent_event_instantiation_valid(self, sample_event_kwargs: dict):
        """Verify happy-path instantiation with all valid fields."""
        event = AgentEvent(**sample_event_kwargs)
        assert event.trace_id == sample_event_kwargs["trace_id"]
        assert event.span_id == sample_event_kwargs["span_id"]
        assert event.agent_id == sample_event_kwargs["agent_id"]
        assert event.policy_version == sample_event_kwargs["policy_version"]
        assert event.event_type == EventType.USER_INPUT
        assert event.principal.user_id == sample_event_kwargs["principal"]["user_id"]
        assert event.provenance_tier == ProvenanceTier.AUTHENTICATED_USER
        assert event.decision.verdict == Verdict.ALLOW
        assert event.drift_snapshot.composite_score == 0.05
        assert event.payload_redacted == {"query": "Check network anomalies"}

    def test_agent_event_default_id_and_timestamp(self, sample_event_kwargs: dict):
        """Verify automatic default generation of event_id (UUID) and timestamp (UTC)."""
        kwargs = dict(sample_event_kwargs)
        del kwargs["event_id"]
        del kwargs["timestamp"]

        event = AgentEvent(**kwargs)
        assert event.event_id is not None
        # Must be valid UUID format
        parsed_uuid = uuid.UUID(event.event_id)
        assert str(parsed_uuid) == event.event_id
        # Must be timezone-aware UTC datetime
        assert event.timestamp is not None
        assert event.timestamp.tzinfo is not None

    def test_agent_event_unique_id_generation(self, sample_event_kwargs: dict):
        """Verify multiple events generate distinct event IDs."""
        kwargs = dict(sample_event_kwargs)
        kwargs.pop("event_id", None)
        events = [AgentEvent(**kwargs) for _ in range(5)]
        unique_ids = {e.event_id for e in events}
        assert len(unique_ids) == 5

    def test_agent_event_frozen_immutability(self, sample_event_kwargs: dict):
        """Verify that AgentEvent instances are strictly immutable (frozen=True)."""
        event = AgentEvent(**sample_event_kwargs)
        with pytest.raises((ValidationError, TypeError)):
            event.trace_id = "mutated-trace-id"  # type: ignore[misc]

        with pytest.raises((ValidationError, TypeError)):
            event.agent_id = "mutated-agent"  # type: ignore[misc]

        with pytest.raises((ValidationError, TypeError)):
            event.decision = Decision(verdict=Verdict.KILL, latency_ms=0.1)  # type: ignore[misc]

    def test_agent_event_extra_fields_forbidden(self, sample_event_kwargs: dict):
        """Verify that extra undeclared fields are strictly forbidden."""
        kwargs = dict(sample_event_kwargs)
        kwargs["malicious_extra_field"] = "injection_attempt"
        with pytest.raises(ValidationError) as exc_info:
            AgentEvent(**kwargs)
        assert "extra_forbidden" in str(exc_info.value) or "extra" in str(exc_info.value).lower()

    def test_agent_event_missing_required_fields_fails(self, sample_event_kwargs: dict):
        """Verify that omitting required fields raises ValidationError."""
        required_fields = ["trace_id", "span_id", "agent_id", "policy_version", "principal", "decision", "drift_snapshot"]
        for field in required_fields:
            kwargs = dict(sample_event_kwargs)
            del kwargs[field]
            with pytest.raises(ValidationError):
                AgentEvent(**kwargs)

    def test_agent_event_json_serialization_roundtrip(self, sample_event_kwargs: dict):
        """Verify full JSON serialization and deserialization preserves fidelity."""
        original = AgentEvent(**sample_event_kwargs)
        json_str = original.model_dump_json()

        # Check it is valid JSON
        data = json.loads(json_str)
        assert data["trace_id"] == original.trace_id
        assert data["event_type"] == "USER_INPUT"

        # Deserialize back
        restored = AgentEvent.model_validate_json(json_str)
        assert restored.event_id == original.event_id
        assert restored.trace_id == original.trace_id
        assert restored.span_id == original.span_id
        assert restored.parent_span_id == original.parent_span_id
        assert restored.agent_id == original.agent_id
        assert restored.policy_version == original.policy_version
        assert restored.event_type == original.event_type
        assert restored.provenance_tier == original.provenance_tier
        assert restored.principal == original.principal
        assert restored.decision == original.decision
        assert restored.drift_snapshot == original.drift_snapshot

    def test_agent_event_parent_span_id_optional(self, sample_event_kwargs: dict):
        """Verify parent_span_id can be None for root spans or a valid string for child spans."""
        root_kwargs = dict(sample_event_kwargs, parent_span_id=None)
        root_event = AgentEvent(**root_kwargs)
        assert root_event.parent_span_id is None

        child_kwargs = dict(sample_event_kwargs, parent_span_id="span-parent-000")
        child_event = AgentEvent(**child_kwargs)
        assert child_event.parent_span_id == "span-parent-000"


# ===========================================================================
# Feature 2: Principal, Decision, DriftSnapshot Sub-models
# ===========================================================================


class TestFeature2SubModels:
    """Tests for Feature 2: Principal, Decision, DriftSnapshot Sub-models."""

    def test_principal_roles_and_scopes(self):
        """Verify Principal fields, default lists, and non-empty user_id validation."""
        p = Principal(user_id="user-42")
        assert p.user_id == "user-42"
        assert p.roles == []
        assert p.effective_scopes == []

        p2 = Principal(
            user_id="analyst-1",
            roles=["soc_lead", "auditor"],
            effective_scopes=["telemetry:read", "quarantine:write"],
        )
        assert p2.roles == ["soc_lead", "auditor"]
        assert len(p2.effective_scopes) == 2

        # Empty user_id must fail
        with pytest.raises(ValidationError):
            Principal(user_id="")

    def test_principal_immutability_and_extra_forbid(self):
        """Verify Principal immutability and rejection of extra fields."""
        p = Principal(user_id="user-1")
        with pytest.raises((ValidationError, TypeError)):
            p.user_id = "user-2"  # type: ignore[misc]

        with pytest.raises(ValidationError):
            Principal(user_id="user-1", unexpected_attr="test")

    def test_decision_fields_and_latency_constraint(self):
        """Verify Decision verdicts, optional rule_id, owasp_ids, and non-negative latency constraint."""
        for verdict in Verdict:
            d = Decision(
                verdict=verdict,
                rule_id=f"RULE_{verdict.name}",
                owasp_ids=["ASI01", "ASI02"],
                latency_ms=1.23,
            )
            assert d.verdict == verdict
            assert d.latency_ms == 1.23

        # Boundary: latency_ms == 0.0 is valid
        d_zero = Decision(verdict=Verdict.ALLOW, latency_ms=0.0)
        assert d_zero.latency_ms == 0.0

        # Boundary: negative latency must raise ValidationError (ge=0.0)
        with pytest.raises(ValidationError):
            Decision(verdict=Verdict.ALLOW, latency_ms=-0.001)

    def test_decision_immutability_and_extra_forbid(self):
        """Verify Decision is frozen and forbids extra fields."""
        d = Decision(verdict=Verdict.ALLOW, latency_ms=1.0)
        with pytest.raises((ValidationError, TypeError)):
            d.verdict = Verdict.BLOCK  # type: ignore[misc]

        with pytest.raises(ValidationError):
            Decision(verdict=Verdict.ALLOW, latency_ms=1.0, extra_prop="bad")

    def test_drift_snapshot_bounded_scores(self):
        """Verify DriftSnapshot scores are strictly bounded in [0.0, 1.0]."""
        # Valid boundary values: 0.0 and 1.0
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

        # Out-of-bounds: below 0.0
        for field_name in ["composite_score", "s_policy", "s_graph", "s_velocity", "s_semantic"]:
            bad_kwargs = {f: 0.5 for f in ["composite_score", "s_policy", "s_graph", "s_velocity", "s_semantic"]}
            bad_kwargs[field_name] = -0.01
            with pytest.raises(ValidationError):
                DriftSnapshot(**bad_kwargs)

        # Out-of-bounds: above 1.0
        for field_name in ["composite_score", "s_policy", "s_graph", "s_velocity", "s_semantic"]:
            bad_kwargs = {f: 0.5 for f in ["composite_score", "s_policy", "s_graph", "s_velocity", "s_semantic"]}
            bad_kwargs[field_name] = 1.01
            with pytest.raises(ValidationError):
                DriftSnapshot(**bad_kwargs)

    def test_submodels_embedded_in_agent_event(self, sample_event_kwargs: dict):
        """Verify sub-models can be passed directly as instantiated Pydantic objects."""
        principal = Principal(user_id="sec-admin-99", roles=["admin"])
        decision = Decision(verdict=Verdict.PAUSE_FOR_HITL, rule_id="HITL-01", latency_ms=2.5)
        drift = DriftSnapshot(
            composite_score=0.76,
            s_policy=0.8,
            s_graph=0.7,
            s_velocity=0.5,
            s_semantic=0.6,
        )

        kwargs = dict(sample_event_kwargs)
        kwargs["principal"] = principal
        kwargs["decision"] = decision
        kwargs["drift_snapshot"] = drift

        event = AgentEvent(**kwargs)
        assert event.principal.user_id == "sec-admin-99"
        assert event.decision.verdict == Verdict.PAUSE_FOR_HITL
        assert event.drift_snapshot.composite_score == 0.76


# ===========================================================================
# Feature 3: Event Enums
# ===========================================================================


class TestFeature3EventEnums:
    """Tests for Feature 3: Event Enums."""

    def test_event_type_nine_members(self):
        """Verify EventType enum contains exactly the 9 required lifecycle events."""
        expected_members = {
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
        actual_members = {e.name for e in EventType}
        assert actual_members == expected_members
        assert len(EventType) == 9
        for member in EventType:
            assert member.value == member.name

    def test_provenance_tier_five_members(self):
        """Verify ProvenanceTier enum contains exactly the 5 required trust tiers."""
        expected_members = {
            "TRUSTED_SYSTEM",
            "AUTHENTICATED_USER",
            "RESTRICTED_INTERNAL",
            "VERIFIED_MEMORY",
            "UNTRUSTED_EXTERNAL",
        }
        actual_members = {p.name for p in ProvenanceTier}
        assert actual_members == expected_members
        assert len(ProvenanceTier) == 5

    def test_verdict_five_members(self):
        """Verify Verdict enum contains exactly the 5 canonical verdicts."""
        expected_members = {
            "ALLOW",
            "MASK_AND_ALLOW",
            "PAUSE_FOR_HITL",
            "BLOCK",
            "KILL",
        }
        actual_members = {v.name for v in Verdict}
        assert actual_members == expected_members
        assert len(Verdict) == 5

    def test_tool_tier_three_members(self):
        """Verify ToolTier enum contains exactly automatic, privileged_hitl, blocked."""
        expected_values = {"automatic", "privileged_hitl", "blocked"}
        actual_values = {t.value for t in ToolTier}
        assert actual_values == expected_values
        assert len(ToolTier) == 3

    def test_kill_switch_scope_five_members(self):
        """Verify KillSwitchScope contains GLOBAL, AGENT, SESSION, TOOL, MCP_SERVER."""
        expected_members = {
            "GLOBAL",
            "AGENT",
            "SESSION",
            "TOOL",
            "MCP_SERVER",
        }
        actual_members = {k.name for k in KillSwitchScope}
        assert actual_members == expected_members
        assert len(KillSwitchScope) == 5

    def test_enum_string_coercion_and_invalid_values(self):
        """Verify string coercion works and invalid enum values are rejected."""
        assert EventType("USER_INPUT") == EventType.USER_INPUT
        assert Verdict("ALLOW") == Verdict.ALLOW
        assert ToolTier("automatic") == ToolTier.AUTOMATIC

        with pytest.raises(ValueError):
            EventType("UNKNOWN_EVENT_TYPE")

        with pytest.raises(ValueError):
            Verdict("INVALID_VERDICT")

        with pytest.raises(ValueError):
            ToolTier("unrestricted")


# ===========================================================================
# Feature 4: PolicySchema Declarative Model
# ===========================================================================


class TestFeature4PolicySchema:
    """Tests for Feature 4: PolicySchema Declarative Model."""

    def test_policy_schema_parsing_from_yaml_str(self, sample_policy_yaml: str):
        """Verify parsing a valid YAML string into PolicySchema."""
        policy = PolicySchema.from_yaml_str(sample_policy_yaml)
        assert policy.version == "1.0.0"
        assert policy.agent_id == "sec-ops-agent"
        assert len(policy.tools) == 3
        assert len(policy.taint_rules) == 1
        assert policy.budgets.max_turns == 10
        assert policy.budgets.max_tool_calls == 25

    def test_policy_schema_tool_definitions(self, sample_policy_yaml: str):
        """Verify tool tiers, schema hashes, and parameter constraints."""
        policy = PolicySchema.from_yaml_str(sample_policy_yaml)
        tools_by_name = {t.name: t for t in policy.tools}

        safe_search = tools_by_name["safe_search"]
        assert safe_search.tier == ToolTier.AUTOMATIC
        assert safe_search.schema_sha256 == "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        assert safe_search.parameters is not None
        assert "query" in safe_search.parameters
        assert safe_search.parameters["query"].max_length == 256
        assert safe_search.parameters["query"].pattern == "^[a-zA-Z0-9 _-]+$"

        execute_sql = tools_by_name["execute_sql"]
        assert execute_sql.tier == ToolTier.PRIVILEGED_HITL

        system_shell = tools_by_name["system_shell"]
        assert system_shell.tier == ToolTier.BLOCKED

    def test_policy_schema_taint_rules(self, sample_policy_yaml: str):
        """Verify taint rules structure and fields."""
        policy = PolicySchema.from_yaml_str(sample_policy_yaml)
        rule = policy.taint_rules[0]
        assert "UNTRUSTED_EXTERNAL" in rule.match_taints
        assert "execute_sql" in rule.blocked_tools
        assert "export_data" in rule.blocked_tools
        assert rule.action == "BLOCK"

    def test_policy_schema_budgets_validation(self):
        """Verify budget constraints enforce positive numbers."""
        valid_budgets = BudgetsConfig(
            max_turns=5,
            max_tool_calls=10,
            max_identical_calls=2,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        assert valid_budgets.max_turns == 5

        # Non-positive numbers must fail
        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=0,  # gt=0
                max_tool_calls=10,
                max_identical_calls=2,
                max_session_duration_sec=60.0,
                max_session_cost_usd=1.0,
            )

        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=5,
                max_tool_calls=-1,  # gt=0
                max_identical_calls=2,
                max_session_duration_sec=60.0,
                max_session_cost_usd=1.0,
            )

    def test_policy_schema_hash_calculation(self, sample_policy_yaml: str):
        """Verify canonical policy hash calculation is deterministic and formatted properly."""
        policy = PolicySchema.from_yaml_str(sample_policy_yaml)
        hash1 = policy.compute_policy_hash()
        hash2 = policy.compute_policy_hash()
        assert hash1 == hash2
        assert hash1.startswith("sha256:")
        # sha256: followed by 64 hex characters
        assert len(hash1) == 7 + 64

    def test_policy_schema_duplicate_tool_names_rejected(self):
        """Verify that duplicate tool names are rejected during policy validation."""
        duplicate_tools_yaml = """
version: "1.0.0"
agent_id: "agent-dup"
budgets:
  max_turns: 5
  max_tool_calls: 10
  max_identical_calls: 2
  max_session_duration_sec: 60
  max_session_cost_usd: 1.0
tools:
  - name: "search"
    tier: "automatic"
  - name: "search"
    tier: "blocked"
"""
        with pytest.raises(ValidationError) as exc_info:
            PolicySchema.from_yaml_str(duplicate_tools_yaml)
        assert "duplicate" in str(exc_info.value).lower()


# ===========================================================================
# Feature 5: TaintState State Machine
# ===========================================================================


class TestFeature5TaintState:
    """Tests for Feature 5: TaintState State Machine."""

    def test_taint_state_initial_state(self):
        """Verify initial empty and seeded state."""
        state_empty = TaintState("trace-101")
        assert state_empty.trace_id == "trace-101"
        assert state_empty.to_list() == []
        assert len(state_empty) == 0
        assert not state_empty.has_taint("UNTRUSTED_EXTERNAL")

        state_seeded = TaintState("trace-102", initial_taints=["UNTRUSTED_EXTERNAL"])
        assert state_seeded.has_taint("UNTRUSTED_EXTERNAL")
        assert state_seeded.to_list() == ["UNTRUSTED_EXTERNAL"]
        assert len(state_seeded) == 1

    def test_taint_state_add_taint(self):
        """Verify adding single taints monotonically."""
        state = TaintState("trace-103")
        state.add_taint("CONFIDENTIAL_RAG")
        assert state.has_taint("CONFIDENTIAL_RAG")
        assert "CONFIDENTIAL_RAG" in state
        assert not state.has_taint("UNTRUSTED_EXTERNAL")

    def test_taint_state_add_taints_bulk_and_idempotence(self):
        """Verify bulk taint additions and idempotency (no duplicate entries)."""
        state = TaintState("trace-104")
        state.add_taints(["CONTAINS_PII", "UNTRUSTED_EXTERNAL"])
        # Adding duplicates
        state.add_taint("CONTAINS_PII")
        state.add_taints(["UNTRUSTED_EXTERNAL", "CONTAINS_PII"])

        active = state.to_list()
        assert len(active) == 2
        assert active == ["CONTAINS_PII", "UNTRUSTED_EXTERNAL"]  # to_list is sorted

    def test_taint_state_matches_rule_subset(self):
        """Verify rule matching semantics: subset check against active taints."""
        state = TaintState("trace-105")
        state.add_taints(["UNTRUSTED_EXTERNAL", "CONTAINS_PII"])

        # Matching subset -> True
        assert state.matches_rule(["UNTRUSTED_EXTERNAL"]) is True
        assert state.matches_rule(["CONTAINS_PII"]) is True
        assert state.matches_rule(["UNTRUSTED_EXTERNAL", "CONTAINS_PII"]) is True

        # Non-matching (missing CONFIDENTIAL_RAG) -> False
        assert state.matches_rule(["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"]) is False
        assert state.matches_rule(["CONFIDENTIAL_RAG"]) is False

        # Empty rule match should be False
        assert state.matches_rule([]) is False

    def test_taint_state_monotonicity(self):
        """Verify that TaintState does not expose removal methods (strictly monotonic)."""
        state = TaintState("trace-106", initial_taints=["UNTRUSTED_EXTERNAL"])
        assert not hasattr(state, "remove_taint")
        assert not hasattr(state, "clear")
        assert state.has_taint("UNTRUSTED_EXTERNAL")

    def test_taint_state_validation_and_empty_inputs(self):
        """Verify invalid inputs to TaintState raise ValueError."""
        with pytest.raises(ValueError):
            TaintState("")

        with pytest.raises(ValueError):
            TaintState("   ")

        state = TaintState("trace-107")
        with pytest.raises(ValueError):
            state.add_taint("")

        with pytest.raises(ValueError):
            state.add_taint("   ")


# ===========================================================================
# Feature 6: KillSwitchState Hierarchy
# ===========================================================================


class TestFeature6KillSwitchState:
    """Tests for Feature 6: KillSwitchState Hierarchy."""

    def test_kill_switch_global_activation(self):
        """Verify GLOBAL scope halts all agents, traces, and tools."""
        ks = KillSwitchState()
        assert ks.is_killed("agent-1", "trace-1") is False

        ks.activate(
            scope=KillSwitchScope.GLOBAL,
            target_id="*",
            reason="Fleet-wide emergency halt",
            triggered_by="secops-lead",
        )

        assert ks.is_killed("agent-1", "trace-1") is True
        assert ks.is_killed("agent-2", "trace-2", tool_name="safe_search") is True
        assert ks.is_killed("any-agent", "any-trace", mcp_server="kb-server") is True

    def test_kill_switch_agent_activation(self):
        """Verify AGENT scope kills only the targeted agent."""
        ks = KillSwitchState()
        ks.activate(
            scope=KillSwitchScope.AGENT,
            target_id="compromised-agent",
            reason="Anomalous behavior detected",
            triggered_by="anomaly-detector",
        )

        assert ks.is_killed("compromised-agent", "trace-1") is True
        assert ks.is_killed("compromised-agent", "trace-2", tool_name="safe_search") is True
        # Other agents unaffected
        assert ks.is_killed("benign-agent", "trace-1") is False

    def test_kill_switch_session_activation(self):
        """Verify SESSION scope kills only the targeted trace_id."""
        ks = KillSwitchState()
        ks.activate(
            scope=KillSwitchScope.SESSION,
            target_id="trace-hijacked-999",
            reason="Prompt injection detected in session",
            triggered_by="pep-guardrail",
        )

        assert ks.is_killed("agent-1", "trace-hijacked-999") is True
        # Other sessions for the same agent are unaffected
        assert ks.is_killed("agent-1", "trace-normal-111") is False

    def test_kill_switch_tool_and_mcp_activation(self):
        """Verify TOOL and MCP_SERVER scopes kill targeted tools/servers only."""
        ks = KillSwitchState()
        ks.activate(
            scope=KillSwitchScope.TOOL,
            target_id="dangerous_shell",
            reason="CVE in tool discovered",
            triggered_by="secops",
        )
        ks.activate(
            scope=KillSwitchScope.MCP_SERVER,
            target_id="untrusted-mcp",
            reason="Shadow server disconnected",
            triggered_by="secops",
        )

        # Calling the killed tool is killed
        assert ks.is_killed("agent-1", "trace-1", tool_name="dangerous_shell") is True
        # Calling an unaffected tool is NOT killed
        assert ks.is_killed("agent-1", "trace-1", tool_name="safe_search") is False

        # Calling through the killed MCP server is killed
        assert ks.is_killed("agent-1", "trace-1", mcp_server="untrusted-mcp") is True
        # Calling through an unaffected MCP server is NOT killed
        assert ks.is_killed("agent-1", "trace-1", mcp_server="safe-mcp") is False

    def test_kill_switch_deactivation(self):
        """Verify deactivating an active kill switch restores normal operation."""
        ks = KillSwitchState()
        ks.activate(KillSwitchScope.AGENT, "agent-to-pause", "Maintenance", "admin")
        assert ks.is_killed("agent-to-pause", "trace-1") is True

        deactivated = ks.deactivate(KillSwitchScope.AGENT, "agent-to-pause")
        assert deactivated is True
        assert ks.is_killed("agent-to-pause", "trace-1") is False

        # Deactivating non-existent returns False
        assert ks.deactivate(KillSwitchScope.AGENT, "non-existent") is False

    def test_kill_switch_ttl_expiration(self):
        """Verify TTL expiration restores execution automatically."""
        ks = KillSwitchState()
        ks.activate(
            scope=KillSwitchScope.SESSION,
            target_id="trace-temp-blocked",
            reason="Temporary rate limit cooldown",
            triggered_by="breaker",
            ttl_seconds=1,
        )

        # Immediately active
        assert ks.is_killed("agent-1", "trace-temp-blocked") is True

        # Wait for TTL to elapse
        time.sleep(1.1)

        # Now expired and inactive
        assert ks.is_killed("agent-1", "trace-temp-blocked") is False

    def test_kill_switch_hierarchy_precedence(self):
        """Verify hierarchical precedence: GLOBAL overrides AGENT, AGENT overrides TOOL."""
        ks = KillSwitchState()
        # Activate GLOBAL
        ks.activate(KillSwitchScope.GLOBAL, "*", "Global lock", "admin")
        # Even with safe tool and safe agent, global halts everything
        assert ks.is_killed("safe-agent", "safe-trace", tool_name="safe-tool") is True


# ===========================================================================
# Feature 7: Supporting Event Payloads
# ===========================================================================


class TestFeature7SupportingEventPayloads:
    """Tests for Feature 7: Supporting Event Payloads."""

    def test_tool_invocation_payload_validation(self):
        """Verify ToolInvocationPayload structure, tier, and validation constraints."""
        payload = ToolInvocationPayload(
            tool_name="safe_search",
            mcp_server="kb-server",
            schema_sha256="abcdef1234567890",
            schema_hash_verified=True,
            arguments={"query": "security incident"},
            tier=ToolTier.AUTOMATIC,
            latency_ms=12.5,
            is_shadow_mcp=False,
        )
        assert payload.tool_name == "safe_search"
        assert payload.tier == ToolTier.AUTOMATIC
        assert payload.latency_ms == 12.5

        # Empty tool_name must fail
        with pytest.raises(ValidationError):
            ToolInvocationPayload(tool_name="")

        # Negative latency must fail
        with pytest.raises(ValidationError):
            ToolInvocationPayload(tool_name="valid", latency_ms=-1.0)

    def test_sandbox_exec_payload_validation(self):
        """Verify SandboxExecPayload fields and execution_time constraint."""
        payload = SandboxExecPayload(
            code_hash="sha256:11223344",
            blocked_import=None,
            error_message=None,
            exit_code=0,
            stdout="Analysis completed successfully.",
            stderr="",
            execution_time_sec=0.45,
        )
        assert payload.exit_code == 0
        assert payload.stdout == "Analysis completed successfully."
        assert payload.execution_time_sec == 0.45

        # Negative execution time must fail
        with pytest.raises(ValidationError):
            SandboxExecPayload(code_hash="sha256:11", execution_time_sec=-0.1)

    def test_hitl_decision_payload_validation(self):
        """Verify HitlDecisionPayload fields, decision literals, and persuasion bounds."""
        payload = HitlDecisionPayload(
            ticket_id="ticket-9988",
            approver_id="secops-analyst-1",
            tool_name="execute_sql",
            decision="APPROVE",
            persuasion_score=0.15,
            justification="Verified business requirement",
        )
        assert payload.decision == "APPROVE"
        assert payload.persuasion_score == 0.15

        # Invalid decision literal must fail
        with pytest.raises(ValidationError):
            HitlDecisionPayload(
                ticket_id="t-1",
                approver_id="a-1",
                tool_name="tool",
                decision="MAYBE",  # type: ignore[arg-type]
            )

        # Out-of-bounds persuasion score (> 1.0) must fail
        with pytest.raises(ValidationError):
            HitlDecisionPayload(
                ticket_id="t-1",
                approver_id="a-1",
                tool_name="tool",
                decision="APPROVE",
                persuasion_score=1.5,
            )

    def test_memory_mutation_payload_validation(self):
        """Verify MemoryMutationPayload operations (READ, WRITE, ROLLBACK)."""
        for op in ["READ", "WRITE", "ROLLBACK"]:
            payload = MemoryMutationPayload(
                operation=op,  # type: ignore[arg-type]
                key="session_context",
                previous_value_hash="sha256:prev",
                new_value_hash="sha256:new",
                commit_id="commit-0001",
                taint_labels=["UNTRUSTED_EXTERNAL"],
            )
            assert payload.operation == op

        # Invalid operation literal
        with pytest.raises(ValidationError):
            MemoryMutationPayload(
                operation="DELETE",  # type: ignore[arg-type]
                key="key",
                commit_id="c-1",
            )

    def test_response_action_and_agent_comm_payloads(self):
        """Verify ResponseActionPayload and AgentCommPayload."""
        comm = AgentCommPayload(
            message_id="msg-1234",
            sender_agent_id="agent-alpha",
            receiver_agent_id="agent-beta",
            action="request_data",
            signature_verified=True,
        )
        assert comm.message_id == "msg-1234"
        assert comm.signature_verified is True

        resp = ResponseActionPayload(
            response_type="BLOCKED_SECURITY_VIOLATION",
            details={"reason": "PII detected", "owasp_id": "ASI02"},
        )
        assert resp.response_type == "BLOCKED_SECURITY_VIOLATION"
        assert resp.details["owasp_id"] == "ASI02"

    def test_payload_redacted_embedding_in_agent_event(self, sample_event_kwargs: dict):
        """Verify structured payloads can be dumped into AgentEvent.payload_redacted."""
        tool_payload = ToolInvocationPayload(
            tool_name="safe_search",
            arguments={"query": "[REDACTED_PII]"},
            tier=ToolTier.AUTOMATIC,
            latency_ms=8.5,
        )
        kwargs = dict(sample_event_kwargs)
        kwargs["event_type"] = EventType.TOOL_INVOCATION
        kwargs["payload_redacted"] = tool_payload.model_dump()

        event = AgentEvent(**kwargs)
        assert event.payload_redacted["tool_name"] == "safe_search"
        assert event.payload_redacted["tier"] == "automatic"

        # Roundtrip JSON
        restored = AgentEvent.model_validate_json(event.model_dump_json())
        assert restored.payload_redacted["tool_name"] == "safe_search"


# ===========================================================================
# Feature 8: Package Scaffolding
# ===========================================================================


class TestFeature8PackageScaffolding:
    """Tests for Feature 8: Package Scaffolding."""

    def test_package_import(self):
        """Verify agentxdr top-level package can be imported and has version."""
        import agentxdr

        assert hasattr(agentxdr, "__version__")
        assert isinstance(agentxdr.__version__, str)

    def test_models_package_import(self):
        """Verify agentxdr.models package can be imported directly."""
        import agentxdr.models

        assert agentxdr.models is not None

    def test_models_package_exports(self):
        """Verify all canonical public symbols are exported from agentxdr.models."""
        import agentxdr.models as models

        expected_exports = [
            "AgentEvent",
            "Principal",
            "Decision",
            "DriftSnapshot",
            "EventType",
            "ProvenanceTier",
            "Verdict",
            "ToolTier",
            "KillSwitchScope",
            "KillSwitchState",
            "KillSwitchRecord",
            "TaintState",
            "PolicySchema",
            "BudgetsConfig",
            "ToolPolicy",
            "TaintRule",
            "ToolInvocationPayload",
            "SandboxExecPayload",
            "HitlDecisionPayload",
            "MemoryMutationPayload",
        ]
        for name in expected_exports:
            assert hasattr(models, name), f"Missing expected export: {name}"

    def test_py_typed_marker_presence(self):
        """Verify that PEP 561 py.typed marker file exists in package."""
        import agentxdr

        package_dir = Path(agentxdr.__file__).resolve().parent
        py_typed = package_dir / "py.typed"
        assert py_typed.exists(), f"py.typed not found at {py_typed}"

    def test_pyproject_toml_configuration(self):
        """Verify pyproject.toml exists and declares project metadata and dependencies."""
        workspace_root = Path(__file__).resolve().parent.parent.parent
        pyproject_path = workspace_root / "pyproject.toml"
        assert pyproject_path.exists(), "pyproject.toml not found at workspace root"

        content = pyproject_path.read_text(encoding="utf-8")
        assert "name = " in content
        assert "pydantic" in content
        assert "pyyaml" in content
        assert "pytest" in content

    def test_package_version_semver_format(self):
        """Verify that agentxdr.__version__ complies with Semantic Versioning."""
        import agentxdr

        semver_pattern = r"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?(?:\+[a-zA-Z0-9.]+)?$"
        assert re.match(
            semver_pattern, agentxdr.__version__
        ), f"Version '{agentxdr.__version__}' does not match SemVer format"
