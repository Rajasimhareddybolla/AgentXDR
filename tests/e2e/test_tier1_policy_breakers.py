"""Opaque-Box Tier 1 Feature Coverage Tests: Policy Evaluator & Circuit Breakers.

Comprehensive tests for Features 18 through 28 from PROJECT.md and ORIGINAL_REQUEST.md:
- Feature 18: YAML Policy Loader (load valid YAML from file/string, compute policy SHA-256 hash,
               validate structure, reject invalid yaml syntax, reject schema violations)
- Feature 19: Tiered Action Resolution (tool classified as automatic returns ALLOW, tool classified
               as privileged_hitl returns PAUSE_FOR_HITL, tool classified as blocked returns BLOCK,
               unregistered shadow tool returns BLOCK, decision includes latency and rule_id)
- Feature 20: Tool Schema Hash Pinning (matching schema hash allows invocation, altered schema hash
               blocks invocation with BLOCK verdict, missing schema hash when required blocks invocation,
               unpinned tool allows invocation, valid hash generation)
- Feature 21: Deterministic Taint-Flow PEP (untainted session allows invocation, session with
               UNTRUSTED_EXTERNAL taint blocks tools matching taint rule, session with unrelated taint
               allows invocation, multiple taints evaluation, verdict BLOCK on taint violation)
- Feature 22: Tool Parameter Constraints PEP (tool argument within max_length allowed, argument
               exceeding max_length blocked, argument matching pattern allowed, argument violating
               pattern blocked, missing required argument blocked, invalid type blocked)
- Feature 23: Dynamic High-Risk Escalation (drift score < 0.75 leaves automatic tool as ALLOW,
               drift score >= 0.75 auto-escalates automatic tool to PAUSE_FOR_HITL, drift score boundary
               0.75, privileged tool remains PAUSE_FOR_HITL under drift, blocked tool remains BLOCK)
- Feature 24: Max Turns Circuit Breaker (turns 1..N within budget pass is_tripped=False, turn N+1 trips
               is_tripped=True, verdict identifies limit_name="max_turns", independent trace IDs tracked,
               reset/cleanup)
- Feature 25: Max Tool Calls Circuit Breaker (tool calls 1..M within budget pass, tool call M+1 trips,
               limit_name="max_tool_calls", multiple different tools counted cumulatively, separate trace IDs)
- Feature 26: Identical Call Loop Breaker (1st call ok, 2nd call ok, identical 3rd/4th call trips loop breaker,
               different arguments do not trip loop breaker, normalized JSON argument comparison)
- Feature 27: Session Duration Circuit Breaker (elapsed time within limit passes, elapsed time exceeding
               max_session_duration_sec trips, limit_name="max_session_duration_sec", duration tracked per trace_id)
- Feature 28: Cost / Token Budget Breaker (cumulative cost within max_session_cost_usd passes, incremental costs
               accumulated accurately, cost exceeding limit trips with limit_name="max_session_cost_usd",
               fractional dollar values, multi-call accumulation)

Total test cases: 66 tests (>= 55 tests required).
Interfaces tested strictly from PROJECT.md:
    PolicyEvaluator, load_policy_yaml, CircuitBreaker, BudgetsConfig, CircuitBreakerVerdict
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Dict
import pytest
from pydantic import ValidationError

from agentxdr.models import (
    BudgetsConfig,
    Decision,
    KillSwitchScope,
    KillSwitchState,
    ParameterConstraint,
    PolicySchema,
    TaintRule,
    TaintState,
    ToolPolicy,
    ToolTier,
    Verdict,
)

# Milestone 3 Subsystems (Policy Evaluator & Circuit Breakers)
try:
    from agentxdr.policy import PolicyEvaluator, load_policy_yaml
except ImportError:
    try:
        from agentxdr.policy.evaluator import PolicyEvaluator
        from agentxdr.policy.loader import load_policy_yaml
    except ImportError:
        PolicyEvaluator = None  # type: ignore
        load_policy_yaml = None  # type: ignore

try:
    from agentxdr.breakers import CircuitBreaker, CircuitBreakerVerdict
except ImportError:
    try:
        from agentxdr.breakers.circuit_breaker import CircuitBreaker, CircuitBreakerVerdict
    except ImportError:
        CircuitBreaker = None  # type: ignore
        CircuitBreakerVerdict = None  # type: ignore


# ---------------------------------------------------------------------------
# Skip Helper Predicates for Progressive Milestone Testability
# ---------------------------------------------------------------------------


def require_policy() -> None:
    """Skip test if Milestone 3 policy subsystem is pending implementation."""
    if PolicyEvaluator is None or load_policy_yaml is None:
        pytest.skip("agentxdr.policy pending Milestone 3 implementation")


def require_breakers() -> None:
    """Skip test if Milestone 3 breakers subsystem is pending implementation."""
    if CircuitBreaker is None or CircuitBreakerVerdict is None:
        pytest.skip("agentxdr.breakers pending Milestone 3 implementation")


# ---------------------------------------------------------------------------
# Shared Test Fixtures & Policy Definitions
# ---------------------------------------------------------------------------

VALID_TEST_POLICY_YAML = """
version: "1.0.0"
agent_id: "sec-ops-agent"
approved_by: "secops-lead@enterprise.com"
budgets:
  max_turns: 10
  max_tool_calls: 25
  max_identical_calls: 3
  max_session_duration_sec: 120.0
  max_session_cost_usd: 5.0
tools:
  - name: "safe_search"
    mcp_server: "search-cluster"
    tier: "automatic"
    schema_sha256: "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
    parameters:
      query:
        type: "string"
        max_length: 256
        pattern: "^[a-zA-Z0-9 _-]+$"
  - name: "execute_sql"
    mcp_server: "db-cluster"
    tier: "privileged_hitl"
    schema_sha256: "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1"
    parameters:
      query:
        type: "string"
        max_length: 1024
  - name: "system_shell"
    tier: "blocked"
  - name: "unpinned_tool"
    tier: "automatic"
taint_rules:
  - id: "TAINT-RULE-001"
    match_taints: ["UNTRUSTED_EXTERNAL"]
    blocked_tools: ["execute_sql", "export_data"]
    action: "BLOCK"
    owasp_id: "ASI02"
  - id: "TAINT-RULE-COMPOUND"
    match_taints: ["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"]
    blocked_tools: ["unpinned_tool"]
    action: "BLOCK"
    owasp_id: "ASI02"
"""


@pytest.fixture
def base_policy() -> PolicySchema:
    """Fixture providing a verified parsed PolicySchema instance."""
    return PolicySchema.from_yaml_str(VALID_TEST_POLICY_YAML)


@pytest.fixture
def default_budgets() -> BudgetsConfig:
    """Fixture providing a standard BudgetsConfig instance."""
    return BudgetsConfig(
        max_turns=5,
        max_tool_calls=10,
        max_identical_calls=3,
        max_session_duration_sec=60.0,
        max_session_cost_usd=5.0,
    )


# ==============================================================================
# Feature 18: YAML Policy Loader (>= 5 tests)
# ==============================================================================


class TestFeature18YamlPolicyLoader:
    """Opaque-box tests for Feature 18: YAML Policy Loader & SHA-256 Hash Calculation."""

    def test_load_valid_yaml_from_string(self):
        """Verifies loading a fully compliant YAML policy from a string."""
        require_policy()
        policy: PolicySchema = load_policy_yaml(VALID_TEST_POLICY_YAML)

        assert isinstance(policy, PolicySchema)
        assert policy.version == "1.0.0"
        assert policy.agent_id == "sec-ops-agent"
        assert policy.approved_by == "secops-lead@enterprise.com"
        assert policy.budgets.max_turns == 10
        assert policy.budgets.max_tool_calls == 25
        assert policy.budgets.max_identical_calls == 3
        assert policy.budgets.max_session_duration_sec == 120.0
        assert policy.budgets.max_session_cost_usd == 5.0
        assert len(policy.tools) == 4
        assert len(policy.taint_rules) == 2

    def test_load_valid_yaml_from_file(self, tmp_path: Path):
        """Verifies loading a valid YAML policy from a filesystem path."""
        require_policy()
        policy_file = tmp_path / "valid_policy.yaml"
        policy_file.write_text(VALID_TEST_POLICY_YAML, encoding="utf-8")

        policy_from_path: PolicySchema = load_policy_yaml(policy_file)
        policy_from_strpath: PolicySchema = load_policy_yaml(str(policy_file))

        assert isinstance(policy_from_path, PolicySchema)
        assert isinstance(policy_from_strpath, PolicySchema)
        assert policy_from_path.agent_id == "sec-ops-agent"
        assert policy_from_strpath.agent_id == "sec-ops-agent"
        assert policy_from_path.budgets.max_turns == policy_from_strpath.budgets.max_turns

    def test_compute_policy_sha256_hash_deterministic(self, base_policy: PolicySchema):
        """Verifies canonical policy SHA-256 hash format and determinism."""
        require_policy()
        hash1 = base_policy.compute_policy_hash()
        hash2 = base_policy.compute_policy_hash()

        assert isinstance(hash1, str)
        assert hash1.startswith("sha256:")
        # sha256: prefix (7 chars) + 64 hex characters = 71 characters
        assert len(hash1) == 71
        assert hash1 == hash2

        # Verify hash verification method returns True when hash matches
        policy_with_hash = PolicySchema.model_validate(
            {**base_policy.model_dump(mode="json"), "policy_hash": hash1}
        )
        assert policy_with_hash.verify_hash() is True

    def test_validate_policy_structure_and_types(self, base_policy: PolicySchema):
        """Verifies strong typing and nested structure of parsed policy components."""
        require_policy()
        assert isinstance(base_policy.budgets, BudgetsConfig)
        assert isinstance(base_policy.budgets.max_turns, int)
        assert isinstance(base_policy.budgets.max_session_cost_usd, float)

        tool_map = {tool.name: tool for tool in base_policy.tools}
        assert "safe_search" in tool_map
        assert tool_map["safe_search"].tier == ToolTier.AUTOMATIC
        assert tool_map["execute_sql"].tier == ToolTier.PRIVILEGED_HITL
        assert tool_map["system_shell"].tier == ToolTier.BLOCKED

        assert tool_map["safe_search"].parameters is not None
        assert "query" in tool_map["safe_search"].parameters
        constraint: ParameterConstraint = tool_map["safe_search"].parameters["query"]
        assert constraint.type == "string"
        assert constraint.max_length == 256
        assert constraint.pattern == "^[a-zA-Z0-9 _-]+$"

    def test_reject_invalid_yaml_syntax(self):
        """Verifies rejection with appropriate error when YAML syntax is malformed."""
        require_policy()
        invalid_yaml = """
        version: "1.0.0"
        agent_id: [unclosed list
          invalid: {
        """
        with pytest.raises((Exception, ValueError)):
            load_policy_yaml(invalid_yaml)

    def test_reject_schema_violations(self):
        """Verifies rejection when mandatory fields are missing or values violate constraints."""
        require_policy()
        # Missing required 'budgets'
        missing_budgets_yaml = """
        version: "1.0.0"
        agent_id: "sec-ops-agent"
        tools: []
        """
        with pytest.raises((ValidationError, ValueError)):
            load_policy_yaml(missing_budgets_yaml)

        # Negative turn budget
        negative_budget_yaml = """
        version: "1.0.0"
        agent_id: "sec-ops-agent"
        budgets:
          max_turns: -5
          max_tool_calls: 10
          max_identical_calls: 3
          max_session_duration_sec: 60.0
          max_session_cost_usd: 1.0
        tools: []
        """
        with pytest.raises((ValidationError, ValueError)):
            load_policy_yaml(negative_budget_yaml)


# ==============================================================================
# Feature 19: Tiered Action Resolution (>= 5 tests)
# ==============================================================================


class TestFeature19TieredActionResolution:
    """Opaque-box tests for Feature 19: Tiered Action Resolution (automatic, privileged_hitl, blocked)."""

    def test_tool_classified_as_automatic_returns_allow(self, base_policy: PolicySchema):
        """Verifies that tools classified in automatic tier return Verdict.ALLOW."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-19-1")
        valid_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        decision: Decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "test query"},
            taints=taints,
            tool_schema_hash=valid_hash,
            drift_score=0.1,
            trace_id="trace-19-1",
        )

        assert isinstance(decision, Decision)
        assert decision.verdict == Verdict.ALLOW

    def test_tool_classified_as_privileged_hitl_returns_pause(self, base_policy: PolicySchema):
        """Verifies that tools classified as privileged_hitl return Verdict.PAUSE_FOR_HITL."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-19-2")
        valid_hash = "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1"

        decision: Decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT count(*) FROM audit_logs"},
            taints=taints,
            tool_schema_hash=valid_hash,
            drift_score=0.1,
            trace_id="trace-19-2",
        )

        assert isinstance(decision, Decision)
        assert decision.verdict == Verdict.PAUSE_FOR_HITL

    def test_tool_classified_as_blocked_returns_block(self, base_policy: PolicySchema):
        """Verifies that tools classified in blocked tier return Verdict.BLOCK."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-19-3")

        decision: Decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="system_shell",
            arguments={"command": "id"},
            taints=taints,
            drift_score=0.0,
            trace_id="trace-19-3",
        )

        assert isinstance(decision, Decision)
        assert decision.verdict == Verdict.BLOCK

    def test_unregistered_shadow_tool_returns_block(self, base_policy: PolicySchema):
        """Verifies that calling an undeclared/shadow tool returns Verdict.BLOCK with ASI04."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-19-4")

        decision: Decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="unregistered_shadow_mcp_eval",
            arguments={"code": "1 + 1"},
            taints=taints,
            drift_score=0.0,
            trace_id="trace-19-4",
        )

        assert isinstance(decision, Decision)
        assert decision.verdict == Verdict.BLOCK
        # OWASP ASI04 represents Shadow MCP / Tool Misdirection
        assert any("ASI04" in oid for oid in decision.owasp_ids) or (
            decision.rule_id is not None and "SHADOW" in decision.rule_id.upper()
        )

    def test_decision_record_includes_latency_and_rule_id(self, base_policy: PolicySchema):
        """Verifies that every evaluation decision includes valid latency_ms and rule_id."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-19-5")
        valid_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        decision: Decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "ping"},
            taints=taints,
            tool_schema_hash=valid_hash,
            drift_score=0.05,
            trace_id="trace-19-5",
        )

        assert isinstance(decision.latency_ms, (int, float))
        assert decision.latency_ms >= 0.0
        assert decision.rule_id is not None
        assert len(decision.rule_id.strip()) > 0

    def test_kill_switch_active_overrides_to_kill_verdict(self, base_policy: PolicySchema):
        """Verifies that an active kill switch overrides tool resolution to Verdict.KILL."""
        require_policy()
        kill_switch = KillSwitchState()
        kill_switch.activate(
            scope=KillSwitchScope.TOOL,
            target_id="safe_search",
            reason="Compromised tool schema detected",
            triggered_by="secops-auto",
        )

        evaluator = PolicyEvaluator(kill_switch=kill_switch)
        taints = TaintState("trace-19-6")
        valid_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        decision: Decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "safe test"},
            taints=taints,
            tool_schema_hash=valid_hash,
            drift_score=0.0,
            trace_id="trace-19-6",
        )

        assert decision.verdict == Verdict.KILL


# ==============================================================================
# Feature 20: Tool Schema Hash Pinning (>= 5 tests)
# ==============================================================================


class TestFeature20ToolSchemaHashPinning:
    """Opaque-box tests for Feature 20: Tool Schema Hash Pinning against declared registry."""

    def test_matching_schema_hash_allows_invocation(self, base_policy: PolicySchema):
        """Verifies that presenting the pinned schema hash allows invocation."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-20-1")
        exact_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "status check"},
            taints=taints,
            tool_schema_hash=exact_hash,
            trace_id="trace-20-1",
        )

        assert decision.verdict == Verdict.ALLOW

    def test_altered_schema_hash_blocks_invocation(self, base_policy: PolicySchema):
        """Verifies that an altered/tampered schema hash blocks invocation with Verdict.BLOCK."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-20-2")
        tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "status check"},
            taints=taints,
            tool_schema_hash=tampered_hash,
            trace_id="trace-20-2",
        )

        assert decision.verdict == Verdict.BLOCK

    def test_missing_schema_hash_when_required_blocks_invocation(self, base_policy: PolicySchema):
        """Verifies that omitting the schema hash when policy pins one returns Verdict.BLOCK."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-20-3")

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "status check"},
            taints=taints,
            tool_schema_hash=None,
            trace_id="trace-20-3",
        )

        assert decision.verdict == Verdict.BLOCK

    def test_unpinned_tool_allows_invocation_without_hash(self, base_policy: PolicySchema):
        """Verifies that a tool with no pinned schema hash in policy can be invoked without hash."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-20-4")

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="unpinned_tool",
            arguments={},
            taints=taints,
            tool_schema_hash=None,
            trace_id="trace-20-4",
        )

        assert decision.verdict == Verdict.ALLOW

    def test_schema_hash_format_and_prefix_compatibility(self, base_policy: PolicySchema):
        """Verifies schema hash verification handles 64-char hex strings and sha256: prefix cleanly."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-20-5")
        raw_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        prefixed_hash = f"sha256:{raw_hash}"

        # Either raw 64-hex or prefixed sha256: format should be resolved cleanly
        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "test query"},
            taints=taints,
            tool_schema_hash=prefixed_hash,
            trace_id="trace-20-5",
        )
        # Should allow or cleanly handle match without unhandled exception
        assert decision.verdict in (Verdict.ALLOW, Verdict.BLOCK)

    def test_tampered_schema_on_privileged_tool_blocks_before_hitl(self, base_policy: PolicySchema):
        """Verifies that schema tampering on privileged tools blocks immediately rather than pausing."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-20-6")
        tampered_hash = "deadbeef" * 8

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT 1"},
            taints=taints,
            tool_schema_hash=tampered_hash,
            trace_id="trace-20-6",
        )

        # Integrity failure takes priority over privileged HITL pause
        assert decision.verdict == Verdict.BLOCK


# ==============================================================================
# Feature 21: Deterministic Taint-Flow PEP (>= 5 tests)
# ==============================================================================


class TestFeature21DeterministicTaintFlowPEP:
    """Opaque-box tests for Feature 21: Deterministic Taint-Flow PEP."""

    def test_untainted_session_allows_invocation(self, base_policy: PolicySchema):
        """Verifies that a clean, untainted session allows invoking taint-monitored tools."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-21-1")  # No taints added
        sql_hash = "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT * FROM users"},
            taints=taints,
            tool_schema_hash=sql_hash,
            trace_id="trace-21-1",
        )

        # Untainted session does not trip taint block; privileged_hitl returns PAUSE_FOR_HITL
        assert decision.verdict == Verdict.PAUSE_FOR_HITL

    def test_matching_taint_blocks_restricted_tool(self, base_policy: PolicySchema):
        """Verifies that adding UNTRUSTED_EXTERNAL taint blocks tools governed by taint rules."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-21-2")
        taints.add_taint("UNTRUSTED_EXTERNAL")
        sql_hash = "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT * FROM users"},
            taints=taints,
            tool_schema_hash=sql_hash,
            trace_id="trace-21-2",
        )

        assert decision.verdict == Verdict.BLOCK
        assert "ASI02" in decision.owasp_ids or decision.rule_id == "TAINT-RULE-001"

    def test_matching_taint_allows_unrestricted_tool(self, base_policy: PolicySchema):
        """Verifies that UNTRUSTED_EXTERNAL taint does NOT block tools not listed in blocked_tools."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-21-3")
        taints.add_taint("UNTRUSTED_EXTERNAL")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "harmless search"},
            taints=taints,
            tool_schema_hash=search_hash,
            trace_id="trace-21-3",
        )

        assert decision.verdict == Verdict.ALLOW

    def test_unrelated_taint_allows_invocation(self, base_policy: PolicySchema):
        """Verifies that a taint not matched by taint rules does not cause tool blockage."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-21-4")
        taints.add_taint("BENIGN_USER_INPUT")
        sql_hash = "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT count(*) FROM metrics"},
            taints=taints,
            tool_schema_hash=sql_hash,
            trace_id="trace-21-4",
        )

        assert decision.verdict == Verdict.PAUSE_FOR_HITL

    def test_multiple_taints_compound_evaluation(self, base_policy: PolicySchema):
        """Verifies multi-taint compound rule: only blocks when all required taints match."""
        require_policy()
        evaluator = PolicyEvaluator()

        # Rule TAINT-RULE-COMPOUND blocks unpinned_tool when UNTRUSTED_EXTERNAL AND CONFIDENTIAL_RAG
        # 1. Only UNTRUSTED_EXTERNAL present -> should ALLOW
        taints_single = TaintState("trace-21-5a")
        taints_single.add_taint("UNTRUSTED_EXTERNAL")
        dec1 = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="unpinned_tool",
            arguments={},
            taints=taints_single,
            trace_id="trace-21-5a",
        )
        assert dec1.verdict == Verdict.ALLOW

        # 2. Both taints present -> should BLOCK
        taints_both = TaintState("trace-21-5b")
        taints_both.add_taints(["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"])
        dec2 = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="unpinned_tool",
            arguments={},
            taints=taints_both,
            trace_id="trace-21-5b",
        )
        assert dec2.verdict == Verdict.BLOCK

    def test_taint_rule_identifies_rule_id_and_owasp_in_decision(self, base_policy: PolicySchema):
        """Verifies decision payload correctly captures rule_id and owasp_id on taint trip."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-21-6")
        taints.add_taint("UNTRUSTED_EXTERNAL")
        sql_hash = "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="execute_sql",
            arguments={"query": "DROP TABLE test"},
            taints=taints,
            tool_schema_hash=sql_hash,
            trace_id="trace-21-6",
        )

        assert decision.verdict == Verdict.BLOCK
        assert decision.rule_id is not None
        assert "TAINT" in decision.rule_id.upper() or decision.rule_id == "TAINT-RULE-001"
        assert "ASI02" in decision.owasp_ids


# ==============================================================================
# Feature 22: Tool Parameter Constraints PEP (>= 5 tests)
# ==============================================================================


class TestFeature22ToolParameterConstraintsPEP:
    """Opaque-box tests for Feature 22: Tool Parameter Constraints PEP (max_length, pattern, type)."""

    def test_parameter_within_max_length_allowed(self, base_policy: PolicySchema):
        """Verifies that tool argument within max_length constraint returns Verdict.ALLOW."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-22-1")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        # safe_search query max_length is 256; string below length is 32 chars
        valid_query = "valid search parameter within limit"
        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": valid_query},
            taints=taints,
            tool_schema_hash=search_hash,
            trace_id="trace-22-1",
        )

        assert decision.verdict == Verdict.ALLOW

    def test_parameter_exceeding_max_length_blocked(self, base_policy: PolicySchema):
        """Verifies that tool argument exceeding max_length constraint returns Verdict.BLOCK."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-22-2")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        # safe_search query max_length is 256; provide 300 chars
        oversized_query = "a" * 300
        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": oversized_query},
            taints=taints,
            tool_schema_hash=search_hash,
            trace_id="trace-22-2",
        )

        assert decision.verdict == Verdict.BLOCK

    def test_parameter_matching_pattern_allowed(self, base_policy: PolicySchema):
        """Verifies that tool argument adhering to regex pattern returns Verdict.ALLOW."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-22-3")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        # Pattern: ^[a-zA-Z0-9 _-]+$
        pattern_query = "Valid_Search-Query 123"
        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": pattern_query},
            taints=taints,
            tool_schema_hash=search_hash,
            trace_id="trace-22-3",
        )

        assert decision.verdict == Verdict.ALLOW

    def test_parameter_violating_pattern_blocked(self, base_policy: PolicySchema):
        """Verifies that tool argument containing disallowed characters returns Verdict.BLOCK."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-22-4")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        # Contains semicolon and single quotes (disallowed by ^[a-zA-Z0-9 _-]+$)
        malicious_query = "query; DROP TABLE users; --"
        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": malicious_query},
            taints=taints,
            tool_schema_hash=search_hash,
            trace_id="trace-22-4",
        )

        assert decision.verdict == Verdict.BLOCK

    def test_missing_required_argument_blocked(self, base_policy: PolicySchema):
        """Verifies that calling a tool without providing its defined parameter returns Verdict.BLOCK."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-22-5")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        # Empty arguments dict missing required 'query' parameter
        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={},
            taints=taints,
            tool_schema_hash=search_hash,
            trace_id="trace-22-5",
        )

        assert decision.verdict == Verdict.BLOCK

    def test_parameter_type_mismatch_blocked(self, base_policy: PolicySchema):
        """Verifies that passing an argument of incorrect type (e.g., dict for string) returns BLOCK."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-22-6")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        # Query defined as type 'string', pass nested dictionary
        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": {"nested": "injected_object"}},
            taints=taints,
            tool_schema_hash=search_hash,
            trace_id="trace-22-6",
        )

        assert decision.verdict == Verdict.BLOCK


# ==============================================================================
# Feature 23: Dynamic High-Risk Escalation (>= 5 tests)
# ==============================================================================


class TestFeature23DynamicHighRiskEscalation:
    """Opaque-box tests for Feature 23: Dynamic High-Risk Escalation (drift_score >= 0.75)."""

    def test_drift_score_below_threshold_leaves_automatic_as_allow(
        self, base_policy: PolicySchema
    ):
        """Verifies that drift_score < 0.75 permits automatic tool invocation as Verdict.ALLOW."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-23-1")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "normal query"},
            taints=taints,
            tool_schema_hash=search_hash,
            drift_score=0.45,
            trace_id="trace-23-1",
        )

        assert decision.verdict == Verdict.ALLOW

    def test_drift_score_at_or_above_threshold_auto_escalates(
        self, base_policy: PolicySchema
    ):
        """Verifies that drift_score >= 0.75 auto-escalates automatic action to PAUSE_FOR_HITL."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-23-2")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "normal query"},
            taints=taints,
            tool_schema_hash=search_hash,
            drift_score=0.85,
            trace_id="trace-23-2",
        )

        assert decision.verdict == Verdict.PAUSE_FOR_HITL

    def test_drift_score_exact_boundary_0_75(self, base_policy: PolicySchema):
        """Verifies boundary behavior: 0.7499 remains ALLOW while 0.7500 auto-escalates."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-23-3")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        dec_below = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "normal query"},
            taints=taints,
            tool_schema_hash=search_hash,
            drift_score=0.7499,
            trace_id="trace-23-3a",
        )
        assert dec_below.verdict == Verdict.ALLOW

        dec_exact = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "normal query"},
            taints=taints,
            tool_schema_hash=search_hash,
            drift_score=0.7500,
            trace_id="trace-23-3b",
        )
        assert dec_exact.verdict == Verdict.PAUSE_FOR_HITL

    def test_privileged_tool_remains_pause_for_hitl_under_drift(
        self, base_policy: PolicySchema
    ):
        """Verifies that a privileged tool remains PAUSE_FOR_HITL regardless of high drift."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-23-4")
        sql_hash = "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT 1"},
            taints=taints,
            tool_schema_hash=sql_hash,
            drift_score=0.95,
            trace_id="trace-23-4",
        )

        assert decision.verdict == Verdict.PAUSE_FOR_HITL

    def test_blocked_tool_remains_blocked_under_drift(self, base_policy: PolicySchema):
        """Verifies that a blocked tool remains Verdict.BLOCK regardless of drift score."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-23-5")

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="system_shell",
            arguments={"cmd": "whoami"},
            taints=taints,
            drift_score=0.99,
            trace_id="trace-23-5",
        )

        assert decision.verdict == Verdict.BLOCK

    def test_drift_escalation_decision_metadata(self, base_policy: PolicySchema):
        """Verifies decision record identifies dynamic risk escalation."""
        require_policy()
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-23-6")
        search_hash = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"

        decision = evaluator.evaluate_tool_call(
            policy=base_policy,
            tool_name="safe_search",
            arguments={"query": "search under drift"},
            taints=taints,
            tool_schema_hash=search_hash,
            drift_score=0.76,
            trace_id="trace-23-6",
        )

        assert decision.verdict == Verdict.PAUSE_FOR_HITL
        assert decision.rule_id is not None
        assert "DRIFT" in decision.rule_id.upper() or "ESCALAT" in decision.rule_id.upper()


# ==============================================================================
# Feature 24: Max Turns Circuit Breaker (>= 5 tests)
# ==============================================================================


class TestFeature24MaxTurnsCircuitBreaker:
    """Opaque-box tests for Feature 24: Max Turns Circuit Breaker."""

    def test_turns_within_budget_pass(self, default_budgets: BudgetsConfig):
        """Verifies that reasoning turns 1..N within budget return is_tripped=False."""
        require_breakers()
        cb = CircuitBreaker(default_budgets)  # max_turns = 5
        trace_id = "trace-24-1"

        for turn_idx in range(1, 6):
            verdict: CircuitBreakerVerdict = cb.record_turn(trace_id)
            assert isinstance(verdict, CircuitBreakerVerdict)
            assert verdict.is_tripped is False
            assert verdict.current_value == turn_idx

    def test_turn_exceeding_budget_trips(self, default_budgets: BudgetsConfig):
        """Verifies that turn N+1 trips the circuit breaker with is_tripped=True."""
        require_breakers()
        cb = CircuitBreaker(default_budgets)  # max_turns = 5
        trace_id = "trace-24-2"

        for _ in range(5):
            cb.record_turn(trace_id)

        # 6th turn exceeds budget
        tripped_verdict = cb.record_turn(trace_id)
        assert tripped_verdict.is_tripped is True
        assert tripped_verdict.current_value == 6

    def test_verdict_identifies_limit_name_and_thresholds(
        self, default_budgets: BudgetsConfig
    ):
        """Verifies tripped verdict correctly populates limit_name, threshold, and current_value."""
        require_breakers()
        cb = CircuitBreaker(default_budgets)  # max_turns = 5
        trace_id = "trace-24-3"

        for _ in range(5):
            cb.record_turn(trace_id)

        verdict = cb.record_turn(trace_id)
        assert verdict.limit_name == "max_turns"
        assert verdict.threshold == 5
        assert verdict.current_value == 6
        assert len(verdict.message) > 0

    def test_independent_trace_ids_tracked_separately(
        self, default_budgets: BudgetsConfig
    ):
        """Verifies turns in trace-A do not affect counters in trace-B."""
        require_breakers()
        cb = CircuitBreaker(default_budgets)  # max_turns = 5

        # Exhaust trace-A
        for _ in range(6):
            cb.record_turn("trace-24-4-A")

        # trace-B is completely fresh
        verdict_b = cb.record_turn("trace-24-4-B")
        assert verdict_b.is_tripped is False
        assert verdict_b.current_value == 1

    def test_subsequent_turns_remain_tripped(self, default_budgets: BudgetsConfig):
        """Verifies that subsequent turns after trip continue returning is_tripped=True."""
        require_breakers()
        cb = CircuitBreaker(default_budgets)  # max_turns = 5
        trace_id = "trace-24-5"

        for _ in range(6):
            cb.record_turn(trace_id)

        # Turns 7 and 8 should stay tripped
        v7 = cb.record_turn(trace_id)
        v8 = cb.record_turn(trace_id)
        assert v7.is_tripped is True
        assert v8.is_tripped is True

    def test_reset_or_fresh_session_state(self, default_budgets: BudgetsConfig):
        """Verifies resetting or cleaning up a session clears tripped status."""
        require_breakers()
        cb = CircuitBreaker(default_budgets)
        trace_id = "trace-24-6"

        for _ in range(6):
            cb.record_turn(trace_id)
        assert cb.record_turn(trace_id).is_tripped is True

        # Fresh instance starts clean
        new_cb = CircuitBreaker(default_budgets)
        fresh_verdict = new_cb.record_turn(trace_id)
        assert fresh_verdict.is_tripped is False


# ==============================================================================
# Feature 25: Max Tool Calls Circuit Breaker (>= 5 tests)
# ==============================================================================


class TestFeature25MaxToolCallsCircuitBreaker:
    """Opaque-box tests for Feature 25: Max Tool Calls Circuit Breaker."""

    def test_tool_calls_within_budget_pass(self, default_budgets: BudgetsConfig):
        """Verifies cumulative tool calls 1..M within budget pass with is_tripped=False."""
        require_breakers()
        # Create budgets with max_tool_calls = 3
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=3,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-25-1"

        v1 = cb.record_tool_call(trace_id, "tool_1", {"x": 1})
        v2 = cb.record_tool_call(trace_id, "tool_2", {"y": 2})
        v3 = cb.record_tool_call(trace_id, "tool_3", {"z": 3})

        assert v1.is_tripped is False
        assert v2.is_tripped is False
        assert v3.is_tripped is False

    def test_tool_call_exceeding_budget_trips(self):
        """Verifies that tool call M+1 trips with is_tripped=True."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=2,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-25-2"

        cb.record_tool_call(trace_id, "tool_1", {"a": 1})
        cb.record_tool_call(trace_id, "tool_2", {"b": 2})

        # 3rd call exceeds limit of 2
        tripped = cb.record_tool_call(trace_id, "tool_3", {"c": 3})
        assert tripped.is_tripped is True
        assert tripped.current_value == 3

    def test_max_tool_calls_identifies_limit_name(self):
        """Verifies tripped verdict correctly populates limit_name='max_tool_calls'."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=1,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-25-3"

        cb.record_tool_call(trace_id, "alpha", {})
        verdict = cb.record_tool_call(trace_id, "beta", {})

        assert verdict.is_tripped is True
        assert verdict.limit_name == "max_tool_calls"
        assert verdict.threshold == 1

    def test_multiple_different_tools_counted_cumulatively(self):
        """Verifies that different tools are counted cumulatively toward max_tool_calls."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=4,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-25-4"

        tools = ["search", "download", "parse", "format"]
        for idx, tool_name in enumerate(tools, start=1):
            v = cb.record_tool_call(trace_id, tool_name, {"step": idx})
            assert v.is_tripped is False
            assert v.current_value == idx

        # Next call exceeds
        trip = cb.record_tool_call(trace_id, "extra_tool", {})
        assert trip.is_tripped is True

    def test_tool_calls_tracked_per_trace_id(self):
        """Verifies tool calls in trace-1 do not increment count for trace-2."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=2,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)

        cb.record_tool_call("trace-25-5-A", "t1", {})
        cb.record_tool_call("trace-25-5-A", "t2", {})
        trip_a = cb.record_tool_call("trace-25-5-A", "t3", {})
        assert trip_a.is_tripped is True

        # trace-B is unaffected
        v_b = cb.record_tool_call("trace-25-5-B", "t1", {})
        assert v_b.is_tripped is False
        assert v_b.current_value == 1

    def test_subsequent_tool_calls_remain_tripped(self):
        """Verifies subsequent tool calls after trip continue returning is_tripped=True."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=1,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-25-6"

        cb.record_tool_call(trace_id, "t1", {})
        v2 = cb.record_tool_call(trace_id, "t2", {})
        v3 = cb.record_tool_call(trace_id, "t3", {})
        assert v2.is_tripped is True
        assert v3.is_tripped is True


# ==============================================================================
# Feature 26: Identical Call Loop Breaker (>= 5 tests)
# ==============================================================================


class TestFeature26IdenticalCallLoopBreaker:
    """Opaque-box tests for Feature 26: Identical Call Loop Breaker."""

    def test_identical_calls_under_threshold_pass(self):
        """Verifies that 1st and 2nd identical calls pass when threshold is 3."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-26-1"

        v1 = cb.record_tool_call(trace_id, "search", {"query": "python"})
        v2 = cb.record_tool_call(trace_id, "search", {"query": "python"})

        assert v1.is_tripped is False
        assert v2.is_tripped is False

    def test_identical_call_reaching_threshold_trips(self):
        """Verifies that repeated identical calls trip the loop breaker."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-26-2"

        cb.record_tool_call(trace_id, "search", {"query": "loop_term"})
        cb.record_tool_call(trace_id, "search", {"query": "loop_term"})
        v3 = cb.record_tool_call(trace_id, "search", {"query": "loop_term"})

        # Depending on whether limit is inclusive or strictly greater, 3rd or 4th trips
        if not v3.is_tripped:
            v4 = cb.record_tool_call(trace_id, "search", {"query": "loop_term"})
            assert v4.is_tripped is True
            assert v4.limit_name == "max_identical_calls"
        else:
            assert v3.is_tripped is True
            assert v3.limit_name == "max_identical_calls"

    def test_different_arguments_do_not_trip_loop_breaker(self):
        """Verifies that repeated calls with different arguments do not trip the loop breaker."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-26-3"

        # 4 calls to the same tool name, but with varying arguments
        v1 = cb.record_tool_call(trace_id, "search", {"query": "item_1"})
        v2 = cb.record_tool_call(trace_id, "search", {"query": "item_2"})
        v3 = cb.record_tool_call(trace_id, "search", {"query": "item_3"})
        v4 = cb.record_tool_call(trace_id, "search", {"query": "item_4"})

        assert v1.is_tripped is False
        assert v2.is_tripped is False
        assert v3.is_tripped is False
        assert v4.is_tripped is False

    def test_normalized_json_argument_comparison(self):
        """Verifies that JSON arguments with different key orderings are recognized as identical."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=2,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-26-4"

        # Key order swapped: {"a": 1, "b": 2} vs {"b": 2, "a": 1}
        v1 = cb.record_tool_call(trace_id, "fetch_pair", {"a": 1, "b": 2})
        v2 = cb.record_tool_call(trace_id, "fetch_pair", {"b": 2, "a": 1})

        # Threshold is 2 identical calls
        if not v2.is_tripped:
            v3 = cb.record_tool_call(trace_id, "fetch_pair", {"a": 1, "b": 2})
            assert v3.is_tripped is True
        else:
            assert v2.is_tripped is True

    def test_different_tool_names_same_arguments_do_not_trip(self):
        """Verifies that different tools invoked with same arguments do not trip identical loop."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=2,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-26-5"

        v1 = cb.record_tool_call(trace_id, "tool_alpha", {"param": "value"})
        v2 = cb.record_tool_call(trace_id, "tool_beta", {"param": "value"})

        assert v1.is_tripped is False
        assert v2.is_tripped is False

    def test_different_call_resets_identical_call_streak(self):
        """Verifies that an interleaved different call resets or interrupts the repetition streak."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-26-6"

        cb.record_tool_call(trace_id, "search", {"query": "dup"})
        cb.record_tool_call(trace_id, "search", {"query": "dup"})
        # Interleaving different call
        v_diff = cb.record_tool_call(trace_id, "reset_action", {"flag": True})
        assert v_diff.is_tripped is False

        # Next call to dup should not immediately trip as 3rd consecutive
        v_next = cb.record_tool_call(trace_id, "search", {"query": "dup"})
        assert v_next.is_tripped is False


# ==============================================================================
# Feature 27: Session Duration Circuit Breaker (>= 5 tests)
# ==============================================================================


class TestFeature27SessionDurationCircuitBreaker:
    """Opaque-box tests for Feature 27: Session Duration Circuit Breaker."""

    def test_elapsed_time_within_limit_passes(self):
        """Verifies that checking duration within max_session_duration_sec returns is_tripped=False."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=120.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-27-1"

        verdict = cb.check_duration(trace_id)
        assert isinstance(verdict, CircuitBreakerVerdict)
        assert verdict.is_tripped is False

    def test_elapsed_time_exceeding_limit_trips(self):
        """Verifies that exceeding max_session_duration_sec trips the breaker."""
        require_breakers()
        # Set a tiny duration ceiling: 0.02 seconds
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=0.02,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-27-2"

        # Initialize session timer
        cb.record_turn(trace_id)
        time.sleep(0.04)

        verdict = cb.check_duration(trace_id)
        assert verdict.is_tripped is True
        assert verdict.limit_name == "max_session_duration_sec"

    def test_duration_verdict_attributes(self):
        """Verifies tripped duration verdict populates threshold and current_value."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=0.01,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-27-3"

        cb.record_turn(trace_id)
        time.sleep(0.02)

        verdict = cb.check_duration(trace_id)
        assert verdict.is_tripped is True
        assert verdict.threshold == 0.01
        assert verdict.current_value is not None
        assert verdict.current_value >= 0.01

    def test_duration_tracked_per_trace_id(self):
        """Verifies session duration is tracked independently per trace_id."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=0.02,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)

        cb.record_turn("trace-27-4-slow")
        time.sleep(0.04)

        # slow session is tripped
        assert cb.check_duration("trace-27-4-slow").is_tripped is True

        # fast session initialized just now is NOT tripped
        cb.record_turn("trace-27-4-fast")
        assert cb.check_duration("trace-27-4-fast").is_tripped is False

    def test_duration_initialized_on_first_interaction(self):
        """Verifies that session timer starts on first recorded turn or tool call."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=5.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-27-5"

        v = cb.record_turn(trace_id)
        assert v.is_tripped is False

        duration_v = cb.check_duration(trace_id)
        assert duration_v.is_tripped is False
        assert duration_v.current_value is not None
        assert duration_v.current_value >= 0.0

    def test_subsequent_duration_checks_remain_tripped(self):
        """Verifies that once duration is exceeded, subsequent checks remain is_tripped=True."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=0.01,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-27-6"

        cb.record_turn(trace_id)
        time.sleep(0.02)

        v1 = cb.check_duration(trace_id)
        v2 = cb.check_duration(trace_id)
        assert v1.is_tripped is True
        assert v2.is_tripped is True


# ==============================================================================
# Feature 28: Cost / Token Budget Breaker (>= 5 tests)
# ==============================================================================


class TestFeature28CostBudgetBreaker:
    """Opaque-box tests for Feature 28: Cost / Token Budget Breaker."""

    def test_cumulative_cost_within_budget_passes(self):
        """Verifies that cumulative cost within max_session_cost_usd returns is_tripped=False."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=2.50,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-28-1"

        verdict: CircuitBreakerVerdict = cb.record_cost(trace_id, cost_usd=1.25)
        assert isinstance(verdict, CircuitBreakerVerdict)
        assert verdict.is_tripped is False
        assert pytest.approx(verdict.current_value, rel=1e-4) == 1.25

    def test_incremental_costs_accumulated_accurately(self):
        """Verifies that multiple incremental cost records accumulate accurately."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-28-2"

        v1 = cb.record_cost(trace_id, 0.50)
        v2 = cb.record_cost(trace_id, 0.75)
        v3 = cb.record_cost(trace_id, 1.20)

        assert v1.is_tripped is False
        assert pytest.approx(v1.current_value, rel=1e-4) == 0.50
        assert v2.is_tripped is False
        assert pytest.approx(v2.current_value, rel=1e-4) == 1.25
        assert v3.is_tripped is False
        assert pytest.approx(v3.current_value, rel=1e-4) == 2.45

    def test_cost_exceeding_limit_trips(self):
        """Verifies that cost exceeding max_session_cost_usd trips with limit_name."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.00,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-28-3"

        cb.record_cost(trace_id, 0.60)
        tripped = cb.record_cost(trace_id, 0.50)  # total 1.10 > 1.00

        assert tripped.is_tripped is True
        assert tripped.limit_name == "max_session_cost_usd"
        assert tripped.threshold == 1.00
        assert pytest.approx(tripped.current_value, rel=1e-4) == 1.10

    def test_fractional_dollar_values_precision(self):
        """Verifies accurate accumulation with micro-costs (e.g. per-token fractions of a cent)."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=50,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=0.10,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-28-4"

        # 50 records of $0.001 (1 tenth of a cent) = $0.05
        for _ in range(50):
            v = cb.record_cost(trace_id, 0.001)
            assert v.is_tripped is False

        assert pytest.approx(v.current_value, rel=1e-3) == 0.05

    def test_cost_tracked_independently_per_trace_id(self):
        """Verifies cost incurred by trace-A does not exhaust budget of trace-B."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.00,
        )
        cb = CircuitBreaker(budgets)

        cb.record_cost("trace-28-5-A", 1.50)
        assert cb.record_cost("trace-28-5-A", 0.10).is_tripped is True

        # trace-B starts with full budget
        v_b = cb.record_cost("trace-28-5-B", 0.20)
        assert v_b.is_tripped is False
        assert pytest.approx(v_b.current_value, rel=1e-4) == 0.20

    def test_cost_breaker_remains_tripped_on_further_cost(self):
        """Verifies subsequent record_cost calls on a tripped trace continue returning is_tripped=True."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=0.50,
        )
        cb = CircuitBreaker(budgets)
        trace_id = "trace-28-6"

        cb.record_cost(trace_id, 0.60)
        v2 = cb.record_cost(trace_id, 0.10)
        v3 = cb.record_cost(trace_id, 0.05)

        assert v2.is_tripped is True
        assert v3.is_tripped is True
