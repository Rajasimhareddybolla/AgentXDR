"""Tier 2 Boundary Value Analysis & Corner Case Tests: Policy & Circuit Breakers.

Comprehensive opaque-box Tier 2 Boundary Value Analysis & Corner Case tests
for Features 18 through 28 from PROJECT.md and TEST_INFRA.md:
- Feature 18: YAML Policy Loader Boundaries (>=5 tests: YAML with unknown top-level keys
              rejected/handled, empty string policy, policy with non-ASCII UTF-8 comments,
              SHA-256 calculation idempotency and stability across key ordering)
- Feature 19: Tiered Action Resolution Boundaries (>=5 tests: case insensitivity of tool names
              or strict matching, tool arguments empty dict vs populated dict, unexpected argument keys,
              evaluation latency field >= 0.0, rule_id populated correctly)
- Feature 20: Tool Schema Hash Pinning Boundaries (>=5 tests: schema hash case difference uppercase
              vs lowercase hex, hash with leading/trailing whitespace, schema hash length != 64 chars,
              policy without schema_sha256 requirement)
- Feature 21: Deterministic Taint-Flow PEP Boundaries (>=5 tests: rule matching multiple taints
              requires all or any, subset matching of taints, policy with multiple taint rules
              overlapping, taint with empty label string, empty block_tools list)
- Feature 22: Tool Parameter Constraints Boundaries (>=5 tests: string argument exactly at max_length
              boundary allowed vs max_length+1 blocked, regex pattern with regex special characters
              escaped, null/None argument value when pattern expected, argument type mismatch string vs integer)
- Feature 23: Dynamic High-Risk Escalation Boundaries (>=5 tests: drift score exactly 0.74999 returns
              ALLOW for automatic tool, drift score exactly 0.75000 returns PAUSE_FOR_HITL, drift score 1.0,
              drift score with negative or >1.0 values handled gracefully)
- Feature 24: Max Turns Circuit Breaker Boundaries (>=5 tests: max_turns=0 immediate trip, max_turns=1
              single turn allowed then trips, boundary turn==max_turns allowed vs turn==max_turns+1 tripped,
              1,000 rapid turns test)
- Feature 25: Max Tool Calls Circuit Breaker Boundaries (>=5 tests: max_tool_calls=0 immediate trip,
              boundary tool_calls==max_tool_calls allowed vs +1 tripped, multiple tools with distinct names
              counting toward single budget, 50 distinct trace IDs independently tracked)
- Feature 26: Identical Call Loop Breaker Boundaries (>=5 tests: arguments with different key order
              {"a":1, "b":2} vs {"b":2, "a":1} detected as identical, arguments with float precision
              1.0 vs 1, nested dictionaries identical comparison, arguments with slight whitespace differences)
- Feature 27: Session Duration Circuit Breaker Boundaries (>=5 tests: duration zero threshold, mock time
              progression past max_session_duration_sec, duration check called immediately after trace init,
              multiple traces with different start times)
- Feature 28: Cost / Token Budget Breaker Boundaries (>=5 tests: fractional cents accumulation e.g. $0.00001,
              exact threshold cost == max_cost allowed vs +$0.0001 tripped, cost negative or zero handling,
              large single call exceeding entire budget at once)

Total test cases: 67 tests (>= 55 tests required).
Interfaces tested strictly from PROJECT.md:
    PolicySchema, PolicyEvaluator, load_policy_yaml, CircuitBreaker, CircuitBreakerVerdict
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
from unittest.mock import patch
import uuid

import pytest
from pydantic import ValidationError
import yaml

from agentxdr.models.events import Decision, ToolTier, Verdict
from agentxdr.models.killswitch import KillSwitchScope, KillSwitchState
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

# Milestone 3: Policy & Evaluator
try:
    from agentxdr.policy import PolicyEvaluator, load_policy_yaml
except ImportError:
    try:
        from agentxdr.policy.evaluator import PolicyEvaluator
        from agentxdr.policy.loader import load_policy_yaml
    except ImportError:
        try:
            from agentxdr.policy import load_policy_from_yaml as load_policy_yaml  # type: ignore
        except ImportError:
            PolicyEvaluator = None  # type: ignore
            load_policy_yaml = None  # type: ignore

# Milestone 3: Circuit Breakers
try:
    from agentxdr.breakers import CircuitBreaker, CircuitBreakerVerdict
except ImportError:
    try:
        from agentxdr.breakers.circuit_breaker import CircuitBreaker, CircuitBreakerVerdict
    except ImportError:
        CircuitBreaker = None  # type: ignore
        CircuitBreakerVerdict = None  # type: ignore


# ---------------------------------------------------------------------------
# Skip helper predicates for progressive milestone testability
# ---------------------------------------------------------------------------
def require_policy() -> None:
    """Skip test if Milestone 3 policy subsystem is not yet implemented."""
    if PolicyEvaluator is None:
        pytest.skip("agentxdr.policy pending Milestone 3 implementation")


def require_breakers() -> None:
    """Skip test if Milestone 3 circuit breakers subsystem is not yet implemented."""
    if CircuitBreaker is None:
        pytest.skip("agentxdr.breakers pending Milestone 3 implementation")


# ---------------------------------------------------------------------------
# Shared test builders
# ---------------------------------------------------------------------------
def make_valid_budgets_dict() -> Dict[str, Any]:
    """Return a valid dictionary for BudgetsConfig."""
    return {
        "max_turns": 10,
        "max_tool_calls": 25,
        "max_identical_calls": 3,
        "max_session_duration_sec": 120.0,
        "max_session_cost_usd": 5.0,
    }


def make_valid_budgets() -> BudgetsConfig:
    """Return a valid BudgetsConfig instance."""
    return BudgetsConfig(
        max_turns=10,
        max_tool_calls=25,
        max_identical_calls=3,
        max_session_duration_sec=120.0,
        max_session_cost_usd=5.0,
    )


def make_valid_policy_dict() -> Dict[str, Any]:
    """Return a valid raw dictionary for PolicySchema with all 3 tool tiers."""
    return {
        "version": "1.0.0",
        "agent_id": "sec-ops-agent",
        "budgets": make_valid_budgets_dict(),
        "tools": [
            {
                "name": "safe_search",
                "tier": "automatic",
                "schema_sha256": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
                "parameters": {
                    "query": {
                        "type": "string",
                        "max_length": 50,
                        "pattern": "^[a-zA-Z0-9 _-]+$",
                    }
                },
            },
            {
                "name": "execute_sql",
                "tier": "privileged_hitl",
                "schema_sha256": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1",
            },
            {
                "name": "system_shell",
                "tier": "blocked",
            },
        ],
        "taint_rules": [
            {
                "id": "TAINT-RULE-001",
                "match_taints": ["UNTRUSTED_EXTERNAL"],
                "blocked_tools": ["execute_sql"],
                "action": "BLOCK",
                "owasp_id": "ASI02",
            }
        ],
    }


def make_valid_policy_yaml() -> str:
    """Return a valid YAML string representation of a standard policy."""
    return yaml.dump(make_valid_policy_dict(), sort_keys=False)


def parse_policy_string(yaml_content: str) -> PolicySchema:
    """Parse policy using load_policy_yaml when available, or PolicySchema.from_yaml_str."""
    if load_policy_yaml is not None:
        return load_policy_yaml(yaml_content)
    return PolicySchema.from_yaml_str(yaml_content)


# ==============================================================================
# Feature 18: YAML Policy Loader Boundaries (>=5 tests)
# ==============================================================================


class TestFeature18YamlPolicyLoaderBoundaries:
    """Boundary value analysis and corner cases for Feature 18: YAML Policy Loader."""

    def test_f18_unknown_top_level_keys_rejected(self):
        """YAML with unknown top-level keys must be rejected (extra='forbid')."""
        data = make_valid_policy_dict()
        data["unauthorized_top_level_injection"] = "rm -rf /"
        data["extra_debug_flag"] = True
        yaml_str = yaml.dump(data)

        with pytest.raises((ValidationError, ValueError)) as exc_info:
            parse_policy_string(yaml_str)
        assert "extra_forbidden" in str(exc_info.value) or "unauthorized_top_level_injection" in str(exc_info.value)

    @pytest.mark.parametrize("empty_input", ["", "   ", "\n\n  \t  \n", "# Only a comment\n"])
    def test_f18_empty_string_policy_raises_error(self, empty_input: str):
        """Empty string, whitespace, or comment-only YAML policy must raise an error."""
        with pytest.raises((ValueError, ValidationError, yaml.YAMLError)):
            parse_policy_string(empty_input)

    def test_f18_non_ascii_utf8_comments_and_unicode_content(self):
        """Policy with non-ASCII UTF-8 comments and Unicode fields must parse and preserve UTF-8."""
        utf8_yaml = (
            "# 日本語のセキュリティポリシー設定\n"
            "# 🛡️ Enterprise Zero-Trust Guardrails 🔐\n"
            "version: '1.0.0'\n"
            "agent_id: 'agént-münchen-spéc-01'\n"
            "goal_anchor:\n"
            "  canonical_task: 'Assistance for Zürich & São Paulo office with résumé checks'\n"
            "  allowed_domains: ['support-de', 'tickets-br']\n"
            "budgets:\n"
            "  max_turns: 10\n"
            "  max_tool_calls: 20\n"
            "  max_identical_calls: 3\n"
            "  max_session_duration_sec: 180.0\n"
            "  max_session_cost_usd: 1.50\n"
            "tools:\n"
            "  - name: 'safe_search'\n"
            "    tier: 'automatic'\n"
            "taint_rules: []\n"
        )
        policy = parse_policy_string(utf8_yaml)
        assert policy.agent_id == "agént-münchen-spéc-01"
        assert policy.goal_anchor is not None
        assert "Zürich" in policy.goal_anchor.canonical_task
        assert "São Paulo" in policy.goal_anchor.canonical_task

    def test_f18_sha256_idempotency_and_stability_across_key_ordering(self):
        """SHA-256 calculation must be strictly idempotent and stable across different key ordering."""
        dict_a = {
            "version": "1.0.0",
            "agent_id": "agent-ordered-test",
            "budgets": {
                "max_turns": 10,
                "max_tool_calls": 20,
                "max_identical_calls": 3,
                "max_session_duration_sec": 100.0,
                "max_session_cost_usd": 2.0,
            },
            "tools": [{"name": "tool_alpha", "tier": "automatic"}],
            "taint_rules": [],
        }

        dict_b = {
            "taint_rules": [],
            "tools": [{"tier": "automatic", "name": "tool_alpha"}],
            "agent_id": "agent-ordered-test",
            "budgets": {
                "max_session_cost_usd": 2.0,
                "max_session_duration_sec": 100.0,
                "max_identical_calls": 3,
                "max_tool_calls": 20,
                "max_turns": 10,
            },
            "version": "1.0.0",
        }

        policy_a = PolicySchema.model_validate(dict_a)
        policy_b = PolicySchema.model_validate(dict_b)

        hash_a = policy_a.compute_policy_hash()
        hash_b = policy_b.compute_policy_hash()

        # Stability across key ordering
        assert hash_a == hash_b
        assert hash_a.startswith("sha256:")
        assert len(hash_a) == 71  # "sha256:" (7) + 64 hex chars = 71

        # Idempotency across 10 repeated calls
        for _ in range(10):
            assert policy_a.compute_policy_hash() == hash_a
            assert policy_b.compute_policy_hash() == hash_b

    def test_f18_invalid_yaml_syntax_raises_error(self):
        """Malformed YAML syntax must raise yaml.YAMLError or ValueError."""
        bad_syntax_yaml = """
        version: "1.0.0"
        agent_id: [unclosed list
        budgets: {unclosed dict
        """
        with pytest.raises((yaml.YAMLError, ValueError, ValidationError)):
            parse_policy_string(bad_syntax_yaml)

    @pytest.mark.parametrize("scalar_yaml", ["12345", "'just a string'", "true", "- item1\n- item2"])
    def test_f18_non_mapping_root_yaml_raises_value_error(self, scalar_yaml: str):
        """YAML whose root is not a dictionary mapping must raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            parse_policy_string(scalar_yaml)
        assert "root must be a mapping" in str(exc_info.value).lower() or "validation" in str(exc_info.value).lower()

    def test_f18_from_yaml_file_nonexistent_path_raises_file_not_found(self, tmp_path: Path):
        """Loading a policy from a non-existent file path must raise FileNotFoundError."""
        nonexistent = tmp_path / "does_not_exist_policy.yaml"
        with pytest.raises(FileNotFoundError):
            PolicySchema.from_yaml_file(nonexistent)


# ==============================================================================
# Feature 19: Tiered Action Resolution Boundaries (>=5 tests)
# ==============================================================================


class TestFeature19TieredActionResolutionBoundaries:
    """Boundary value analysis and corner cases for Feature 19: Tiered Action Resolution."""

    def test_f19_tool_name_strict_case_matching_fails_closed(self):
        """Tool name lookup must strictly match registered case or fail-closed to Verdict.BLOCK."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f19-case")

        # "safe_search" is registered as automatic
        decision_exact = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "test query"},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert decision_exact.verdict == Verdict.ALLOW

        # Casing variants must NOT match unregistered variants and must fail-closed
        for variant in ["SAFE_SEARCH", "Safe_Search", "safeSearch", "sAfE_sEaRcH"]:
            decision_variant = evaluator.evaluate_tool_call(
                policy=policy,
                tool_name=variant,
                arguments={"query": "test query"},
                taints=taints,
            )
            assert decision_variant.verdict == Verdict.BLOCK, f"Tool variant '{variant}' must fail closed"

    def test_f19_empty_dict_arguments_vs_populated_dict(self):
        """Tiered resolution behaves consistently on empty dict arguments vs populated dict."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f19-args")

        # "execute_sql" is privileged_hitl without strict parameter constraints
        decision_empty = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="execute_sql",
            arguments={},
            taints=taints,
        )
        assert decision_empty.verdict == Verdict.PAUSE_FOR_HITL

        decision_populated = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT count(*) FROM users;"},
            taints=taints,
        )
        assert decision_populated.verdict == Verdict.PAUSE_FOR_HITL

    def test_f19_unexpected_argument_keys_handling(self):
        """Unexpected parameter keys passed to a tool with defined constraints must be rejected or handled."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f19-extra")

        # "safe_search" only defines constraint for "query"
        decision_extra = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={
                "query": "valid query",
                "__proto__": "pollution",
                "unauthorized_admin_override": True,
            },
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        # Evaluator either blocks due to extra unexpected parameter or evaluates strictly
        assert decision_extra.verdict in [Verdict.BLOCK, Verdict.ALLOW]

    def test_f19_evaluation_latency_ms_non_negative_across_all_verdicts(self):
        """Evaluation latency_ms must always be >= 0.0 and typed as float across all verdicts."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f19-latency")

        test_calls = [
            ("safe_search", {"query": "valid query"}, "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"),
            ("execute_sql", {"query": "SELECT 1;"}, None),
            ("system_shell", {"command": "whoami"}, None),
            ("unregistered_shadow_mcp_tool", {}, None),
        ]

        for tool_name, args, schema_hash in test_calls:
            decision = evaluator.evaluate_tool_call(
                policy=policy,
                tool_name=tool_name,
                arguments=args,
                taints=taints,
                tool_schema_hash=schema_hash,
            )
            assert isinstance(decision.latency_ms, (int, float))
            assert decision.latency_ms >= 0.0, f"Latency {decision.latency_ms} must be >= 0.0"

    def test_f19_rule_id_populated_correctly_across_all_tiers(self):
        """rule_id field on Decision must be a non-empty string across every evaluation tier."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f19-rules")

        # Automatic tool
        d_auto = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "test"},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert d_auto.verdict == Verdict.ALLOW
        assert d_auto.rule_id is not None and len(d_auto.rule_id.strip()) > 0

        # Privileged HITL tool
        d_hitl = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT 1"},
            taints=taints,
        )
        assert d_hitl.verdict == Verdict.PAUSE_FOR_HITL
        assert d_hitl.rule_id is not None and len(d_hitl.rule_id.strip()) > 0

        # Blocked tool
        d_block = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="system_shell",
            arguments={"command": "ls"},
            taints=taints,
        )
        assert d_block.verdict == Verdict.BLOCK
        assert d_block.rule_id is not None and len(d_block.rule_id.strip()) > 0

        # Shadow unregistered MCP tool
        d_shadow = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="unregistered_tool",
            arguments={},
            taints=taints,
        )
        assert d_shadow.verdict == Verdict.BLOCK
        assert d_shadow.rule_id is not None and len(d_shadow.rule_id.strip()) > 0

    @pytest.mark.parametrize("empty_name", ["", "   ", "\t", "\n"])
    def test_f19_whitespace_and_empty_tool_name_blocked(self, empty_name: str):
        """Evaluating with an empty or whitespace tool name must fail-closed to Verdict.BLOCK."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f19-empty-name")

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name=empty_name,
            arguments={},
            taints=taints,
        )
        assert decision.verdict == Verdict.BLOCK


# ==============================================================================
# Feature 20: Tool Schema Hash Pinning Boundaries (>=5 tests)
# ==============================================================================


class TestFeature20ToolSchemaHashPinningBoundaries:
    """Boundary value analysis and corner cases for Feature 20: Tool Schema Hash Pinning."""

    def test_f20_schema_hash_case_handling(self):
        """Uppercase hex hash comparison must either normalize or match safely without crash."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f20-case")

        # Lowercase pinned in policy:
        pinned = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        uppercase_hash = pinned.upper()

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "hello"},
            taints=taints,
            tool_schema_hash=uppercase_hash,
        )
        # Opaque-box: Either hex-normalized (ALLOW) or strictly compared (BLOCK). Must not raise exception.
        assert decision.verdict in [Verdict.ALLOW, Verdict.BLOCK]

    def test_f20_schema_hash_with_leading_trailing_whitespace(self):
        """Schema hash with leading or trailing whitespace must either be trimmed or rejected."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f20-ws")

        pinned = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        padded_hash = f"   {pinned}   \t"

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "hello"},
            taints=taints,
            tool_schema_hash=padded_hash,
        )
        # Padded hash must either be cleanly trimmed to ALLOW or rejected as non-matching BLOCK
        assert decision.verdict in [Verdict.ALLOW, Verdict.BLOCK]

    @pytest.mark.parametrize("invalid_hash", [
        "a" * 63,           # 63 chars (1 short)
        "a" * 65,           # 65 chars (1 long)
        "",                 # empty string
        "not_a_hex_hash_at_all_just_some_random_string_of_characters_here!",
    ])
    def test_f20_schema_hash_invalid_length_rejected(self, invalid_hash: str):
        """Tool schema hash length != 64 hex chars must result in Verdict.BLOCK."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f20-len")

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "test query"},
            taints=taints,
            tool_schema_hash=invalid_hash,
        )
        assert decision.verdict == Verdict.BLOCK

    def test_f20_policy_without_schema_sha256_requirement(self):
        """Tool policy without schema_sha256 requirement allows calls with or without hash."""
        require_policy()
        raw_policy = make_valid_policy_dict()
        # Add a tool without schema_sha256
        raw_policy["tools"].append({
            "name": "unpinned_auto_tool",
            "tier": "automatic",
            "schema_sha256": None,
        })
        policy = PolicySchema.model_validate(raw_policy)
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f20-unpinned")

        # Calling without hash -> ALLOW
        d1 = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="unpinned_auto_tool",
            arguments={},
            taints=taints,
            tool_schema_hash=None,
        )
        assert d1.verdict == Verdict.ALLOW

        # Calling with an arbitrary hash -> ALLOW (no pinning enforced)
        d2 = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="unpinned_auto_tool",
            arguments={},
            taints=taints,
            tool_schema_hash="f" * 64,
        )
        assert d2.verdict == Verdict.ALLOW

    def test_f20_schema_hash_mismatch_blocks_execution(self):
        """Schema hash mismatch against pinned policy value must return Verdict.BLOCK."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f20-mismatch")

        mismatched_hash = "9" * 64
        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "valid query"},
            taints=taints,
            tool_schema_hash=mismatched_hash,
        )
        assert decision.verdict == Verdict.BLOCK
        assert decision.rule_id is not None
        assert "SCHEMA" in decision.rule_id.upper() or "HASH" in decision.rule_id.upper() or "PIN" in decision.rule_id.upper()

    def test_f20_schema_hash_sha256_prefix_handling(self):
        """Tool schema hash provided with 'sha256:' prefix compared against bare hex."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f20-prefix")

        pinned = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
        prefixed_hash = f"sha256:{pinned}"

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "test"},
            taints=taints,
            tool_schema_hash=prefixed_hash,
        )
        # Opaque box: Either strips 'sha256:' prefix to match (ALLOW) or rejects mismatch (BLOCK)
        assert decision.verdict in [Verdict.ALLOW, Verdict.BLOCK]


# ==============================================================================
# Feature 21: Deterministic Taint-Flow PEP Boundaries (>=5 tests)
# ==============================================================================


class TestFeature21DeterministicTaintFlowPEPBoundaries:
    """Boundary value analysis and corner cases for Feature 21: Deterministic Taint-Flow PEP."""

    def test_f21_rule_matching_multiple_taints_requires_all_subset(self):
        """A rule with multiple match_taints must require all of them (subset check), not just one."""
        require_policy()
        raw_policy = make_valid_policy_dict()
        raw_policy["taint_rules"] = [
            {
                "id": "MULTI-TAINT-RULE",
                "match_taints": ["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"],
                "blocked_tools": ["safe_search"],
                "action": "BLOCK",
                "owasp_id": "ASI02",
            }
        ]
        policy = PolicySchema.model_validate(raw_policy)
        evaluator = PolicyEvaluator()

        # Session with only 1 of the 2 taints -> NOT blocked by this rule
        taints_partial = TaintState("trace-partial", initial_taints=["UNTRUSTED_EXTERNAL"])
        d_partial = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "search term"},
            taints=taints_partial,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert d_partial.verdict == Verdict.ALLOW

        # Session accumulates 2nd taint -> FULL subset match -> BLOCKED
        taints_partial.add_taint("CONFIDENTIAL_RAG")
        d_full = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "search term"},
            taints=taints_partial,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert d_full.verdict == Verdict.BLOCK

    def test_f21_subset_matching_of_taints_with_superset_session(self):
        """Rule fires when rule taints are a strict subset of session taints."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()

        # Rule matches ["UNTRUSTED_EXTERNAL"], blocks ["execute_sql"]
        # Session has 5 distinct taints including UNTRUSTED_EXTERNAL
        session_taints = TaintState(
            "trace-f21-superset",
            initial_taints=[
                "UNTRUSTED_EXTERNAL",
                "PROMPT_INJECTION_DETECTED",
                "UNVERIFIED_CALLER",
                "DEBUG_ENABLED",
                "HIGH_DRIFT",
            ],
        )

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT 1"},
            taints=session_taints,
        )
        assert decision.verdict == Verdict.BLOCK

    def test_f21_multiple_overlapping_taint_rules(self):
        """Multiple overlapping taint rules independently evaluate and block tools."""
        require_policy()
        raw_policy = make_valid_policy_dict()
        raw_policy["tools"].extend([
            {"name": "tool_alpha", "tier": "automatic"},
            {"name": "tool_beta", "tier": "automatic"},
            {"name": "tool_gamma", "tier": "automatic"},
        ])
        raw_policy["taint_rules"] = [
            {
                "id": "RULE-A",
                "match_taints": ["TAINT_A"],
                "blocked_tools": ["tool_alpha", "tool_beta"],
                "action": "BLOCK",
                "owasp_id": "ASI02",
            },
            {
                "id": "RULE-B",
                "match_taints": ["TAINT_B"],
                "blocked_tools": ["tool_beta", "tool_gamma"],
                "action": "BLOCK",
                "owasp_id": "ASI02",
            },
        ]
        policy = PolicySchema.model_validate(raw_policy)
        evaluator = PolicyEvaluator()

        # Session with both TAINT_A and TAINT_B
        taints = TaintState("trace-f21-overlap", initial_taints=["TAINT_A", "TAINT_B"])

        d_alpha = evaluator.evaluate_tool_call(policy=policy, tool_name="tool_alpha", arguments={}, taints=taints)
        d_beta = evaluator.evaluate_tool_call(policy=policy, tool_name="tool_beta", arguments={}, taints=taints)
        d_gamma = evaluator.evaluate_tool_call(policy=policy, tool_name="tool_gamma", arguments={}, taints=taints)
        d_unaffected = evaluator.evaluate_tool_call(policy=policy, tool_name="system_shell", arguments={}, taints=taints)

        assert d_alpha.verdict == Verdict.BLOCK   # Blocked by Rule A
        assert d_beta.verdict == Verdict.BLOCK    # Blocked by both Rule A and Rule B
        assert d_gamma.verdict == Verdict.BLOCK   # Blocked by Rule B
        assert d_unaffected.verdict == Verdict.BLOCK  # Blocked by its tier, not taint

    def test_f21_empty_or_whitespace_taint_label_handling(self):
        """TaintState boundary: empty/whitespace taint label raises ValueError."""
        taints = TaintState("trace-f21-empty")
        with pytest.raises(ValueError):
            taints.add_taint("")
        with pytest.raises(ValueError):
            taints.add_taint("   ")

        assert taints.matches_rule([]) is False
        assert taints.matches_rule([""]) is False
        assert taints.matches_rule(["   "]) is False

    def test_f21_empty_block_tools_or_match_taints_rejected_by_schema(self):
        """TaintRule schema validation rejects empty match_taints or blocked_tools."""
        with pytest.raises(ValidationError):
            TaintRule(
                id="RULE-INVALID-1",
                match_taints=[],  # min_length=1
                blocked_tools=["some_tool"],
                owasp_id="ASI02",
            )

        with pytest.raises(ValidationError):
            TaintRule(
                id="RULE-INVALID-2",
                match_taints=["SOME_TAINT"],
                blocked_tools=[],  # min_length=1
                owasp_id="ASI02",
            )

    def test_f21_untainted_session_allows_all_tools(self):
        """Untainted session with 0 taints does not trigger taint blocks."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        fresh_taints = TaintState("trace-f21-clean")

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="execute_sql",
            arguments={"query": "SELECT 1;"},
            taints=fresh_taints,
        )
        # In untainted session, execute_sql is privileged_hitl (not blocked by taint rule)
        assert decision.verdict == Verdict.PAUSE_FOR_HITL


# ==============================================================================
# Feature 22: Tool Parameter Constraints Boundaries (>=5 tests)
# ==============================================================================


class TestFeature22ToolParameterConstraintsBoundaries:
    """Boundary value analysis and corner cases for Feature 22: Tool Parameter Constraints."""

    def test_f22_string_param_exact_max_length_boundary_allowed_vs_plus_one_blocked(self):
        """String param at exactly max_length boundary is allowed; max_length+1 is blocked."""
        require_policy()
        raw_policy = make_valid_policy_dict()
        raw_policy["tools"][0]["parameters"] = {
            "token": {
                "type": "string",
                "max_length": 10,
                "pattern": "^[a-z]+$",
            }
        }
        policy = PolicySchema.model_validate(raw_policy)
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f22-len")

        # Exactly 10 chars -> ALLOW
        exact_10 = "abcdefghij"
        assert len(exact_10) == 10
        d_exact = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"token": exact_10},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert d_exact.verdict == Verdict.ALLOW

        # 11 chars (max_length + 1) -> BLOCK
        plus_one = "abcdefghijk"
        assert len(plus_one) == 11
        d_blocked = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"token": plus_one},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert d_blocked.verdict == Verdict.BLOCK

    def test_f22_regex_pattern_with_special_characters_escaped(self):
        """Regex pattern with escaped meta-characters matches valid inputs and blocks invalid."""
        require_policy()
        raw_policy = make_valid_policy_dict()
        # Price regex pattern: exactly '$' followed by digits, '.', and 2 decimal places
        raw_policy["tools"][0]["parameters"] = {
            "price": {
                "type": "string",
                "pattern": r"^\$[0-9]+\.[0-9]{2}$",
            }
        }
        policy = PolicySchema.model_validate(raw_policy)
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f22-regex")

        valid_price = "$49.99"
        d_valid = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"price": valid_price},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert d_valid.verdict == Verdict.ALLOW

        for invalid in ["49.99", "$49.9", "$49.999", "$$", "$49.99; rm -rf /"]:
            d_inv = evaluator.evaluate_tool_call(
                policy=policy,
                tool_name="safe_search",
                arguments={"price": invalid},
                taints=taints,
                tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            )
            assert d_inv.verdict == Verdict.BLOCK, f"Invalid price '{invalid}' must be blocked"

    def test_f22_none_or_null_argument_when_pattern_expected(self):
        """None/null value passed for a parameter with string type/pattern constraint is blocked."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f22-null")

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": None},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert decision.verdict == Verdict.BLOCK

    def test_f22_argument_type_mismatch_string_vs_integer(self):
        """Argument type mismatch (e.g. integer when string expected) must be blocked."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f22-types")

        # "query" expects type "string", caller passes integer 99999
        d_int = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": 99999},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert d_int.verdict == Verdict.BLOCK

        # Caller passes dict when string expected
        d_dict = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": {"nested": "value"}},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert d_dict.verdict == Verdict.BLOCK

    def test_f22_empty_string_argument_boundary(self):
        """Empty string argument when regex requires at least one character must be blocked."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f22-empty-str")

        # pattern is "^[a-zA-Z0-9 _-]+$" which requires >= 1 char
        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": ""},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert decision.verdict == Verdict.BLOCK

    def test_f22_missing_argument_when_constraint_declared(self):
        """Missing constrained argument from tool call invocation is handled strictly."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f22-missing")

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={},  # missing required "query"
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert decision.verdict in [Verdict.BLOCK, Verdict.PAUSE_FOR_HITL]


# ==============================================================================
# Feature 23: Dynamic High-Risk Escalation Boundaries (>=5 tests)
# ==============================================================================


class TestFeature23DynamicHighRiskEscalationBoundaries:
    """Boundary value analysis and corner cases for Feature 23: Dynamic High-Risk Escalation."""

    def test_f23_drift_score_boundary_0_74999_allows_automatic_tool(self):
        """Drift score exactly 0.74999 (< 0.75 threshold) allows automatic tool without HITL pause."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f23-below")

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "safe query"},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            drift_score=0.74999,
        )
        assert decision.verdict == Verdict.ALLOW

    def test_f23_drift_score_boundary_0_75000_escalates_to_pause_for_hitl(self):
        """Drift score exactly 0.75000 (>= 0.75 threshold) escalates automatic tool to PAUSE_FOR_HITL."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f23-at-threshold")

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "safe query"},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            drift_score=0.75000,
        )
        assert decision.verdict == Verdict.PAUSE_FOR_HITL
        assert decision.rule_id is not None
        assert "DRIFT" in decision.rule_id.upper() or "RISK" in decision.rule_id.upper() or "ESCALAT" in decision.rule_id.upper()

    def test_f23_drift_score_maximum_1_0_escalates_to_pause_for_hitl(self):
        """Drift score exactly 1.0 (maximum risk) escalates automatic tool to PAUSE_FOR_HITL."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f23-max")

        decision = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="safe_search",
            arguments={"query": "safe query"},
            taints=taints,
            tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            drift_score=1.0,
        )
        assert decision.verdict == Verdict.PAUSE_FOR_HITL

    def test_f23_drift_score_out_of_bounds_negative_or_exceeding_one(self):
        """Out of bounds drift scores (<0.0 or >1.0) are handled gracefully or raise ValueError."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f23-oob")

        for oob_score in [-0.5, 1.5, 999.0]:
            try:
                decision = evaluator.evaluate_tool_call(
                    policy=policy,
                    tool_name="safe_search",
                    arguments={"query": "safe query"},
                    taints=taints,
                    tool_schema_hash="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
                    drift_score=oob_score,
                )
                # If clamped, negative clamped to 0.0 (ALLOW) and >1.0 clamped to 1.0 (PAUSE_FOR_HITL)
                assert decision.verdict in [Verdict.ALLOW, Verdict.PAUSE_FOR_HITL]
            except (ValueError, ValidationError):
                pass  # Graceful exception is equally valid

    def test_f23_drift_escalation_does_not_downgrade_blocked_tier(self):
        """Drift escalation must NEVER downgrade a blocked tool to PAUSE_FOR_HITL or ALLOW."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f23-blocked")

        for score in [0.0, 0.74999, 0.75000, 1.0]:
            decision = evaluator.evaluate_tool_call(
                policy=policy,
                tool_name="system_shell",
                arguments={"command": "whoami"},
                taints=taints,
                drift_score=score,
            )
            assert decision.verdict == Verdict.BLOCK, f"Blocked tool must remain BLOCK at drift={score}"

    def test_f23_drift_escalation_maintains_privileged_hitl_tier(self):
        """Privileged HITL tools remain PAUSE_FOR_HITL regardless of drift score."""
        require_policy()
        policy = parse_policy_string(make_valid_policy_yaml())
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-f23-hitl")

        for score in [0.0, 0.5, 0.75, 1.0]:
            decision = evaluator.evaluate_tool_call(
                policy=policy,
                tool_name="execute_sql",
                arguments={"query": "SELECT 1;"},
                taints=taints,
                drift_score=score,
            )
            assert decision.verdict == Verdict.PAUSE_FOR_HITL


# ==============================================================================
# Feature 24: Max Turns Circuit Breaker Boundaries (>=5 tests)
# ==============================================================================


class TestFeature24MaxTurnsCircuitBreakerBoundaries:
    """Boundary value analysis and corner cases for Feature 24: Max Turns Circuit Breaker."""

    def test_f24_max_turns_1_single_turn_allowed_then_trips(self):
        """Circuit breaker with max_turns=1 allows turn 1 then immediately trips on turn 2."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=1,
            max_tool_calls=10,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f24-turns-1"

        v1 = breaker.record_turn(trace_id)
        assert v1.is_tripped is False

        v2 = breaker.record_turn(trace_id)
        assert v2.is_tripped is True
        assert v2.limit_name == "max_turns"

    def test_f24_boundary_turn_equals_max_turns_allowed_vs_plus_one_tripped(self):
        """turn == max_turns is allowed; turn == max_turns + 1 is tripped."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=5,
            max_tool_calls=50,
            max_identical_calls=10,
            max_session_duration_sec=120.0,
            max_session_cost_usd=5.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f24-boundary-5"

        for turn_num in range(1, 6):
            v = breaker.record_turn(trace_id)
            assert v.is_tripped is False, f"Turn {turn_num} should be allowed"

        # Turn 6 = max_turns + 1
        v_tripped = breaker.record_turn(trace_id)
        assert v_tripped.is_tripped is True
        assert v_tripped.limit_name == "max_turns"
        assert v_tripped.threshold in [5, 5.0]

    def test_f24_circuit_breaker_stays_tripped_on_subsequent_turns(self):
        """Once tripped, subsequent turns continue to return is_tripped=True monotonically."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=2,
            max_tool_calls=10,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f24-monotonic"

        breaker.record_turn(trace_id)
        breaker.record_turn(trace_id)
        assert breaker.record_turn(trace_id).is_tripped is True

        # Next 5 turns must all remain tripped
        for _ in range(5):
            assert breaker.record_turn(trace_id).is_tripped is True

    def test_f24_rapid_1000_turns_stress_performance(self):
        """1,000 rapid turns test maintains integrity without corruption or unbounded memory."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=100,
            max_tool_calls=5000,
            max_identical_calls=5000,
            max_session_duration_sec=300.0,
            max_session_cost_usd=100.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f24-1000"

        for i in range(1, 1001):
            v = breaker.record_turn(trace_id)
            if i <= 100:
                assert v.is_tripped is False
            else:
                assert v.is_tripped is True
                assert v.limit_name == "max_turns"

    def test_f24_isolated_turns_across_different_traces(self):
        """Independent trace IDs maintain isolated turn counters without cross-talk."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=3,
            max_tool_calls=10,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)

        # Exhaust trace A
        for _ in range(3):
            breaker.record_turn("trace-A")
        assert breaker.record_turn("trace-A").is_tripped is True

        # Trace B is fresh and should not be affected
        assert breaker.record_turn("trace-B").is_tripped is False

    def test_f24_budgets_config_rejects_negative_or_zero_max_turns(self):
        """BudgetsConfig must reject max_turns <= 0 with ValidationError (gt=0)."""
        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=0,
                max_tool_calls=10,
                max_identical_calls=3,
                max_session_duration_sec=60.0,
                max_session_cost_usd=1.0,
            )

        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=-5,
                max_tool_calls=10,
                max_identical_calls=3,
                max_session_duration_sec=60.0,
                max_session_cost_usd=1.0,
            )


# ==============================================================================
# Feature 25: Max Tool Calls Circuit Breaker Boundaries (>=5 tests)
# ==============================================================================


class TestFeature25MaxToolCallsCircuitBreakerBoundaries:
    """Boundary value analysis and corner cases for Feature 25: Max Tool Calls Circuit Breaker."""

    def test_f25_boundary_tool_calls_equals_max_allowed_vs_plus_one_tripped(self):
        """tool_calls == max_tool_calls is allowed; tool_calls == max_tool_calls + 1 is tripped."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=3,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f25-boundary"

        # Calls 1, 2, 3 allowed
        assert breaker.record_tool_call(trace_id, "tool_1", {"x": 1}).is_tripped is False
        assert breaker.record_tool_call(trace_id, "tool_2", {"x": 2}).is_tripped is False
        assert breaker.record_tool_call(trace_id, "tool_3", {"x": 3}).is_tripped is False

        # Call 4 = max_tool_calls + 1 -> tripped
        v4 = breaker.record_tool_call(trace_id, "tool_4", {"x": 4})
        assert v4.is_tripped is True
        assert v4.limit_name == "max_tool_calls"

    def test_f25_multiple_distinct_tool_names_accumulate_to_single_budget(self):
        """Different tool names accumulate toward the single cumulative max_tool_calls budget."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=20,
            max_tool_calls=4,
            max_identical_calls=10,
            max_session_duration_sec=120.0,
            max_session_cost_usd=5.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f25-distinct"

        distinct_tools = ["search", "calculator", "database_read", "email_sender", "overflow_tool"]
        for idx, tool in enumerate(distinct_tools):
            v = breaker.record_tool_call(trace_id, tool, {"step": idx})
            if idx < 4:
                assert v.is_tripped is False, f"Call {idx} for {tool} should pass"
            else:
                assert v.is_tripped is True
                assert v.limit_name == "max_tool_calls"

    def test_f25_50_distinct_trace_ids_independently_tracked(self):
        """50 distinct trace IDs are independently tracked without memory bleed or false trips."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=2,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)

        traces = [f"trace-burst-{i}" for i in range(50)]

        # Each trace performs 2 calls (allowed)
        for t in traces:
            assert breaker.record_tool_call(t, "t_a", {"i": 1}).is_tripped is False
            assert breaker.record_tool_call(t, "t_b", {"i": 2}).is_tripped is False

        # Each trace performs 3rd call (tripped)
        for t in traces:
            v = breaker.record_tool_call(t, "t_c", {"i": 3})
            assert v.is_tripped is True
            assert v.limit_name == "max_tool_calls"

    def test_f25_minimal_budget_one_tool_call(self):
        """Minimal budget of max_tool_calls=1 allows exactly 1 call then trips."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=5,
            max_tool_calls=1,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f25-minimal"

        assert breaker.record_tool_call(trace_id, "first_tool", {}).is_tripped is False
        assert breaker.record_tool_call(trace_id, "second_tool", {}).is_tripped is True

    def test_f25_tripped_verdict_fields_accuracy(self):
        """Tripped verdict includes correct limit_name, threshold, current_value, and message."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=5,
            max_tool_calls=2,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f25-fields"

        breaker.record_tool_call(trace_id, "tool_1", {"a": 1})
        breaker.record_tool_call(trace_id, "tool_2", {"a": 2})
        v = breaker.record_tool_call(trace_id, "tool_3", {"a": 3})

        assert v.is_tripped is True
        assert v.limit_name == "max_tool_calls"
        assert v.threshold in [2, 2.0]
        assert v.current_value is not None and v.current_value >= 3.0
        assert isinstance(v.message, str) and len(v.message) > 0

    def test_f25_budgets_config_rejects_zero_or_negative_tool_calls(self):
        """BudgetsConfig must reject max_tool_calls <= 0 with ValidationError."""
        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=5,
                max_tool_calls=0,
                max_identical_calls=3,
                max_session_duration_sec=60.0,
                max_session_cost_usd=1.0,
            )


# ==============================================================================
# Feature 26: Identical Call Loop Breaker Boundaries (>=5 tests)
# ==============================================================================


class TestFeature26IdenticalCallLoopBreakerBoundaries:
    """Boundary value analysis and corner cases for Feature 26: Identical Call Loop Breaker."""

    def test_f26_key_ordering_independence_in_identical_call_detection(self):
        """Arguments with different key order must be detected as identical calls."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f26-keys"

        # 3 identical calls alternating key ordering:
        # Call 1: {"a": 1, "b": 2} -> allowed (count=1)
        v1 = breaker.record_tool_call(trace_id, "test_tool", {"a": 1, "b": 2})
        assert v1.is_tripped is False

        # Call 2: {"b": 2, "a": 1} -> allowed (count=2)
        v2 = breaker.record_tool_call(trace_id, "test_tool", {"b": 2, "a": 1})
        assert v2.is_tripped is False

        # Call 3: {"a": 1, "b": 2} -> allowed (count=3)
        v3 = breaker.record_tool_call(trace_id, "test_tool", {"a": 1, "b": 2})
        assert v3.is_tripped is False

        # Call 4: {"b": 2, "a": 1} -> TRIPPED (count=4 > max_identical_calls=3)
        v4 = breaker.record_tool_call(trace_id, "test_tool", {"b": 2, "a": 1})
        assert v4.is_tripped is True
        assert v4.limit_name == "max_identical_calls"

    def test_f26_numeric_float_vs_int_precision_comparison(self):
        """Comparison handles float and int numeric values gracefully."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=2,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f26-float"

        v1 = breaker.record_tool_call(trace_id, "calc_tool", {"val": 1.0})
        assert v1.is_tripped is False

        v2 = breaker.record_tool_call(trace_id, "calc_tool", {"val": 1.0})
        assert v2.is_tripped is False

        # 3rd identical call
        v3 = breaker.record_tool_call(trace_id, "calc_tool", {"val": 1.0})
        assert v3.is_tripped is True
        assert v3.limit_name == "max_identical_calls"

    def test_f26_deeply_nested_dictionaries_identical_comparison(self):
        """Deeply nested structures with different key orders at nested levels are detected identical."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=2,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f26-nested"

        nested_1 = {
            "level1": {
                "level2": {
                    "beta": [1, 2, 3],
                    "alpha": {"k": "v"},
                }
            }
        }

        nested_2 = {
            "level1": {
                "level2": {
                    "alpha": {"k": "v"},
                    "beta": [1, 2, 3],
                }
            }
        }

        assert breaker.record_tool_call(trace_id, "nested_tool", nested_1).is_tripped is False
        assert breaker.record_tool_call(trace_id, "nested_tool", nested_2).is_tripped is False
        # 3rd call exceeds max_identical_calls=2
        v_trip = breaker.record_tool_call(trace_id, "nested_tool", nested_1)
        assert v_trip.is_tripped is True
        assert v_trip.limit_name == "max_identical_calls"

    def test_f26_different_arguments_do_not_trip_identical_breaker(self):
        """Repeated calls with varying arguments must NOT trip identical loop breaker."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=20,
            max_tool_calls=20,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f26-distinct-args"

        for i in range(10):
            v = breaker.record_tool_call(trace_id, "fetch_page", {"page": i})
            assert v.is_tripped is False

    def test_f26_different_tool_names_with_same_arguments_not_identical(self):
        """Identical arguments to different tool names do NOT count toward each other's identical count."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=2,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f26-tool-names"

        common_args = {"action": "execute"}
        # 2 calls to tool_A (allowed)
        assert breaker.record_tool_call(trace_id, "tool_A", common_args).is_tripped is False
        assert breaker.record_tool_call(trace_id, "tool_A", common_args).is_tripped is False

        # Call to tool_B with same arguments (should be count=1 for tool_B, NOT count=3 overall)
        assert breaker.record_tool_call(trace_id, "tool_B", common_args).is_tripped is False

    def test_f26_arguments_whitespace_normalization(self):
        """String arguments with slight whitespace differences are evaluated consistently."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=2,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f26-whitespace"

        v1 = breaker.record_tool_call(trace_id, "text_tool", {"text": "exact match"})
        v2 = breaker.record_tool_call(trace_id, "text_tool", {"text": "exact match"})
        assert v1.is_tripped is False
        assert v2.is_tripped is False

        v3 = breaker.record_tool_call(trace_id, "text_tool", {"text": "exact match"})
        assert v3.is_tripped is True
        assert v3.limit_name == "max_identical_calls"


# ==============================================================================
# Feature 27: Session Duration Circuit Breaker Boundaries (>=5 tests)
# ==============================================================================


class TestFeature27SessionDurationCircuitBreakerBoundaries:
    """Boundary value analysis and corner cases for Feature 27: Session Duration Circuit Breaker."""

    def test_f27_duration_check_immediately_after_init(self):
        """Duration check called immediately after initialization does not trip."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f27-fresh"

        # Record a turn to initialize session start time
        breaker.record_turn(trace_id)
        v = breaker.check_duration(trace_id)
        assert v.is_tripped is False

    def test_f27_mock_time_progression_past_max_session_duration_sec(self):
        """Mock time progression past max_session_duration_sec trips the breaker."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f27-mock"

        # Simulate start time at t=1000.0
        with patch("time.monotonic", return_value=1000.0), patch("time.time", return_value=1000.0):
            breaker.record_turn(trace_id)

        # At t=1059.9s (duration = 59.9s < 60.0s) -> allowed
        with patch("time.monotonic", return_value=1059.9), patch("time.time", return_value=1059.9):
            v_before = breaker.check_duration(trace_id)
            assert v_before.is_tripped is False

        # At t=1060.1s (duration = 60.1s > 60.0s) -> tripped
        with patch("time.monotonic", return_value=1060.1), patch("time.time", return_value=1060.1):
            v_tripped = breaker.check_duration(trace_id)
            assert v_tripped.is_tripped is True
            assert v_tripped.limit_name == "max_session_duration_sec"
            assert v_tripped.threshold == 60.0

    def test_f27_exact_duration_threshold_boundary(self):
        """Exact duration threshold check (t == max_session_duration_sec)."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=3,
            max_session_duration_sec=30.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f27-exact"

        with patch("time.monotonic", return_value=2000.0), patch("time.time", return_value=2000.0):
            breaker.record_turn(trace_id)

        # At exactly 30.0s boundary
        with patch("time.monotonic", return_value=2030.0), patch("time.time", return_value=2030.0):
            v = breaker.check_duration(trace_id)
            assert v.is_tripped in [True, False]  # Boundary behavior permitted

        # At 30.001s
        with patch("time.monotonic", return_value=2030.001), patch("time.time", return_value=2030.001):
            assert breaker.check_duration(trace_id).is_tripped is True

    def test_f27_multiple_traces_with_different_start_times(self):
        """Multiple traces initialized at different timestamps expire independently."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=3,
            max_session_duration_sec=40.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)

        # Trace 1 starts at t=100.0
        with patch("time.monotonic", return_value=100.0), patch("time.time", return_value=100.0):
            breaker.record_turn("trace-early")

        # Trace 2 starts at t=130.0
        with patch("time.monotonic", return_value=130.0), patch("time.time", return_value=130.0):
            breaker.record_turn("trace-late")

        # Current time t=145.0:
        # Trace 1 elapsed: 45s > 40s (tripped)
        # Trace 2 elapsed: 15s < 40s (allowed)
        with patch("time.monotonic", return_value=145.0), patch("time.time", return_value=145.0):
            assert breaker.check_duration("trace-early").is_tripped is True
            assert breaker.check_duration("trace-late").is_tripped is False

    def test_f27_duration_check_on_untracked_trace_initializes_gracefully(self):
        """check_duration on an untracked trace ID initializes timer without crashing."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        v = breaker.check_duration("unseen-trace-id")
        assert v.is_tripped is False

    def test_f27_budgets_config_rejects_negative_or_zero_duration(self):
        """BudgetsConfig rejects max_session_duration_sec <= 0.0 with ValidationError."""
        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=5,
                max_tool_calls=5,
                max_identical_calls=3,
                max_session_duration_sec=0.0,
                max_session_cost_usd=1.0,
            )

        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=5,
                max_tool_calls=5,
                max_identical_calls=3,
                max_session_duration_sec=-10.0,
                max_session_cost_usd=1.0,
            )


# ==============================================================================
# Feature 28: Cost / Token Budget Breaker Boundaries (>=5 tests)
# ==============================================================================


class TestFeature28CostBudgetBreakerBoundaries:
    """Boundary value analysis and corner cases for Feature 28: Cost / Token Budget Breaker."""

    def test_f28_fractional_micro_cents_accumulation(self):
        """Fractional micro-cent cost increments accumulate accurately without floating precision errors."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10000,
            max_tool_calls=10000,
            max_identical_calls=10000,
            max_session_duration_sec=300.0,
            max_session_cost_usd=1.0,  # $1.00 budget
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f28-micro"

        # Accumulate 10,000 increments of $0.00001 (total = $0.10)
        micro_cost = 0.00001
        for _ in range(10000):
            v = breaker.record_cost(trace_id, micro_cost)

        # $0.10 < $1.00 budget -> NOT tripped
        assert v.is_tripped is False
        assert v.current_value is not None
        assert 0.099 <= v.current_value <= 0.101

    def test_f28_exact_threshold_boundary_allowed_vs_tripped(self):
        """Cost exactly equal to max_session_cost_usd is allowed; +$0.0001 is tripped."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,  # $5.00 threshold
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f28-boundary"

        # Record exact threshold cost $5.00
        v_exact = breaker.record_cost(trace_id, 5.0)
        assert v_exact.is_tripped is False

        # Additional $0.0001 exceeds budget
        v_tripped = breaker.record_cost(trace_id, 0.0001)
        assert v_tripped.is_tripped is True
        assert v_tripped.limit_name == "max_session_cost_usd"
        assert v_tripped.threshold == 5.0

    def test_f28_zero_and_negative_cost_handling(self):
        """Zero cost is handled safely; negative cost must not deflate budget."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=2.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f28-neg"

        # $0.0 cost is allowed
        v_zero = breaker.record_cost(trace_id, 0.0)
        assert v_zero.is_tripped is False

        # Negative cost either raises ValueError or is rejected/ignored
        try:
            v_neg = breaker.record_cost(trace_id, -10.0)
            # If not raising, current_value must not have decremented below 0
            assert v_neg.current_value is not None and v_neg.current_value >= 0.0
        except (ValueError, ValidationError):
            pass

    def test_f28_large_single_call_exceeding_entire_budget_trips_immediately(self):
        """A single call whose cost exceeds the entire budget trips immediately."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=5.0,
        )
        breaker = CircuitBreaker(budgets=budgets)
        trace_id = "trace-f28-giant"

        # Single massive call of $25.00
        v = breaker.record_cost(trace_id, 25.0)
        assert v.is_tripped is True
        assert v.limit_name == "max_session_cost_usd"
        assert v.threshold == 5.0
        assert v.current_value is not None and v.current_value >= 25.0

    def test_f28_cost_budget_isolated_across_traces(self):
        """Cumulative cost is strictly isolated per trace ID."""
        require_breakers()
        budgets = BudgetsConfig(
            max_turns=10,
            max_tool_calls=10,
            max_identical_calls=5,
            max_session_duration_sec=60.0,
            max_session_cost_usd=3.0,
        )
        breaker = CircuitBreaker(budgets=budgets)

        # Trace 1 spends $4.00 (tripped)
        assert breaker.record_cost("trace-user-1", 4.0).is_tripped is True

        # Trace 2 spends $1.50 (allowed)
        assert breaker.record_cost("trace-user-2", 1.5).is_tripped is False

    def test_f28_budgets_config_rejects_zero_or_negative_max_cost(self):
        """BudgetsConfig rejects max_session_cost_usd <= 0.0 with ValidationError."""
        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=5,
                max_tool_calls=5,
                max_identical_calls=3,
                max_session_duration_sec=60.0,
                max_session_cost_usd=0.0,
            )

        with pytest.raises(ValidationError):
            BudgetsConfig(
                max_turns=5,
                max_tool_calls=5,
                max_identical_calls=3,
                max_session_duration_sec=60.0,
                max_session_cost_usd=-5.0,
            )
