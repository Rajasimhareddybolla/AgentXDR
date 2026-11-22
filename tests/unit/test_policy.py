"""Unit tests for agentxdr.policy: YAML loader and PolicyEvaluator."""

from __future__ import annotations

from pathlib import Path
import pytest
from pydantic import ValidationError

from agentxdr.models import (
    BudgetsConfig,
    Decision,
    KillSwitchScope,
    KillSwitchState,
    PolicySchema,
    TaintState,
    ToolTier,
    Verdict,
)
from agentxdr.policy import PolicyEvaluator, load_policy_yaml


SAMPLE_POLICY_YAML = """
version: "1.0.0"
agent_id: "test-unit-agent"
approved_by: "secops@enterprise.com"
budgets:
  max_turns: 5
  max_tool_calls: 10
  max_identical_calls: 3
  max_session_duration_sec: 60.0
  max_session_cost_usd: 2.0
tools:
  - name: "web_search"
    tier: "automatic"
    schema_sha256: "1111111111111111111111111111111111111111111111111111111111111111"
    parameters:
      query:
        type: "string"
        max_length: 50
        pattern: "^[a-zA-Z0-9 ]+$"
  - name: "database_exec"
    tier: "privileged_hitl"
    parameters:
      query:
        type: "string"
  - name: "rm_rf"
    tier: "blocked"
taint_rules:
  - id: "RULE-BLOCK-EXT"
    match_taints: ["TAINT_DIRTY"]
    blocked_tools: ["database_exec"]
    action: "BLOCK"
    owasp_id: "ASI02"
"""


class TestPolicyLoader:
    """Unit tests for load_policy_yaml."""

    def test_load_from_valid_yaml_string(self):
        policy = load_policy_yaml(SAMPLE_POLICY_YAML)
        assert policy.agent_id == "test-unit-agent"
        assert len(policy.tools) == 3
        assert policy.verify_hash() is False  # policy_hash was not set

    def test_load_from_valid_yaml_file(self, tmp_path: Path):
        f = tmp_path / "policy.yaml"
        f.write_text(SAMPLE_POLICY_YAML, encoding="utf-8")
        policy = load_policy_yaml(f)
        assert policy.agent_id == "test-unit-agent"

    def test_load_from_str_path(self, tmp_path: Path):
        f = tmp_path / "policy.yaml"
        f.write_text(SAMPLE_POLICY_YAML, encoding="utf-8")
        policy = load_policy_yaml(str(f))
        assert policy.agent_id == "test-unit-agent"

    def test_load_empty_or_whitespace_raises_value_error(self):
        with pytest.raises(ValueError):
            load_policy_yaml("")
        with pytest.raises(ValueError):
            load_policy_yaml("   \n  \t")

    def test_invalid_type_raises_type_error(self):
        with pytest.raises(TypeError):
            load_policy_yaml(12345)  # type: ignore


class TestPolicyEvaluator:
    """Unit tests for PolicyEvaluator PEP logic."""

    @pytest.fixture
    def policy(self) -> PolicySchema:
        return load_policy_yaml(SAMPLE_POLICY_YAML)

    def test_automatic_tool_allowed(self, policy: PolicySchema):
        evaluator = PolicyEvaluator()
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="web_search",
            arguments={"query": "test query"},
            tool_schema_hash="1111111111111111111111111111111111111111111111111111111111111111",
        )
        assert d.verdict == Verdict.ALLOW
        assert d.latency_ms >= 0.0
        assert d.rule_id == "AUTOMATIC_TOOL_ALLOWED"

    def test_privileged_hitl_tool_pauses(self, policy: PolicySchema):
        evaluator = PolicyEvaluator()
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="database_exec",
            arguments={"query": "SELECT 1"},
        )
        assert d.verdict == Verdict.PAUSE_FOR_HITL
        assert d.rule_id == "PRIVILEGED_HITL_REQUIRED"

    def test_blocked_tool_blocks(self, policy: PolicySchema):
        evaluator = PolicyEvaluator()
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="rm_rf",
            arguments={},
        )
        assert d.verdict == Verdict.BLOCK
        assert d.rule_id == "TOOL_TIER_BLOCKED"

    def test_shadow_tool_blocks(self, policy: PolicySchema):
        evaluator = PolicyEvaluator()
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="unregistered_tool",
            arguments={},
        )
        assert d.verdict == Verdict.BLOCK
        assert "SHADOW" in d.rule_id

    def test_kill_switch_overrides_to_kill(self, policy: PolicySchema):
        ks = KillSwitchState()
        ks.activate(KillSwitchScope.TOOL, "web_search", "testing kill", "admin")
        evaluator = PolicyEvaluator(kill_switch=ks)
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="web_search",
            arguments={"query": "safe"},
            tool_schema_hash="1111111111111111111111111111111111111111111111111111111111111111",
        )
        assert d.verdict == Verdict.KILL

    def test_taint_blocks_restricted_tool(self, policy: PolicySchema):
        evaluator = PolicyEvaluator()
        taints = TaintState("trace-taint-test", initial_taints=["TAINT_DIRTY"])
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="database_exec",
            arguments={"query": "SELECT 1"},
            taints=taints,
        )
        assert d.verdict == Verdict.BLOCK
        assert d.rule_id == "RULE-BLOCK-EXT"
        assert "ASI02" in d.owasp_ids

    def test_param_constraint_max_length_violation(self, policy: PolicySchema):
        evaluator = PolicyEvaluator()
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="web_search",
            arguments={"query": "a" * 51},
            tool_schema_hash="1111111111111111111111111111111111111111111111111111111111111111",
        )
        assert d.verdict == Verdict.BLOCK
        assert "MAX_LENGTH" in d.rule_id

    def test_param_constraint_pattern_violation(self, policy: PolicySchema):
        evaluator = PolicyEvaluator()
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="web_search",
            arguments={"query": "invalid; drop tables"},
            tool_schema_hash="1111111111111111111111111111111111111111111111111111111111111111",
        )
        assert d.verdict == Verdict.BLOCK
        assert "PATTERN" in d.rule_id

    def test_drift_score_escalation(self, policy: PolicySchema):
        evaluator = PolicyEvaluator()
        d = evaluator.evaluate_tool_call(
            policy=policy,
            tool_name="web_search",
            arguments={"query": "normal query"},
            tool_schema_hash="1111111111111111111111111111111111111111111111111111111111111111",
            drift_score=0.85,
        )
        assert d.verdict == Verdict.PAUSE_FOR_HITL
        assert "DRIFT" in d.rule_id
