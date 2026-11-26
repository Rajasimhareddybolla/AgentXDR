"""Unit tests for CI PolicyDiffEngine and DependencyAuditor."""

from __future__ import annotations

import json
from pathlib import Path

from agentxdr.ci.dependency_audit import DependencyAuditor
from agentxdr.ci.policy_diff import PolicyDiffEngine, RegressionSeverity
from agentxdr.policy.loader import load_policy_yaml

_BASE_POLICY = """
version: "1.0.0"
agent_id: "secops-agent"
approved_by: "ciso@corp.local"
goal_anchor:
  canonical_task: "Inspect telemetry logs safely."
  allowed_domains: ["internal.corp"]
tools:
  - name: "read_logs"
    tier: "automatic"
    schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    parameters:
      query:
        type: "string"
        max_length: 200
        pattern: "^[a-zA-Z0-9_ ]+$"
  - name: "execute_sql"
    tier: "privileged_hitl"
  - name: "system_shell"
    tier: "blocked"
taint_rules:
  - id: "TR-01"
    match_taints: ["UNTRUSTED_EXTERNAL"]
    blocked_tools: ["system_shell", "execute_sql"]
    action: "BLOCK"
    owasp_id: "ASI01"
code_sandbox:
  enabled: true
  provider: "docker_rootless"
  timeout_sec: 10
  memory_limit_mb: 256
  blocked_imports: ["os", "subprocess"]
output_guardrails:
  dlp:
    mask_pii: true
    mask_secrets: true
  prompt_leak:
    max_similarity: 0.65
budgets:
  max_turns: 10
  max_tool_calls: 20
  max_identical_calls: 3
  max_session_duration_sec: 120.0
  max_session_cost_usd: 5.0
"""


class TestPolicyDiffEngine:
    def test_identical_policy_passes(self):
        base = load_policy_yaml(_BASE_POLICY)
        head = load_policy_yaml(_BASE_POLICY)
        report = PolicyDiffEngine().compare(base, head)
        assert not report.has_regressions
        assert report.critical_count == 0
        assert report.high_count == 0
        assert "PASSED" in report.to_markdown()

    def test_detects_overprivileged_tool_and_unpinned_automatic(self):
        head_yaml = _BASE_POLICY.replace(
            '  - name: "system_shell"\n    tier: "blocked"',
            '  - name: "system_shell"\n    tier: "automatic"\n  - name: "new_unpinned"\n    tier: "automatic"',
        )
        report = PolicyDiffEngine().compare(load_policy_yaml(_BASE_POLICY), load_policy_yaml(head_yaml))
        assert report.has_regressions
        paths = {f.field_path for f in report.findings if f.severity == RegressionSeverity.CRITICAL}
        assert "tools.system_shell.tier" in paths
        assert "tools.new_unpinned" in paths

    def test_detects_parameter_and_schema_pin_weakening(self):
        head_yaml = _BASE_POLICY.replace(
            '    schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n',
            "",
        ).replace('max_length: 200', "max_length: 2000").replace('        pattern: "^[a-zA-Z0-9_ ]+$"\n', "")
        report = PolicyDiffEngine().compare(load_policy_yaml(_BASE_POLICY), load_policy_yaml(head_yaml))
        assert report.has_regressions
        paths = {f.field_path for f in report.findings}
        assert "tools.read_logs.schema_sha256" in paths
        assert "tools.read_logs.parameters.query.max_length" in paths
        assert "tools.read_logs.parameters.query.pattern" in paths

    def test_detects_taint_sandbox_dlp_and_goal_anchor_regressions(self):
        head_yaml = (
            _BASE_POLICY.replace('approved_by: "ciso@corp.local"\n', "")
            .replace('allowed_domains: ["internal.corp"]', 'allowed_domains: ["internal.corp", "*"]')
            .replace("blocked_tools: [\"system_shell\", \"execute_sql\"]", "blocked_tools: [\"system_shell\"]")
            .replace("enabled: true", "enabled: false")
            .replace("mask_secrets: true", "mask_secrets: false")
            .replace("max_similarity: 0.65", "max_similarity: 0.90")
        )
        report = PolicyDiffEngine().compare(load_policy_yaml(_BASE_POLICY), load_policy_yaml(head_yaml))
        assert report.has_regressions
        paths = {f.field_path for f in report.findings}
        assert "approved_by" in paths
        assert "goal_anchor.allowed_domains" in paths
        assert "taint_rules.TR-01.blocked_tools" in paths
        assert "code_sandbox.enabled" in paths
        assert "output_guardrails.dlp.mask_secrets" in paths
        assert "output_guardrails.prompt_leak.max_similarity" in paths

    def test_budget_increase_flag_behavior(self):
        head_yaml = _BASE_POLICY.replace("max_turns: 10", "max_turns: 50")
        base, head = load_policy_yaml(_BASE_POLICY), load_policy_yaml(head_yaml)

        strict_report = PolicyDiffEngine().compare(base, head, allow_budget_increase=False)
        assert strict_report.has_regressions
        assert strict_report.findings[0].field_path == "budgets.max_turns"

        relaxed_report = PolicyDiffEngine().compare(base, head, allow_budget_increase=True)
        assert not relaxed_report.has_regressions


class TestDependencyAuditor:
    def test_detects_vulnerable_pypi_and_unpinned_npm_mcp(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("starlette==0.38.0\npydantic==2.10.0\n")
        mcp_cfg = {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.1", "/tmp"],
                },
                "git": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-git"],
                },
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(mcp_cfg))

        report = DependencyAuditor().scan(root_path=tmp_path, offline=True)
        assert report.packages_checked == 4
        assert report.has_blocking_findings
        cves = {f.cve_id for f in report.findings}
        assert "CVE-2024-47874" in cves
        assert "ADV-MCP-FS-001" in cves
        assert "HYGIENE-UNPINNED-DEP" in cves

    def test_clean_workspace_dependencies_pass(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("starlette>=0.41.0\npydantic>=2.10.0\n")
        report = DependencyAuditor().scan(root_path=tmp_path, offline=True)
        assert report.packages_checked == 2
        assert not report.has_blocking_findings
