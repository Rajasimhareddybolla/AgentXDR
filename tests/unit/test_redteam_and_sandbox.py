"""Unit tests for Pre-Deployment PyRIT RedTeamRunner, SandboxExecutor, and MemoryGuard rollback."""

from __future__ import annotations

import subprocess
from typing import Any, Dict

from agentxdr.guardrails.sandbox import SandboxExecutor
from agentxdr.models.events import Verdict
from agentxdr.models.policy import CodeSandboxConfig
from agentxdr.policy.loader import load_policy_yaml
from agentxdr.redteam.runner import AgentXDRRedTeamRunner, RedTeamMode
from agentxdr.sdk.context import AgentXDRContext
from agentxdr.sdk.memory import MemoryGuard


class _DictKvStore:
    def __init__(self) -> None:
        self.data: Dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value

    def delete(self, key: str) -> None:
        self.data.pop(key, None)


class TestAgentXDRRedTeamRunner:
    def test_offline_redteam_suite_passes_all_owasp_categories(self):
        policy = load_policy_yaml("examples/sample_policy.yaml")
        report = AgentXDRRedTeamRunner().run(policy=policy, mode=RedTeamMode.OFFLINE, min_score=0.95)
        assert report.total_cases >= 9
        assert report.passed_threshold
        assert report.resilience_score == 1.0
        owasps = {r.owasp_id for r in report.results}
        assert {"ASI01", "ASI02", "ASI04", "ASI05", "ASI06", "ASI08", "ASI09"}.issubset(owasps)


class TestSandboxExecutor:
    def test_blocks_ast_violations_prior_to_execution(self):
        called = False

        def _fake_runner(*args, **kwargs):
            nonlocal called
            called = True
            return subprocess.CompletedProcess(args[0], 0, "", "")

        exe = SandboxExecutor(
            config=CodeSandboxConfig(provider="docker_rootless"),
            subprocess_runner=_fake_runner,
        )
        res = exe.execute("import os\nos.system('whoami')")
        assert res.verdict == Verdict.BLOCK
        assert res.payload.blocked_import == "os"
        assert not called

    def test_ast_only_allows_safe_code(self):
        exe = SandboxExecutor(config=CodeSandboxConfig(provider="ast_only"))
        res = exe.execute("x = 2 + 3\ny = x * 10")
        assert res.verdict == Verdict.ALLOW
        assert res.payload.exit_code == 0

    def test_docker_rootless_builds_hardened_flags_and_handles_timeout(self):
        captured_cmds = []

        def _ok_runner(cmd, **kwargs):
            captured_cmds.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "42\n", "")

        exe = SandboxExecutor(
            config=CodeSandboxConfig(provider="docker_rootless", memory_limit_mb=128, timeout_sec=5),
            subprocess_runner=_ok_runner,
        )
        ok_res = exe.execute("print(6 * 7)")
        assert ok_res.verdict == Verdict.ALLOW
        assert ok_res.payload.stdout == "42\n"
        cmd = captured_cmds[0]
        assert "--network" in cmd and "none" in cmd
        assert "--read-only" in cmd
        assert "--cap-drop" in cmd and "ALL" in cmd
        assert "128m" in cmd

        def _timeout_runner(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=5)

        exe_to = SandboxExecutor(
            config=CodeSandboxConfig(provider="docker_rootless", timeout_sec=5),
            subprocess_runner=_timeout_runner,
        )
        to_res = exe_to.execute("print(1)")
        assert to_res.verdict == Verdict.BLOCK
        assert "SANDBOX_TIMEOUT" in (to_res.payload.error_message or "")

    def test_fail_closed_when_docker_daemon_unavailable(self):
        def _err_runner(cmd, **kwargs):
            raise FileNotFoundError("docker daemon unreachable")

        exe = SandboxExecutor(
            config=CodeSandboxConfig(provider="docker_rootless"),
            subprocess_runner=_err_runner,
        )
        res = exe.execute("print(1)")
        assert res.verdict == Verdict.BLOCK
        assert "SANDBOX_RUNTIME_UNAVAILABLE" in (res.payload.error_message or "")


class TestMemoryGuardRollback:
    def test_rollback_restores_overwritten_and_deletes_new_keys(self):
        ctx = AgentXDRContext(
            user_id="secops",
            user_roles=["admin"],
            agent_id="mem-agent",
            trace_id="trace-mem-rb",
        )
        guard = MemoryGuard(ctx=ctx)
        store = _DictKvStore()
        store.set("theme", "light")

        s1 = guard.write(store, "theme", "dark")
        s2 = guard.write(store, "extra_flag", "enabled")
        s3 = guard.write(store, "theme", "broken")
        assert s1.allowed and s2.allowed and s3.allowed
        assert store.data == {"theme": "broken", "extra_flag": "enabled"}

        # Roll back from s2 -> undoes s3 and s2, restoring theme="dark" and removing extra_flag
        rb = guard.rollback(store, s2.snapshot_id)
        assert rb.success
        assert rb.reverted_count == 2
        assert store.data == {"theme": "dark"}

        # Unknown snapshot returns failure gracefully
        bad_rb = guard.rollback(store, "missing-id")
        assert not bad_rb.success
        assert bad_rb.reason == "SNAPSHOT_NOT_FOUND"
