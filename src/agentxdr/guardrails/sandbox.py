"""Pre-execution AST validation and rootless Docker container sandbox executor."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

from agentxdr.guardrails.ast_sanitizer import AstSanitizer, AstViolation
from agentxdr.models.events import SandboxExecPayload, Verdict
from agentxdr.models.policy import CodeSandboxConfig


class SandboxExecResult(BaseModel):
    """Execution verdict, payload telemetry, and static/runtime findings."""

    verdict: Verdict
    provider: str
    payload: SandboxExecPayload
    violations: List[AstViolation] = Field(default_factory=list)


class SandboxExecutor:
    """Executes untrusted Python snippets inside AST + rootless container enclaves.

    Stage 1: Always runs deterministic ``AstSanitizer`` before any execution.
    Stage 2: Executes in ``docker_rootless`` (network disabled, read-only rootfs,
             dropped capabilities, strict memory/CPU/PID/timeout caps) or
             ``ast_only`` validated static mode. Fails closed if Docker daemon
             is unavailable when ``docker_rootless`` is required.
    """

    def __init__(
        self,
        config: Optional[CodeSandboxConfig] = None,
        subprocess_runner: Optional[Callable[..., subprocess.CompletedProcess[str]]] = None,
    ) -> None:
        self.config = config or CodeSandboxConfig()
        blocked = self.config.blocked_imports if self.config.blocked_imports else None
        self.sanitizer = AstSanitizer(blocked_imports=blocked)
        self._runner = subprocess_runner or subprocess.run

    def execute(self, code: str) -> SandboxExecResult:
        """Analyze *code* via AST sanitizer and execute within configured sandbox."""
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        if not self.config.enabled:
            return SandboxExecResult(
                verdict=Verdict.BLOCK,
                provider=self.config.provider,
                payload=SandboxExecPayload(
                    code_hash=code_hash,
                    error_message="Code execution sandbox is disabled by policy.",
                    exit_code=1,
                ),
            )

        # Stage 1: Static AST pre-execution check
        ast_res = self.sanitizer.sanitize(code)
        if not ast_res.is_safe:
            first_imp = next(
                (v.name for v in ast_res.violations if v.rule == "FORBIDDEN_IMPORT"),
                None,
            )
            err_summary = "; ".join(f"{v.rule}:{v.name}" for v in ast_res.violations)
            return SandboxExecResult(
                verdict=Verdict.BLOCK,
                provider=self.config.provider,
                payload=SandboxExecPayload(
                    code_hash=code_hash,
                    blocked_import=first_imp,
                    error_message=f"AST check blocked unsafe code: {err_summary}",
                    exit_code=1,
                ),
                violations=list(ast_res.violations),
            )

        # Stage 2: Provider execution
        if self.config.provider == "ast_only":
            return SandboxExecResult(
                verdict=Verdict.ALLOW,
                provider="ast_only",
                payload=SandboxExecPayload(
                    code_hash=code_hash,
                    exit_code=0,
                    stdout="AST validation passed (ast_only execution mode).",
                    execution_time_sec=round(ast_res.latency_ms / 1000.0, 6),
                ),
            )

        return self._run_docker_rootless(code=code, code_hash=code_hash)

    def _run_docker_rootless(self, code: str, code_hash: str) -> SandboxExecResult:
        docker_bin = shutil.which("docker")
        if not docker_bin and self._runner is subprocess.run:
            return SandboxExecResult(
                verdict=Verdict.BLOCK,
                provider="docker_rootless",
                payload=SandboxExecPayload(
                    code_hash=code_hash,
                    error_message="SANDBOX_RUNTIME_UNAVAILABLE: docker binary not found (fail-closed).",
                    exit_code=127,
                ),
            )

        cmd = [
            docker_bin or "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            f"{self.config.memory_limit_mb}m",
            "--cpus",
            "0.5",
            "python:3.11-slim",
            "python",
            "-I",
            "-c",
            code,
        ]
        t0 = time.perf_counter()
        try:
            proc = self._runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_sec,
                check=False,
            )
            elapsed = time.perf_counter() - t0
            verdict = Verdict.ALLOW if proc.returncode == 0 else Verdict.BLOCK
            return SandboxExecResult(
                verdict=verdict,
                provider="docker_rootless",
                payload=SandboxExecPayload(
                    code_hash=code_hash,
                    exit_code=proc.returncode,
                    stdout=proc.stdout or "",
                    stderr=proc.stderr or "",
                    error_message=(
                        f"Container exited with code {proc.returncode}: {proc.stderr.strip()}"
                        if proc.returncode != 0
                        else None
                    ),
                    execution_time_sec=round(elapsed, 6),
                ),
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - t0
            return SandboxExecResult(
                verdict=Verdict.BLOCK,
                provider="docker_rootless",
                payload=SandboxExecPayload(
                    code_hash=code_hash,
                    exit_code=124,
                    error_message=f"SANDBOX_TIMEOUT after {self.config.timeout_sec}s",
                    execution_time_sec=round(elapsed, 6),
                ),
            )
        except Exception as exc:
            elapsed = time.perf_counter() - t0
            return SandboxExecResult(
                verdict=Verdict.BLOCK,
                provider="docker_rootless",
                payload=SandboxExecPayload(
                    code_hash=code_hash,
                    exit_code=1,
                    error_message=f"SANDBOX_RUNTIME_UNAVAILABLE: {exc}",
                    execution_time_sec=round(elapsed, 6),
                ),
            )
