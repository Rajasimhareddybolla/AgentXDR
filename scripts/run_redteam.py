#!/usr/bin/env python3
"""Standalone Pre-Deployment Red-Teaming Runner (PyRIT + AgentXDR)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from agentxdr.policy.loader import load_policy_yaml
from agentxdr.redteam.runner import AgentXDRRedTeamRunner, RedTeamMode


def _resolve_meta_key() -> str | None:
    key = os.environ.get("meta_api_key") or os.environ.get("MODEL_API_KEY")
    if key:
        return key
    env_file = REPO_ROOT / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("meta_api_key="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AgentXDR PyRIT Pre-Deployment Red-Team Suite")
    parser.add_argument("--policy", default=str(REPO_ROOT / "examples" / "sample_policy.yaml"))
    parser.add_argument("--mode", choices=["offline", "live"], default="offline")
    parser.add_argument("--min-score", type=float, default=0.95)
    args = parser.parse_args()

    policy = load_policy_yaml(args.policy)
    mode = RedTeamMode(args.mode)
    api_key = _resolve_meta_key() if mode == RedTeamMode.LIVE else None

    runner = AgentXDRRedTeamRunner()
    report = runner.run(
        policy=policy,
        mode=mode,
        min_score=args.min_score,
        upstream_url="https://api.meta.ai/v1",
        upstream_api_key=api_key,
    )
    print(report.to_text())
    return 0 if report.passed_threshold else 1


if __name__ == "__main__":
    sys.exit(main())
