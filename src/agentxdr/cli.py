"""AgentXDR Command-Line Interface (CLI).

Provides commands to start the unified runtime server, execute KQL-Lite queries,
validate security policies, export visual topologies, and run live security demos.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentxdr",
        description="AgentXDR: Enterprise Security Control Plane and Inline Runtime Protection for Agentic AI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-command to execute")

    # 1. serve / server
    serve_parser = subparsers.add_parser(
        "serve",
        aliases=["server"],
        help="Start the unified AgentXDR runtime server",
    )
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    serve_parser.add_argument("--policy", help="Path to declarative policy YAML file")
    serve_parser.add_argument("--db-path", default=":memory:", help="DuckDB database path (default: :memory:)")
    serve_parser.add_argument("--upstream-url", default="https://api.meta.ai/v1", help="Upstream LLM base URL (default: https://api.meta.ai/v1)")

    # 2. kql
    kql_parser = subparsers.add_parser("kql", help="Execute a KQL-Lite query against DuckDB telemetry")
    kql_parser.add_argument("query", help="KQL pipeline query string, e.g. 'events | take 5'")
    kql_parser.add_argument("--db-path", default=":memory:", help="DuckDB database path")
    kql_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    # 3. policy
    policy_parser = subparsers.add_parser("policy", help="Security policy tools")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)
    val_parser = policy_sub.add_parser("validate", help="Validate a policy YAML file against PolicySchema")
    val_parser.add_argument("policy_file", help="Path to policy YAML file")

    diff_parser = policy_sub.add_parser("diff", help="Detect policy-weakening regressions between two policy files")
    diff_parser.add_argument("base_policy", help="Path to base policy YAML")
    diff_parser.add_argument("head_policy", help="Path to head/PR policy YAML")
    diff_parser.add_argument("--format", choices=["text", "json", "markdown"], default="markdown", help="Output format")
    diff_parser.add_argument("--allow-budget-increase", action="store_true", help="Do not fail on budget ceiling increases")

    # 4. topology
    topo_parser = subparsers.add_parser("topology", help="Export visual agent topology model")
    topo_parser.add_argument("policy_file", help="Path to policy YAML file")
    topo_parser.add_argument("--format", choices=["mermaid", "json"], default="mermaid", help="Output format")

    # 5. demo
    demo_parser = subparsers.add_parser("demo", help="Run end-to-end AgentXDR security demonstration")
    demo_parser.add_argument("--policy", help="Optional custom policy YAML")

    # 6. deps
    deps_parser = subparsers.add_parser("deps", help="Dependency and external MCP package auditing")
    deps_sub = deps_parser.add_subparsers(dest="deps_command", required=True)
    deps_scan = deps_sub.add_parser("scan", help="Scan pyproject, requirements, and MCP configs for vulnerabilities")
    deps_scan.add_argument("--path", default=".", help="Workspace root directory")
    deps_scan.add_argument("--mcp-config", help="Optional explicit MCP config JSON path")
    deps_scan.add_argument("--offline", action="store_true", help="Run using curated offline advisories only")
    deps_scan.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # 7. mcp
    mcp_parser = subparsers.add_parser("mcp", help="External MCP server discovery and SHA-256 schema pinning")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_command", required=True)
    mcp_disc = mcp_sub.add_parser("discover", help="Discover shadow or unpinned MCP servers in workspace configs")
    mcp_disc.add_argument("--path", default=".", help="Workspace root directory")
    mcp_disc.add_argument("--config", help="Optional explicit MCP JSON config path")
    mcp_disc.add_argument("--policy", default="examples/sample_policy.yaml", help="Policy YAML to audit against")
    mcp_disc.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    mcp_pin = mcp_sub.add_parser("pin", help="Connect to a stdio MCP server and compute SHA-256 schema hashes")
    mcp_pin.add_argument("--command", required=True, help="MCP server executable command")
    mcp_pin.add_argument("--args", nargs="*", default=[], help="Command arguments")
    mcp_pin.add_argument("--policy", default="examples/sample_policy.yaml", help="Baseline policy YAML")
    mcp_pin.add_argument("--format", choices=["json", "yaml"], default="json", help="Output format")

    # 8. redteam
    rt_parser = subparsers.add_parser("redteam", help="Run pre-deployment adversarial red-team suite (PyRIT)")
    rt_parser.add_argument("--policy", default="examples/sample_policy.yaml", help="Policy YAML path")
    rt_parser.add_argument("--mode", choices=["offline", "live"], default="offline", help="Execution mode")
    rt_parser.add_argument("--min-score", type=float, default=0.95, help="Minimum pass resilience ratio (0.0-1.0)")
    rt_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    return parser


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from agentxdr.server.app import create_agentxdr_app

    print(f"[*] Starting AgentXDR Unified Control Plane on {args.host}:{args.port}")
    if args.policy:
        print(f"[*] Loading active security policy: {args.policy}")
    print(f"[*] DuckDB telemetry store: {args.db_path}")

    app = create_agentxdr_app(
        policy_path=args.policy,
        db_path=args.db_path,
        upstream_llm_url=args.upstream_url,
    )
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def cmd_kql(args: argparse.Namespace) -> int:
    from agentxdr.analytics.duckdb_store import DuckDbAnalyticsStore

    store = DuckDbAnalyticsStore(db_path=args.db_path)
    try:
        result = store.execute_kql(args.query)
        if args.json:
            print(json.dumps({"columns": result.columns, "rows": result.rows, "execution_time_ms": result.execution_time_ms}, indent=2, default=str))
        else:
            print(f"Execution time: {result.execution_time_ms:.2f} ms | Rows: {len(result.rows)}")
            if result.rows:
                # Pretty print table
                header = " | ".join(result.columns)
                sep = "-+-".join("-" * len(c) for c in result.columns)
                print(header)
                print(sep)
                for r in result.rows:
                    print(" | ".join(str(r.get(c, "")) for c in result.columns))
            else:
                print("No rows returned.")
        return 0
    except Exception as e:
        print(f"Error executing KQL query: {e}", file=sys.stderr)
        return 1


def cmd_policy_validate(args: argparse.Namespace) -> int:
    from agentxdr.policy.loader import load_policy_yaml

    path = Path(args.policy_file)
    if not path.is_file():
        print(f"Error: Policy file not found: {path}", file=sys.stderr)
        return 1

    try:
        with open(path, "r", encoding="utf-8") as f:
            policy = load_policy_yaml(f.read())
        print(f"[✓] Policy {policy.agent_id} (v{policy.version}) is VALID.")
        print(f"    - Tools declared: {len(policy.tools)}")
        print(f"    - Taint rules: {len(policy.taint_rules)}")
        print(f"    - Max turns: {policy.budgets.max_turns}")
        print(f"    - Max tool calls: {policy.budgets.max_tool_calls}")
        if policy.goal_anchor:
            print(f"    - Goal anchor: \"{policy.goal_anchor.canonical_task}\"")
        return 0
    except Exception as e:
        print(f"[✗] Policy validation failed: {e}", file=sys.stderr)
        return 1


def cmd_topology(args: argparse.Namespace) -> int:
    from agentxdr.policy.loader import load_policy_yaml
    from agentxdr.topology.builder import AgentTopologyBuilder

    path = Path(args.policy_file)
    if not path.is_file():
        print(f"Error: File not found: {path}", file=sys.stderr)
        return 1

    with open(path, "r", encoding="utf-8") as f:
        policy = load_policy_yaml(f.read())

    model = AgentTopologyBuilder.build_topology(policy)
    if args.format == "mermaid":
        print(model.to_mermaid())
    else:
        print(json.dumps(model.to_react_flow(), indent=2))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from scripts.run_demo import run_comprehensive_demo
    return run_comprehensive_demo(policy_path=args.policy)


def cmd_policy_diff(args: argparse.Namespace) -> int:
    from agentxdr.ci.policy_diff import PolicyDiffEngine
    from agentxdr.policy.loader import load_policy_yaml

    try:
        base = load_policy_yaml(args.base_policy)
        head = load_policy_yaml(args.head_policy)
    except Exception as exc:
        print(f"Error loading policy files: {exc}", file=sys.stderr)
        return 1

    report = PolicyDiffEngine().compare(
        base=base,
        head=head,
        allow_budget_increase=args.allow_budget_increase,
    )
    if args.format == "json":
        print(report.to_json())
    else:
        print(report.to_markdown())
    return 1 if report.has_regressions else 0


def cmd_deps_scan(args: argparse.Namespace) -> int:
    from agentxdr.ci.dependency_audit import DependencyAuditor

    report = DependencyAuditor().scan(
        root_path=args.path,
        mcp_config_path=args.mcp_config,
        offline=args.offline,
    )
    print(report.to_json() if args.format == "json" else report.to_text())
    return 1 if report.has_blocking_findings else 0


def cmd_mcp_discover(args: argparse.Namespace) -> int:
    from agentxdr.mcp.shadow_scanner import ShadowMcpScanner
    from agentxdr.policy.loader import load_policy_yaml

    policy = load_policy_yaml(args.policy)
    scanner = ShadowMcpScanner()
    if args.config:
        report = scanner.scan_files([Path(args.config)], policy=policy)
    else:
        report = scanner.discover_workspace(args.path, policy=policy)

    if args.format == "json":
        print(report.to_json())
    else:
        print(
            f"Discovered servers: {len(report.discovered_servers)} | "
            f"Shadow/Unpinned findings: {len(report.findings)}"
        )
        for f in report.findings:
            print(f"  [{f.severity}] {f.owasp_id} {f.reason} -> server={f.server_name} tool={f.tool_name or '-'}")
    return 1 if report.has_shadow_risks else 0


def cmd_mcp_pin(args: argparse.Namespace) -> int:
    import asyncio
    import yaml
    from agentxdr.mcp.stdio_client import GuardedStdioMcpClient, McpServerTarget
    from agentxdr.policy.loader import load_policy_yaml

    policy = load_policy_yaml(args.policy)
    target = McpServerTarget(server_id="cli-pin", command=args.command, args=list(args.args))
    client = GuardedStdioMcpClient(target=target, policy=policy)
    hashes = asyncio.run(client.snapshot_tool_hashes())
    if args.format == "yaml":
        print(yaml.safe_dump({"pinned_tools": [{"name": k, "schema_sha256": v} for k, v in hashes.items()]}))
    else:
        print(json.dumps(hashes, indent=2))
    return 0


def cmd_redteam(args: argparse.Namespace) -> int:
    import os
    from agentxdr.policy.loader import load_policy_yaml
    from agentxdr.redteam.runner import AgentXDRRedTeamRunner, RedTeamMode

    policy = load_policy_yaml(args.policy)
    mode = RedTeamMode(args.mode)
    api_key = os.environ.get("meta_api_key") or os.environ.get("MODEL_API_KEY")
    report = AgentXDRRedTeamRunner().run(
        policy=policy,
        mode=mode,
        min_score=args.min_score,
        upstream_api_key=api_key,
    )
    print(report.to_json() if args.format == "json" else report.to_text())
    return 0 if report.passed_threshold else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(argv)

    if parsed.command in ("serve", "server"):
        return cmd_serve(parsed)
    elif parsed.command == "kql":
        return cmd_kql(parsed)
    elif parsed.command == "policy":
        if parsed.policy_command == "validate":
            return cmd_policy_validate(parsed)
        elif parsed.policy_command == "diff":
            return cmd_policy_diff(parsed)
    elif parsed.command == "topology":
        return cmd_topology(parsed)
    elif parsed.command == "demo":
        return cmd_demo(parsed)
    elif parsed.command == "deps":
        if parsed.deps_command == "scan":
            return cmd_deps_scan(parsed)
    elif parsed.command == "mcp":
        if parsed.mcp_command == "discover":
            return cmd_mcp_discover(parsed)
        elif parsed.mcp_command == "pin":
            return cmd_mcp_pin(parsed)
    elif parsed.command == "redteam":
        return cmd_redteam(parsed)

    return 0


if __name__ == "__main__":
    sys.exit(main())
