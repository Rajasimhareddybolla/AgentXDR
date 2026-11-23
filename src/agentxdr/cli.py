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

    # 4. topology
    topo_parser = subparsers.add_parser("topology", help="Export visual agent topology model")
    topo_parser.add_argument("policy_file", help="Path to policy YAML file")
    topo_parser.add_argument("--format", choices=["mermaid", "json"], default="mermaid", help="Output format")

    # 5. demo
    demo_parser = subparsers.add_parser("demo", help="Run end-to-end AgentXDR security demonstration")
    demo_parser.add_argument("--policy", help="Optional custom policy YAML")

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
    elif parsed.command == "topology":
        return cmd_topology(parsed)
    elif parsed.command == "demo":
        return cmd_demo(parsed)

    return 0


if __name__ == "__main__":
    sys.exit(main())
