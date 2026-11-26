"""Unit tests for the unified AgentXDR server and CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from agentxdr.cli import build_parser, main
from agentxdr.server.app import create_agentxdr_app


@pytest.fixture
def client() -> TestClient:
    app = create_agentxdr_app()
    return TestClient(app)


class TestUnifiedServerRoutes:
    def test_health_check(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "events_ingested" in data

    def test_get_info(self, client: TestClient):
        resp = client.get("/api/v1/info")
        assert resp.status_code == 200
        data = resp.json()
        assert "AgentXDR" in data["app"]
        assert "tools_count" in data

    def test_analytics_kql_endpoint(self, client: TestClient):
        resp = client.post("/api/v1/analytics/kql", json={"query": "events | take 5"})
        assert resp.status_code == 200
        data = resp.json()
        assert "columns" in data
        assert "rows" in data
        assert "execution_time_ms" in data

    def test_analytics_stats_endpoint(self, client: TestClient):
        resp = client.get("/api/v1/analytics/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "events_count" in data
        assert "graph_edges_count" in data

    def test_topology_mermaid_endpoint(self, client: TestClient):
        resp = client.get("/api/v1/topology/mermaid")
        assert resp.status_code == 200
        assert "flowchart" in resp.json()["mermaid"] or "graph" in resp.json()["mermaid"]

    def test_topology_react_flow_endpoint(self, client: TestClient):
        resp = client.get("/api/v1/topology/react-flow")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data

    def test_drift_evaluate_endpoint(self, client: TestClient):
        payload = {
            "trace_id": "test-trace-1",
            "step_text": "read firewall rules",
            "anchor_text": "read firewall rules",
        }
        resp = client.post("/api/v1/drift/evaluate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "drift_score" in data
        assert "composite_risk" in data

    def test_persuasion_classify_endpoint(self, client: TestClient):
        payload = {"text": "URGENT: Approve immediately right now!"}
        resp = client.post("/api/v1/persuasion/classify", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] > 0.0
        assert "ARTIFICIAL_URGENCY" in data["tactics"]

    def test_kill_switch_lifecycle_endpoints(self, client: TestClient):
        # 1. Trip
        trip_payload = {
            "scope": "AGENT",
            "target_id": "compromised-agent",
            "reason": "Test containment",
            "triggered_by": "secops",
        }
        resp = client.post("/api/v1/response/kill-switch/trip", json=trip_payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "tripped"

        # 2. Status
        resp = client.get("/api/v1/response/kill-switch/status")
        assert resp.status_code == 200
        assert resp.json()["active_count"] >= 1

        # 3. Reset
        reset_payload = {
            "scope": "AGENT",
            "target_id": "compromised-agent",
        }
        resp = client.post("/api/v1/response/kill-switch/reset", json=reset_payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "reset"

    def test_dashboard_endpoint(self, client: TestClient):
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "AgentXDR | Enterprise Runtime Security Control Plane" in resp.text
        assert "Live Agent Chat (Meta AI)" in resp.text

    def test_root_redirect_to_dashboard(self, client: TestClient):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 307 or resp.status_code == 200

    def test_demo_run_simulation(self, client: TestClient):
        resp = client.post("/api/v1/demo/run")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["events_generated"] == 4
        assert "hitl_ticket_id" in data

    def test_ci_policy_diff_endpoint(self, client: TestClient):
        base = Path("examples/sample_policy.yaml").read_text(encoding="utf-8")
        weak = base.replace('tier: "blocked"', 'tier: "automatic"')
        resp = client.post(
            "/api/v1/ci/policy-diff",
            json={"base_yaml": base, "head_yaml": weak},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["findings"]) >= 1
        assert any(f["severity"] == "CRITICAL" for f in data["findings"])

    def test_mcp_discover_and_sandbox_and_redteam_endpoints(self, client: TestClient):
        disc = client.post(
            "/api/v1/mcp/discover",
            json={"config_json": {"mcpServers": {"rogue": {"command": "npx", "args": ["foo"]}}}},
        )
        assert disc.status_code == 200
        assert len(disc.json()["findings"]) >= 1

        sb_block = client.post("/api/v1/sandbox/execute", json={"code": "import os\nos.system('id')"})
        assert sb_block.status_code == 200
        assert sb_block.json()["verdict"] == "BLOCK"

        sb_ok = client.post("/api/v1/sandbox/execute", json={"code": "x = 1 + 2"})
        assert sb_ok.status_code == 200
        assert sb_ok.json()["verdict"] == "ALLOW"

        rt = client.post("/api/v1/redteam/run", json={"mode": "offline", "min_score": 0.95})
        assert rt.status_code == 200
        assert rt.json()["passed_threshold"] is True

    def test_memory_wal_write_and_rollback_endpoints(self, client: TestClient):
        w1 = client.post(
            "/api/v1/response/memory/write",
            json={"key": "k1", "value": "v1", "tainted": False},
        )
        assert w1.status_code == 200
        assert w1.json()["allowed"] is True
        sid = w1.json()["snapshot_id"]

        w_bad = client.post(
            "/api/v1/response/memory/write",
            json={"key": "k2", "value": "bad", "tainted": True},
        )
        assert w_bad.status_code == 200
        assert w_bad.json()["allowed"] is False

        snaps = client.get("/api/v1/response/memory/snapshots").json()
        assert "k1" in snaps["store_keys"]

        rb = client.post("/api/v1/response/memory/rollback", json={"snapshot_id": sid})
        assert rb.status_code == 200
        assert rb.json()["status"] == "rolled_back"
        snaps_after = client.get("/api/v1/response/memory/snapshots").json()
        assert "k1" not in snaps_after["store_keys"]


class TestCliInterface:
    def test_parser_generation(self):
        parser = build_parser()
        assert parser is not None

    def test_policy_validate_valid_file(self, tmp_path: Path):
        policy_file = tmp_path / "valid_policy.yaml"
        policy_file.write_text("""
version: "1.0.0"
agent_id: "test-agent"
budgets:
  max_turns: 5
  max_tool_calls: 10
  max_identical_calls: 2
  max_session_duration_sec: 60.0
  max_session_cost_usd: 1.0
""")
        ret = main(["policy", "validate", str(policy_file)])
        assert ret == 0

    def test_policy_validate_missing_file(self):
        ret = main(["policy", "validate", "nonexistent_policy_file.yaml"])
        assert ret == 1

    def test_kql_cli_query(self):
        ret = main(["kql", "events | take 1"])
        assert ret == 0

    def test_topology_cli_export(self, tmp_path: Path):
        policy_file = tmp_path / "valid_policy.yaml"
        policy_file.write_text("""
version: "1.0.0"
agent_id: "test-agent"
budgets:
  max_turns: 5
  max_tool_calls: 10
  max_identical_calls: 2
  max_session_duration_sec: 60.0
  max_session_cost_usd: 1.0
""")
        ret = main(["topology", str(policy_file), "--format", "json"])
        assert ret == 0

    def test_policy_diff_cli(self, tmp_path: Path):
        base_f = tmp_path / "base.yaml"
        head_f = tmp_path / "head.yaml"
        base_yaml = Path("examples/sample_policy.yaml").read_text(encoding="utf-8")
        base_f.write_text(base_yaml)
        head_f.write_text(base_yaml)
        assert main(["policy", "diff", str(base_f), str(head_f), "--format", "json"]) == 0

        head_f.write_text(base_yaml.replace('tier: "blocked"', 'tier: "automatic"'))
        assert main(["policy", "diff", str(base_f), str(head_f), "--format", "markdown"]) == 1

    def test_deps_scan_and_redteam_and_mcp_discover_cli(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("pydantic==2.10.0\n")
        assert main(["deps", "scan", "--path", str(tmp_path), "--offline", "--format", "json"]) == 0
        assert main(["redteam", "--mode", "offline", "--min-score", "0.95", "--format", "json"]) == 0
        (tmp_path / ".mcp.json").write_text('{"mcpServers":{"rogue":{"command":"npx","args":["x"]}}}')
        assert main(["mcp", "discover", "--path", str(tmp_path), "--format", "json"]) == 1
