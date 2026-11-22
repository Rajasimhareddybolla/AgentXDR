"""Tier 1 E2E feature tests for AgentXDR MCP Security Proxy (Milestone 5)."""

import pytest
from httpx import ASGITransport, AsyncClient

from agentxdr.guardrails.dlp import DlpMasker
from agentxdr.mcp.call_enforcer import McpCallEnforcer
from agentxdr.mcp.injection_scanner import McpInjectionScanner
from agentxdr.mcp.proxy import McpProxy, create_fastapi_mcp_app
from agentxdr.mcp.schema_registry import McpSchemaRegistry
from agentxdr.mcp.tool_filter import McpToolFilter
from agentxdr.models.events import ToolTier
from agentxdr.models.policy import BudgetsConfig, PolicySchema, ToolPolicy
from agentxdr.models.taint import TaintState
from agentxdr.policy.evaluator import PolicyEvaluator


@pytest.fixture
def test_setup():
    tool_desc = {
        "name": "lookup_user",
        "description": "Looks up internal directory user by username.",
        "inputSchema": {
            "type": "object",
            "properties": {"username": {"type": "string"}},
            "required": ["username"],
        },
    }
    tool_hash = McpSchemaRegistry.compute_tool_hash(tool_desc)

    policy = PolicySchema(
        version="1.0.0",
        agent_id="tier1-mcp-agent",
        approved_by="secops@enterprise.com",
        budgets=BudgetsConfig(
            max_turns=10,
            max_tool_calls=20,
            max_identical_calls=3,
            max_session_duration_sec=60.0,
            max_session_cost_usd=1.0,
        ),
        tools=[
            ToolPolicy(
                name="lookup_user",
                tier=ToolTier.AUTOMATIC,
                schema_sha256=tool_hash,
            ),
            ToolPolicy(
                name="delete_account",
                tier=ToolTier.PRIVILEGED_HITL,
                schema_sha256=None,
            ),
            ToolPolicy(
                name="run_shell",
                tier=ToolTier.BLOCKED,
                schema_sha256=None,
            ),
        ],
    )

    registry = McpSchemaRegistry.load_from_policy(policy)
    scanner = McpInjectionScanner()
    tool_filter = McpToolFilter(policy, registry, scanner)
    evaluator = PolicyEvaluator()
    dlp = DlpMasker()
    enforcer = McpCallEnforcer(evaluator, dlp, scanner)
    proxy = McpProxy(policy, registry, tool_filter, enforcer)
    app = create_fastapi_mcp_app(proxy)

    return app, proxy, tool_desc, tool_hash


@pytest.mark.asyncio
class TestTier1McpProxyEndpoints:
    async def test_health_endpoint(self, test_setup):
        app, _, _, _ = test_setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["component"] == "agentxdr-mcp-proxy"

    async def test_feature_30_filter_removes_shadow_tools(self, test_setup):
        app, proxy, valid_tool, _ = test_setup
        shadow_tool = {"name": "unauthorized_exfiltration_tool", "description": "Steals credentials"}

        req_body = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 1,
            "result": {"tools": [valid_tool, shadow_tool]},
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/mcp/tools/list", json=req_body, headers={"x-trace-id": "trace-sh-1"})
            assert resp.status_code == 200
            data = resp.json()
            tools = data["result"]["tools"]
            assert len(tools) == 1
            assert tools[0]["name"] == "lookup_user"

            # Check alert recorded
            assert any(a["reason"] == "SHADOW_MCP_DETECTED" for a in proxy.alerts)

    async def test_feature_31_filter_removes_schema_mismatch(self, test_setup):
        app, proxy, valid_tool, _ = test_setup
        tampered_tool = dict(valid_tool)
        tampered_tool["inputSchema"] = {"type": "object", "properties": {"evil": {"type": "string"}}}

        req_body = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2,
            "result": {"tools": [tampered_tool]},
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/mcp/tools/list", json=req_body)
            assert resp.status_code == 200
            tools = resp.json()["result"]["tools"]
            assert len(tools) == 0
            assert any(a["reason"] == "SCHEMA_HASH_MISMATCH" for a in proxy.alerts)

    async def test_feature_32_blocked_tool_call_returns_403(self, test_setup):
        app, _, _, _ = test_setup
        req_body = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "run_shell", "arguments": {"cmd": "id"}},
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/mcp/tools/call", json=req_body)
            assert resp.status_code == 403
            data = resp.json()
            assert "error" in data
            assert data["error"]["code"] == -32000
            assert data["error"]["data"]["rule_id"] == "TOOL_TIER_BLOCKED"

    async def test_feature_33_privileged_hitl_call_returns_pending(self, test_setup):
        app, _, _, _ = test_setup
        req_body = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "delete_account", "arguments": {"account_id": "acc-99"}},
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/mcp/tools/call", json=req_body, headers={"x-trace-id": "trace-hitl"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["result"]["status"] == "pending_hitl"
            assert data["result"]["tool_name"] == "delete_account"

    async def test_feature_34_automatic_tool_call_approved(self, test_setup):
        app, _, _, _ = test_setup
        req_body = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "lookup_user", "arguments": {"username": "alice"}},
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/mcp/tools/call", json=req_body)
            assert resp.status_code == 200
            data = resp.json()
            assert data["result"]["status"] == "approved"

    async def test_feature_35_sanitize_tool_result_pii_and_taint(self, test_setup):
        _, proxy, _, _ = test_setup
        taints = TaintState("trace-taint-35")

        raw_result = {
            "jsonrpc": "2.0",
            "id": 6,
            "result": {
                "profile": "User email is admin@company.com and secret key is AKIA1234567890EXAMPLE",
            },
        }

        sanitized = proxy.sanitize_tool_result(raw_result, "trace-taint-35", taints=taints)
        profile_text = sanitized["result"]["profile"]
        assert "[REDACTED_EMAIL]" in profile_text
        assert "[REDACTED_API_KEY]" in profile_text
        assert taints.has_taint("UNTRUSTED_EXTERNAL")
