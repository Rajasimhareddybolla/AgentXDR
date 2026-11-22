"""MCP Security Proxy — mediates JSON-RPC 2.0 tool discovery and execution flows."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentxdr.mcp.call_enforcer import McpCallEnforcer
from agentxdr.mcp.schema_registry import McpSchemaRegistry
from agentxdr.mcp.tool_filter import McpToolFilter
from agentxdr.models.events import Verdict
from agentxdr.models.policy import PolicySchema
from agentxdr.models.taint import TaintState


from agentxdr.policy.evaluator import _UNSET


class McpProxy:
    """Zero-trust proxy mediating Model Context Protocol (MCP) JSON-RPC traffic."""

    def __init__(
        self,
        policy: PolicySchema,
        registry: McpSchemaRegistry,
        filter: McpToolFilter,
        enforcer: McpCallEnforcer,
    ) -> None:
        self.policy = policy
        self.registry = registry
        self.filter = filter
        self.enforcer = enforcer
        self._alerts: List[Dict[str, Any]] = []

    def handle_tools_list(self, raw_response: Dict[str, Any], trace_id: str) -> Dict[str, Any]:
        """Filter a raw tools/list JSON-RPC response from an MCP server."""
        result = raw_response.get("result", {})
        raw_tools = result.get("tools", [])

        approved_tools, rejected_tools = self.filter.filter_tools_list(raw_tools)

        for rej in rejected_tools:
            self._alerts.append({
                "trace_id": trace_id,
                "tool_name": rej.get("name"),
                "reason": rej.get("reason"),
                "owasp_id": rej.get("owasp_id"),
            })

        out = dict(raw_response)
        out["result"] = dict(result)
        out["result"]["tools"] = approved_tools
        return out

    def handle_tools_call(
        self,
        request: Dict[str, Any],
        trace_id: str,
        taints: Optional[TaintState] = None,
        tool_schema_hash: Any = _UNSET,
    ) -> Dict[str, Any]:
        """Enforce policy and tiered action authorization on a tools/call request."""
        req_id = request.get("id")
        params = request.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        decision, refusal = self.enforcer.enforce_call(
            policy=self.policy,
            tool_name=tool_name,
            arguments=arguments,
            trace_id=trace_id,
            taints=taints,
            tool_schema_hash=tool_schema_hash,
        )

        if refusal is not None:
            refusal["id"] = req_id
            return refusal

        if decision.verdict == Verdict.PAUSE_FOR_HITL:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "status": "pending_hitl",
                    "tool_name": tool_name,
                    "trace_id": trace_id,
                    "message": "Tool execution paused pending human-in-the-loop approval.",
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "status": "approved",
                "tool_name": tool_name,
                "trace_id": trace_id,
            },
        }

    def sanitize_tool_result(
        self,
        raw_result: Dict[str, Any],
        trace_id: str,
        taints: Optional[TaintState] = None,
    ) -> Dict[str, Any]:
        """Sanitize an MCP tool execution result payload before returning to agent."""
        inner_result = raw_result.get("result", {})
        sanitized_content, was_injected, taint_labels = self.enforcer.sanitize_response(
            inner_result, trace_id=trace_id, taints=taints
        )

        out = dict(raw_result)
        out["result"] = sanitized_content
        return out

    @property
    def alerts(self) -> List[Dict[str, Any]]:
        """Return list of generated security alerts."""
        return list(self._alerts)


def create_fastapi_mcp_app(proxy: McpProxy) -> FastAPI:
    """Create a FastAPI application serving MCP proxy endpoints."""
    app = FastAPI(title="AgentXDR MCP Security Proxy", version="1.0.0")

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "component": "agentxdr-mcp-proxy"}

    @app.post("/mcp/tools/list")
    async def tools_list(request: Request) -> JSONResponse:
        body: Dict[str, Any] = await request.json()
        trace_id = request.headers.get("x-trace-id") or str(uuid.uuid4())
        filtered = proxy.handle_tools_list(body, trace_id=trace_id)
        return JSONResponse(status_code=200, content=filtered)

    @app.post("/mcp/tools/call")
    async def tools_call(request: Request) -> JSONResponse:
        body: Dict[str, Any] = await request.json()
        trace_id = request.headers.get("x-trace-id") or str(uuid.uuid4())
        params = body.get("params", {})
        tool_hash = params.get("schema_sha256") or params.get("tool_schema_hash")
        kw = {"tool_schema_hash": tool_hash} if tool_hash is not None else {}
        result = proxy.handle_tools_call(body, trace_id=trace_id, **kw)
        if "error" in result:
            return JSONResponse(status_code=403, content=result)
        return JSONResponse(status_code=200, content=result)

    return app
