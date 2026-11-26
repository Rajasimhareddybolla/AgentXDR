"""Guarded Stdio MCP Client — connects real external MCP servers over stdio with zero-trust enforcement."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel, Field

from agentxdr.guardrails.dlp import DlpMasker
from agentxdr.mcp.call_enforcer import McpCallEnforcer
from agentxdr.mcp.injection_scanner import McpInjectionScanner
from agentxdr.mcp.schema_registry import McpSchemaRegistry
from agentxdr.mcp.tool_filter import McpToolFilter
from agentxdr.models.events import Verdict
from agentxdr.models.killswitch import KillSwitchState
from agentxdr.models.policy import PolicySchema
from agentxdr.models.taint import TaintState
from agentxdr.policy.evaluator import PolicyEvaluator, _UNSET

_SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH", "VIRTUAL_ENV", "TMPDIR")


class McpServerTarget(BaseModel):
    """Connection specification for an external stdio MCP server process."""

    server_id: str
    command: str
    args: List[str] = Field(default_factory=list)
    cwd: Optional[str] = None
    allowed_env_vars: List[str] = Field(default_factory=list)


class GuardedStdioMcpClient:
    """Zero-trust MCP client mediating real subprocess ``stdio`` sessions.

    All discovered tools pass through ``McpToolFilter`` (shadow tool rejection,
    description prompt-injection scanning, canonical SHA-256 pinning) and all
    invocations pass through ``McpCallEnforcer`` before and after execution.
    """

    def __init__(
        self,
        target: McpServerTarget,
        policy: PolicySchema,
        registry: Optional[McpSchemaRegistry] = None,
        scanner: Optional[McpInjectionScanner] = None,
        dlp: Optional[DlpMasker] = None,
        kill_switch: Optional[KillSwitchState] = None,
    ) -> None:
        self.target = target
        self.policy = policy
        self.registry = registry or McpSchemaRegistry.load_from_policy(policy)
        self.scanner = scanner or McpInjectionScanner()
        self.dlp = dlp or DlpMasker()
        self.evaluator = PolicyEvaluator(kill_switch=kill_switch)
        self.tool_filter = McpToolFilter(
            policy=self.policy,
            registry=self.registry,
            scanner=self.scanner,
        )
        self.enforcer = McpCallEnforcer(
            evaluator=self.evaluator,
            dlp=self.dlp,
            scanner=self.scanner,
        )

    def build_server_params(self) -> StdioServerParameters:
        """Build sanitized StdioServerParameters stripping sensitive host credentials."""
        safe_env: Dict[str, str] = {}
        for key in _SAFE_ENV_KEYS:
            if key in os.environ:
                safe_env[key] = os.environ[key]
        for key in self.target.allowed_env_vars:
            if key in os.environ:
                safe_env[key] = os.environ[key]

        return StdioServerParameters(
            command=self.target.command,
            args=self.target.args,
            env=safe_env,
            cwd=self.target.cwd,
        )

    @staticmethod
    def _tool_to_dict(tool: Any) -> Dict[str, Any]:
        return {
            "name": getattr(tool, "name", ""),
            "description": getattr(tool, "description", "") or "",
            "inputSchema": getattr(tool, "inputSchema", {}) or {},
        }

    @staticmethod
    def _extract_result_payload(call_result: Any) -> Any:
        content_items = getattr(call_result, "content", []) or []
        extracted: List[Any] = []
        for item in content_items:
            if hasattr(item, "text") and item.text is not None:
                extracted.append(item.text)
            elif hasattr(item, "model_dump"):
                extracted.append(item.model_dump())
            else:
                extracted.append(str(item))
        if len(extracted) == 1 and isinstance(extracted[0], str):
            return extracted[0]
        return extracted

    async def snapshot_tool_hashes(self) -> Dict[str, str]:
        """Connect to the MCP server and compute canonical SHA-256 hashes for all tools."""
        params = self.build_server_params()
        hashes: Dict[str, str] = {}
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                resp = await session.list_tools()
                for tool in resp.tools:
                    td = self._tool_to_dict(tool)
                    hashes[td["name"]] = McpSchemaRegistry.compute_tool_hash(td)
        return hashes

    async def list_tools(self, trace_id: str) -> Dict[str, Any]:
        """Fetch tools over stdio and filter through AgentXDR security checks."""
        params = self.build_server_params()
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                resp = await session.list_tools()
                raw_tools = [self._tool_to_dict(t) for t in resp.tools]

        approved, rejected = self.tool_filter.filter_tools_list(raw_tools)
        return {
            "server_id": self.target.server_id,
            "trace_id": trace_id,
            "approved": approved,
            "rejected": rejected,
        }

    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        trace_id: str,
        taints: Optional[TaintState] = None,
    ) -> Dict[str, Any]:
        """Verify schema hash, enforce policy, invoke external MCP tool, and sanitize result."""
        params = self.build_server_params()
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_resp = await session.list_tools()
                raw_tools = [self._tool_to_dict(t) for t in tools_resp.tools]
                target_tool = next((t for t in raw_tools if t["name"] == tool_name), None)

                # Fail closed on tool description prompt injection
                if target_tool is not None:
                    is_inj, patterns = self.scanner.scan_tool_description(
                        target_tool.get("description", "")
                    )
                    if is_inj:
                        return {
                            "status": "blocked",
                            "rule_id": "TOOL_DESCRIPTION_INJECTION",
                            "owasp_ids": ["ASI01"],
                            "patterns": patterns,
                            "trace_id": trace_id,
                        }

                live_hash: Any = (
                    McpSchemaRegistry.compute_tool_hash(target_tool)
                    if target_tool is not None
                    else _UNSET
                )

                decision, refusal = self.enforcer.enforce_call(
                    policy=self.policy,
                    tool_name=tool_name,
                    arguments=arguments,
                    trace_id=trace_id,
                    taints=taints,
                    tool_schema_hash=live_hash,
                )

                if refusal is not None:
                    return {
                        "status": "blocked",
                        "decision": decision.model_dump(mode="json"),
                        "refusal": refusal,
                    }

                if decision.verdict == Verdict.PAUSE_FOR_HITL:
                    return {
                        "status": "pending_hitl",
                        "tool_name": tool_name,
                        "trace_id": trace_id,
                        "decision": decision.model_dump(mode="json"),
                    }

                raw_call_result = await session.call_tool(tool_name, arguments=arguments)
                raw_payload = self._extract_result_payload(raw_call_result)
                sanitized, was_injected, added_taints = self.enforcer.sanitize_response(
                    raw_payload, trace_id=trace_id, taints=taints
                )

                return {
                    "status": "ok",
                    "tool_name": tool_name,
                    "trace_id": trace_id,
                    "is_error": bool(getattr(raw_call_result, "isError", False)),
                    "injection_detected": was_injected,
                    "taints_added": added_taints,
                    "result": sanitized,
                }
