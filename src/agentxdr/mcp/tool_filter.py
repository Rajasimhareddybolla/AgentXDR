"""MCP Tool Filter — filters MCP tool catalogs against declarative policies and schema pins."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from agentxdr.mcp.injection_scanner import McpInjectionScanner
from agentxdr.mcp.schema_registry import McpSchemaRegistry
from agentxdr.models.policy import PolicySchema


class McpToolFilter:
    """Filter tools/list catalogs to enforce approved schemas and detect shadow tools."""

    def __init__(
        self,
        policy: PolicySchema,
        registry: McpSchemaRegistry,
        scanner: McpInjectionScanner,
    ) -> None:
        self.policy = policy
        self.registry = registry
        self.scanner = scanner

    def filter_tools_list(
        self, raw_tools: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Filter a list of tool descriptors.

        Returns
        -------
        (approved_tools, rejected_tools)
            `approved_tools` is the subset of tools that meet all security criteria.
            `rejected_tools` contains descriptors with rejection metadata added:
            `{"name": str, "reason": str, "owasp_id": str}`.
        """
        approved: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []

        # Map of approved policy tool names to PolicyTool models
        policy_tool_map = {t.name: t for t in self.policy.tools}

        for tool in raw_tools:
            name = tool.get("name", "")
            description = tool.get("description", "")

            # 1. Shadow tool detection: tool not declared in policy
            if name not in policy_tool_map:
                rejected.append({
                    "name": name,
                    "reason": "SHADOW_MCP_DETECTED",
                    "owasp_id": "ASI04",
                    "tool": tool,
                })
                continue

            # 2. Description prompt injection detection
            is_malicious, patterns = self.scanner.scan_tool_description(description)
            if is_malicious:
                rejected.append({
                    "name": name,
                    "reason": "TOOL_DESCRIPTION_INJECTION",
                    "owasp_id": "ASI01",
                    "patterns": patterns,
                    "tool": tool,
                })
                continue

            # 3. Schema hash pinning verification
            tool_policy = policy_tool_map[name]
            if tool_policy.schema_sha256 is not None:
                is_verified, expected_hash = self.registry.verify_tool(tool)
                if not is_verified:
                    rejected.append({
                        "name": name,
                        "reason": "SCHEMA_HASH_MISMATCH",
                        "owasp_id": "ASI04",
                        "expected_hash": expected_hash,
                        "tool": tool,
                    })
                    continue

            # Tool passed all checks
            approved.append(tool)

        return approved, rejected
