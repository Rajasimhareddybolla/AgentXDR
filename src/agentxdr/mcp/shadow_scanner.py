"""Shadow MCP Server Discovery & Configuration Auditor (OWASP ASI04)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from agentxdr.mcp.schema_registry import McpSchemaRegistry
from agentxdr.models.events import ToolTier
from agentxdr.models.policy import PolicySchema

_DEFAULT_MCP_CONFIG_CANDIDATES = (
    ".mcp.json",
    "mcp.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
)


class ShadowFinding(BaseModel):
    """Single shadow MCP or unpinned schema finding."""

    server_name: str
    tool_name: Optional[str] = None
    reason: str
    owasp_id: str = "ASI04"
    severity: str = "HIGH"
    source_file: str = "inline"
    command: Optional[str] = None


class ShadowDiscoveryReport(BaseModel):
    """Aggregate report of discovered MCP configurations and shadow risks."""

    scanned_sources: List[str] = Field(default_factory=list)
    discovered_servers: List[str] = Field(default_factory=list)
    findings: List[ShadowFinding] = Field(default_factory=list)

    @property
    def has_shadow_risks(self) -> bool:
        return len(self.findings) > 0

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)


class ShadowMcpScanner:
    """Discovers undeclared MCP servers and unpinned tools across workspace configs."""

    def scan_config_dict(
        self,
        config_data: Dict[str, Any],
        policy: PolicySchema,
        registry: Optional[McpSchemaRegistry] = None,
        source_name: str = "inline",
    ) -> ShadowDiscoveryReport:
        """Audit an MCP JSON config dictionary against *policy* and *registry*."""
        servers = config_data.get("mcpServers", config_data.get("servers", {}))
        discovered: List[str] = []
        findings: List[ShadowFinding] = []

        declared_servers = {t.mcp_server for t in policy.tools if t.mcp_server}
        policy_tool_map = {t.name: t for t in policy.tools}

        if isinstance(servers, dict):
            for srv_name, srv_cfg in servers.items():
                discovered.append(srv_name)
                cmd = (
                    f"{srv_cfg.get('command', '')} {' '.join(map(str, srv_cfg.get('args', [])))}"
                    if isinstance(srv_cfg, dict)
                    else ""
                ).strip()

                if declared_servers and srv_name not in declared_servers:
                    findings.append(
                        ShadowFinding(
                            server_name=srv_name,
                            reason="UNREGISTERED_MCP_SERVER",
                            owasp_id="ASI04",
                            severity="CRITICAL",
                            source_file=source_name,
                            command=cmd or None,
                        )
                    )
                elif not declared_servers:
                    # Policy has no explicit mcp_server bindings at all -> flag any configured server as unreviewed
                    findings.append(
                        ShadowFinding(
                            server_name=srv_name,
                            reason="UNBOUND_MCP_SERVER",
                            owasp_id="ASI04",
                            severity="HIGH",
                            source_file=source_name,
                            command=cmd or None,
                        )
                    )

                # Optional declared tools inside config
                if isinstance(srv_cfg, dict) and isinstance(srv_cfg.get("tools"), list):
                    for t_desc in srv_cfg["tools"]:
                        t_name = t_desc.get("name", "") if isinstance(t_desc, dict) else str(t_desc)
                        if t_name not in policy_tool_map:
                            findings.append(
                                ShadowFinding(
                                    server_name=srv_name,
                                    tool_name=t_name,
                                    reason="SHADOW_MCP_DETECTED",
                                    owasp_id="ASI04",
                                    severity="CRITICAL",
                                    source_file=source_name,
                                )
                            )

        # Check policy automatic tools without schema SHA-256 pinning
        reg = registry or McpSchemaRegistry.load_from_policy(policy)
        for tool in policy.tools:
            if tool.tier == ToolTier.AUTOMATIC and tool.schema_sha256 is None:
                # Only allow skipping hash if manually registered in runtime registry
                if not reg.verify_tool({"name": tool.name, "description": "", "inputSchema": {}})[1]:
                    findings.append(
                        ShadowFinding(
                            server_name=tool.mcp_server or "policy-inline",
                            tool_name=tool.name,
                            reason="UNPINNED_SCHEMA",
                            owasp_id="ASI04",
                            severity="MEDIUM",
                            source_file="policy.yaml",
                        )
                    )

        return ShadowDiscoveryReport(
            scanned_sources=[source_name],
            discovered_servers=discovered,
            findings=findings,
        )

    def scan_files(
        self,
        paths: List[Path],
        policy: PolicySchema,
        registry: Optional[McpSchemaRegistry] = None,
    ) -> ShadowDiscoveryReport:
        """Scan explicit MCP config file paths and aggregate findings."""
        scanned: List[str] = []
        discovered: List[str] = []
        findings: List[ShadowFinding] = []
        seen_unpinned = False

        for p in paths:
            if not p.is_file():
                continue
            scanned.append(str(p))
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception as exc:
                findings.append(
                    ShadowFinding(
                        server_name="unknown",
                        reason=f"INVALID_MCP_CONFIG: {exc}",
                        severity="MEDIUM",
                        source_file=str(p),
                    )
                )
                continue
            sub = self.scan_config_dict(
                data, policy=policy, registry=registry, source_name=str(p)
            )
            discovered.extend(sub.discovered_servers)
            for f in sub.findings:
                if f.reason == "UNPINNED_SCHEMA":
                    if seen_unpinned:
                        continue
                findings.append(f)
            seen_unpinned = True

        if not scanned:
            # Still audit policy tools for unpinned schemas
            sub = self.scan_config_dict({}, policy=policy, registry=registry, source_name="policy")
            findings.extend(sub.findings)

        return ShadowDiscoveryReport(
            scanned_sources=scanned,
            discovered_servers=discovered,
            findings=findings,
        )

    def discover_workspace(
        self,
        root_path: Path | str,
        policy: PolicySchema,
        registry: Optional[McpSchemaRegistry] = None,
    ) -> ShadowDiscoveryReport:
        """Search common workspace MCP config locations and audit them."""
        root = Path(root_path)
        candidates = [root / rel for rel in _DEFAULT_MCP_CONFIG_CANDIDATES if (root / rel).is_file()]
        return self.scan_files(candidates, policy=policy, registry=registry)
