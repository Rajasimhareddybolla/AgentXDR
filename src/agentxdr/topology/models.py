"""Visual Agent Topology models, layers, nodes, and serializers for AgentXDR."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from agentxdr.models.events import ToolTier, Verdict


class AgentStatus(str, Enum):
    """Operational health status of the Agent Digital Twin."""

    HEALTHY = "HEALTHY"
    IN_FLIGHT = "IN_FLIGHT"
    HITL_PENDING = "HITL_PENDING"
    DEGRADED = "DEGRADED"
    QUARANTINED = "QUARANTINED"
    KILLED = "KILLED"


class UserPrincipalNode(BaseModel):
    """Layer 1: Originating human user-principal representation."""

    model_config = ConfigDict(extra="ignore")

    id: str = "node_user_principal"
    user_id: str
    roles: List[str] = Field(default_factory=list)
    effective_scopes: List[str] = Field(default_factory=list)
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None


class AgentHubNode(BaseModel):
    """Layer 2: Agent Digital Twin central command hub."""

    model_config = ConfigDict(extra="ignore")

    id: str = "node_agent_hub"
    agent_id: str
    model_name: str = "default-model"
    policy_version: str = "v1.0.0"
    status: AgentStatus = AgentStatus.HEALTHY
    composite_risk: float = 0.0
    goal_anchor: Optional[str] = None
    allowed_domains: List[str] = Field(default_factory=list)
    drift_decomposition: Dict[str, float] = Field(default_factory=dict)
    is_active: bool = False


class ContextPerimeterNode(BaseModel):
    """Layer 3: Bound context source (System Prompt, RAG collection, or Memory)."""

    model_config = ConfigDict(extra="ignore")

    id: str
    context_type: str  # "SYSTEM_PROMPT", "RAG_COLLECTION", "PERSISTENT_MEMORY"
    name: str
    integrity_hash: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = False


class McpToolNode(BaseModel):
    """Layer 4: MCP Tool capability categorized by enforcement tier."""

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    mcp_server: Optional[str] = None
    tier: ToolTier = ToolTier.AUTOMATIC
    schema_sha256: Optional[str] = None
    schema_verified: bool = True
    parameters: Optional[Dict[str, Any]] = None
    is_active: bool = False
    taint_badges: List[str] = Field(default_factory=list)


class SandboxEnclaveNode(BaseModel):
    """Layer 5: Isolated execution enclave configuration."""

    model_config = ConfigDict(extra="ignore")

    id: str = "node_sandbox_enclave"
    provider: str = "docker_rootless"
    enabled: bool = True
    network_isolated: bool = True
    read_only_fs: bool = True
    timeout_sec: int = 10
    memory_limit_mb: int = 256
    blocked_imports: List[str] = Field(default_factory=list)
    is_active: bool = False


class ActiveExecutionOverlay(BaseModel):
    """Real-time active trace telemetry overlay for live war-room visualization."""

    model_config = ConfigDict(extra="ignore")

    trace_id: str
    active_node_id: Optional[str] = None
    step_number: int = 0
    current_verdict: Optional[Verdict] = None
    composite_risk: float = 0.0
    active_taints: List[str] = Field(default_factory=list)
    available_actions: List[str] = Field(
        default_factory=lambda: ["KILL_TRACE", "QUARANTINE_AGENT", "ROLLBACK_MEMORY", "ESCALATE_HITL"]
    )


class AgentTopologyModel(BaseModel):
    """Comprehensive 5-layer visual agent topology model with serializers."""

    model_config = ConfigDict(extra="ignore")

    agent_hub: AgentHubNode
    user_principal: Optional[UserPrincipalNode] = None
    context_perimeter: List[ContextPerimeterNode] = Field(default_factory=list)
    tools: List[McpToolNode] = Field(default_factory=list)
    enclave: Optional[SandboxEnclaveNode] = None
    active_execution: Optional[ActiveExecutionOverlay] = None

    def get_tools_by_tier(self, tier: ToolTier) -> List[McpToolNode]:
        """Filter tools strictly by authorization tier."""
        return [t for t in self.tools if t.tier == tier]

    def to_react_flow(self) -> Dict[str, Any]:
        """Serialize topology model into React Flow compatible nodes and edges structure."""
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        # 1. User Principal Node (Layer 1)
        if self.user_principal:
            nodes.append({
                "id": self.user_principal.id,
                "type": "user_principal",
                "position": {"x": 50, "y": 250},
                "data": {
                    "label": f"User: {self.user_principal.user_id}",
                    "user_id": self.user_principal.user_id,
                    "roles": self.user_principal.roles,
                    "effective_scopes": self.user_principal.effective_scopes,
                    "tenant_id": self.user_principal.tenant_id,
                },
                "style": {
                    "backgroundColor": "#ddf4ff",
                    "border": "2px solid #0969da",
                    "borderRadius": "8px",
                    "padding": "10px",
                },
            })
            edges.append({
                "id": f"edge_{self.user_principal.id}_{self.agent_hub.id}",
                "source": self.user_principal.id,
                "target": self.agent_hub.id,
                "type": "smoothstep",
                "label": "Authenticated Delegation",
                "animated": self.agent_hub.is_active,
                "data": {"taint_badges": []},
            })

        # 2. Context Perimeter Nodes (Layer 3 - rendered at x=320)
        base_y_ctx = 60
        for i, ctx in enumerate(self.context_perimeter):
            ctx_y = base_y_ctx + (i * 90)
            ctx_border = "3px dashed #0969da" if ctx.is_active else "2px solid #d0d7de"
            nodes.append({
                "id": ctx.id,
                "type": "context_source",
                "position": {"x": 320, "y": ctx_y},
                "data": {
                    "label": ctx.name,
                    "context_type": ctx.context_type,
                    "integrity_hash": ctx.integrity_hash,
                    "details": ctx.details,
                    "is_active": ctx.is_active,
                },
                "style": {
                    "backgroundColor": "#f6f8fa",
                    "border": ctx_border,
                    "borderRadius": "8px",
                    "padding": "10px",
                },
            })
            edges.append({
                "id": f"edge_{ctx.id}_{self.agent_hub.id}",
                "source": ctx.id,
                "target": self.agent_hub.id,
                "type": "smoothstep",
                "label": "Context Ingestion",
                "animated": ctx.is_active,
                "data": {"taint_badges": []},
            })

        # 3. Agent Digital Twin Node (Layer 2 - rendered at x=600)
        agent_border = "3px dashed #0969da" if self.agent_hub.is_active else "2px solid #0969da"
        nodes.append({
            "id": self.agent_hub.id,
            "type": "agent_twin",
            "position": {"x": 600, "y": 250},
            "data": {
                "label": f"Agent: {self.agent_hub.agent_id}",
                "agent_id": self.agent_hub.agent_id,
                "model_name": self.agent_hub.model_name,
                "policy_version": self.agent_hub.policy_version,
                "status": self.agent_hub.status.value,
                "composite_risk": self.agent_hub.composite_risk,
                "drift_decomposition": self.agent_hub.drift_decomposition,
                "goal_anchor": self.agent_hub.goal_anchor,
                "is_active": self.agent_hub.is_active,
            },
            "style": {
                "backgroundColor": "#f0f6fc",
                "border": agent_border,
                "borderRadius": "8px",
                "padding": "10px",
            },
        })

        # 4. MCP Tools (Layer 4 - rendered at x=880)
        base_y_tool = 50
        for j, tool in enumerate(self.tools):
            tool_y = base_y_tool + (j * 85)
            tier_val = tool.tier.value if isinstance(tool.tier, ToolTier) else str(tool.tier)
            if tier_val in (ToolTier.AUTOMATIC.value, "automatic"):
                bg_color = "#e6ffed"
                solid_color = "#2ea44f"
            elif tier_val in (ToolTier.PRIVILEGED_HITL.value, "privileged_hitl"):
                bg_color = "#fff8c5"
                solid_color = "#d4a72c"
            else:
                bg_color = "#ffebe9"
                solid_color = "#cf222e"
            tool_border = "3px dashed #0969da" if tool.is_active else f"2px solid {solid_color}"

            nodes.append({
                "id": tool.id,
                "type": "mcp_tool",
                "position": {"x": 880, "y": tool_y},
                "data": {
                    "label": tool.name,
                    "tool_name": tool.name,
                    "mcp_server": tool.mcp_server,
                    "tier": tier_val,
                    "schema_sha256": tool.schema_sha256,
                    "schema_verified": tool.schema_verified,
                    "is_active": tool.is_active,
                    "taint_badges": tool.taint_badges,
                },
                "style": {
                    "backgroundColor": bg_color,
                    "border": tool_border,
                    "borderRadius": "8px",
                    "padding": "10px",
                },
            })
            edges.append({
                "id": f"edge_{self.agent_hub.id}_{tool.id}",
                "source": self.agent_hub.id,
                "target": tool.id,
                "type": "smoothstep",
                "label": f"Governed ({tier_val})",
                "animated": tool.is_active,
                "data": {"taint_badges": tool.taint_badges},
            })

        # 5. Sandbox Enclave (Layer 5 - rendered at x=1150)
        if self.enclave:
            enclave_border = "3px dashed #0969da" if self.enclave.is_active else "2px solid #57606a"
            nodes.append({
                "id": self.enclave.id,
                "type": "sandbox_enclave",
                "position": {"x": 1150, "y": 250},
                "data": {
                    "label": f"Sandbox: {self.enclave.provider}",
                    "provider": self.enclave.provider,
                    "enabled": self.enclave.enabled,
                    "network_isolated": self.enclave.network_isolated,
                    "read_only_fs": self.enclave.read_only_fs,
                    "timeout_sec": self.enclave.timeout_sec,
                    "memory_limit_mb": self.enclave.memory_limit_mb,
                    "is_active": self.enclave.is_active,
                },
                "style": {
                    "backgroundColor": "#f6f8fa",
                    "border": enclave_border,
                    "borderRadius": "8px",
                    "padding": "10px",
                },
            })
            edges.append({
                "id": f"edge_{self.agent_hub.id}_{self.enclave.id}",
                "source": self.agent_hub.id,
                "target": self.enclave.id,
                "type": "smoothstep",
                "label": "Isolated Exec",
                "animated": self.enclave.is_active,
                "data": {"taint_badges": []},
            })

        # Metadata payload
        metadata = {
            "agent_id": self.agent_hub.agent_id,
            "policy_version": self.agent_hub.policy_version,
            "status": self.agent_hub.status.value,
            "composite_risk": self.agent_hub.composite_risk,
            "tool_counts": {
                "automatic": len(self.get_tools_by_tier(ToolTier.AUTOMATIC)),
                "privileged_hitl": len(self.get_tools_by_tier(ToolTier.PRIVILEGED_HITL)),
                "blocked": len(self.get_tools_by_tier(ToolTier.BLOCKED)),
            },
            "active_execution": self.active_execution.model_dump(mode="json") if self.active_execution else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        return {"nodes": nodes, "edges": edges, "metadata": metadata}

    @staticmethod
    def _escape_mermaid_label(text: Any) -> str:
        """Escape double quotes and replace newlines for Mermaid node labels."""
        if text is None:
            return ""
        s = str(text).replace('"', "#quot;")
        return s.replace("\r\n", "<br/>").replace("\n", "<br/>")

    def to_mermaid(self) -> str:
        """Generate valid Mermaid flowchart LR syntax adhering to AgentXDR specifications."""
        lines: List[str] = ["flowchart LR"]

        # Subgraph 1: User Layer
        lines.append('    subgraph USER_LAYER["1. Originating Human Principal"]')
        if self.user_principal:
            u_id = self._sanitize_mermaid_id(self.user_principal.id)
            user_id_esc = self._escape_mermaid_label(self.user_principal.user_id)
            roles_str = ", ".join(self.user_principal.roles) if self.user_principal.roles else "Standard User"
            roles_str_esc = self._escape_mermaid_label(roles_str)
            scopes_str = ", ".join(self.user_principal.effective_scopes) if self.user_principal.effective_scopes else "none"
            scopes_str_esc = self._escape_mermaid_label(scopes_str)
            lines.append(
                f'        {u_id}["User: {user_id_esc}<br/>'
                f'Role: {roles_str_esc}<br/>Scopes: {scopes_str_esc}"]'
            )
        else:
            lines.append('        USER_DEFAULT["User: Anonymous / Unspecified"]')
        lines.append("    end")
        lines.append("")

        # Subgraph 2: Agent Layer
        lines.append('    subgraph AGENT_LAYER["2. Agent Digital Twin"]')
        a_id = self._sanitize_mermaid_id(self.agent_hub.id)
        agent_id_esc = self._escape_mermaid_label(self.agent_hub.agent_id)
        model_name_esc = self._escape_mermaid_label(self.agent_hub.model_name)
        policy_ver_esc = self._escape_mermaid_label(self.agent_hub.policy_version)
        status_val = self.agent_hub.status.value
        risk_str = f"R_t: {self.agent_hub.composite_risk:.2f}"
        lines.append(
            f'        {a_id}["Agent: {agent_id_esc}<br/>'
            f'Model: {model_name_esc} | Policy: {policy_ver_esc}<br/>'
            f'Status: {status_val} ({risk_str})"]'
        )
        lines.append("    end")
        lines.append("")

        # Subgraph 3: Context Layer
        lines.append('    subgraph CONTEXT_LAYER["3. Bound Context Sources"]')
        ctx_ids: List[str] = []
        if self.context_perimeter:
            for ctx in self.context_perimeter:
                c_id = self._sanitize_mermaid_id(ctx.id)
                ctx_ids.append(c_id)
                hash_note = f"<br/>[{self._escape_mermaid_label(ctx.integrity_hash[:16])}...]" if ctx.integrity_hash else ""
                ctx_name_esc = self._escape_mermaid_label(ctx.name)
                lines.append(f'        {c_id}["{ctx_name_esc}{hash_note}"]')
        else:
            lines.append('        CTX_EMPTY["No Context Sources Bound"]')
            ctx_ids.append("CTX_EMPTY")
        lines.append("    end")
        lines.append("")

        # Subgraph 4: Tools Layer
        lines.append('    subgraph TOOLS_LAYER["4. Tools & MCP Periphery"]')
        tool_ids: List[str] = []
        allowed_ids: List[str] = []
        paused_ids: List[str] = []
        blocked_ids: List[str] = []

        if self.tools:
            for t in self.tools:
                tid = self._sanitize_mermaid_id(t.id)
                tool_ids.append(tid)
                tier_val = t.tier.value if isinstance(t.tier, ToolTier) else str(t.tier)
                if tier_val == ToolTier.AUTOMATIC.value or tier_val == "automatic":
                    tier_badge = "🟢 Automatic"
                    allowed_ids.append(tid)
                elif tier_val == ToolTier.PRIVILEGED_HITL.value or tier_val == "privileged_hitl":
                    tier_badge = "🟡 Privileged HITL"
                    paused_ids.append(tid)
                else:
                    tier_badge = "🔴 Blocked"
                    blocked_ids.append(tid)

                tool_name_esc = self._escape_mermaid_label(t.name)
                lines.append(f'        {tid}["{tool_name_esc}<br/>{tier_badge}"]')
        else:
            lines.append('        TOOLS_EMPTY["No Tools Configured"]')
            tool_ids.append("TOOLS_EMPTY")
        lines.append("    end")
        lines.append("")

        # Subgraph 5: Enclave Layer
        lines.append('    subgraph ENCLAVE_LAYER["5. Execution Enclave"]')
        if self.enclave:
            e_id = self._sanitize_mermaid_id(self.enclave.id)
            net_str = "net=none" if self.enclave.network_isolated else "net=host"
            fs_str = "ro-fs" if self.enclave.read_only_fs else "rw-fs"
            provider_esc = self._escape_mermaid_label(self.enclave.provider)
            lines.append(f'        {e_id}["{provider_esc}<br/>{net_str}, {fs_str}"]')
        else:
            e_id = "SANDBOX_DEFAULT"
            lines.append('        SANDBOX_DEFAULT["Subprocess Sandbox<br/>Restricted"]')
        lines.append("    end")
        lines.append("")

        # Relationships
        user_node_ref = self._sanitize_mermaid_id(self.user_principal.id) if self.user_principal else "USER_DEFAULT"
        lines.append(f"    {user_node_ref} -->|Authenticated Delegation| {a_id}")

        if ctx_ids:
            joined_ctx = " & ".join(ctx_ids)
            lines.append(f"    {joined_ctx} -->|Context Ingestion| {a_id}")

        if tool_ids:
            joined_tools = " & ".join(tool_ids)
            lines.append(f"    {a_id} -->|Governed Calls| {joined_tools}")

        lines.append(f"    {a_id} -->|Isolated Code Exec| {e_id}")
        lines.append("")

        # Styling classes
        lines.append("    classDef allowed fill:#e6ffed,stroke:#2ea44f,stroke-width:2px;")
        lines.append("    classDef paused fill:#fff8c5,stroke:#d4a72c,stroke-width:2px;")
        lines.append("    classDef blocked fill:#ffebe9,stroke:#cf222e,stroke-width:2px;")
        lines.append("    classDef user fill:#ddf4ff,stroke:#0969da,stroke-width:2px;")
        lines.append("    classDef active stroke:#0969da,stroke-width:3px,stroke-dasharray: 5 5;")

        if self.user_principal:
            lines.append(f"    class {user_node_ref} user;")
        if allowed_ids:
            lines.append(f"    class {','.join(allowed_ids)} allowed;")
        if paused_ids:
            lines.append(f"    class {','.join(paused_ids)} paused;")
        if blocked_ids:
            lines.append(f"    class {','.join(blocked_ids)} blocked;")

        active_ids: List[str] = []
        if self.agent_hub.is_active:
            active_ids.append(a_id)
        for t in self.tools:
            if t.is_active:
                active_ids.append(self._sanitize_mermaid_id(t.id))
        for ctx in self.context_perimeter:
            if ctx.is_active:
                active_ids.append(self._sanitize_mermaid_id(ctx.id))
        if self.enclave and self.enclave.is_active:
            active_ids.append(self._sanitize_mermaid_id(self.enclave.id))

        if active_ids:
            lines.append(f"    class {','.join(active_ids)} active;")

        return "\n".join(lines)

    def _sanitize_mermaid_id(self, raw_id: str) -> str:
        """Sanitize an ID string so it is valid in Mermaid syntax."""
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", raw_id)
        if not sanitized or sanitized[0].isdigit():
            sanitized = f"n_{sanitized}"
        if sanitized.lower() in {"graph", "flowchart", "subgraph", "end", "class", "classdef", "style", "click"}:
            sanitized = f"n_{sanitized}"
        return sanitized
