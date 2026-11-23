"""Topology builder for generating AgentTopologyModel from policy schemas and telemetry."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from agentxdr.graph.action_graph import ActionGraph
from agentxdr.graph.models import GraphNode, GraphNodeType
from agentxdr.models.events import AgentEvent, EventType, Principal, ToolTier, Verdict
from agentxdr.models.policy import PolicySchema
from agentxdr.topology.models import (
    ActiveExecutionOverlay,
    AgentHubNode,
    AgentStatus,
    AgentTopologyModel,
    ContextPerimeterNode,
    McpToolNode,
    SandboxEnclaveNode,
    UserPrincipalNode,
)


class AgentTopologyBuilder:
    """Constructs comprehensive visual topology representations for governed agents."""

    @classmethod
    def build_topology(
        cls,
        policy: PolicySchema,
        user_principal: Optional[Principal] = None,
        active_event: Optional[AgentEvent] = None,
        action_graph: Optional[ActionGraph] = None,
        trace_id: Optional[str] = None,
        active_trace: Optional[str] = None,
    ) -> AgentTopologyModel:
        """Build an AgentTopologyModel combining static policy blueprint and active execution."""
        # 1. Layer 1: User-Principal
        user_node: Optional[UserPrincipalNode] = None
        principal_source = user_principal or (active_event.principal if active_event else None)

        if principal_source:
            user_node = UserPrincipalNode(
                id=f"user_{principal_source.user_id}",
                user_id=principal_source.user_id,
                roles=list(principal_source.roles),
                effective_scopes=list(principal_source.effective_scopes),
            )

        resolved_trace_id = trace_id or active_trace or (active_event.trace_id if active_event else None)

        if user_node is None and action_graph is not None and resolved_trace_id:
            user_nodes = [
                n for n in action_graph.get_nodes(trace_id=resolved_trace_id)
                if n.node_type == GraphNodeType.USER
            ]
            if user_nodes:
                u_obj = user_nodes[0]
                u_meta = u_obj.metadata or {}
                user_node = UserPrincipalNode(
                    id=u_obj.id,
                    user_id=u_meta.get("user_id") or u_obj.label.replace("User: ", "").replace("User Input (", "").rstrip(")"),
                    roles=list(u_meta.get("roles", [])),
                    effective_scopes=list(u_meta.get("effective_scopes", u_meta.get("scopes", []))),
                )

        # 2. Layer 3: Context Perimeter
        context_perimeter = cls._build_context_perimeter(policy)

        # 3. Layer 4: MCP Tools categorized strictly by tier
        tools = cls._build_mcp_tools(policy)

        # 4. Layer 5: Sandbox Enclave
        enclave = cls._build_sandbox_enclave(policy)

        # 5. Layer 2: Agent Digital Twin Hub
        goal_anchor_text = policy.goal_anchor.canonical_task if policy.goal_anchor else None
        allowed_domains = list(policy.goal_anchor.allowed_domains) if policy.goal_anchor else []

        agent_hub = AgentHubNode(
            id=f"agent_{policy.agent_id}",
            agent_id=policy.agent_id,
            model_name="gpt-4o",  # Default baseline foundation model
            policy_version=policy.version,
            status=AgentStatus.HEALTHY,
            composite_risk=0.0,
            goal_anchor=goal_anchor_text,
            allowed_domains=allowed_domains,
            drift_decomposition={"policy": 0.0, "graph": 0.0, "velocity": 0.0, "semantic": 0.0},
            is_active=False,
        )

        overlay: Optional[ActiveExecutionOverlay] = None

        # 6. Apply Active Execution Overlay if active_event or action_graph provided
        if active_event is not None:
            overlay = cls._apply_event_overlay(
                active_event=active_event,
                agent_hub=agent_hub,
                context_perimeter=context_perimeter,
                tools=tools,
                enclave=enclave,
            )
        elif action_graph is not None and resolved_trace_id:
            active_node = action_graph.get_active_node(resolved_trace_id)
            if active_node:
                overlay = cls._apply_graph_node_overlay(
                    active_node=active_node,
                    agent_hub=agent_hub,
                    context_perimeter=context_perimeter,
                    tools=tools,
                    enclave=enclave,
                )

        return AgentTopologyModel(
            agent_hub=agent_hub,
            user_principal=user_node,
            context_perimeter=context_perimeter,
            tools=tools,
            enclave=enclave,
            active_execution=overlay,
        )

    @classmethod
    def build_from_events(
        cls,
        policy: PolicySchema,
        events: Sequence[AgentEvent],
    ) -> AgentTopologyModel:
        """Build topology and overlay using the latest event in an event sequence."""
        if not events:
            return cls.build_topology(policy)
        latest_event = events[-1]
        action_graph = ActionGraph()
        action_graph.ingest_events(events)
        return cls.build_topology(
            policy=policy,
            active_event=latest_event,
            action_graph=action_graph,
            trace_id=latest_event.trace_id,
        )

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    @classmethod
    def _build_context_perimeter(cls, policy: PolicySchema) -> List[ContextPerimeterNode]:
        """Construct ContextPerimeterNode cards from policy."""
        ctx_list: List[ContextPerimeterNode] = []

        # System Prompt
        policy_hash = policy.policy_hash or policy.compute_policy_hash()
        ctx_list.append(
            ContextPerimeterNode(
                id="ctx_system_prompt",
                context_type="SYSTEM_PROMPT",
                name="System Prompt [SHA-256 Pinned]",
                integrity_hash=policy_hash,
                details={"pinned": True, "immutable": True},
            )
        )

        # RAG Knowledge Collections
        rag_details: Dict[str, Any] = {"acl_enforced": True}
        if policy.goal_anchor and policy.goal_anchor.allowed_domains:
            rag_details["allowed_domains"] = list(policy.goal_anchor.allowed_domains)
        ctx_list.append(
            ContextPerimeterNode(
                id="ctx_rag_kb",
                context_type="RAG_COLLECTION",
                name="RAG: Knowledge Collections",
                details=rag_details,
            )
        )

        # Persistent Memory
        ctx_list.append(
            ContextPerimeterNode(
                id="ctx_persistent_memory",
                context_type="PERSISTENT_MEMORY",
                name="Memory Store [Snapshots On]",
                details={"snapshots_enabled": True, "write_gate": "active"},
            )
        )

        return ctx_list

    @classmethod
    def _build_mcp_tools(cls, policy: PolicySchema) -> List[McpToolNode]:
        """Construct McpToolNode instances categorized strictly by ToolTier."""
        tools: List[McpToolNode] = []
        for t in policy.tools:
            tool_id = f"tool_{t.name}"
            tools.append(
                McpToolNode(
                    id=tool_id,
                    name=t.name,
                    mcp_server=t.mcp_server or "default-mcp",
                    tier=t.tier,
                    schema_sha256=t.schema_sha256,
                    schema_verified=bool(t.schema_sha256),
                    parameters=t.parameters,
                    is_active=False,
                    taint_badges=[],
                )
            )
        return tools

    @classmethod
    def _build_sandbox_enclave(cls, policy: PolicySchema) -> SandboxEnclaveNode:
        """Construct SandboxEnclaveNode from policy code_sandbox configuration."""
        if policy.code_sandbox:
            sb = policy.code_sandbox
            return SandboxEnclaveNode(
                id="sandbox_enclave",
                provider=sb.provider,
                enabled=sb.enabled,
                network_isolated=True,
                read_only_fs=True,
                timeout_sec=sb.timeout_sec,
                memory_limit_mb=sb.memory_limit_mb,
                blocked_imports=list(sb.blocked_imports),
            )
        return SandboxEnclaveNode(
            id="sandbox_enclave",
            provider="docker_rootless",
            enabled=True,
            network_isolated=True,
            read_only_fs=True,
            timeout_sec=10,
            memory_limit_mb=256,
            blocked_imports=[],
        )

    @classmethod
    def _apply_event_overlay(
        cls,
        active_event: AgentEvent,
        agent_hub: AgentHubNode,
        context_perimeter: List[ContextPerimeterNode],
        tools: List[McpToolNode],
        enclave: Optional[SandboxEnclaveNode],
    ) -> ActiveExecutionOverlay:
        """Update node visual states and generate ActiveExecutionOverlay from an AgentEvent."""
        composite_score = 0.0
        drift_decomp = {"policy": 0.0, "graph": 0.0, "velocity": 0.0, "semantic": 0.0}

        if active_event.drift_snapshot:
            composite_score = active_event.drift_snapshot.composite_score
            drift_decomp = {
                "policy": active_event.drift_snapshot.s_policy,
                "graph": active_event.drift_snapshot.s_graph,
                "velocity": active_event.drift_snapshot.s_velocity,
                "semantic": active_event.drift_snapshot.s_semantic,
            }

        agent_hub.composite_risk = composite_score
        agent_hub.drift_decomposition = drift_decomp

        # Determine agent status
        verdict = active_event.decision.verdict if active_event.decision else None
        if verdict == Verdict.KILL:
            agent_hub.status = AgentStatus.KILLED
        elif verdict == Verdict.PAUSE_FOR_HITL:
            agent_hub.status = AgentStatus.HITL_PENDING
        elif verdict == Verdict.BLOCK or composite_score >= 0.75:
            agent_hub.status = AgentStatus.DEGRADED
        else:
            agent_hub.status = AgentStatus.IN_FLIGHT

        # Highlight corresponding active layer node
        ev_type = active_event.event_type
        payload = active_event.payload_redacted or {}

        if ev_type == EventType.TOOL_INVOCATION:
            tool_name = payload.get("tool_name")
            matched = False
            for t in tools:
                if t.name == tool_name:
                    t.is_active = True
                    t.taint_badges = list(active_event.taint_labels)
                    matched = True
                    break
            if not matched:
                agent_hub.is_active = True
        elif ev_type == EventType.SANDBOX_EXEC and enclave:
            enclave.is_active = True
        elif ev_type == EventType.RAG_ACCESS:
            for ctx in context_perimeter:
                if ctx.context_type == "RAG_COLLECTION":
                    ctx.is_active = True
                    break
        elif ev_type == EventType.MEMORY_MUTATION:
            for ctx in context_perimeter:
                if ctx.context_type == "PERSISTENT_MEMORY":
                    ctx.is_active = True
                    break
        else:
            agent_hub.is_active = True

        return ActiveExecutionOverlay(
            trace_id=active_event.trace_id,
            active_node_id=active_event.span_id,
            current_verdict=verdict,
            composite_risk=composite_score,
            active_taints=list(active_event.taint_labels),
            available_actions=["KILL_TRACE", "QUARANTINE_AGENT", "ROLLBACK_MEMORY", "ESCALATE_HITL"],
        )

    @classmethod
    def _apply_graph_node_overlay(
        cls,
        active_node: GraphNode,
        agent_hub: AgentHubNode,
        context_perimeter: List[ContextPerimeterNode],
        tools: List[McpToolNode],
        enclave: Optional[SandboxEnclaveNode],
    ) -> ActiveExecutionOverlay:
        """Update node visual states and generate ActiveExecutionOverlay from a GraphNode."""
        composite_score = active_node.drift_score or 0.0
        drift_decomp = {"policy": 0.0, "graph": 0.0, "velocity": 0.0, "semantic": 0.0}

        if active_node.drift_snapshot:
            drift_decomp = {
                "policy": active_node.drift_snapshot.s_policy,
                "graph": active_node.drift_snapshot.s_graph,
                "velocity": active_node.drift_snapshot.s_velocity,
                "semantic": active_node.drift_snapshot.s_semantic,
            }

        agent_hub.composite_risk = composite_score
        agent_hub.drift_decomposition = drift_decomp

        verdict = active_node.verdict
        if verdict == Verdict.KILL:
            agent_hub.status = AgentStatus.KILLED
        elif verdict == Verdict.PAUSE_FOR_HITL:
            agent_hub.status = AgentStatus.HITL_PENDING
        elif verdict == Verdict.BLOCK or composite_score >= 0.75:
            agent_hub.status = AgentStatus.DEGRADED
        else:
            agent_hub.status = AgentStatus.IN_FLIGHT

        # Highlight layer node
        if active_node.node_type == GraphNodeType.TOOL_CALL:
            tool_name = active_node.payload.get("tool_name")
            matched = False
            for t in tools:
                if t.name == tool_name:
                    t.is_active = True
                    t.taint_badges = list(active_node.taint_labels)
                    matched = True
                    break
            if not matched:
                agent_hub.is_active = True
        elif active_node.node_type == GraphNodeType.SANDBOX and enclave:
            enclave.is_active = True
        elif active_node.node_type == GraphNodeType.RAG_DOC:
            for ctx in context_perimeter:
                if ctx.context_type == "RAG_COLLECTION":
                    ctx.is_active = True
                    break
        elif active_node.node_type == GraphNodeType.MEMORY_STORE:
            for ctx in context_perimeter:
                if ctx.context_type == "PERSISTENT_MEMORY":
                    ctx.is_active = True
                    break
        else:
            agent_hub.is_active = True

        return ActiveExecutionOverlay(
            trace_id=active_node.trace_id or "unknown",
            active_node_id=active_node.id,
            current_verdict=verdict,
            composite_risk=composite_score,
            active_taints=list(active_node.taint_labels),
            available_actions=["KILL_TRACE", "QUARANTINE_AGENT", "ROLLBACK_MEMORY", "ESCALATE_HITL"],
        )
