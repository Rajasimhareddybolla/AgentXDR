"""Unit tests for Visual Agent Topology models, builder, and serializers."""

from __future__ import annotations

import json
import pytest

from agentxdr.graph.action_graph import ActionGraph
from agentxdr.models.events import (
    AgentEvent,
    Decision,
    DriftSnapshot,
    EventType,
    Principal,
    ProvenanceTier,
    ToolTier,
    Verdict,
)
from agentxdr.models.policy import (
    BudgetsConfig,
    CodeSandboxConfig,
    GoalAnchorConfig,
    PolicySchema,
    ToolPolicy,
)
from agentxdr.topology import (
    ActiveExecutionOverlay,
    AgentHubNode,
    AgentStatus,
    AgentTopologyBuilder,
    AgentTopologyModel,
    ContextPerimeterNode,
    McpToolNode,
    SandboxEnclaveNode,
    UserPrincipalNode,
)


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_policy() -> PolicySchema:
    return PolicySchema(
        version="v1.0.0",
        agent_id="doc-support-agent",
        approved_by="secops@enterprise.com",
        goal_anchor=GoalAnchorConfig(
            canonical_task="Assist SecOps operators with incident triage and documentation",
            allowed_domains=["internal.corp", "docs.secops.io"],
        ),
        budgets=BudgetsConfig(
            max_turns=10,
            max_tool_calls=25,
            max_identical_calls=3,
            max_session_duration_sec=300.0,
            max_session_cost_usd=5.0,
        ),
        tools=[
            ToolPolicy(
                name="search_kb",
                mcp_server="secops-kb-server",
                tier=ToolTier.AUTOMATIC,
                schema_sha256="sha256:aaaa1111bbbb2222cccc3333dddd4444",
            ),
            ToolPolicy(
                name="create_jira_ticket",
                mcp_server="jira-gateway",
                tier=ToolTier.PRIVILEGED_HITL,
                schema_sha256="sha256:eeee5555ffff6666aaaa7777bbbb8888",
            ),
            ToolPolicy(
                name="shell_exec",
                mcp_server="system-mcp",
                tier=ToolTier.BLOCKED,
            ),
        ],
        code_sandbox=CodeSandboxConfig(
            enabled=True,
            provider="docker_rootless",
            timeout_sec=15,
            memory_limit_mb=512,
            blocked_imports=["os", "subprocess", "socket"],
        ),
    )


@pytest.fixture
def sample_principal() -> Principal:
    return Principal(
        user_id="alice@enterprise.com",
        roles=["SecOps Lead", "Operator"],
        effective_scopes=["kb:read", "jira:create"],
    )


# ===========================================================================
# 1. Topology Data Models Tests
# ===========================================================================


class TestTopologyModels:
    """Verify individual layer nodes and topology model container."""

    def test_agent_status_enum(self) -> None:
        assert AgentStatus.HEALTHY.value == "HEALTHY"
        assert AgentStatus.IN_FLIGHT.value == "IN_FLIGHT"
        assert AgentStatus.HITL_PENDING.value == "HITL_PENDING"
        assert AgentStatus.DEGRADED.value == "DEGRADED"
        assert AgentStatus.QUARANTINED.value == "QUARANTINED"
        assert AgentStatus.KILLED.value == "KILLED"

    def test_user_principal_node(self) -> None:
        user = UserPrincipalNode(
            user_id="bob@corp.com",
            roles=["Analyst"],
            effective_scopes=["read:all"],
            tenant_id="tenant_finance",
        )
        assert user.id == "node_user_principal"
        assert user.user_id == "bob@corp.com"
        assert user.tenant_id == "tenant_finance"

    def test_agent_hub_node(self) -> None:
        hub = AgentHubNode(
            agent_id="agent_alpha",
            model_name="claude-3-5-sonnet",
            policy_version="2.1.0",
            status=AgentStatus.HEALTHY,
            composite_risk=0.15,
            goal_anchor="Summarize security reports",
            allowed_domains=["reports.internal"],
        )
        assert hub.agent_id == "agent_alpha"
        assert hub.status == AgentStatus.HEALTHY
        assert hub.composite_risk == 0.15

    def test_mcp_tool_node(self) -> None:
        tool = McpToolNode(
            id="tool_search",
            name="search_kb",
            mcp_server="kb_server",
            tier=ToolTier.AUTOMATIC,
            schema_sha256="sha256:123",
            schema_verified=True,
            taint_badges=["TAINT_OK"],
        )
        assert tool.name == "search_kb"
        assert tool.tier == ToolTier.AUTOMATIC
        assert tool.schema_verified is True
        assert tool.taint_badges == ["TAINT_OK"]

    def test_sandbox_enclave_node(self) -> None:
        enclave = SandboxEnclaveNode(
            provider="docker_rootless",
            enabled=True,
            network_isolated=True,
            read_only_fs=True,
            timeout_sec=10,
            memory_limit_mb=256,
            blocked_imports=["sys", "os"],
        )
        assert enclave.provider == "docker_rootless"
        assert enclave.network_isolated is True
        assert "os" in enclave.blocked_imports

    def test_active_execution_overlay(self) -> None:
        overlay = ActiveExecutionOverlay(
            trace_id="tr_101",
            active_node_id="span_5",
            step_number=5,
            current_verdict=Verdict.PAUSE_FOR_HITL,
            composite_risk=0.62,
            active_taints=["UNTRUSTED_EXTERNAL"],
        )
        assert overlay.trace_id == "tr_101"
        assert overlay.current_verdict == Verdict.PAUSE_FOR_HITL
        assert overlay.composite_risk == 0.62
        assert "KILL_TRACE" in overlay.available_actions


# ===========================================================================
# 2. AgentTopologyBuilder Tests
# ===========================================================================


class TestAgentTopologyBuilder:
    """Verify building 5-layer topologies and active execution state overlays."""

    def test_build_static_topology_hierarchy(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            user_principal=sample_principal,
        )

        # Layer 1: User Principal
        assert model.user_principal is not None
        assert model.user_principal.user_id == "alice@enterprise.com"
        assert "SecOps Lead" in model.user_principal.roles

        # Layer 2: Agent Digital Twin Hub
        assert model.agent_hub.agent_id == "doc-support-agent"
        assert model.agent_hub.policy_version == "v1.0.0"
        assert model.agent_hub.status == AgentStatus.HEALTHY
        assert "internal.corp" in model.agent_hub.allowed_domains

        # Layer 3: Context Perimeter
        assert len(model.context_perimeter) == 3
        ctx_types = [c.context_type for c in model.context_perimeter]
        assert "SYSTEM_PROMPT" in ctx_types
        assert "RAG_COLLECTION" in ctx_types
        assert "PERSISTENT_MEMORY" in ctx_types

        # Layer 4: MCP Tools categorized strictly by tier
        assert len(model.tools) == 3
        auto_tools = model.get_tools_by_tier(ToolTier.AUTOMATIC)
        hitl_tools = model.get_tools_by_tier(ToolTier.PRIVILEGED_HITL)
        blocked_tools = model.get_tools_by_tier(ToolTier.BLOCKED)

        assert len(auto_tools) == 1
        assert auto_tools[0].name == "search_kb"
        assert auto_tools[0].schema_verified is True

        assert len(hitl_tools) == 1
        assert hitl_tools[0].name == "create_jira_ticket"

        assert len(blocked_tools) == 1
        assert blocked_tools[0].name == "shell_exec"

        # Layer 5: Sandbox Enclave
        assert model.enclave is not None
        assert model.enclave.provider == "docker_rootless"
        assert model.enclave.timeout_sec == 15
        assert model.enclave.memory_limit_mb == 512

    def test_build_topology_with_active_tool_event(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        active_event = AgentEvent(
            trace_id="tr_active_01",
            span_id="span_tool_exec",
            parent_span_id="span_llm",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.TOOL_INVOCATION,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            taint_labels=["UNTRUSTED_EXTERNAL"],
            payload_redacted={"tool_name": "search_kb", "arguments": {"query": "CVE-2024"}},
            decision=Decision(
                verdict=Verdict.ALLOW,
                rule_id="rule_allow",
                owasp_ids=[],
                latency_ms=8.0,
            ),
            drift_snapshot=DriftSnapshot(
                composite_score=0.35,
                s_policy=0.1,
                s_graph=0.1,
                s_velocity=0.05,
                s_semantic=0.1,
            ),
        )

        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            active_event=active_event,
        )

        assert model.active_execution is not None
        assert model.active_execution.trace_id == "tr_active_01"
        assert model.active_execution.composite_risk == 0.35
        assert model.agent_hub.status == AgentStatus.IN_FLIGHT

        # Active tool node should be highlighted with taint badges
        search_tool = next(t for t in model.tools if t.name == "search_kb")
        assert search_tool.is_active is True
        assert "UNTRUSTED_EXTERNAL" in search_tool.taint_badges

    def test_build_topology_hitl_pending_state(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        hitl_event = AgentEvent(
            trace_id="tr_hitl_02",
            span_id="span_hitl",
            parent_span_id="span_llm",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.TOOL_INVOCATION,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            taint_labels=["UNTRUSTED_EXTERNAL"],
            payload_redacted={"tool_name": "create_jira_ticket"},
            decision=Decision(
                verdict=Verdict.PAUSE_FOR_HITL,
                rule_id="rule_hitl_gate",
                owasp_ids=["ASI01"],
                latency_ms=2.0,
            ),
            drift_snapshot=DriftSnapshot(
                composite_score=0.45,
                s_policy=0.45,
                s_graph=0.0,
                s_velocity=0.0,
                s_semantic=0.0,
            ),
        )

        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            active_event=hitl_event,
        )

        assert model.agent_hub.status == AgentStatus.HITL_PENDING
        assert model.active_execution.current_verdict == Verdict.PAUSE_FOR_HITL

    def test_build_topology_killed_state(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        kill_event = AgentEvent(
            trace_id="tr_kill_03",
            span_id="span_kill",
            parent_span_id="span_llm",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.TOOL_INVOCATION,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            taint_labels=[],
            payload_redacted={"tool_name": "shell_exec"},
            decision=Decision(
                verdict=Verdict.KILL,
                rule_id="rule_blocked_kill",
                owasp_ids=["ASI02"],
                latency_ms=1.0,
            ),
            drift_snapshot=DriftSnapshot(
                composite_score=0.95,
                s_policy=0.95,
                s_graph=0.0,
                s_velocity=0.0,
                s_semantic=0.0,
            ),
        )

        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            active_event=kill_event,
        )

        assert model.agent_hub.status == AgentStatus.KILLED
        assert model.agent_hub.composite_risk == 0.95

    def test_build_from_events_sequence(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        e1 = AgentEvent(
            trace_id="tr_seq",
            span_id="s1",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.USER_INPUT,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            decision=Decision(verdict=Verdict.ALLOW, latency_ms=1.0),
            drift_snapshot=DriftSnapshot(composite_score=0.05, s_policy=0, s_graph=0, s_velocity=0, s_semantic=0.05),
        )
        e2 = AgentEvent(
            trace_id="tr_seq",
            span_id="s2",
            parent_span_id="s1",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.TOOL_INVOCATION,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            payload_redacted={"tool_name": "search_kb"},
            decision=Decision(verdict=Verdict.ALLOW, latency_ms=5.0),
            drift_snapshot=DriftSnapshot(composite_score=0.12, s_policy=0, s_graph=0, s_velocity=0, s_semantic=0.12),
        )

        model = AgentTopologyBuilder.build_from_events(sample_policy, [e1, e2])
        assert model.active_execution is not None
        assert model.active_execution.active_node_id == "s2"
        assert model.active_execution.composite_risk == 0.12


# ===========================================================================
# 3. React Flow Serializer Tests
# ===========================================================================


class TestReactFlowSerializer:
    """Verify React Flow serialization schema, coordinates, and metadata."""

    def test_to_react_flow_structure(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            user_principal=sample_principal,
        )
        rf_dict = model.to_react_flow()

        assert "nodes" in rf_dict
        assert "edges" in rf_dict
        assert "metadata" in rf_dict

        nodes = rf_dict["nodes"]
        edges = rf_dict["edges"]
        meta = rf_dict["metadata"]

        # Check nodes
        node_ids = {n["id"] for n in nodes}
        assert model.user_principal.id in node_ids
        assert f"agent_{sample_policy.agent_id}" in node_ids
        assert "tool_search_kb" in node_ids
        assert "tool_create_jira_ticket" in node_ids
        assert "tool_shell_exec" in node_ids
        assert "sandbox_enclave" in node_ids

        # Check positioning (layered x-coordinates: 50 -> 320 -> 600 -> 880 -> 1150)
        user_node = next(n for n in nodes if n["id"] == model.user_principal.id)
        agent_node = next(n for n in nodes if n["id"] == f"agent_{sample_policy.agent_id}")
        enclave_node = next(n for n in nodes if n["id"] == "sandbox_enclave")

        assert user_node["position"]["x"] == 50
        assert agent_node["position"]["x"] == 600
        assert enclave_node["position"]["x"] == 1150

        # Check metadata
        assert meta["agent_id"] == "doc-support-agent"
        assert meta["tool_counts"]["automatic"] == 1
        assert meta["tool_counts"]["privileged_hitl"] == 1
        assert meta["tool_counts"]["blocked"] == 1

        # Check JSON serializability
        serialized_json = json.dumps(rf_dict)
        assert len(serialized_json) > 0


# ===========================================================================
# 4. Mermaid Flowchart Serializer Tests
# ===========================================================================


class TestMermaidSerializer:
    """Verify Mermaid flowchart LR generation and compliance with specifications."""

    def test_to_mermaid_syntax_and_subgraphs(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            user_principal=sample_principal,
        )
        mermaid_text = model.to_mermaid()

        # Must start with flowchart LR
        assert mermaid_text.startswith("flowchart LR")

        # Must contain all 5 layer subgraphs
        assert 'subgraph USER_LAYER["1. Originating Human Principal"]' in mermaid_text
        assert 'subgraph AGENT_LAYER["2. Agent Digital Twin"]' in mermaid_text
        assert 'subgraph CONTEXT_LAYER["3. Bound Context Sources"]' in mermaid_text
        assert 'subgraph TOOLS_LAYER["4. Tools & MCP Periphery"]' in mermaid_text
        assert 'subgraph ENCLAVE_LAYER["5. Execution Enclave"]' in mermaid_text

        # Must display tool tiers
        assert "🟢 Automatic" in mermaid_text
        assert "🟡 Privileged HITL" in mermaid_text
        assert "🔴 Blocked" in mermaid_text

        # Must contain standard relationship arrows
        assert "-->|Authenticated Delegation|" in mermaid_text
        assert "-->|Context Ingestion|" in mermaid_text
        assert "-->|Governed Calls|" in mermaid_text
        assert "-->|Isolated Code Exec|" in mermaid_text

        # Must contain styling class definitions
        assert "classDef allowed fill:#e6ffed,stroke:#2ea44f,stroke-width:2px;" in mermaid_text
        assert "classDef paused fill:#fff8c5,stroke:#d4a72c,stroke-width:2px;" in mermaid_text
        assert "classDef blocked fill:#ffebe9,stroke:#cf222e,stroke-width:2px;" in mermaid_text
        assert "classDef user fill:#ddf4ff,stroke:#0969da,stroke-width:2px;" in mermaid_text
        assert "classDef active stroke:#0969da,stroke-width:3px,stroke-dasharray: 5 5;" in mermaid_text

    def test_mermaid_generation_with_double_quotes_in_labels_and_user_ids(
        self,
        sample_policy: PolicySchema,
    ) -> None:
        """Verify Mermaid generation escapes double quotes in user IDs and labels as #quot;."""
        principal_with_quotes = Principal(
            user_id='alice"operator"@corp.com',
            roles=['"Lead" Analyst', 'SecOps"Admin"'],
            effective_scopes=['scope"read"', 'scope"write"'],
        )
        policy_with_quotes = sample_policy.model_copy(
            update={"agent_id": 'agent"primary"'},
            deep=True,
        )

        model = AgentTopologyBuilder.build_topology(
            policy=policy_with_quotes,
            user_principal=principal_with_quotes,
        )
        # Add tool and context with quotes
        model.tools.append(
            McpToolNode(
                id='tool"quote"',
                name='custom"tool"',
                tier=ToolTier.AUTOMATIC,
            )
        )
        model.context_perimeter.append(
            ContextPerimeterNode(
                id='ctx"quote"',
                context_type="RAG_COLLECTION",
                name='RAG "Special" Docs',
            )
        )

        mermaid_text = model.to_mermaid()

        # Double quotes should be escaped as #quot; in node label text
        assert "#quot;" in mermaid_text
        assert "alice#quot;operator#quot;@corp.com" in mermaid_text
        assert "agent#quot;primary#quot;" in mermaid_text
        assert "#quot;Lead#quot; Analyst" in mermaid_text
        assert "custom#quot;tool#quot;" in mermaid_text
        assert "RAG #quot;Special#quot; Docs" in mermaid_text

        # Verify no unescaped inner double quotes exist inside ["..."] label brackets
        for line in mermaid_text.splitlines():
            line_str = line.strip()
            if '["' in line_str and line_str.endswith('"]'):
                inner_label = line_str[line_str.index('["') + 2 : -2]
                assert '"' not in inner_label, f"Found unescaped double quote in label: {line_str}"

    def test_mermaid_integrity_hash_quote_escaping(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        """Verify Mermaid generation escapes double quotes in context integrity hashes."""
        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            user_principal=sample_principal,
        )
        model.context_perimeter.append(
            ContextPerimeterNode(
                id="ctx_with_hash",
                context_type="RAG_COLLECTION",
                name="Secure Vault",
                integrity_hash='sha256"hash"12345',
            )
        )
        mermaid_text = model.to_mermaid()

        # Integrity hash quotes should be escaped
        assert "sha256#quot;hash#quot;123" in mermaid_text

        # Verify no unescaped inner double quotes exist inside ["..."] label brackets
        for line in mermaid_text.splitlines():
            line_str = line.strip()
            if '["' in line_str and line_str.endswith('"]'):
                inner_label = line_str[line_str.index('["') + 2 : -2]
                assert '"' not in inner_label, f"Found unescaped double quote in label: {line_str}"

    def test_mermaid_reserved_keyword_id_sanitization(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        """Verify reserved Mermaid keywords are prefixed with n_ to prevent syntax errors."""
        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            user_principal=sample_principal,
        )

        reserved_words = ["graph", "flowchart", "subgraph", "end", "class", "classdef", "style", "click"]
        for word in reserved_words:
            assert model._sanitize_mermaid_id(word) == f"n_{word}"
            assert model._sanitize_mermaid_id(word.upper()) == f"n_{word.upper()}"

        # Standard IDs should not be modified
        assert model._sanitize_mermaid_id("normal_id") == "normal_id"
        assert model._sanitize_mermaid_id("agent_1") == "agent_1"

        # Model with tool having reserved keyword id
        model.tools.append(
            McpToolNode(
                id="end",
                name="Terminator Tool",
                tier=ToolTier.AUTOMATIC,
            )
        )
        mermaid_text = model.to_mermaid()
        assert "n_end[" in mermaid_text

    def test_active_trace_alias_and_direct_action_graph_overlay(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        """Verify build_topology supports active_trace alias and overlays directly from an ActionGraph."""
        # Create an ActionGraph and ingest events
        graph = ActionGraph()
        e1 = AgentEvent(
            trace_id="tr_overlay_42",
            span_id="span_u",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.USER_INPUT,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            decision=Decision(verdict=Verdict.ALLOW, latency_ms=1.0),
            drift_snapshot=DriftSnapshot(composite_score=0.05, s_policy=0, s_graph=0, s_velocity=0, s_semantic=0.05),
        )
        e2 = AgentEvent(
            trace_id="tr_overlay_42",
            span_id="span_tool_run",
            parent_span_id="span_u",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.TOOL_INVOCATION,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            taint_labels=["UNTRUSTED_EXTERNAL"],
            payload_redacted={"tool_name": "search_kb"},
            decision=Decision(verdict=Verdict.ALLOW, latency_ms=5.0),
            drift_snapshot=DriftSnapshot(composite_score=0.25, s_policy=0.1, s_graph=0.1, s_velocity=0.05, s_semantic=0.1),
        )
        graph.ingest_events([e1, e2])

        # Build topology using active_trace alias and action_graph without active_event or user_principal
        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            action_graph=graph,
            active_trace="tr_overlay_42",
        )

        assert model.active_execution is not None
        assert model.active_execution.trace_id == "tr_overlay_42"
        assert model.active_execution.active_node_id == "span_tool_run"
        assert model.active_execution.composite_risk == 0.25
        assert "UNTRUSTED_EXTERNAL" in model.active_execution.active_taints

        # User principal node reconstructed from action graph
        assert model.user_principal is not None
        assert model.user_principal.user_id == sample_principal.user_id

        # Tool node active state
        search_tool = next(t for t in model.tools if t.name == "search_kb")
        assert search_tool.is_active is True

    def test_active_tool_mermaid_highlighting(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        """Verify active tool node ID is included in Mermaid 'class <ids> active;' output."""
        active_event = AgentEvent(
            trace_id="tr_mermaid_active",
            span_id="span_tool",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.TOOL_INVOCATION,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            payload_redacted={"tool_name": "search_kb"},
            decision=Decision(verdict=Verdict.ALLOW, latency_ms=2.0),
            drift_snapshot=DriftSnapshot(composite_score=0.1, s_policy=0, s_graph=0, s_velocity=0, s_semantic=0.1),
        )

        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            active_event=active_event,
        )

        mermaid_str = model.to_mermaid()
        assert "classDef active stroke:#0969da,stroke-width:3px,stroke-dasharray: 5 5;" in mermaid_str
        assert "class tool_search_kb active;" in mermaid_str

    def test_react_flow_node_styling_schema(
        self,
        sample_policy: PolicySchema,
        sample_principal: Principal,
    ) -> None:
        """Verify React Flow serialization includes style dictionaries with colors and active dashed borders."""
        active_event = AgentEvent(
            trace_id="tr_rf_active",
            span_id="span_tool_rf",
            agent_id="doc-support-agent",
            policy_version="v1.0.0",
            event_type=EventType.TOOL_INVOCATION,
            principal=sample_principal,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            payload_redacted={"tool_name": "search_kb"},
            decision=Decision(verdict=Verdict.ALLOW, latency_ms=2.0),
            drift_snapshot=DriftSnapshot(composite_score=0.1, s_policy=0, s_graph=0, s_velocity=0, s_semantic=0.1),
        )

        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            active_event=active_event,
        )
        rf_dict = model.to_react_flow()
        nodes = rf_dict["nodes"]

        # Every node must have a style dictionary
        for node in nodes:
            assert "style" in node, f"Node {node['id']} missing style dictionary"
            style = node["style"]
            assert "backgroundColor" in style
            assert "border" in style
            assert "borderRadius" in style
            assert "padding" in style

        # Active search_kb tool must have dashed border
        search_node = next(n for n in nodes if n["id"] == "tool_search_kb")
        assert "dashed" in search_node["style"]["border"]

    def test_defensive_newline_escaping_in_mermaid(
        self,
        sample_policy: PolicySchema,
    ) -> None:
        """Verify newlines and multi-line text are escaped to <br/> preventing Mermaid parse failure."""
        multiline_principal = Principal(
            user_id="user\nwith\nnewlines",
            roles=["role1\r\nrole2"],
            effective_scopes=["scope:read\nscope:write"],
        )
        model = AgentTopologyBuilder.build_topology(
            policy=sample_policy,
            user_principal=multiline_principal,
        )
        mermaid_text = model.to_mermaid()

        # Labels must not contain raw unescaped newlines inside quotes
        for line in mermaid_text.splitlines():
            assert "\r" not in line
            if '["' in line and line.endswith('"]'):
                assert "\n" not in line

        assert "User: user<br/>with<br/>newlines" in mermaid_text
        assert "role1<br/>role2" in mermaid_text
        assert "scope:read<br/>scope:write" in mermaid_text

    def test_top_level_package_re_exports(self) -> None:
        """Verify core M7 models, builders, and detectors are re-exported at top-level package agentxdr."""
        import agentxdr

        expected_symbols = [
            "ActionGraph",
            "GraphEdge",
            "GraphEdgeType",
            "GraphNode",
            "GraphNodeType",
            "MotifAnomalyDetector",
            "MotifSeverity",
            "MotifType",
            "MotifViolation",
            "ActiveExecutionOverlay",
            "AgentHubNode",
            "AgentStatus",
            "AgentTopologyBuilder",
            "AgentTopologyModel",
            "ContextPerimeterNode",
            "McpToolNode",
            "SandboxEnclaveNode",
            "UserPrincipalNode",
        ]
        for sym in expected_symbols:
            assert hasattr(agentxdr, sym), f"Expected top-level export '{sym}' in agentxdr"
            assert getattr(agentxdr, sym) is not None

