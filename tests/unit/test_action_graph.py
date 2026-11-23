"""Unit tests for ActionGraph DAG builder and MotifAnomalyDetector."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import networkx as nx
import pytest

from agentxdr.graph import (
    ActionGraph,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    MotifAnomalyDetector,
    MotifSeverity,
    MotifType,
    MotifViolation,
)
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


# ---------------------------------------------------------------------------
# Helper: Create valid AgentEvent
# ---------------------------------------------------------------------------

def make_test_event(
    trace_id: str = "trace_001",
    span_id: str = "span_001",
    parent_span_id: Optional[str] = None,
    agent_id: str = "agent_primary",
    event_type: EventType = EventType.USER_INPUT,
    provenance_tier: ProvenanceTier = ProvenanceTier.AUTHENTICATED_USER,
    taint_labels: Optional[List[str]] = None,
    payload: Optional[Dict[str, Any]] = None,
    verdict: Verdict = Verdict.ALLOW,
    composite_risk: float = 0.1,
    user_id: str = "alice",
    roles: Optional[List[str]] = None,
    scopes: Optional[List[str]] = None,
) -> AgentEvent:
    return AgentEvent(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        agent_id=agent_id,
        policy_version="v1.0.0",
        event_type=event_type,
        principal=Principal(
            user_id=user_id,
            roles=roles or ["operator"],
            effective_scopes=scopes or ["kb:read", "ticket:create"],
        ),
        provenance_tier=provenance_tier,
        taint_labels=taint_labels or [],
        payload_redacted=payload or {},
        decision=Decision(
            verdict=verdict,
            rule_id="rule_default",
            owasp_ids=["ASI01"],
            latency_ms=1.5,
        ),
        drift_snapshot=DriftSnapshot(
            composite_score=composite_risk,
            s_policy=0.0,
            s_graph=0.0,
            s_velocity=0.0,
            s_semantic=composite_risk,
        ),
    )


# ===========================================================================
# 1. Graph Models Tests
# ===========================================================================


class TestGraphModels:
    """Verify GraphNode, GraphEdge, MotifViolation models and enums."""

    def test_enums(self) -> None:
        assert GraphNodeType.USER.value == "USER"
        assert GraphNodeType.TOOL_CALL.value == "TOOL_CALL"
        assert GraphEdgeType.INVOKES.value == "INVOKES"
        assert MotifType.FORBIDDEN_TAINT_SUBGRAPH.value == "FORBIDDEN_TAINT_SUBGRAPH"
        assert MotifSeverity.CRITICAL.value == "CRITICAL"

    def test_graph_node_instantiation(self) -> None:
        node = GraphNode(
            id="node_1",
            node_type=GraphNodeType.TOOL_CALL,
            label="TOOL: search_kb",
            trace_id="trace_1",
            span_id="span_1",
            is_active=True,
            taint_labels=["UNTRUSTED_EXTERNAL"],
            drift_score=0.45,
        )
        assert node.id == "node_1"
        assert node.is_active is True
        assert "UNTRUSTED_EXTERNAL" in node.taint_labels
        assert node.drift_score == 0.45

        dumped = node.model_dump(mode="json")
        assert dumped["id"] == "node_1"
        assert dumped["node_type"] == "TOOL_CALL"

    def test_graph_edge_instantiation(self) -> None:
        edge = GraphEdge(
            id="edge_1_2",
            source="node_1",
            target="node_2",
            edge_type=GraphEdgeType.INVOKES,
            taint_badges=["UNTRUSTED_EXTERNAL"],
        )
        assert edge.source == "node_1"
        assert edge.target == "node_2"
        assert edge.edge_type == GraphEdgeType.INVOKES
        assert edge.taint_badges == ["UNTRUSTED_EXTERNAL"]

    def test_motif_violation_instantiation(self) -> None:
        violation = MotifViolation(
            motif_type=MotifType.EXECUTION_LOOP,
            severity=MotifSeverity.HIGH,
            description="Infinite cycle detected",
            trace_id="trace_1",
            affected_nodes=["node_a", "node_b"],
            owasp_id="ASI08",
            mitigation="Trip circuit breaker",
        )
        assert violation.motif_type == MotifType.EXECUTION_LOOP
        assert violation.severity == MotifSeverity.HIGH
        assert len(violation.affected_nodes) == 2
        assert violation.owasp_id == "ASI08"


# ===========================================================================
# 2. ActionGraph DAG Builder Tests
# ===========================================================================


class TestActionGraph:
    """Verify live DAG construction, causal edge mapping, active tracking, and subgraphs."""

    def test_initialization_and_clear(self) -> None:
        graph = ActionGraph()
        assert graph.node_count == 0
        assert graph.edge_count == 0
        assert isinstance(graph.graph, nx.DiGraph)

        ev = make_test_event(span_id="s1")
        graph.ingest_event(ev)
        assert graph.node_count > 0

        graph.clear()
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_ingest_single_user_event_creates_root_and_node(self) -> None:
        graph = ActionGraph()
        ev = make_test_event(
            trace_id="t1",
            span_id="s1",
            parent_span_id=None,
            event_type=EventType.USER_INPUT,
            user_id="alice",
        )
        node_id = graph.ingest_event(ev)
        assert node_id == "s1"

        # User principal root node is created and connected
        assert graph.node_count == 2  # user_alice_t1 and s1
        assert graph.edge_count == 1

        user_node = graph.get_node("user_alice_t1")
        assert user_node is not None
        assert user_node.node_type == GraphNodeType.USER

        s1_node = graph.get_node("s1")
        assert s1_node is not None
        assert s1_node.is_active is True

    def test_causal_chain_and_edge_types(self) -> None:
        graph = ActionGraph()
        # Turn 1: User input
        e1 = make_test_event(trace_id="t1", span_id="s1", event_type=EventType.USER_INPUT)
        # Turn 2: RAG Access
        e2 = make_test_event(
            trace_id="t1",
            span_id="s2",
            parent_span_id="s1",
            event_type=EventType.RAG_ACCESS,
            payload={"chunks_retrieved": 3},
        )
        # Turn 3: LLM Generation
        e3 = make_test_event(
            trace_id="t1",
            span_id="s3",
            parent_span_id="s2",
            event_type=EventType.LLM_GENERATION,
            payload={"model_name": "gpt-4o"},
        )
        # Turn 4: Tool Invocation
        e4 = make_test_event(
            trace_id="t1",
            span_id="s4",
            parent_span_id="s3",
            event_type=EventType.TOOL_INVOCATION,
            payload={"tool_name": "search_kb", "arguments": {"query": "security"}},
        )
        # Turn 5: Memory write
        e5 = make_test_event(
            trace_id="t1",
            span_id="s5",
            parent_span_id="s4",
            event_type=EventType.MEMORY_MUTATION,
            payload={"operation": "WRITE", "key": "session_state"},
        )

        graph.ingest_events([e1, e2, e3, e4, e5])

        # Verify edge types
        edges = graph.get_edges(trace_id="t1")
        edge_map = {(e.source, e.target): e.edge_type for e in edges}

        assert edge_map.get(("s1", "s2")) == GraphEdgeType.READS_FROM
        assert edge_map.get(("s2", "s3")) == GraphEdgeType.CAUSAL_FLOW
        assert edge_map.get(("s3", "s4")) == GraphEdgeType.INVOKES
        assert edge_map.get(("s4", "s5")) == GraphEdgeType.WRITES_TO

    def test_out_of_order_event_resolution(self) -> None:
        """Verify child event ingested before parent correctly links when parent arrives."""
        graph = ActionGraph()
        # Child arrives first
        child = make_test_event(
            trace_id="t1",
            span_id="s_child",
            parent_span_id="s_parent",
            event_type=EventType.TOOL_INVOCATION,
            payload={"tool_name": "execute_task"},
        )
        graph.ingest_event(child)
        assert graph.edge_count == 0

        # Parent arrives later
        parent = make_test_event(
            trace_id="t1",
            span_id="s_parent",
            parent_span_id=None,
            event_type=EventType.LLM_GENERATION,
        )
        graph.ingest_event(parent)

        # Edge s_parent -> s_child is automatically resolved
        assert graph.graph.has_edge("s_parent", "s_child")
        edge_data = graph.graph.get_edge_data("s_parent", "s_child")
        assert edge_data["edge_type"] == GraphEdgeType.INVOKES.value

    def test_active_node_tracking(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(trace_id="t1", span_id="s1")
        graph.ingest_event(e1)
        assert graph.get_active_node("t1").id == "s1"
        assert graph.get_node("s1").is_active is True

        e2 = make_test_event(trace_id="t1", span_id="s2", parent_span_id="s1")
        graph.ingest_event(e2)
        assert graph.get_active_node("t1").id == "s2"
        assert graph.get_node("s1").is_active is False
        assert graph.get_node("s2").is_active is True

    def test_taint_propagation_on_edges(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(
            trace_id="t1",
            span_id="s1",
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        e2 = make_test_event(
            trace_id="t1",
            span_id="s2",
            parent_span_id="s1",
            taint_labels=["CONFIDENTIAL_RAG"],
        )
        graph.ingest_events([e1, e2])

        edge_data = graph.graph.get_edge_data("s1", "s2")
        badges = edge_data["taint_badges"]
        assert "UNTRUSTED_EXTERNAL" in badges
        assert "CONFIDENTIAL_RAG" in badges

    def test_subgraph_filtering(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(trace_id="trace_A", span_id="sA1", agent_id="agent_1")
        e2 = make_test_event(trace_id="trace_A", span_id="sA2", parent_span_id="sA1", agent_id="agent_1")
        e3 = make_test_event(trace_id="trace_B", span_id="sB1", agent_id="agent_2")

        graph.ingest_events([e1, e2, e3])

        # Filter by trace_id
        sub_a = graph.get_subgraph(trace_id="trace_A")
        assert "sA1" in sub_a.nodes
        assert "sA2" in sub_a.nodes
        assert "sB1" not in sub_a.nodes

        # Filter by agent_id
        sub_agent2 = graph.get_subgraph(agent_id="agent_2")
        assert "sB1" in sub_agent2.nodes
        assert "sA1" not in sub_agent2.nodes

    def test_export_dict(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(trace_id="t1", span_id="s1")
        e2 = make_test_event(trace_id="t1", span_id="s2", parent_span_id="s1")
        graph.ingest_events([e1, e2])

        exported = graph.export_dict(trace_id="t1")
        assert exported["trace_id"] == "t1"
        assert exported["node_count"] >= 2
        assert exported["edge_count"] >= 1
        assert len(exported["nodes"]) == exported["node_count"]
        assert len(exported["edges"]) == exported["edge_count"]


# ===========================================================================
# 3. Motif Anomaly Detector Tests
# ===========================================================================


class TestMotifAnomalyDetector:
    """Verify detection of the 5 core attack and anomaly graph motifs."""

    # -----------------------------------------------------------------------
    # Motif 1: Forbidden Taint Subgraphs
    # -----------------------------------------------------------------------

    def test_taint_subgraph_untrusted_to_privileged_tool_without_hitl(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(
            trace_id="t_taint",
            span_id="s1",
            event_type=EventType.USER_INPUT,
            provenance_tier=ProvenanceTier.UNTRUSTED_EXTERNAL,
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        e2 = make_test_event(
            trace_id="t_taint",
            span_id="s2",
            parent_span_id="s1",
            event_type=EventType.LLM_GENERATION,
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        e3 = make_test_event(
            trace_id="t_taint",
            span_id="s3",
            parent_span_id="s2",
            event_type=EventType.TOOL_INVOCATION,
            payload={
                "tool_name": "delete_customer_records",
                "tier": ToolTier.PRIVILEGED_HITL.value,
            },
            verdict=Verdict.ALLOW,  # Executed without prior HITL approval node!
        )
        graph.ingest_events([e1, e2, e3])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_taint")

        taint_violations = [v for v in violations if v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH]
        assert len(taint_violations) >= 1
        assert taint_violations[0].severity == MotifSeverity.CRITICAL
        assert "delete_customer_records" in taint_violations[0].description
        assert taint_violations[0].owasp_id == "ASI01"

    def test_taint_subgraph_with_intermediate_hitl_passes(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(
            trace_id="t_ok",
            span_id="s1",
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        # Intermediate HITL decision approving execution
        e2 = make_test_event(
            trace_id="t_ok",
            span_id="s2",
            parent_span_id="s1",
            event_type=EventType.HITL_DECISION,
            payload={"decision": "APPROVE", "ticket_id": "ticket_101"},
            verdict=Verdict.ALLOW,
        )
        e3 = make_test_event(
            trace_id="t_ok",
            span_id="s3",
            parent_span_id="s2",
            event_type=EventType.TOOL_INVOCATION,
            payload={"tool_name": "delete_customer_records", "tier": ToolTier.PRIVILEGED_HITL.value},
        )
        graph.ingest_events([e1, e2, e3])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_ok")
        taint_violations = [v for v in violations if v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH]
        assert len(taint_violations) == 0

    def test_taint_subgraph_restricted_rag_to_external_egress(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(
            trace_id="t_exfil",
            span_id="s1",
            event_type=EventType.RAG_ACCESS,
            provenance_tier=ProvenanceTier.RESTRICTED_INTERNAL,
            taint_labels=["CONFIDENTIAL_RAG"],
        )
        e2 = make_test_event(
            trace_id="t_exfil",
            span_id="s2",
            parent_span_id="s1",
            event_type=EventType.LLM_GENERATION,
            taint_labels=["CONFIDENTIAL_RAG"],
        )
        e3 = make_test_event(
            trace_id="t_exfil",
            span_id="s3",
            parent_span_id="s2",
            event_type=EventType.TOOL_INVOCATION,
            payload={"tool_name": "send_email", "tier": ToolTier.AUTOMATIC.value},
        )
        graph.ingest_events([e1, e2, e3])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_exfil")
        egress_violations = [
            v for v in violations if v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH and "send_email" in v.description
        ]
        assert len(egress_violations) >= 1
        assert egress_violations[0].owasp_id == "ASI02"

    def test_taint_subgraph_untrusted_to_memory_write(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(
            trace_id="t_mem",
            span_id="s1",
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        e2 = make_test_event(
            trace_id="t_mem",
            span_id="s2",
            parent_span_id="s1",
            event_type=EventType.MEMORY_MUTATION,
            payload={"operation": "WRITE", "key": "system_prompt_override"},
        )
        graph.ingest_events([e1, e2])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_mem")
        mem_violations = [v for v in violations if v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH]
        assert len(mem_violations) >= 1
        assert mem_violations[0].owasp_id == "ASI06"

    # -----------------------------------------------------------------------
    # Motif 2: Execution Loops & Cycle Deadlocks
    # -----------------------------------------------------------------------

    def test_execution_loop_identical_consecutive_tools(self) -> None:
        graph = ActionGraph()
        # 3 consecutive identical tool calls
        events = []
        for i in range(1, 4):
            events.append(
                make_test_event(
                    trace_id="t_loop",
                    span_id=f"tool_step_{i}",
                    event_type=EventType.TOOL_INVOCATION,
                    payload={"tool_name": "query_api", "arguments": {"id": 42}},
                )
            )
        graph.ingest_events(events)

        detector = MotifAnomalyDetector(loop_threshold=3)
        violations = detector.scan_trace(graph.graph, trace_id="t_loop")
        loop_violations = [v for v in violations if v.motif_type == MotifType.EXECUTION_LOOP]
        assert len(loop_violations) >= 1
        assert loop_violations[0].owasp_id == "ASI08"
        assert "3 consecutive identical invocations" in loop_violations[0].description

    def test_execution_loop_alternating_ping_pong(self) -> None:
        graph = ActionGraph()
        tools = ["tool_A", "tool_B", "tool_A", "tool_B"]
        events = []
        for i, t in enumerate(tools, 1):
            events.append(
                make_test_event(
                    trace_id="t_pingpong",
                    span_id=f"step_{i}",
                    event_type=EventType.TOOL_INVOCATION,
                    payload={"tool_name": t, "arguments": {"step": i}},
                )
            )
        graph.ingest_events(events)

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_pingpong")
        loop_violations = [v for v in violations if v.motif_type == MotifType.EXECUTION_LOOP]
        assert any("ping-pong" in v.description for v in loop_violations)

    def test_execution_loop_directed_cycle_deadlock(self) -> None:
        g = nx.DiGraph()
        g.add_node("agent_A", trace_id="t_cyc", node_type=GraphNodeType.PEER_AGENT.value)
        g.add_node("agent_B", trace_id="t_cyc", node_type=GraphNodeType.PEER_AGENT.value)
        g.add_edge("agent_A", "agent_B")
        g.add_edge("agent_B", "agent_A")

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(g, trace_id="t_cyc")
        cycle_violations = [v for v in violations if v.motif_type == MotifType.EXECUTION_LOOP]
        assert len(cycle_violations) >= 1
        assert "cycle deadlock detected" in cycle_violations[0].description

    # -----------------------------------------------------------------------
    # Motif 3: Unauthorized Tool Jumping
    # -----------------------------------------------------------------------

    def test_unauthorized_tool_jumping_from_user_to_shell_exec(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(
            trace_id="t_jump",
            span_id="s1",
            event_type=EventType.USER_INPUT,
            provenance_tier=ProvenanceTier.UNTRUSTED_EXTERNAL,
        )
        # Direct edge from user input to high impact shell_exec skipping reasoning
        e2 = make_test_event(
            trace_id="t_jump",
            span_id="s2",
            parent_span_id="s1",
            event_type=EventType.TOOL_INVOCATION,
            payload={"tool_name": "shell_exec", "arguments": {"cmd": "rm -rf /"}},
        )
        graph.ingest_events([e1, e2])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_jump")
        jump_violations = [v for v in violations if v.motif_type == MotifType.UNAUTHORIZED_TOOL_JUMPING]
        assert len(jump_violations) >= 1
        assert jump_violations[0].severity == MotifSeverity.CRITICAL
        assert jump_violations[0].owasp_id == "ASI02"

    def test_normal_reasoning_flow_no_tool_jumping(self) -> None:
        graph = ActionGraph()
        e1 = make_test_event(trace_id="t_norm", span_id="s1", event_type=EventType.USER_INPUT)
        e2 = make_test_event(trace_id="t_norm", span_id="s2", parent_span_id="s1", event_type=EventType.LLM_GENERATION)
        e3 = make_test_event(
            trace_id="t_norm",
            span_id="s3",
            parent_span_id="s2",
            event_type=EventType.TOOL_INVOCATION,
            payload={"tool_name": "search_kb"},
        )
        graph.ingest_events([e1, e2, e3])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_norm")
        jump_violations = [v for v in violations if v.motif_type == MotifType.UNAUTHORIZED_TOOL_JUMPING]
        assert len(jump_violations) == 0

    # -----------------------------------------------------------------------
    # Motif 4: Privilege Escalation
    # -----------------------------------------------------------------------

    def test_privilege_escalation_delegation_scope_expansion(self) -> None:
        g = nx.DiGraph()
        g.add_node(
            "agent_junior",
            trace_id="t_esc",
            node_type=GraphNodeType.PEER_AGENT.value,
            metadata={"scopes": ["kb:read"]},
        )
        g.add_node(
            "agent_senior",
            trace_id="t_esc",
            node_type=GraphNodeType.PEER_AGENT.value,
            metadata={"scopes": ["kb:read", "database:drop"]},
        )
        g.add_edge("agent_junior", "agent_senior")

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(g, trace_id="t_esc")
        esc_violations = [v for v in violations if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
        assert len(esc_violations) >= 1
        assert esc_violations[0].owasp_id == "ASI03"
        assert "database:drop" in str(esc_violations[0].details)

    def test_privilege_escalation_non_admin_invoking_blocked_tool(self) -> None:
        g = nx.DiGraph()
        g.add_node(
            "user_guest",
            trace_id="t_esc2",
            node_type=GraphNodeType.USER.value,
            metadata={"roles": ["guest"]},
        )
        g.add_node(
            "tool_blocked",
            trace_id="t_esc2",
            node_type=GraphNodeType.TOOL_CALL.value,
            payload={"tool_name": "delete_all_users", "tier": ToolTier.BLOCKED.value},
        )
        g.add_edge("user_guest", "tool_blocked")

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(g, trace_id="t_esc2")
        esc_violations = [v for v in violations if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
        assert len(esc_violations) >= 1
        assert esc_violations[0].severity == MotifSeverity.CRITICAL

    # -----------------------------------------------------------------------
    # Motif 5: Fan-Out Bursts
    # -----------------------------------------------------------------------

    def test_fan_out_burst_detected(self) -> None:
        graph = ActionGraph()
        llm_event = make_test_event(trace_id="t_burst", span_id="llm_root", event_type=EventType.LLM_GENERATION)
        graph.ingest_event(llm_event)

        # 9 concurrent tool calls spawned from llm_root
        for k in range(1, 10):
            tool_event = make_test_event(
                trace_id="t_burst",
                span_id=f"tool_call_{k}",
                parent_span_id="llm_root",
                event_type=EventType.TOOL_INVOCATION,
                payload={"tool_name": f"worker_tool_{k}"},
            )
            graph.ingest_event(tool_event)

        detector = MotifAnomalyDetector(fan_out_threshold=8)
        violations = detector.scan_trace(graph.graph, trace_id="t_burst")
        burst_violations = [v for v in violations if v.motif_type == MotifType.FAN_OUT_BURST]
        assert len(burst_violations) >= 1
        assert burst_violations[0].owasp_id == "ASI08"
        assert burst_violations[0].details["fan_out_count"] == 9

    def test_clean_trace_produces_zero_violations(self) -> None:
        graph = ActionGraph()
        # Normal authenticated benign trace
        e1 = make_test_event(
            trace_id="t_clean",
            span_id="s1",
            event_type=EventType.USER_INPUT,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
            roles=["operator"],
            scopes=["kb:read"],
        )
        e2 = make_test_event(
            trace_id="t_clean",
            span_id="s2",
            parent_span_id="s1",
            event_type=EventType.RAG_ACCESS,
            payload={"chunks_retrieved": 2},
        )
        e3 = make_test_event(
            trace_id="t_clean",
            span_id="s3",
            parent_span_id="s2",
            event_type=EventType.LLM_GENERATION,
            payload={"model_name": "gpt-4o"},
        )
        e4 = make_test_event(
            trace_id="t_clean",
            span_id="s4",
            parent_span_id="s3",
            event_type=EventType.TOOL_INVOCATION,
            payload={"tool_name": "search_kb", "tier": ToolTier.AUTOMATIC.value},
        )
        e5 = make_test_event(
            trace_id="t_clean",
            span_id="s5",
            parent_span_id="s4",
            event_type=EventType.RESPONSE_ACTION,
            payload={"response_type": "FINAL_ANSWER"},
        )
        graph.ingest_events([e1, e2, e3, e4, e5])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_clean")
        assert len(violations) == 0

    # -----------------------------------------------------------------------
    # Remediation Targeted Verification Tests (Verifier Feedback Iteration 2)
    # -----------------------------------------------------------------------

    def test_untrusted_input_llm_allow_privileged_tool_triggers_taint_subgraph(self) -> None:
        """Scenario (a): Untrusted user input -> LLM generation (Verdict.ALLOW) ->

        Privileged tool call MUST trigger FORBIDDEN_TAINT_SUBGRAPH (ASI01) and MUST NOT
        be falsely cleared by the LLM step's ALLOW verdict or falsely flagged as tool jumping.
        """
        graph = ActionGraph()
        e1 = make_test_event(
            trace_id="t_remediate_taint",
            span_id="span_input",
            event_type=EventType.USER_INPUT,
            provenance_tier=ProvenanceTier.UNTRUSTED_EXTERNAL,
            taint_labels=["UNTRUSTED_EXTERNAL"],
        )
        e2 = make_test_event(
            trace_id="t_remediate_taint",
            span_id="span_llm",
            parent_span_id="span_input",
            event_type=EventType.LLM_GENERATION,
            taint_labels=["UNTRUSTED_EXTERNAL"],
            verdict=Verdict.ALLOW,  # Normal LLM reasoning verdict is ALLOW
            payload={"model_name": "claude-3-5-sonnet"},
        )
        e3 = make_test_event(
            trace_id="t_remediate_taint",
            span_id="span_tool",
            parent_span_id="span_llm",
            event_type=EventType.TOOL_INVOCATION,
            verdict=Verdict.ALLOW,
            payload={
                "tool_name": "delete_customer_records",
                "tier": ToolTier.PRIVILEGED_HITL.value,
            },
        )
        graph.ingest_events([e1, e2, e3])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="t_remediate_taint")

        # 1. Must trigger FORBIDDEN_TAINT_SUBGRAPH
        taint_violations = [v for v in violations if v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH]
        assert len(taint_violations) >= 1
        assert any(v.owasp_id == "ASI01" for v in taint_violations)
        assert any("delete_customer_records" in v.description for v in taint_violations)

        # 2. Must NOT trigger UNAUTHORIZED_TOOL_JUMPING because span_llm is a reasoning step
        jump_violations = [v for v in violations if v.motif_type == MotifType.UNAUTHORIZED_TOOL_JUMPING]
        assert len(jump_violations) == 0

    def test_admin_caller_invoking_blocked_tool_no_false_positive_privilege_escalation(self) -> None:
        """Scenario (b): Authenticated user with roles=['admin'] calling a blocked tool

        via ActionGraph MUST NOT trigger false positive privilege escalation.
        Conversely, non-admin callers MUST trigger privilege escalation.
        """
        # Admin caller: No false alarm
        graph_admin = ActionGraph()
        e_admin_1 = make_test_event(
            trace_id="t_admin_caller",
            span_id="span_admin_user",
            user_id="root_secops",
            roles=["admin", "security_lead"],
            scopes=["*"],
            event_type=EventType.USER_INPUT,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
        )
        e_admin_2 = make_test_event(
            trace_id="t_admin_caller",
            span_id="span_admin_llm",
            parent_span_id="span_admin_user",
            user_id="root_secops",
            roles=["admin", "security_lead"],
            scopes=["*"],
            event_type=EventType.LLM_GENERATION,
        )
        e_admin_3 = make_test_event(
            trace_id="t_admin_caller",
            span_id="span_admin_tool",
            parent_span_id="span_admin_llm",
            user_id="root_secops",
            roles=["admin", "security_lead"],
            scopes=["*"],
            event_type=EventType.TOOL_INVOCATION,
            payload={
                "tool_name": "emergency_killswitch",
                "tier": ToolTier.BLOCKED.value,
            },
        )
        graph_admin.ingest_events([e_admin_1, e_admin_2, e_admin_3])

        # Verify node metadata is properly populated in NetworkX DiGraph
        admin_tool_node_data = graph_admin.graph.nodes["span_admin_llm"]
        assert "metadata" in admin_tool_node_data
        assert "admin" in admin_tool_node_data["metadata"]["roles"]

        detector = MotifAnomalyDetector()
        admin_violations = detector.scan_trace(graph_admin.graph, trace_id="t_admin_caller")
        admin_esc_violations = [v for v in admin_violations if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
        assert len(admin_esc_violations) == 0, f"False positive detected: {admin_esc_violations}"

        # Non-admin caller: MUST trigger privilege escalation
        graph_non_admin = ActionGraph()
        e_nonadmin_1 = make_test_event(
            trace_id="t_nonadmin_caller",
            span_id="span_user_op",
            user_id="guest_operator",
            roles=["operator"],
            scopes=["kb:read"],
            event_type=EventType.USER_INPUT,
            provenance_tier=ProvenanceTier.AUTHENTICATED_USER,
        )
        e_nonadmin_2 = make_test_event(
            trace_id="t_nonadmin_caller",
            span_id="span_tool_blocked",
            parent_span_id="span_user_op",
            user_id="guest_operator",
            roles=["operator"],
            scopes=["kb:read"],
            event_type=EventType.TOOL_INVOCATION,
            payload={
                "tool_name": "emergency_killswitch",
                "tier": ToolTier.BLOCKED.value,
            },
        )
        graph_non_admin.ingest_events([e_nonadmin_1, e_nonadmin_2])

        nonadmin_violations = detector.scan_trace(graph_non_admin.graph, trace_id="t_nonadmin_caller")
        nonadmin_esc = [v for v in nonadmin_violations if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
        assert len(nonadmin_esc) >= 1
        assert nonadmin_esc[0].owasp_id == "ASI03"
        assert nonadmin_esc[0].severity == MotifSeverity.CRITICAL

    def test_agent_delegation_scope_expansion_triggers_privilege_escalation(self) -> None:
        """Scenario (c): Agent delegation with scope expansion

        (effective_scopes=['read'] -> effective_scopes=['read', 'admin'])
        ingested via real ActionGraph.ingest_events MUST trigger PRIVILEGE_ESCALATION (ASI03).
        Conversely, delegation with identical or attenuated scopes MUST NOT trigger.
        """
        # Scope escalation: 'read' -> 'read', 'admin'
        graph_esc = ActionGraph()
        e_caller = make_test_event(
            trace_id="t_delegation_esc",
            span_id="span_agent_caller",
            agent_id="agent_caller",
            event_type=EventType.AGENT_COMM,
            scopes=["read"],
            roles=["analyst"],
            payload={"receiver_agent_id": "agent_delegate"},
        )
        e_delegate = make_test_event(
            trace_id="t_delegation_esc",
            span_id="span_agent_delegate",
            parent_span_id="span_agent_caller",
            agent_id="agent_delegate",
            event_type=EventType.AGENT_COMM,
            scopes=["read", "admin"],
            roles=["analyst"],
            payload={"receiver_agent_id": "worker"},
        )
        graph_esc.ingest_events([e_caller, e_delegate])

        # Verify node metadata is populated with scopes
        caller_node_data = graph_esc.graph.nodes["span_agent_caller"]
        delegate_node_data = graph_esc.graph.nodes["span_agent_delegate"]
        assert caller_node_data["metadata"]["scopes"] == ["read"]
        assert "admin" in delegate_node_data["metadata"]["scopes"]

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph_esc.graph, trace_id="t_delegation_esc")
        esc_violations = [v for v in violations if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
        assert len(esc_violations) >= 1
        assert esc_violations[0].owasp_id == "ASI03"
        assert "admin" in esc_violations[0].details["escalated_scopes"]

        # Benign delegation: 'read', 'write' -> 'read' (attenuated)
        graph_benign = ActionGraph()
        e_caller_ok = make_test_event(
            trace_id="t_delegation_ok",
            span_id="span_caller_ok",
            agent_id="agent_caller",
            event_type=EventType.AGENT_COMM,
            scopes=["read", "write"],
            payload={"receiver_agent_id": "agent_delegate"},
        )
        e_delegate_ok = make_test_event(
            trace_id="t_delegation_ok",
            span_id="span_delegate_ok",
            parent_span_id="span_caller_ok",
            agent_id="agent_delegate",
            event_type=EventType.AGENT_COMM,
            scopes=["read"],
            payload={"receiver_agent_id": "worker"},
        )
        graph_benign.ingest_events([e_caller_ok, e_delegate_ok])

        benign_violations = detector.scan_trace(graph_benign.graph, trace_id="t_delegation_ok")
        benign_esc = [v for v in benign_violations if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
        assert len(benign_esc) == 0

    def test_node_and_user_metadata_populated_on_ingest(self) -> None:
        """Verify ActionGraph.ingest_events properly stores metadata on all DiGraph nodes."""
        graph = ActionGraph()
        e = make_test_event(
            trace_id="t_meta",
            span_id="span_1",
            user_id="bob",
            roles=["secops", "incident_responder"],
            scopes=["ticket:read", "ticket:write"],
            event_type=EventType.USER_INPUT,
        )
        graph.ingest_event(e)

        # 1. Event node metadata in NetworkX
        event_node_data = graph.graph.nodes["span_1"]
        assert "metadata" in event_node_data
        assert event_node_data["metadata"]["roles"] == ["secops", "incident_responder"]
        assert event_node_data["metadata"]["scopes"] == ["ticket:read", "ticket:write"]

        # 2. User root node metadata in NetworkX
        user_node_id = "user_bob_t_meta"
        assert graph.graph.has_node(user_node_id)
        user_node_data = graph.graph.nodes[user_node_id]
        assert "metadata" in user_node_data
        assert user_node_data["metadata"]["roles"] == ["secops", "incident_responder"]
        assert user_node_data["metadata"]["scopes"] == ["ticket:read", "ticket:write"]
        assert user_node_data["metadata"]["user_id"] == "bob"

        # 3. GraphNode object preservation
        gn = graph.get_node("span_1")
        assert gn is not None
        assert gn.metadata["roles"] == ["secops", "incident_responder"]

    def test_multi_tenant_concurrent_trace_isolation_no_cross_trace_edges(self) -> None:
        """Verify 50 concurrent multi-tenant traces sharing standard span IDs

        ('root', 'step1', 'step2') create isolated DAGs with zero cross-trace edges.
        """
        import concurrent.futures

        graph = ActionGraph()
        num_traces = 50
        trace_ids = [f"tenant_trace_{i:03d}" for i in range(num_traces)]

        all_events: List[AgentEvent] = []
        for t_id in trace_ids:
            # 3 events sharing standard step names
            e_root = make_test_event(
                trace_id=t_id,
                span_id="root",
                parent_span_id=None,
                event_type=EventType.USER_INPUT,
                user_id=f"user_{t_id}",
            )
            e_step1 = make_test_event(
                trace_id=t_id,
                span_id="step1",
                parent_span_id="root",
                event_type=EventType.LLM_GENERATION,
                user_id=f"user_{t_id}",
            )
            e_step2 = make_test_event(
                trace_id=t_id,
                span_id="step2",
                parent_span_id="step1",
                event_type=EventType.TOOL_INVOCATION,
                payload={"tool_name": "search_kb"},
                user_id=f"user_{t_id}",
            )
            all_events.extend([e_root, e_step1, e_step2])

        # Ingest events concurrently across 10 threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(graph.ingest_event, all_events))

        # 1. Assert exactly 0 cross-trace edges
        cross_trace_edges: List[Any] = []
        for u, v in graph.graph.edges():
            u_data = graph.graph.nodes[u]
            v_data = graph.graph.nodes[v]
            u_trace = u_data.get("trace_id")
            v_trace = v_data.get("trace_id")
            if u_trace != v_trace:
                cross_trace_edges.append((u, v, u_trace, v_trace))

        assert len(cross_trace_edges) == 0, f"Detected cross-trace edges: {cross_trace_edges}"

        # 2. Assert each trace has its own isolated subgraph with correct structure
        for t_id in trace_ids:
            sub = graph.get_subgraph(trace_id=t_id)
            assert sub.number_of_nodes() >= 3
            assert sub.number_of_edges() >= 2
            edges = graph.get_edges(trace_id=t_id)
            for edge in edges:
                u_node = graph.get_node(edge.source)
                v_node = graph.get_node(edge.target)
                assert u_node is not None and u_node.trace_id == t_id
                assert v_node is not None and v_node.trace_id == t_id

    def test_multi_tenant_out_of_order_trace_isolation(self) -> None:
        """Verify out-of-order events across multiple traces with identical span IDs do not cross-link."""
        graph = ActionGraph()
        # Trace A child arrives first
        e_a_child = make_test_event(trace_id="t_A", span_id="step1", parent_span_id="root", event_type=EventType.TOOL_INVOCATION)
        # Trace B parent arrives
        e_b_parent = make_test_event(trace_id="t_B", span_id="root", parent_span_id=None, event_type=EventType.USER_INPUT)
        # Trace B child arrives
        e_b_child = make_test_event(trace_id="t_B", span_id="step1", parent_span_id="root", event_type=EventType.TOOL_INVOCATION)
        # Trace A parent arrives last
        e_a_parent = make_test_event(trace_id="t_A", span_id="root", parent_span_id=None, event_type=EventType.USER_INPUT)

        graph.ingest_events([e_a_child, e_b_parent, e_b_child, e_a_parent])

        cross_trace_edges = []
        for u, v in graph.graph.edges():
            u_trace = graph.graph.nodes[u].get("trace_id")
            v_trace = graph.graph.nodes[v].get("trace_id")
            if u_trace != v_trace:
                cross_trace_edges.append((u, v, u_trace, v_trace))

        assert len(cross_trace_edges) == 0
        # Verify both traces resolved their causal edges
        edges_a = graph.get_edges(trace_id="t_A")
        edges_b = graph.get_edges(trace_id="t_B")
        assert len(edges_a) >= 1
        assert len(edges_b) >= 1

    def test_get_node_multi_tenant_span_id_collision_and_mismatched_trace_id(self) -> None:
        """Verify get_node retrieves the correct tenant node during span_id collisions

        and returns None when queried with a mismatched trace_id.
        """
        graph = ActionGraph()
        e_alpha = make_test_event(
            trace_id="t_alpha",
            span_id="step_common",
            user_id="alice",
            payload={"tenant": "alpha"},
        )
        e_beta = make_test_event(
            trace_id="t_beta",
            span_id="step_common",
            user_id="bob",
            payload={"tenant": "beta"},
        )
        graph.ingest_event(e_alpha)
        beta_node_id = graph.ingest_event(e_beta)

        # 1. Querying by common span_id with trace_id returns tenant-specific nodes
        node_beta = graph.get_node("step_common", trace_id="t_beta")
        assert node_beta is not None
        assert node_beta.trace_id == "t_beta"
        assert node_beta.payload == {"tenant": "beta"}

        node_alpha = graph.get_node("step_common", trace_id="t_alpha")
        assert node_alpha is not None
        assert node_alpha.trace_id == "t_alpha"
        assert node_alpha.payload == {"tenant": "alpha"}

        # 2. Querying with node_id but mismatched trace_id returns None
        assert graph.get_node(beta_node_id, trace_id="t_alpha") is None
        assert graph.get_node("step_common", trace_id="t_gamma") is None

        # 3. Non-existent span_id returns None
        assert graph.get_node("non_existent_span", trace_id="t_alpha") is None

    def test_action_graph_dag_query_helpers_and_empty_graphs(self) -> None:
        """Verify is_dag, has_cycles, and get_topological_order across empty, linear, and cyclic graphs."""
        graph = ActionGraph()

        # 1. Empty graph
        assert graph.is_dag() is True
        assert graph.has_cycles() is False
        assert graph.get_topological_order() == []
        assert graph.is_dag(trace_id="non_existent") is True
        assert graph.has_cycles(trace_id="non_existent") is False
        assert graph.get_topological_order(trace_id="non_existent") == []

        # 2. Linear DAG across trace t_dag
        e1 = make_test_event(trace_id="t_dag", span_id="s1", event_type=EventType.USER_INPUT)
        e2 = make_test_event(trace_id="t_dag", span_id="s2", parent_span_id="s1", event_type=EventType.LLM_GENERATION)
        e3 = make_test_event(trace_id="t_dag", span_id="s3", parent_span_id="s2", event_type=EventType.TOOL_INVOCATION)
        graph.ingest_events([e1, e2, e3])

        assert graph.is_dag() is True
        assert graph.is_dag(trace_id="t_dag") is True
        assert graph.has_cycles() is False
        assert graph.has_cycles(trace_id="t_dag") is False

        topo = graph.get_topological_order(trace_id="t_dag")
        assert len(topo) == 4  # user_alice_t_dag, s1, s2, s3
        assert topo.index("s1") < topo.index("s2") < topo.index("s3")

        # 3. Manually create a cycle in a separate trace t_cycle
        graph.graph.add_node("cyc_1", trace_id="t_cycle")
        graph.graph.add_node("cyc_2", trace_id="t_cycle")
        graph.graph.add_edge("cyc_1", "cyc_2")
        graph.graph.add_edge("cyc_2", "cyc_1")

        assert graph.is_dag(trace_id="t_cycle") is False
        assert graph.has_cycles(trace_id="t_cycle") is True
        assert graph.get_topological_order(trace_id="t_cycle") == []

        # Trace isolation: t_dag remains a valid DAG
        assert graph.is_dag(trace_id="t_dag") is True
        assert graph.has_cycles(trace_id="t_dag") is False

    def test_lossless_fallback_reconstruction_graph_node_and_edge(self) -> None:
        """Verify get_node and get_edges properly parse and restore all attributes during fallback."""
        graph = ActionGraph()

        # Insert node directly into underlying graph without 'node' object
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        graph.graph.add_node(
            "raw_node_1",
            node_type=GraphNodeType.TOOL_CALL.value,
            label="TOOL: raw_test",
            trace_id="tr_raw",
            span_id="raw_span_1",
            parent_span_id="raw_parent",
            agent_id="raw_agent",
            event_type=EventType.TOOL_INVOCATION.value,
            timestamp=now_iso,
            is_active=True,
            provenance_tier=ProvenanceTier.UNTRUSTED_EXTERNAL.value,
            taint_labels=["UNTRUSTED_EXTERNAL", "INJECTION_ATTEMPT"],
            drift_score=0.42,
            drift_snapshot={
                "composite_score": 0.42,
                "s_policy": 0.1,
                "s_graph": 0.1,
                "s_velocity": 0.1,
                "s_semantic": 0.12,
            },
            verdict=Verdict.ALLOW.value,
            payload={"tool_name": "calc", "arguments": {"x": 1}},
            metadata={"source": "external_import", "policy_version": "v1.0.0"},
        )
        graph.graph.add_node(
            "raw_node_2",
            node_type=GraphNodeType.AGENT.value,
            label="Agent Step",
            trace_id="tr_raw",
        )
        graph.graph.add_edge(
            "raw_node_1",
            "raw_node_2",
            edge_type=GraphEdgeType.INVOKES.value,
            taint_badges=["UNTRUSTED_EXTERNAL"],
            metadata={"causal_weight": 0.95},
        )

        # 1. Test get_node fallback reconstruction
        reconstructed = graph.get_node("raw_node_1", trace_id="tr_raw")
        assert reconstructed is not None
        assert reconstructed.id == "raw_node_1"
        assert reconstructed.node_type == GraphNodeType.TOOL_CALL
        assert reconstructed.event_type == EventType.TOOL_INVOCATION
        assert reconstructed.provenance_tier == ProvenanceTier.UNTRUSTED_EXTERNAL
        assert reconstructed.verdict == Verdict.ALLOW
        assert isinstance(reconstructed.timestamp, datetime)
        assert reconstructed.is_active is True
        assert reconstructed.taint_labels == ["UNTRUSTED_EXTERNAL", "INJECTION_ATTEMPT"]
        assert reconstructed.drift_score == 0.42
        assert reconstructed.drift_snapshot is not None
        assert reconstructed.drift_snapshot.composite_score == 0.42
        assert reconstructed.payload == {"tool_name": "calc", "arguments": {"x": 1}}
        assert reconstructed.metadata == {"source": "external_import", "policy_version": "v1.0.0"}

        # 2. Test get_edges fallback reconstruction
        edges = graph.get_edges(trace_id="tr_raw")
        assert len(edges) == 1
        edge = edges[0]
        assert edge.source == "raw_node_1"
        assert edge.target == "raw_node_2"
        assert edge.edge_type == GraphEdgeType.INVOKES
        assert edge.taint_badges == ["UNTRUSTED_EXTERNAL"]
        assert edge.metadata == {"causal_weight": 0.95}

    def test_wildcard_caller_delegation_least_privilege(self) -> None:
        """Verify caller with wildcard scope '*' can delegate without triggering privilege escalation."""
        graph = ActionGraph()
        # Caller agent with wildcard scope
        e_caller = make_test_event(
            trace_id="tr_wild",
            span_id="caller_agent",
            event_type=EventType.AGENT_COMM,
            scopes=["*"],
        )
        # Target agent requested specific scopes
        e_target = make_test_event(
            trace_id="tr_wild",
            span_id="target_agent",
            parent_span_id="caller_agent",
            event_type=EventType.AGENT_COMM,
            scopes=["db:write", "system:manage", "cloud:deploy"],
        )
        graph.ingest_events([e_caller, e_target])

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(graph.graph, trace_id="tr_wild")
        esc_violations = [v for v in violations if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
        assert len(esc_violations) == 0

    def test_administrative_roles_recognition_for_blocked_tools(self) -> None:
        """Verify secops, superadmin, administrator roles and wildcard scopes avoid false positives on blocked tools."""
        detector = MotifAnomalyDetector()
        roles_to_test = ["admin", "administrator", "superadmin", "secops"]

        for role in roles_to_test:
            g = nx.DiGraph()
            g.add_node("caller", node_type=GraphNodeType.AGENT.value, metadata={"roles": [role], "scopes": []})
            g.add_node("tool_blocked", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": "rm_rf", "tier": "BLOCKED"})
            g.add_edge("caller", "tool_blocked")

            violations = detector.scan_trace(g)
            esc = [v for v in violations if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
            assert len(esc) == 0, f"Role '{role}' should be recognized as administrative"

        # Non-admin role (e.g. viewer) MUST be flagged
        g_viewer = nx.DiGraph()
        g_viewer.add_node("caller", node_type=GraphNodeType.AGENT.value, metadata={"roles": ["viewer"], "scopes": []})
        g_viewer.add_node("tool_blocked", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": "rm_rf", "tier": "BLOCKED"})
        g_viewer.add_edge("caller", "tool_blocked")
        violations_viewer = detector.scan_trace(g_viewer)
        esc_viewer = [v for v in violations_viewer if v.motif_type == MotifType.PRIVILEGE_ESCALATION]
        assert len(esc_viewer) == 1

    def test_case_insensitive_evasion_resistance(self) -> None:
        """Verify detector resists casing evasion for high-impact tools, egress tools, and tiers."""
        detector = MotifAnomalyDetector()

        # 1. Tool jumping with uppercase SHELL_EXEC
        g_jump = nx.DiGraph()
        g_jump.add_node("user_1", node_type=GraphNodeType.USER.value)
        g_jump.add_node("tool_jump", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": "SHELL_EXEC", "tier": "BLOCKED"})
        g_jump.add_edge("user_1", "tool_jump")
        v_jump = detector.scan_trace(g_jump)
        assert any(v.motif_type == MotifType.UNAUTHORIZED_TOOL_JUMPING for v in v_jump)

        # 2. Egress with uppercase SEND_EMAIL and POST_WEBHOOK
        g_egress = nx.DiGraph()
        g_egress.add_node("rag_doc", node_type=GraphNodeType.RAG_DOC.value, taint_labels=["RESTRICTED_INTERNAL"])
        g_egress.add_node("tool_egress", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": "SEND_EMAIL"})
        g_egress.add_edge("rag_doc", "tool_egress")
        v_egress = detector.scan_trace(g_egress)
        assert any(v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH for v in v_egress)

        # 3. Privileged tool with mixed-case tier "Privileged_Hitl"
        g_priv = nx.DiGraph()
        g_priv.add_node("untrusted", node_type=GraphNodeType.USER.value, taint_labels=["UNTRUSTED_EXTERNAL"])
        g_priv.add_node("tool_priv", node_type=GraphNodeType.TOOL_CALL.value, payload={"tool_name": "Custom_Exec", "tier": "Privileged_Hitl"})
        g_priv.add_edge("untrusted", "tool_priv")
        v_priv = detector.scan_trace(g_priv)
        assert any(v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH for v in v_priv)

    def test_multi_tenant_isolation_in_loop_detection(self) -> None:
        """Verify independent single tool calls across different traces do not trip execution loops."""
        graph = ActionGraph()
        # 3 different traces each call query_api once with identical arguments
        e1 = make_test_event(trace_id="tenant_1", span_id="s1", event_type=EventType.TOOL_INVOCATION, payload={"tool_name": "query_api", "arguments": {"id": 100}})
        e2 = make_test_event(trace_id="tenant_2", span_id="s1", event_type=EventType.TOOL_INVOCATION, payload={"tool_name": "query_api", "arguments": {"id": 100}})
        e3 = make_test_event(trace_id="tenant_3", span_id="s1", event_type=EventType.TOOL_INVOCATION, payload={"tool_name": "query_api", "arguments": {"id": 100}})
        graph.ingest_events([e1, e2, e3])

        detector = MotifAnomalyDetector(loop_threshold=3)
        # scan_graph scans across entire graph with all tenants
        violations = detector.scan_graph(graph.graph)
        loop_violations = [v for v in violations if v.motif_type == MotifType.EXECUTION_LOOP]
        assert len(loop_violations) == 0

    def test_consecutive_loop_streak_aggregation(self) -> None:
        """Verify 5 consecutive identical calls are aggregated into exactly 1 violation rather than 3 cascading alerts."""
        graph = ActionGraph()
        events = [
            make_test_event(
                trace_id="t_streak",
                span_id=f"step_{i}",
                event_type=EventType.TOOL_INVOCATION,
                payload={"tool_name": "fetch_metric", "arguments": {"metric": "cpu"}},
            )
            for i in range(1, 6)
        ]
        graph.ingest_events(events)

        detector = MotifAnomalyDetector(loop_threshold=3)
        violations = detector.scan_trace(graph.graph, trace_id="t_streak")
        loop_violations = [v for v in violations if v.motif_type == MotifType.EXECUTION_LOOP]

        # Exactly 1 aggregated violation for the streak
        assert len(loop_violations) == 1
        assert "5 consecutive identical invocations" in loop_violations[0].description
        assert len(loop_violations[0].affected_nodes) == 5

    def test_diamond_dag_taint_deduplication(self) -> None:
        """Verify diamond DAG with 2 unapproved paths emits exactly 1 violation on the shortest path."""
        g = nx.DiGraph()
        # Source untrusted
        g.add_node("source_node", node_type=GraphNodeType.USER.value, taint_labels=["UNTRUSTED_EXTERNAL"], trace_id="t_diamond")
        # Intermediate path 1
        g.add_node("path_1_step", node_type=GraphNodeType.LLM_STEP.value, event_type=EventType.LLM_GENERATION.value, trace_id="t_diamond")
        # Intermediate path 2 (longer: step 2a -> step 2b)
        g.add_node("path_2_step_a", node_type=GraphNodeType.LLM_STEP.value, event_type=EventType.LLM_GENERATION.value, trace_id="t_diamond")
        g.add_node("path_2_step_b", node_type=GraphNodeType.LLM_STEP.value, event_type=EventType.LLM_GENERATION.value, trace_id="t_diamond")
        # Target privileged tool
        g.add_node(
            "target_tool",
            node_type=GraphNodeType.TOOL_CALL.value,
            event_type=EventType.TOOL_INVOCATION.value,
            payload={"tool_name": "admin_db_drop", "tier": "PRIVILEGED_HITL"},
            trace_id="t_diamond",
        )

        # Path 1: length 3
        g.add_edge("source_node", "path_1_step")
        g.add_edge("path_1_step", "target_tool")

        # Path 2: length 4
        g.add_edge("source_node", "path_2_step_a")
        g.add_edge("path_2_step_a", "path_2_step_b")
        g.add_edge("path_2_step_b", "target_tool")

        detector = MotifAnomalyDetector()
        violations = detector.scan_trace(g, trace_id="t_diamond")
        taint_violations = [v for v in violations if v.motif_type == MotifType.FORBIDDEN_TAINT_SUBGRAPH]

        # Deduplication must yield exactly 1 violation for (source_node, target_tool)
        assert len(taint_violations) == 1
        # Selected path should be the shortest path: source_node -> path_1_step -> target_tool (len 3)
        assert taint_violations[0].affected_nodes == ["source_node", "path_1_step", "target_tool"]

