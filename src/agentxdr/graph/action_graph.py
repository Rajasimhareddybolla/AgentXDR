"""ActionGraph DAG builder wrapping NetworkX DiGraph for AgentXDR telemetry."""

from __future__ import annotations

from datetime import datetime
import threading
import uuid
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import networkx as nx

from agentxdr.graph.models import (
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
)
from agentxdr.models.events import AgentEvent, DriftSnapshot, EventType, ProvenanceTier, ToolTier, Verdict


class ActionGraph:
    """Thread-safe live execution action-graph (DAG) tracking AgentXDR telemetry."""

    def __init__(self) -> None:
        self._graph = nx.DiGraph()
        self._lock = threading.RLock()
        self._span_to_node: Dict[Tuple[str, str], str] = {}
        self._trace_to_nodes: Dict[str, List[str]] = {}
        self._agent_to_nodes: Dict[str, List[str]] = {}
        self._active_node_by_trace: Dict[str, str] = {}
        self._pending_parents: Dict[Tuple[str, str], List[str]] = {}  # (trace_id, parent_span_id) -> [child_node_id]

    @property
    def graph(self) -> nx.DiGraph:
        """Direct reference to underlying NetworkX DiGraph."""
        return self._graph

    @property
    def node_count(self) -> int:
        """Total number of nodes in graph."""
        with self._lock:
            return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        """Total number of edges in graph."""
        with self._lock:
            return self._graph.number_of_edges()

    def clear(self) -> None:
        """Reset the graph and all internal indexes."""
        with self._lock:
            self._graph.clear()
            self._span_to_node.clear()
            self._trace_to_nodes.clear()
            self._agent_to_nodes.clear()
            self._active_node_by_trace.clear()
            self._pending_parents.clear()

    def ingest_event(self, event: AgentEvent) -> str:
        """Ingest a single AgentEvent into the DAG and resolve causal edges.

        Returns the node ID of the newly added node.
        """
        with self._lock:
            node_id = self._determine_node_id(event)
            node_type = self._map_event_to_node_type(event.event_type)
            label = self._build_node_label(event, node_type)

            # Deactivate previous active node for this trace
            if event.trace_id in self._active_node_by_trace:
                prev_active_id = self._active_node_by_trace[event.trace_id]
                if self._graph.has_node(prev_active_id):
                    self._graph.nodes[prev_active_id]["is_active"] = False
                    prev_node_obj = self._graph.nodes[prev_active_id].get("node")
                    if isinstance(prev_node_obj, GraphNode):
                        prev_node_obj.is_active = False

            # Create GraphNode instance
            drift_score = (
                event.drift_snapshot.composite_score
                if event.drift_snapshot is not None
                else None
            )

            node_metadata = {
                "event_id": event.event_id,
                "policy_version": event.policy_version,
                "principal_user": event.principal.user_id if event.principal else None,
                "roles": list(event.principal.roles) if event.principal else [],
                "scopes": list(event.principal.effective_scopes) if event.principal else [],
                "effective_scopes": list(event.principal.effective_scopes) if event.principal else [],
            }

            graph_node = GraphNode(
                id=node_id,
                node_type=node_type,
                label=label,
                trace_id=event.trace_id,
                span_id=event.span_id,
                parent_span_id=event.parent_span_id,
                agent_id=event.agent_id,
                event_type=event.event_type,
                timestamp=event.timestamp,
                is_active=True,
                provenance_tier=event.provenance_tier,
                taint_labels=list(event.taint_labels),
                drift_score=drift_score,
                drift_snapshot=event.drift_snapshot,
                verdict=event.decision.verdict if event.decision else None,
                payload=dict(event.payload_redacted),
                metadata=node_metadata,
            )

            # Add node to NetworkX graph
            self._graph.add_node(
                node_id,
                node=graph_node,
                node_type=node_type.value,
                label=label,
                trace_id=event.trace_id,
                span_id=event.span_id,
                parent_span_id=event.parent_span_id,
                agent_id=event.agent_id,
                event_type=event.event_type.value,
                timestamp=event.timestamp.isoformat() if event.timestamp else None,
                is_active=True,
                provenance_tier=event.provenance_tier.value if event.provenance_tier else None,
                taint_labels=list(event.taint_labels),
                drift_score=drift_score,
                drift_snapshot=event.drift_snapshot,
                verdict=event.decision.verdict.value if event.decision else None,
                payload=dict(event.payload_redacted),
                metadata=graph_node.metadata,
            )

            # Update indexing
            self._span_to_node[(event.trace_id, event.span_id)] = node_id
            self._trace_to_nodes.setdefault(event.trace_id, []).append(node_id)
            self._agent_to_nodes.setdefault(event.agent_id, []).append(node_id)
            self._active_node_by_trace[event.trace_id] = node_id

            # Connect user principal node if this is the root event
            if event.principal and (
                event.parent_span_id is None or event.event_type == EventType.USER_INPUT
            ):
                user_node_id = f"user_{event.principal.user_id}_{event.trace_id}"
                if not self._graph.has_node(user_node_id):
                    user_metadata = {
                        "user_id": event.principal.user_id,
                        "roles": list(event.principal.roles),
                        "scopes": list(event.principal.effective_scopes),
                        "effective_scopes": list(event.principal.effective_scopes),
                    }
                    user_node = GraphNode(
                        id=user_node_id,
                        node_type=GraphNodeType.USER,
                        label=f"User: {event.principal.user_id}",
                        trace_id=event.trace_id,
                        agent_id=event.agent_id,
                        provenance_tier=event.provenance_tier,
                        metadata=user_metadata,
                    )
                    self._graph.add_node(
                        user_node_id,
                        node=user_node,
                        node_type=GraphNodeType.USER.value,
                        label=user_node.label,
                        trace_id=event.trace_id,
                        agent_id=event.agent_id,
                        metadata=user_node.metadata,
                    )
                    self._trace_to_nodes.setdefault(event.trace_id, []).append(user_node_id)

                # Connect user node to first event node if not self
                if user_node_id != node_id and not self._graph.has_edge(user_node_id, node_id):
                    edge = GraphEdge(
                        id=f"edge_{user_node_id}_{node_id}",
                        source=user_node_id,
                        target=node_id,
                        edge_type=GraphEdgeType.CAUSAL_FLOW,
                    )
                    self._graph.add_edge(
                        user_node_id,
                        node_id,
                        edge=edge,
                        edge_type=GraphEdgeType.CAUSAL_FLOW.value,
                        taint_badges=[],
                        metadata=dict(edge.metadata),
                    )

            # Resolve causal edge via parent_span_id
            if event.parent_span_id:
                parent_node_id = self._span_to_node.get((event.trace_id, event.parent_span_id))
                if parent_node_id:
                    self._add_causal_edge(parent_node_id, node_id, event)
                else:
                    # Register pending child
                    self._pending_parents.setdefault((event.trace_id, event.parent_span_id), []).append(node_id)

            # Check if this new node resolves any pending children
            if (event.trace_id, event.span_id) in self._pending_parents:
                children = self._pending_parents.pop((event.trace_id, event.span_id))
                for child_id in children:
                    child_node = self.get_node(child_id)
                    child_event_type = child_node.event_type if child_node else None
                    self._add_causal_edge(
                        parent_id=node_id,
                        child_id=child_id,
                        child_event=None,
                        child_event_type=child_event_type,
                    )

            return node_id

    def ingest_events(self, events: Sequence[AgentEvent]) -> List[str]:
        """Batch ingest a sequence of events."""
        with self._lock:
            return [self.ingest_event(event) for event in events]

    def _determine_node_id(self, event: AgentEvent) -> str:
        """Generate unique node ID for an event ensuring trace isolation."""
        # Check if this exact (trace_id, span_id) has already been seen in this trace
        if (event.trace_id, event.span_id) in self._span_to_node:
            base = event.span_id
            if self._graph.has_node(base) and self._graph.nodes[base].get("trace_id") != event.trace_id:
                base = f"{event.trace_id}:{event.span_id}"
            return f"{base}_{event.event_id[:8]}"

        # First time seeing this (trace_id, span_id)
        if not self._graph.has_node(event.span_id):
            return event.span_id

        # event.span_id already exists in the graph. Check which trace owns it.
        existing_trace = self._graph.nodes[event.span_id].get("trace_id")
        if existing_trace == event.trace_id:
            return f"{event.span_id}_{event.event_id[:8]}"

        # Belongs to a different trace -> disambiguate with trace_id
        candidate = f"{event.trace_id}:{event.span_id}"
        if not self._graph.has_node(candidate):
            return candidate
        return f"{candidate}_{event.event_id[:8]}"

    def _map_event_to_node_type(self, event_type: EventType) -> GraphNodeType:
        """Map canonical EventType to GraphNodeType."""
        mapping = {
            EventType.USER_INPUT: GraphNodeType.USER,
            EventType.LLM_GENERATION: GraphNodeType.LLM_STEP,
            EventType.RAG_ACCESS: GraphNodeType.RAG_DOC,
            EventType.MEMORY_MUTATION: GraphNodeType.MEMORY_STORE,
            EventType.TOOL_INVOCATION: GraphNodeType.TOOL_CALL,
            EventType.AGENT_COMM: GraphNodeType.PEER_AGENT,
            EventType.SANDBOX_EXEC: GraphNodeType.SANDBOX,
            EventType.HITL_DECISION: GraphNodeType.USER,
            EventType.RESPONSE_ACTION: GraphNodeType.AGENT,
        }
        return mapping.get(event_type, GraphNodeType.AGENT)

    def _build_node_label(self, event: AgentEvent, node_type: GraphNodeType) -> str:
        """Build human-friendly node display label."""
        payload = event.payload_redacted or {}
        if event.event_type == EventType.TOOL_INVOCATION:
            tool_name = payload.get("tool_name", "tool")
            return f"TOOL: {tool_name}"
        elif event.event_type == EventType.USER_INPUT:
            user_id = event.principal.user_id if event.principal else "User"
            return f"User Input ({user_id})"
        elif event.event_type == EventType.LLM_GENERATION:
            model = payload.get("model_name", "llm")
            return f"LLM Step ({model})"
        elif event.event_type == EventType.RAG_ACCESS:
            chunks = payload.get("chunks_retrieved", 0)
            return f"RAG Access ({chunks} chunks)"
        elif event.event_type == EventType.MEMORY_MUTATION:
            op = payload.get("operation", "MUTATION")
            key = payload.get("key", "mem")
            return f"Memory {op} [{key}]"
        elif event.event_type == EventType.AGENT_COMM:
            receiver = payload.get("receiver_agent_id", "peer")
            return f"Delegation -> {receiver}"
        elif event.event_type == EventType.SANDBOX_EXEC:
            return "Sandbox Execution"
        elif event.event_type == EventType.HITL_DECISION:
            decision = payload.get("decision", "HITL")
            return f"HITL Decision: {decision}"
        elif event.event_type == EventType.RESPONSE_ACTION:
            resp_type = payload.get("response_type", "Response")
            return f"Response: {resp_type}"
        return f"{node_type.value}: {event.span_id}"

    def _determine_edge_type(
        self,
        parent_node: Optional[GraphNode],
        child_node: Optional[GraphNode],
        child_event_type: Optional[EventType],
    ) -> GraphEdgeType:
        """Determine edge semantics between parent and child nodes."""
        if child_event_type == EventType.TOOL_INVOCATION:
            return GraphEdgeType.INVOKES
        elif child_event_type == EventType.RAG_ACCESS:
            return GraphEdgeType.READS_FROM
        elif child_event_type == EventType.MEMORY_MUTATION:
            op = child_node.payload.get("operation", "") if child_node else ""
            return GraphEdgeType.WRITES_TO if op in ("WRITE", "ROLLBACK") else GraphEdgeType.READS_FROM
        elif child_event_type == EventType.AGENT_COMM:
            return GraphEdgeType.DELEGATES_TO
        elif parent_node and parent_node.node_type == GraphNodeType.TOOL_CALL:
            return GraphEdgeType.RETURNS_TO
        return GraphEdgeType.CAUSAL_FLOW

    def _add_causal_edge(
        self,
        parent_id: str,
        child_id: str,
        child_event: Optional[AgentEvent] = None,
        child_event_type: Optional[EventType] = None,
    ) -> None:
        """Add directed causal edge between parent and child nodes."""
        parent_node = self.get_node(parent_id)
        child_node = self.get_node(child_id)
        event_type = (
            child_event.event_type
            if child_event
            else (child_event_type or (child_node.event_type if child_node else None))
        )
        edge_type = self._determine_edge_type(parent_node, child_node, event_type)

        # Propagate taint badges
        taint_badges: List[str] = []
        if parent_node and parent_node.taint_labels:
            taint_badges.extend(parent_node.taint_labels)
        if child_event and child_event.taint_labels:
            for t in child_event.taint_labels:
                if t not in taint_badges:
                    taint_badges.append(t)
        elif child_node and child_node.taint_labels:
            for t in child_node.taint_labels:
                if t not in taint_badges:
                    taint_badges.append(t)

        edge = GraphEdge(
            id=f"edge_{parent_id}_{child_id}",
            source=parent_id,
            target=child_id,
            edge_type=edge_type,
            taint_badges=taint_badges,
        )

        self._graph.add_edge(
            parent_id,
            child_id,
            edge=edge,
            edge_type=edge_type.value,
            taint_badges=taint_badges,
            metadata=dict(edge.metadata),
        )

    def get_node(self, node_id: str, trace_id: Optional[str] = None) -> Optional[GraphNode]:
        """Fetch GraphNode instance by node ID or (span_id, trace_id)."""
        with self._lock:
            target_id = node_id
            if trace_id and (trace_id, node_id) in self._span_to_node:
                target_id = self._span_to_node[(trace_id, node_id)]
            elif not self._graph.has_node(target_id):
                if trace_id:
                    target_id = self._span_to_node.get((trace_id, node_id), target_id)
                else:
                    matches = [nid for (t, s), nid in self._span_to_node.items() if s == node_id]
                    if len(matches) == 1:
                        target_id = matches[0]

            if not self._graph.has_node(target_id):
                return None
            data = self._graph.nodes[target_id]
            if trace_id and data.get("trace_id") != trace_id:
                return None
            node_obj = data.get("node")
            if isinstance(node_obj, GraphNode):
                return node_obj
            # Reconstruct GraphNode if stored as raw dict
            raw_node_type = data.get("node_type", GraphNodeType.AGENT.value)
            node_type = GraphNodeType(raw_node_type) if isinstance(raw_node_type, str) else raw_node_type

            raw_et = data.get("event_type")
            if isinstance(raw_et, EventType):
                event_type = raw_et
            elif isinstance(raw_et, str):
                try:
                    event_type = EventType(raw_et)
                except ValueError:
                    event_type = None
            else:
                event_type = None

            raw_pt = data.get("provenance_tier")
            if isinstance(raw_pt, ProvenanceTier):
                provenance_tier = raw_pt
            elif isinstance(raw_pt, str):
                try:
                    provenance_tier = ProvenanceTier(raw_pt)
                except ValueError:
                    provenance_tier = None
            else:
                provenance_tier = None

            raw_vd = data.get("verdict")
            if isinstance(raw_vd, Verdict):
                verdict = raw_vd
            elif isinstance(raw_vd, str):
                try:
                    verdict = Verdict(raw_vd)
                except ValueError:
                    verdict = None
            else:
                verdict = None

            raw_ts = data.get("timestamp")
            if isinstance(raw_ts, datetime):
                timestamp = raw_ts
            elif isinstance(raw_ts, str):
                try:
                    timestamp = datetime.fromisoformat(raw_ts)
                except ValueError:
                    timestamp = None
            else:
                timestamp = None

            raw_ds = data.get("drift_snapshot")
            if isinstance(raw_ds, DriftSnapshot):
                drift_snapshot = raw_ds
            elif isinstance(raw_ds, dict):
                try:
                    drift_snapshot = DriftSnapshot(**raw_ds)
                except Exception:
                    drift_snapshot = None
            else:
                drift_snapshot = None

            return GraphNode(
                id=target_id,
                node_type=node_type,
                label=data.get("label", target_id),
                trace_id=data.get("trace_id"),
                span_id=data.get("span_id"),
                parent_span_id=data.get("parent_span_id"),
                agent_id=data.get("agent_id"),
                event_type=event_type,
                timestamp=timestamp,
                is_active=data.get("is_active", False),
                provenance_tier=provenance_tier,
                taint_labels=list(data.get("taint_labels", [])),
                drift_score=data.get("drift_score"),
                drift_snapshot=drift_snapshot,
                verdict=verdict,
                payload=dict(data.get("payload", {})),
                metadata=dict(data.get("metadata", {})),
            )

    def get_nodes(self, trace_id: Optional[str] = None) -> List[GraphNode]:
        """Return list of all nodes, optionally filtered by trace_id."""
        with self._lock:
            if trace_id:
                node_ids = self._trace_to_nodes.get(trace_id, [])
                return [n for nid in node_ids if (n := self.get_node(nid, trace_id=trace_id)) is not None]
            return [n for nid in self._graph.nodes if (n := self.get_node(nid)) is not None]

    def get_edges(self, trace_id: Optional[str] = None) -> List[GraphEdge]:
        """Return list of all edges, optionally filtered by trace_id."""
        with self._lock:
            edges: List[GraphEdge] = []
            for u, v, data in self._graph.edges(data=True):
                if trace_id:
                    u_node = self.get_node(u)
                    v_node = self.get_node(v)
                    if not (u_node and u_node.trace_id == trace_id and v_node and v_node.trace_id == trace_id):
                        continue
                edge_obj = data.get("edge")
                if isinstance(edge_obj, GraphEdge):
                    edges.append(edge_obj)
                else:
                    edges.append(
                        GraphEdge(
                            id=f"edge_{u}_{v}",
                            source=u,
                            target=v,
                            edge_type=GraphEdgeType(data.get("edge_type", GraphEdgeType.CAUSAL_FLOW.value)),
                            taint_badges=list(data.get("taint_badges", [])),
                            metadata=dict(data.get("metadata", {})),
                        )
                    )
            return edges

    def get_active_node(self, trace_id: str) -> Optional[GraphNode]:
        """Get the currently active node for a given trace_id."""
        with self._lock:
            node_id = self._active_node_by_trace.get(trace_id)
            if node_id:
                return self.get_node(node_id)
            return None

    def get_subgraph(
        self,
        trace_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> nx.DiGraph:
        """Return an independent subgraph filtered by trace_id or agent_id."""
        with self._lock:
            matching_nodes: Set[str] = set()
            for nid, data in self._graph.nodes(data=True):
                t_match = True
                a_match = True
                if trace_id is not None:
                    t_match = data.get("trace_id") == trace_id
                if agent_id is not None:
                    a_match = data.get("agent_id") == agent_id
                if t_match and a_match:
                    matching_nodes.add(nid)

            return self._graph.subgraph(matching_nodes).copy()

    def export_dict(self, trace_id: Optional[str] = None) -> Dict[str, Any]:
        """Export serialized dictionary representation of nodes and edges atomically."""
        with self._lock:
            nodes = self.get_nodes(trace_id=trace_id)
            edges = self.get_edges(trace_id=trace_id)
            return {
                "trace_id": trace_id,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "nodes": [n.model_dump(mode="json") for n in nodes],
                "edges": [e.model_dump(mode="json") for e in edges],
            }

    def is_dag(self, trace_id: Optional[str] = None) -> bool:
        """Check whether the action graph (or trace subgraph) is a Directed Acyclic Graph."""
        with self._lock:
            subg = self.get_subgraph(trace_id=trace_id) if trace_id else self._graph
            return nx.is_directed_acyclic_graph(subg)

    def has_cycles(self, trace_id: Optional[str] = None) -> bool:
        """Check whether the action graph (or trace subgraph) contains directed cycles."""
        with self._lock:
            return not self.is_dag(trace_id=trace_id)

    def get_topological_order(self, trace_id: Optional[str] = None) -> List[str]:
        """Return node IDs in topological order; returns empty list if cycle exists or graph is empty."""
        with self._lock:
            subg = self.get_subgraph(trace_id=trace_id) if trace_id else self._graph
            if subg.number_of_nodes() == 0:
                return []
            try:
                return list(nx.topological_sort(subg))
            except (nx.NetworkXUnfeasible, nx.NetworkXError):
                return []
