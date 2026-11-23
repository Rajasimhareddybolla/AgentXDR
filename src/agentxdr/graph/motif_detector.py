"""Motif anomaly detector for identifying attack patterns across action-graphs."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

import networkx as nx

from agentxdr.graph.models import (
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    MotifSeverity,
    MotifType,
    MotifViolation,
)
from agentxdr.models.events import EventType, ToolTier, Verdict


class MotifAnomalyDetector:
    """Detects the 5 core attack and anomaly graph motifs in execution DAGs."""

    DEFAULT_EGRESS_TOOLS: Set[str] = {
        "send_email",
        "post_webhook",
        "slack_post",
        "http_post",
        "external_api",
        "upload_file",
        "egress_data",
        "export_telemetry",
    }

    DEFAULT_HIGH_IMPACT_TOOLS: Set[str] = {
        "shell_exec",
        "terminal_exec",
        "bash",
        "delete_file",
        "drop_db",
        "database_drop",
        "eval",
        "system_reboot",
        "modify_system_config",
    }

    ADMIN_ROLES: Set[str] = {
        "admin",
        "administrator",
        "superadmin",
        "secops",
    }

    def __init__(
        self,
        loop_threshold: int = 3,
        fan_out_threshold: int = 8,
        egress_tools: Optional[Set[str]] = None,
        high_impact_tools: Optional[Set[str]] = None,
    ) -> None:
        self.loop_threshold = loop_threshold
        self.fan_out_threshold = fan_out_threshold
        self.egress_tools = {t.lower() for t in egress_tools} if egress_tools is not None else {t.lower() for t in self.DEFAULT_EGRESS_TOOLS}
        self.high_impact_tools = (
            {t.lower() for t in high_impact_tools} if high_impact_tools is not None else {t.lower() for t in self.DEFAULT_HIGH_IMPACT_TOOLS}
        )

    def scan_trace(
        self,
        graph: nx.DiGraph,
        trace_id: Optional[str] = None,
    ) -> List[MotifViolation]:
        """Scan a graph (or trace subgraph) for all 5 core motif anomalies."""
        violations: List[MotifViolation] = []

        # If trace_id specified, filter graph to trace nodes
        target_graph = graph
        if trace_id is not None:
            nodes_in_trace = [
                n for n, data in graph.nodes(data=True) if data.get("trace_id") == trace_id
            ]
            target_graph = graph.subgraph(nodes_in_trace).copy()

        if target_graph.number_of_nodes() == 0:
            return violations

        # 1. Detect forbidden taint subgraphs
        violations.extend(self._detect_taint_subgraphs(target_graph, trace_id))

        # 2. Detect execution loops and cycle deadlocks
        violations.extend(self._detect_execution_loops(target_graph, trace_id))

        # 3. Detect unauthorized tool jumping
        violations.extend(self._detect_tool_jumping(target_graph, trace_id))

        # 4. Detect privilege escalation sequences
        violations.extend(self._detect_privilege_escalation(target_graph, trace_id))

        # 5. Detect fan-out bursts
        violations.extend(self._detect_fan_out_bursts(target_graph, trace_id))

        return violations

    def scan_graph(self, graph: nx.DiGraph) -> List[MotifViolation]:
        """Alias for scan_trace across entire graph."""
        return self.scan_trace(graph, trace_id=None)

    # -----------------------------------------------------------------------
    # 1. Forbidden Taint Subgraphs
    # -----------------------------------------------------------------------

    def _detect_taint_subgraphs(
        self,
        graph: nx.DiGraph,
        trace_id: Optional[str],
    ) -> List[MotifViolation]:
        """Detect forbidden taint propagation paths.

        Patterns:
        a) UNTRUSTED_EXTERNAL -> privileged tool without intermediate HITL approval
        b) RESTRICTED_INTERNAL / CONFIDENTIAL_RAG -> external egress tool
        c) UNTRUSTED_EXTERNAL -> MEMORY_STORE write
        """
        violations: List[MotifViolation] = []

        for source in graph.nodes():
            s_data = graph.nodes[source]
            taint_labels = s_data.get("taint_labels") or []
            prov_tier = s_data.get("provenance_tier") or ""

            is_untrusted = "UNTRUSTED_EXTERNAL" in taint_labels or prov_tier == "UNTRUSTED_EXTERNAL"
            is_restricted = (
                "RESTRICTED_INTERNAL" in taint_labels
                or "CONFIDENTIAL_RAG" in taint_labels
                or prov_tier == "RESTRICTED_INTERNAL"
            )

            if not (is_untrusted or is_restricted):
                continue

            # Check reachable descendants
            try:
                descendants = nx.descendants(graph, source)
            except Exception:
                continue

            for target in descendants:
                t_data = graph.nodes[target]
                t_type = t_data.get("node_type")
                t_event_type = t_data.get("event_type")
                payload = t_data.get("payload") or {}

                # Pattern A: UNTRUSTED_EXTERNAL -> Privileged Tool without HITL
                if is_untrusted and (
                    t_type == GraphNodeType.TOOL_CALL.value
                    or t_event_type == EventType.TOOL_INVOCATION.value
                    or t_type == "TOOL_CALL"
                    or t_event_type == "TOOL_INVOCATION"
                ):
                    tool_tier = payload.get("tier")
                    tool_tier_str = (
                        tool_tier.value if isinstance(tool_tier, ToolTier) else str(tool_tier)
                    ).lower() if tool_tier else ""
                    tool_name = payload.get("tool_name", "")
                    tool_name_lower = tool_name.lower()
                    is_privileged = tool_tier_str in (
                        ToolTier.PRIVILEGED_HITL.value.lower(),
                        ToolTier.BLOCKED.value.lower(),
                        "privileged_hitl",
                        "blocked",
                    )
                    # Check if paths pass through an approved HITL node
                    all_paths = list(nx.all_simple_paths(graph, source, target))
                    unapproved_paths = []
                    for path in all_paths:
                        hitl_approved = False
                        for intermediate in path[1:-1]:
                            i_data = graph.nodes[intermediate]
                            i_event = i_data.get("event_type")
                            i_verdict = i_data.get("verdict")
                            i_payload = i_data.get("payload") or {}
                            if (
                                i_event == EventType.HITL_DECISION.value
                                or i_event == EventType.HITL_DECISION
                                or i_event == "HITL_DECISION"
                            ) and (
                                i_payload.get("decision") == "APPROVE"
                                or i_verdict in (Verdict.ALLOW.value, Verdict.ALLOW, "ALLOW")
                            ):
                                hitl_approved = True
                                break

                        if not hitl_approved:
                            unapproved_paths.append(path)

                    if unapproved_paths and (is_privileged or tool_name_lower in self.high_impact_tools):
                        shortest_path = min(unapproved_paths, key=len)
                        violations.append(
                            MotifViolation(
                                motif_type=MotifType.FORBIDDEN_TAINT_SUBGRAPH,
                                severity=MotifSeverity.CRITICAL,
                                description=(
                                    f"Untrusted external taint from node '{source}' flows to privileged "
                                    f"tool '{tool_name}' ('{target}') without HITL approval."
                                ),
                                trace_id=trace_id or s_data.get("trace_id"),
                                affected_nodes=shortest_path,
                                owasp_id="ASI01",
                                mitigation="Enforce mandatory HITL approval gate before executing privileged tool calls.",
                                details={
                                    "source_node": source,
                                    "target_node": target,
                                    "tool_name": tool_name,
                                    "tool_tier": tool_tier,
                                    "taint_labels": taint_labels,
                                },
                            )
                        )

                # Pattern B: RESTRICTED_INTERNAL -> External Egress
                if is_restricted and (
                    t_type == GraphNodeType.TOOL_CALL.value
                    or t_event_type == EventType.TOOL_INVOCATION.value
                    or t_type == "TOOL_CALL"
                    or t_event_type == "TOOL_INVOCATION"
                ):
                    tool_name = payload.get("tool_name", "")
                    if tool_name.lower() in self.egress_tools:
                        path = nx.shortest_path(graph, source, target)
                        violations.append(
                            MotifViolation(
                                motif_type=MotifType.FORBIDDEN_TAINT_SUBGRAPH,
                                severity=MotifSeverity.CRITICAL,
                                description=(
                                    f"Restricted internal knowledge from '{source}' flows to external "
                                    f"egress tool '{tool_name}' ('{target}')."
                                ),
                                trace_id=trace_id or s_data.get("trace_id"),
                                affected_nodes=path,
                                owasp_id="ASI02",
                                mitigation="Block external data egress when context includes restricted internal knowledge.",
                                details={
                                    "source_node": source,
                                    "target_node": target,
                                    "tool_name": tool_name,
                                    "taint_labels": taint_labels,
                                },
                            )
                        )

                # Pattern C: UNTRUSTED_EXTERNAL -> Memory Write
                if is_untrusted and (
                    t_type == GraphNodeType.MEMORY_STORE.value
                    or t_event_type == EventType.MEMORY_MUTATION.value
                ):
                    op = payload.get("operation", "")
                    if op in ("WRITE", "ROLLBACK"):
                        path = nx.shortest_path(graph, source, target)
                        violations.append(
                            MotifViolation(
                                motif_type=MotifType.FORBIDDEN_TAINT_SUBGRAPH,
                                severity=MotifSeverity.HIGH,
                                description=(
                                    f"Untrusted external taint from '{source}' flows to memory mutation "
                                    f"operation '{op}' on key '{payload.get('key')}' ('{target}')."
                                ),
                                trace_id=trace_id or s_data.get("trace_id"),
                                affected_nodes=path,
                                owasp_id="ASI06",
                                mitigation="Quarantine and sanitize untrusted context prior to persistent memory mutation.",
                                details={
                                    "source_node": source,
                                    "target_node": target,
                                    "operation": op,
                                    "memory_key": payload.get("key"),
                                    "taint_labels": taint_labels,
                                },
                            )
                        )

        return violations

    # -----------------------------------------------------------------------
    # 2. Execution Loops & Cycle Deadlocks
    # -----------------------------------------------------------------------

    def _detect_execution_loops(
        self,
        graph: nx.DiGraph,
        trace_id: Optional[str],
    ) -> List[MotifViolation]:
        """Detect execution loops, directed graph cycles, and repetitive calls."""
        violations: List[MotifViolation] = []

        # Sub-pattern 1: Directed cycles in the graph (e.g. A -> B -> A)
        try:
            cycles = list(nx.simple_cycles(graph))
            for cycle in cycles:
                violations.append(
                    MotifViolation(
                        motif_type=MotifType.EXECUTION_LOOP,
                        severity=MotifSeverity.HIGH,
                        description=f"Directed cycle deadlock detected across {len(cycle)} nodes: {cycle}",
                        trace_id=trace_id,
                        affected_nodes=cycle,
                        owasp_id="ASI08",
                        mitigation="Break execution cycle via loop circuit breaker and fail closed.",
                        details={"cycle": cycle, "cycle_length": len(cycle)},
                    )
                )
        except Exception:
            pass

        # Sub-pattern 2: Consecutive identical tool calls & alternating 2-tool loops
        # Collect tool invocation nodes grouped by trace_id to ensure multi-tenant isolation
        tool_nodes_by_trace: Dict[str, List[Dict[str, Any]]] = {}
        for nid, data in graph.nodes(data=True):
            if (
                data.get("node_type") == GraphNodeType.TOOL_CALL.value
                or data.get("event_type") == EventType.TOOL_INVOCATION.value
                or data.get("node_type") == "TOOL_CALL"
                or data.get("event_type") == "TOOL_INVOCATION"
            ):
                payload = data.get("payload") or {}
                t_trace = data.get("trace_id") or trace_id or "default"
                tool_nodes_by_trace.setdefault(t_trace, []).append({
                    "id": nid,
                    "trace_id": t_trace,
                    "tool_name": payload.get("tool_name", ""),
                    "arguments": payload.get("arguments", {}),
                    "timestamp": data.get("timestamp") or "",
                })

        for current_trace, tool_nodes in tool_nodes_by_trace.items():
            # Sort by timestamp (or insertion order)
            tool_nodes.sort(key=lambda x: str(x.get("timestamp", "")))

            # Check consecutive identical tool calls with streak aggregation
            if len(tool_nodes) >= self.loop_threshold:
                streak_count = 1
                streak_start = 0
                for i in range(1, len(tool_nodes)):
                    prev = tool_nodes[i - 1]
                    curr = tool_nodes[i]
                    same_name = (prev["tool_name"] or "").lower() == (curr["tool_name"] or "").lower()
                    try:
                        same_args = json.dumps(prev["arguments"], sort_keys=True) == json.dumps(
                            curr["arguments"], sort_keys=True
                        )
                    except Exception:
                        same_args = prev["arguments"] == curr["arguments"]

                    if same_name and same_args:
                        streak_count += 1
                    else:
                        if streak_count >= self.loop_threshold:
                            affected = [tool_nodes[k]["id"] for k in range(streak_start, streak_start + streak_count)]
                            violations.append(
                                MotifViolation(
                                    motif_type=MotifType.EXECUTION_LOOP,
                                    severity=MotifSeverity.HIGH,
                                    description=(
                                        f"Detected {streak_count} consecutive identical invocations "
                                        f"of tool '{tool_nodes[streak_start]['tool_name']}'."
                                    ),
                                    trace_id=trace_id or current_trace,
                                    affected_nodes=affected,
                                    owasp_id="ASI08",
                                    mitigation="Trip identical-call budget circuit breaker.",
                                    details={
                                        "tool_name": tool_nodes[streak_start]["tool_name"],
                                        "consecutive_count": streak_count,
                                        "arguments": tool_nodes[streak_start]["arguments"],
                                    },
                                )
                            )
                        streak_count = 1
                        streak_start = i

                # Check final streak
                if streak_count >= self.loop_threshold:
                    affected = [tool_nodes[k]["id"] for k in range(streak_start, streak_start + streak_count)]
                    violations.append(
                        MotifViolation(
                            motif_type=MotifType.EXECUTION_LOOP,
                            severity=MotifSeverity.HIGH,
                            description=(
                                f"Detected {streak_count} consecutive identical invocations "
                                f"of tool '{tool_nodes[streak_start]['tool_name']}'."
                            ),
                            trace_id=trace_id or current_trace,
                            affected_nodes=affected,
                            owasp_id="ASI08",
                            mitigation="Trip identical-call budget circuit breaker.",
                            details={
                                "tool_name": tool_nodes[streak_start]["tool_name"],
                                "consecutive_count": streak_count,
                                "arguments": tool_nodes[streak_start]["arguments"],
                            },
                        )
                    )

            # Check alternating 2-tool loops (e.g. A, B, A, B)
            if len(tool_nodes) >= 4:
                names = [(t["tool_name"] or "").lower() for t in tool_nodes]
                orig_names = [t["tool_name"] for t in tool_nodes]
                for i in range(len(names) - 3):
                    t1, t2 = names[i], names[i + 1]
                    if t1 != t2 and names[i + 2] == t1 and names[i + 3] == t2:
                        affected = [tool_nodes[k]["id"] for k in range(i, i + 4)]
                        violations.append(
                            MotifViolation(
                                motif_type=MotifType.EXECUTION_LOOP,
                                severity=MotifSeverity.MEDIUM,
                                description=(
                                    f"Detected alternating tool execution ping-pong loop: '{orig_names[i]}' <-> '{orig_names[i+1]}'."
                                ),
                                trace_id=trace_id or current_trace,
                                affected_nodes=affected,
                                owasp_id="ASI08",
                                mitigation="Enforce progress validation between alternating tool invocations.",
                                details={"tool_a": orig_names[i], "tool_b": orig_names[i + 1], "sequence_start_index": i},
                            )
                        )
                        break

        return violations

    # -----------------------------------------------------------------------
    # 3. Unauthorized Tool Jumping / Transition Anomalies
    # -----------------------------------------------------------------------

    def _detect_tool_jumping(
        self,
        graph: nx.DiGraph,
        trace_id: Optional[str],
    ) -> List[MotifViolation]:
        """Detect jumping directly from untrusted input to high-impact tool without reasoning."""
        violations: List[MotifViolation] = []

        for u, v in graph.edges():
            u_data = graph.nodes[u]
            v_data = graph.nodes[v]

            u_type = u_data.get("node_type")
            u_event = u_data.get("event_type")
            u_prov = u_data.get("provenance_tier") or ""
            u_taints = u_data.get("taint_labels") or []

            v_type = v_data.get("node_type")
            v_event = v_data.get("event_type")
            v_payload = v_data.get("payload") or {}
            tool_name = v_payload.get("tool_name", "")
            tool_name_lower = tool_name.lower()
            tool_tier = v_payload.get("tier", "")
            tool_tier_str = (
                tool_tier.value if isinstance(tool_tier, ToolTier) else str(tool_tier)
            ).lower() if tool_tier else ""

            # Direct transition without LLM_STEP reasoning
            is_reasoning_step = (
                u_type == GraphNodeType.LLM_STEP.value
                or u_event == EventType.LLM_GENERATION.value
                or u_type == "LLM_STEP"
                or u_event == "LLM_GENERATION"
            )

            # If u is USER_INPUT (or untrusted context) and v is TOOL_CALL
            is_input_or_untrusted = not is_reasoning_step and (
                u_type == GraphNodeType.USER.value
                or u_event == EventType.USER_INPUT.value
                or u_type == "USER"
                or u_event == "USER_INPUT"
                or "UNTRUSTED_EXTERNAL" in u_taints
                or u_prov == "UNTRUSTED_EXTERNAL"
            )
            is_tool = (
                v_type == GraphNodeType.TOOL_CALL.value
                or v_event == EventType.TOOL_INVOCATION.value
                or v_type == "TOOL_CALL"
                or v_event == "TOOL_INVOCATION"
            )

            if is_input_or_untrusted and is_tool:
                # Direct transition without LLM_STEP reasoning
                is_high_impact = (
                    tool_name_lower in self.high_impact_tools
                    or tool_tier_str in (
                        ToolTier.BLOCKED.value.lower(),
                        ToolTier.PRIVILEGED_HITL.value.lower(),
                        "blocked",
                        "privileged_hitl",
                    )
                )
                if is_high_impact:
                    violations.append(
                        MotifViolation(
                            motif_type=MotifType.UNAUTHORIZED_TOOL_JUMPING,
                            severity=MotifSeverity.CRITICAL,
                            description=(
                                f"Direct tool jumping detected from input node '{u}' to high-impact "
                                f"tool '{tool_name}' ('{v}') bypassing reasoning and planning steps."
                            ),
                            trace_id=trace_id or u_data.get("trace_id"),
                            affected_nodes=[u, v],
                            owasp_id="ASI02",
                            mitigation="Require LLM planning and policy inspection prior to invoking high-impact tools.",
                            details={
                                "from_node": u,
                                "to_node": v,
                                "tool_name": tool_name,
                                "tool_tier": tool_tier,
                            },
                        )
                    )

        return violations

    # -----------------------------------------------------------------------
    # 4. Privilege Escalation Sequences
    # -----------------------------------------------------------------------

    def _detect_privilege_escalation(
        self,
        graph: nx.DiGraph,
        trace_id: Optional[str],
    ) -> List[MotifViolation]:
        """Detect privilege escalation across multi-agent delegation boundaries."""
        violations: List[MotifViolation] = []

        for u, v in graph.edges():
            u_data = graph.nodes[u]
            v_data = graph.nodes[v]

            u_type = u_data.get("node_type")
            u_event = u_data.get("event_type")
            v_type = v_data.get("node_type")
            v_event = v_data.get("event_type")

            # Check agent delegation edges
            if (
                u_type == GraphNodeType.PEER_AGENT.value
                or u_event == EventType.AGENT_COMM.value
                or v_type == GraphNodeType.PEER_AGENT.value
                or v_event == EventType.AGENT_COMM.value
                or u_type == "PEER_AGENT"
                or u_event == "AGENT_COMM"
                or v_type == "PEER_AGENT"
                or v_event == "AGENT_COMM"
            ):
                u_meta = u_data.get("metadata") or (u_data.get("node").metadata if hasattr(u_data.get("node"), "metadata") else None) or {}
                v_meta = v_data.get("metadata") or (v_data.get("node").metadata if hasattr(v_data.get("node"), "metadata") else None) or {}
                u_scopes = set(u_meta.get("scopes") or u_meta.get("effective_scopes") or [])
                v_scopes = set(v_meta.get("scopes") or v_meta.get("effective_scopes") or [])

                # If caller has defined scopes and target requested/has scopes not in caller,
                # unless caller has superuser wildcard scope "*"
                has_wildcard = "*" in u_scopes
                if u_scopes and v_scopes and not has_wildcard and not v_scopes.issubset(u_scopes):
                    escalated_scopes = list(v_scopes - u_scopes)
                    violations.append(
                        MotifViolation(
                            motif_type=MotifType.PRIVILEGE_ESCALATION,
                            severity=MotifSeverity.HIGH,
                            description=(
                                f"Privilege escalation in delegation from '{u}' to '{v}': "
                                f"target scopes {escalated_scopes} exceed caller scopes."
                            ),
                            trace_id=trace_id or u_data.get("trace_id"),
                            affected_nodes=[u, v],
                            owasp_id="ASI03",
                            mitigation="Attenuate delegated scopes to caller principal permissions.",
                            details={
                                "caller_node": u,
                                "target_node": v,
                                "caller_scopes": list(u_scopes),
                                "target_scopes": list(v_scopes),
                                "escalated_scopes": escalated_scopes,
                            },
                        )
                    )

            # Check if an untrusted or non-admin caller invokes admin/privileged downstream nodes
            u_meta = u_data.get("metadata") or (u_data.get("node").metadata if hasattr(u_data.get("node"), "metadata") else None) or {}
            u_roles = {str(r).lower() for r in (u_meta.get("roles") or [])}
            u_scopes = set(u_meta.get("scopes") or u_meta.get("effective_scopes") or [])
            v_payload = v_data.get("payload") or {}
            v_tier = v_payload.get("tier")
            v_tier_str = (
                v_tier.value if isinstance(v_tier, ToolTier) else str(v_tier)
            ).lower() if v_tier else ""

            is_admin_caller = bool(u_roles.intersection(self.ADMIN_ROLES)) or ("*" in u_scopes) or ("*" in u_roles)
            if not is_admin_caller and v_tier_str in (ToolTier.BLOCKED.value.lower(), "blocked"):
                violations.append(
                    MotifViolation(
                        motif_type=MotifType.PRIVILEGE_ESCALATION,
                        severity=MotifSeverity.CRITICAL,
                        description=(
                            f"Non-admin caller '{u}' attempting to trigger blocked tool '{v_payload.get('tool_name')}' ('{v}')."
                        ),
                        trace_id=trace_id or u_data.get("trace_id"),
                        affected_nodes=[u, v],
                        owasp_id="ASI03",
                        mitigation="Strictly enforce caller role validation before blocked tool access.",
                        details={"caller": u, "tool": v_payload.get("tool_name")},
                    )
                )

        return violations

    # -----------------------------------------------------------------------
    # 5. Fan-Out Bursts
    # -----------------------------------------------------------------------

    def _detect_fan_out_bursts(
        self,
        graph: nx.DiGraph,
        trace_id: Optional[str],
    ) -> List[MotifViolation]:
        """Detect excessive concurrent out-degree tool calls or delegations from a single node."""
        violations: List[MotifViolation] = []

        for node in graph.nodes():
            n_data = graph.nodes[node]
            # Count out-degree to tool calls or delegations
            successors = list(graph.successors(node))
            tool_successors = []
            for s in successors:
                s_data = graph.nodes[s]
                s_type = s_data.get("node_type")
                s_event = s_data.get("event_type")
                if (
                    s_type in (GraphNodeType.TOOL_CALL.value, GraphNodeType.PEER_AGENT.value)
                    or s_event in (EventType.TOOL_INVOCATION.value, EventType.AGENT_COMM.value)
                ):
                    tool_successors.append(s)

            if len(tool_successors) >= self.fan_out_threshold:
                violations.append(
                    MotifViolation(
                        motif_type=MotifType.FAN_OUT_BURST,
                        severity=MotifSeverity.HIGH,
                        description=(
                            f"Fan-out burst anomaly: node '{node}' spawned {len(tool_successors)} "
                            f"concurrent tool calls/delegations (threshold: {self.fan_out_threshold})."
                        ),
                        trace_id=trace_id or n_data.get("trace_id"),
                        affected_nodes=[node] + tool_successors,
                        owasp_id="ASI08",
                        mitigation="Apply rate-limiting and fan-out throttling to prevent cascading DoS.",
                        details={
                            "source_node": node,
                            "fan_out_count": len(tool_successors),
                            "threshold": self.fan_out_threshold,
                            "targets": tool_successors,
                        },
                    )
                )

        return violations
