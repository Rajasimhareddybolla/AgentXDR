"""Policy Enforcement Point (PEP) and Tiered Action Resolver for AgentXDR."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from agentxdr.models.events import Decision, ToolTier, Verdict
from agentxdr.models.killswitch import KillSwitchState
from agentxdr.models.policy import PolicySchema
from agentxdr.models.taint import TaintState

_UNSET = object()


class PolicyEvaluator:
    """Zero-trust policy evaluator enforcing inline deterministic guardrails.

    Evaluates tool execution requests against:
    1. Active hierarchical kill-switch state
    2. Tool declaration registry (shadow MCP tool prevention - ASI04)
    3. Tool classification tier (automatic, privileged_hitl, blocked)
    4. Tool schema hash pinning (MCP schema integrity - ASI04)
    5. Deterministic session taint-flow policies (ASI02)
    6. Tool parameter constraints (type, length, regex - ASI05)
    7. Dynamic high-risk drift escalation (threshold 0.75 - ASI01)
    """

    def __init__(self, kill_switch: Optional[KillSwitchState] = None) -> None:
        self.kill_switch = kill_switch

    def evaluate_tool_call(
        self,
        policy: PolicySchema,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        taints: Optional[TaintState] = None,
        tool_schema_hash: Any = _UNSET,
        drift_score: float = 0.0,
        trace_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Decision:
        """Evaluate a tool invocation request against the security policy.

        Parameters
        ----------
        policy: PolicySchema
            Active declarative policy schema governing this agent session.
        tool_name: str
            Name of the tool requested by the agent.
        arguments: Optional[Dict[str, Any]]
            Dictionary of tool call arguments.
        taints: Optional[TaintState]
            Session taint accumulation state machine.
        tool_schema_hash: Any
            SHA-256 hash presented by the MCP tool or caller. If explicitly None when
            the policy requires a pinned hash on automatic tools, invocation is blocked.
        drift_score: float
            Composite semantic/behavioral drift score [0.0, 1.0].
        trace_id: Optional[str]
            Session execution trace ID.
        agent_id: Optional[str]
            Optional agent ID override.
        **kwargs: Any
            Additional metadata accepted gracefully for forward compatibility.

        Returns
        -------
        Decision
            Deterministic verdict with latency_ms, rule_id, and owasp_ids.
        """
        start_time = time.perf_counter()

        def _make_decision(
            verdict: Verdict, rule_id: str, owasp_ids: Optional[List[str]] = None
        ) -> Decision:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return Decision(
                verdict=verdict,
                rule_id=rule_id,
                owasp_ids=owasp_ids or [],
                latency_ms=max(0.0, elapsed_ms),
            )

        effective_agent_id = agent_id or policy.agent_id

        # 1. Kill Switch Enforcement (Hierarchical)
        if self.kill_switch is not None:
            effective_trace_id = trace_id or (taints.trace_id if taints else "")
            if self.kill_switch.is_killed(
                agent_id=effective_agent_id,
                trace_id=effective_trace_id,
                tool_name=tool_name,
            ):
                return _make_decision(
                    Verdict.KILL,
                    rule_id="KILL_SWITCH_ACTIVE",
                    owasp_ids=["ASI01"],
                )

        # 2. Tool Name Validation (Empty / Whitespace Fail-Closed)
        if not tool_name or not tool_name.strip():
            return _make_decision(
                Verdict.BLOCK,
                rule_id="INVALID_TOOL_NAME",
                owasp_ids=["ASI04"],
            )

        # 3. Tool Registration & Shadow Tool Detection (Strict Case Matching)
        tool = next((t for t in policy.tools if t.name == tool_name), None)
        if tool is None:
            return _make_decision(
                Verdict.BLOCK,
                rule_id="SHADOW_MCP_DETECTED",
                owasp_ids=["ASI04"],
            )

        # 4. Blocked Tier Immediate Action
        if tool.tier == ToolTier.BLOCKED:
            return _make_decision(
                Verdict.BLOCK,
                rule_id="TOOL_TIER_BLOCKED",
                owasp_ids=["ASI05"],
            )

        # 5. Tool Schema Hash Pinning PEP (Integrity check takes priority)
        if tool.schema_sha256 is not None:
            if tool_schema_hash is None:
                # Explicitly passed None when policy requires pinned hash
                return _make_decision(
                    Verdict.BLOCK,
                    rule_id="MCP_SCHEMA_HASH_REQUIRED",
                    owasp_ids=["ASI04"],
                )
            elif tool_schema_hash is not _UNSET:
                expected_norm = tool.schema_sha256.strip().lower()
                if expected_norm.startswith("sha256:"):
                    expected_norm = expected_norm[7:]

                actual_norm = str(tool_schema_hash).strip().lower()
                if actual_norm.startswith("sha256:"):
                    actual_norm = actual_norm[7:]

                # For AUTOMATIC-tier tools: enforce strict hex format (64 lowercase hex chars).
                # This catches malformed / zero-length hashes before comparing.
                if tool.tier == ToolTier.AUTOMATIC:
                    _HEX_CHARS = frozenset("0123456789abcdef")
                    hex_valid = len(actual_norm) == 64 and all(c in _HEX_CHARS for c in actual_norm)
                    if not hex_valid or actual_norm != expected_norm:
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id="MCP_SCHEMA_MISMATCH",
                            owasp_ids=["ASI04"],
                        )
                elif actual_norm != expected_norm:
                    return _make_decision(
                        Verdict.BLOCK,
                        rule_id="MCP_SCHEMA_MISMATCH",
                        owasp_ids=["ASI04"],
                    )

        # 6. Deterministic Taint-Flow PEP
        if taints is not None and policy.taint_rules:
            for rule in policy.taint_rules:
                if tool_name in rule.blocked_tools:
                    if taints.matches_rule(rule.match_taints):
                        owasps = [rule.owasp_id] if rule.owasp_id else ["ASI02"]
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=rule.id,
                            owasp_ids=owasps,
                        )

        # 7. Tool Parameter Constraints PEP
        if tool.parameters:
            args = arguments if arguments is not None else {}
            for param_name, constraint in tool.parameters.items():
                if param_name not in args:
                    return _make_decision(
                        Verdict.BLOCK,
                        rule_id=f"PARAM_MISSING_{param_name.upper()}",
                        owasp_ids=["ASI05"],
                    )

                val = args[param_name]
                if val is None:
                    return _make_decision(
                        Verdict.BLOCK,
                        rule_id=f"PARAM_NULL_{param_name.upper()}",
                        owasp_ids=["ASI05"],
                    )

                # Type Verification
                t = constraint.type.lower()
                if t in ("string", "str"):
                    if not isinstance(val, str):
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=f"PARAM_TYPE_MISMATCH_{param_name.upper()}",
                            owasp_ids=["ASI05"],
                        )
                elif t in ("int", "integer"):
                    if not isinstance(val, int) or isinstance(val, bool):
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=f"PARAM_TYPE_MISMATCH_{param_name.upper()}",
                            owasp_ids=["ASI05"],
                        )
                elif t in ("float", "number"):
                    if not isinstance(val, (int, float)) or isinstance(val, bool):
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=f"PARAM_TYPE_MISMATCH_{param_name.upper()}",
                            owasp_ids=["ASI05"],
                        )
                elif t in ("bool", "boolean"):
                    if not isinstance(val, bool):
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=f"PARAM_TYPE_MISMATCH_{param_name.upper()}",
                            owasp_ids=["ASI05"],
                        )
                elif t in ("dict", "object"):
                    if not isinstance(val, dict):
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=f"PARAM_TYPE_MISMATCH_{param_name.upper()}",
                            owasp_ids=["ASI05"],
                        )
                elif t in ("list", "array"):
                    if not isinstance(val, list):
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=f"PARAM_TYPE_MISMATCH_{param_name.upper()}",
                            owasp_ids=["ASI05"],
                        )

                # Max Length Verification
                if constraint.max_length is not None:
                    if isinstance(val, str) and len(val) > constraint.max_length:
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=f"PARAM_MAX_LENGTH_EXCEEDED_{param_name.upper()}",
                            owasp_ids=["ASI05"],
                        )

                # Regex Pattern Verification
                if constraint.pattern is not None:
                    if not isinstance(val, str) or not re.search(constraint.pattern, val):
                        return _make_decision(
                            Verdict.BLOCK,
                            rule_id=f"PARAM_PATTERN_MISMATCH_{param_name.upper()}",
                            owasp_ids=["ASI05"],
                        )

        # 8. Dynamic High-Risk Escalation (Drift Score >= 0.75)
        clamped_drift = max(0.0, min(1.0, float(drift_score)))
        if tool.tier == ToolTier.AUTOMATIC and clamped_drift >= 0.75:
            return _make_decision(
                Verdict.PAUSE_FOR_HITL,
                rule_id="DYNAMIC_DRIFT_ESCALATION",
                owasp_ids=["ASI01"],
            )

        # 9. Tool Tier Resolution
        if tool.tier == ToolTier.PRIVILEGED_HITL:
            return _make_decision(
                Verdict.PAUSE_FOR_HITL,
                rule_id="PRIVILEGED_HITL_REQUIRED",
                owasp_ids=["ASI01"],
            )
        elif tool.tier == ToolTier.AUTOMATIC:
            return _make_decision(
                Verdict.ALLOW,
                rule_id="AUTOMATIC_TOOL_ALLOWED",
                owasp_ids=[],
            )
        else:
            return _make_decision(
                Verdict.BLOCK,
                rule_id="TOOL_TIER_BLOCKED",
                owasp_ids=["ASI05"],
            )
