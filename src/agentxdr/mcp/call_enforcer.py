"""MCP Call Enforcer — evaluates tool invocations against PEP and sanitizes return payloads."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agentxdr.guardrails.dlp import DlpMasker
from agentxdr.mcp.injection_scanner import McpInjectionScanner
from agentxdr.models.events import Decision, Verdict
from agentxdr.models.policy import PolicySchema
from agentxdr.models.taint import TaintState
from agentxdr.policy.evaluator import PolicyEvaluator, _UNSET


class McpCallEnforcer:
    """Enforces policy constraints on tool calls and sanitizes tool responses."""

    def __init__(
        self,
        evaluator: PolicyEvaluator,
        dlp: DlpMasker,
        scanner: McpInjectionScanner,
    ) -> None:
        self.evaluator = evaluator
        self.dlp = dlp
        self.scanner = scanner

    def enforce_call(
        self,
        policy: PolicySchema,
        tool_name: str,
        arguments: Dict[str, Any],
        trace_id: str,
        taints: Optional[TaintState] = None,
        tool_schema_hash: Any = _UNSET,
    ) -> Tuple[Decision, Optional[Dict[str, Any]]]:
        """Evaluate a tool execution request against zero-trust policy.

        Returns
        -------
        (decision, refusal_dict)
            If ALLOW or PAUSE_FOR_HITL: refusal_dict is None.
            If BLOCK or KILL: refusal_dict contains JSON-RPC error payload.
        """
        decision = self.evaluator.evaluate_tool_call(
            policy=policy,
            tool_name=tool_name,
            arguments=arguments,
            taints=taints,
            tool_schema_hash=tool_schema_hash,
            trace_id=trace_id,
        )

        if decision.verdict in (Verdict.ALLOW, Verdict.PAUSE_FOR_HITL):
            return decision, None

        refusal = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": f"Tool execution blocked by AgentXDR: {decision.rule_id}",
                "data": {
                    "rule_id": decision.rule_id,
                    "owasp_ids": decision.owasp_ids,
                    "verdict": decision.verdict.value,
                    "trace_id": trace_id,
                    "latency_ms": decision.latency_ms,
                },
            },
        }
        return decision, refusal

    def sanitize_response(
        self,
        tool_response: Any,
        trace_id: str,
        taints: Optional[TaintState] = None,
    ) -> Tuple[Any, bool, List[str]]:
        """Sanitize an outbound tool response payload and update session taint state.

        Returns
        -------
        (sanitized_response, was_injected, taint_labels_added)
        """
        taints_to_add: List[str] = ["UNTRUSTED_EXTERNAL"]
        was_injected = False

        def _walk_and_sanitize(val: Any) -> Any:
            nonlocal was_injected
            if isinstance(val, str):
                # Check for prompt injection in return payload
                is_inj, _ = self.scanner.scan_tool_response(val)
                if is_inj:
                    was_injected = True
                    if "SUSPECTED_INJECTION" not in taints_to_add:
                        taints_to_add.append("SUSPECTED_INJECTION")

                # Mask DLP
                dlp_res = self.dlp.mask_text(val)
                return dlp_res.text
            elif isinstance(val, dict):
                return {k: _walk_and_sanitize(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [_walk_and_sanitize(item) for item in val]
            return val

        sanitized = _walk_and_sanitize(tool_response)

        if taints is not None:
            for label in taints_to_add:
                taints.add_taint(label)

        return sanitized, was_injected, taints_to_add
