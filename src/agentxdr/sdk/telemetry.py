"""OpenTelemetry gen_ai.* compliant instrumentation for AgentXDR."""

from __future__ import annotations

from typing import Any, Optional

from opentelemetry import trace
from opentelemetry.trace import Tracer

from agentxdr.sdk.context import AgentXDRContext


class SdkTelemetry:
    """Emits OpenTelemetry spans aligned with the OpenTelemetry Semantic Conventions for GenAI."""

    def __init__(self, service_name: str = "agentxdr-sdk") -> None:
        self._tracer: Tracer = trace.get_tracer(service_name)

    def start_request_span(self, ctx: AgentXDRContext, model: str) -> Any:
        """Create and return a ``gen_ai.request`` context-manager span."""
        return self._tracer.start_as_current_span(
            "gen_ai.request",
            attributes={
                "gen_ai.system": "openai",
                "gen_ai.request.model": model,
                "gen_ai.agent.id": ctx.agent_id,
                "gen_ai.trace.id": ctx.trace_id,
                "gen_ai.user.id": ctx.user_id,
            },
        )

    def record_tool_call(
        self,
        ctx: AgentXDRContext,
        tool_name: str,
        verdict: str,
        latency_ms: Optional[float] = None,
    ) -> None:
        """Emit a closed ``gen_ai.tool_call`` telemetry span."""
        attrs = {
            "gen_ai.tool.name": tool_name,
            "gen_ai.agent.id": ctx.agent_id,
            "gen_ai.trace.id": ctx.trace_id,
            "gen_ai.tool.verdict": verdict,
        }
        if latency_ms is not None:
            attrs["gen_ai.tool.latency_ms"] = latency_ms

        with self._tracer.start_as_current_span("gen_ai.tool_call", attributes=attrs):
            pass

    def record_response(
        self,
        ctx: AgentXDRContext,
        finish_reason: str,
        was_masked: bool = False,
    ) -> None:
        """Emit a closed ``gen_ai.response`` telemetry span."""
        with self._tracer.start_as_current_span(
            "gen_ai.response",
            attributes={
                "gen_ai.response.finish_reason": finish_reason,
                "gen_ai.agent.id": ctx.agent_id,
                "gen_ai.trace.id": ctx.trace_id,
                "gen_ai.response.was_masked": was_masked,
            },
        ):
            pass
