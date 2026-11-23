"""LLM Gateway — programmatic proxy core and optional FastAPI application.

This module is the central orchestration layer of the AgentXDR LLM Gateway
Proxy (Milestone 4).  ``LlmGateway`` is a plain Python class that is fully
testable without starting a real HTTP server.  ``create_fastapi_app()`` wraps
it in a lightweight FastAPI application.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from agentxdr.breakers.circuit_breaker import CircuitBreaker
from agentxdr.guardrails.dlp import DlpMasker
from agentxdr.policy.evaluator import PolicyEvaluator
from agentxdr.proxy.models import GatewayConfig, InspectionResult
from agentxdr.proxy.request_inspector import RequestInspector
from agentxdr.proxy.response_inspector import ResponseInspector
from agentxdr.proxy.security_refusal import build_refusal
from agentxdr.proxy.session_manager import SessionManager


class LlmGateway:
    """Programmatic LLM gateway with inline security inspection.

    Parameters
    ----------
    config:
        ``GatewayConfig`` instance describing the upstream URL, agent ID,
        active policy, optional kill-switch, and token budget.
    """

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config

        # Shared DLP engine
        self._dlp = DlpMasker()

        # Policy evaluator (kill-switch aware)
        self._policy_evaluator = PolicyEvaluator(kill_switch=config.kill_switch)

        # Circuit breaker driven by the policy budgets
        self._circuit_breaker = CircuitBreaker(budgets=config.policy.budgets)

        # Session tracking
        self.session_manager = SessionManager()

        # Request / response inspectors
        self.request_inspector = RequestInspector(
            dlp=self._dlp,
            policy_evaluator=self._policy_evaluator,
        )
        self.response_inspector = ResponseInspector(dlp=self._dlp)

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    async def process_request(
        self,
        messages: List[dict],
        trace_id: str,
        model: str = "gpt-4o",
        extra_headers: Dict[str, str] | None = None,
    ) -> Tuple[InspectionResult, Optional[dict]]:
        """Inspect an inbound chat request.

        Returns a 2-tuple of ``(InspectionResult, refusal_dict | None)``.
        When *refusal_dict* is not ``None`` the caller MUST NOT forward the
        request to the upstream LLM.

        Steps
        -----
        1. Increment session turn counter.
        2. Check circuit-breaker budget.
        3. Run request inspector (injection + DLP).
        4. Apply masked content if any.
        5. Taint session with ``AUTHENTICATED_USER``.
        6. Return ``(result, None)`` — caller forwards to upstream.
        """
        if extra_headers is None:
            extra_headers = {}

        # 0. Kill switch check
        if self.config.kill_switch is not None:
            if self.config.kill_switch.is_killed(
                agent_id=self.config.agent_id,
                trace_id=trace_id,
            ):
                block_result = InspectionResult(
                    action="block",
                    rule_ids=["KILL_SWITCH_ACTIVE"],
                    owasp_ids=["ASI01"],
                )
                refusal = build_refusal(
                    rule_id="KILL_SWITCH_ACTIVE",
                    owasp_id="ASI01",
                    trace_id=trace_id,
                    verdict="KILL",
                )
                return block_result, refusal

        # 1. Increment turn
        self.session_manager.increment_turn(trace_id)

        # 2. Circuit-breaker check
        cb_verdict = self._circuit_breaker.record_turn(trace_id)
        if cb_verdict.is_tripped:
            block_result = InspectionResult(
                action="block",
                rule_ids=["CIRCUIT_BREAKER_TRIPPED"],
                owasp_ids=["ASI01"],
            )
            refusal = build_refusal(
                rule_id="CIRCUIT_BREAKER_TRIPPED",
                owasp_id="ASI01",
                trace_id=trace_id,
                verdict="BLOCKED",
            )
            return block_result, refusal

        # 3. Request inspection
        result = self.request_inspector.inspect(messages, trace_id)

        # 4. Blocked by injection or policy
        if result.action == "block":
            rule_id = result.rule_ids[0] if result.rule_ids else "BLOCKED"
            owasp_id = result.owasp_ids[0] if result.owasp_ids else "ASI01"
            refusal = build_refusal(
                rule_id=rule_id,
                owasp_id=owasp_id,
                trace_id=trace_id,
                verdict="BLOCKED",
            )
            return result, refusal

        # 5. Apply masked content (mutate messages in-place conceptually; the
        #    caller receives the result object which carries masked_content).
        # (Nothing extra needed here — the caller reads result.masked_content.)

        # 6. Taint session
        self.session_manager.add_taint(trace_id, "AUTHENTICATED_USER")

        return result, None

    async def process_response(
        self,
        content: str,
        trace_id: str,
    ) -> Tuple[InspectionResult, str]:
        """Inspect an upstream LLM response.

        Returns a 2-tuple of ``(InspectionResult, final_content)``.
        ``final_content`` is either the original text, the DLP-masked text,
        or a JSON-serialised security refusal string.
        """
        result = self.response_inspector.inspect(content, trace_id)

        if result.action == "block":
            rule_id = result.rule_ids[0] if result.rule_ids else "BLOCKED"
            owasp_id = result.owasp_ids[0] if result.owasp_ids else "ASI06"
            refusal = build_refusal(
                rule_id=rule_id,
                owasp_id=owasp_id,
                trace_id=trace_id,
                verdict="BLOCKED",
            )
            return result, json.dumps(refusal)

        if result.action == "mask" and result.masked_content is not None:
            return result, result.masked_content

        return result, content

    async def forward_upstream(
        self, body: Dict[str, Any], headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """Forward request payload to upstream LLM API and return parsed response JSON."""
        base = self.config.upstream_url.rstrip("/")
        if base.endswith("/chat/completions"):
            endpoint_url = base
        elif base.endswith("/v1"):
            endpoint_url = base + "/chat/completions"
        else:
            endpoint_url = base + "/v1/chat/completions"

        req_headers = dict(headers or {})
        if self.config.api_key and "Authorization" not in req_headers:
            req_headers["Authorization"] = f"Bearer {self.config.api_key}"

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                endpoint_url,
                json=body,
                headers=req_headers,
                timeout=60.0,
            )
            resp.raise_for_status()
            return resp.json()

    # ------------------------------------------------------------------
    # FastAPI application factory
    # ------------------------------------------------------------------

    def create_fastapi_app(self) -> FastAPI:
        """Return a FastAPI application wrapping this gateway instance."""
        app = FastAPI(title="AgentXDR LLM Gateway", version="1.0.0")
        gateway = self  # capture for closures

        @app.get("/health")
        async def health() -> dict:
            return {"status": "ok", "component": "agentxdr-gateway"}

        @app.get("/metrics")
        async def metrics() -> dict:
            return {
                "sessions_active": gateway.session_manager.sessions_active,
                "requests_total": gateway.session_manager.requests_total,
            }

        @app.post("/v1/chat/completions")
        async def chat_completions(request: Request) -> Response:
            # --- Parse incoming body ---
            try:
                body: Dict[str, Any] = await request.json()
            except Exception:
                return JSONResponse(
                    status_code=400,
                    content={"error": {"type": "bad_request", "message": "Invalid JSON body."}},
                )

            messages: List[dict] = body.get("messages", [])
            model: str = body.get("model", "gpt-4o")

            # --- Resolve trace ID ---
            trace_id: str = (
                request.headers.get("x-trace-id")
                or request.headers.get("x-request-id")
                or str(uuid.uuid4())
            )

            # --- Extra headers to forward ---
            extra_headers: Dict[str, str] = {
                k: v
                for k, v in request.headers.items()
                if k.lower().startswith("x-")
            }

            # --- Request inspection ---
            insp_result, refusal = await gateway.process_request(
                messages=messages,
                trace_id=trace_id,
                model=model,
                extra_headers=extra_headers,
            )

            if refusal is not None:
                return JSONResponse(status_code=403, content=refusal)

            # --- Determine effective messages ---
            if insp_result.action == "mask" and insp_result.masked_content:
                try:
                    effective_messages: List[dict] = json.loads(insp_result.masked_content)
                except (json.JSONDecodeError, ValueError):
                    effective_messages = messages
            else:
                effective_messages = messages

            upstream_body = dict(body)
            upstream_body["messages"] = effective_messages

            # --- Forward to upstream LLM ---
            try:
                upstream_json: Dict[str, Any] = await gateway.forward_upstream(
                    upstream_body, extra_headers
                )
            except httpx.HTTPStatusError as exc:
                return JSONResponse(
                    status_code=exc.response.status_code,
                    content={"error": {"type": "upstream_error", "message": str(exc)}},
                )
            except Exception as exc:
                return JSONResponse(
                    status_code=502,
                    content={"error": {"type": "upstream_error", "message": str(exc)}},
                )

            # --- Response inspection ---
            raw_content: str = ""
            choices = upstream_json.get("choices", [])
            if choices:
                raw_content = (choices[0].get("message") or {}).get("content") or ""

            resp_result, final_content = await gateway.process_response(raw_content, trace_id)

            # Reconstruct the upstream JSON with inspected content
            if choices:
                upstream_json["choices"][0]["message"]["content"] = final_content

            if resp_result.action == "block":
                # final_content is a JSON refusal string
                try:
                    refusal_body: Dict[str, Any] = json.loads(final_content)
                except (json.JSONDecodeError, ValueError):
                    refusal_body = {"error": {"type": "security_refusal", "message": final_content}}
                return JSONResponse(status_code=403, content=refusal_body)

            return JSONResponse(status_code=200, content=upstream_json)

        return app
