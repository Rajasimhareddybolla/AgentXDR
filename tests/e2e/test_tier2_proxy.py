"""Tier 2 boundary and performance tests for AgentXDR LLM Gateway Proxy (Milestone 4)."""

import asyncio
import time
import pytest
from unittest.mock import AsyncMock, patch
from httpx import ASGITransport, AsyncClient

from agentxdr.models.policy import BudgetsConfig, PolicySchema
from agentxdr.proxy.gateway import LlmGateway
from agentxdr.proxy.models import GatewayConfig


@pytest.fixture
def test_policy() -> PolicySchema:
    return PolicySchema(
        version="1.0.0",
        agent_id="tier2-agent",
        approved_by="secops@enterprise.com",
        budgets=BudgetsConfig(
            max_turns=20,
            max_tool_calls=50,
            max_identical_calls=5,
            max_session_duration_sec=300.0,
            max_session_cost_usd=5.0,
        ),
        tools=[],
    )


@pytest.fixture
def gateway_app(test_policy: PolicySchema):
    cfg = GatewayConfig(
        upstream_url="https://mock-upstream.internal",
        agent_id="tier2-agent",
        policy=test_policy,
    )
    gateway = LlmGateway(cfg)
    return gateway.create_fastapi_app(), gateway


@pytest.mark.asyncio
class TestTier2GatewayBoundaries:
    async def test_empty_messages_list(self, gateway_app):
        app, gateway = gateway_app
        mock_resp = {"choices": [{"message": {"role": "assistant", "content": "Hello"}}]}

        with patch.object(gateway, "forward_upstream", new=AsyncMock(return_value=mock_resp)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4o", "messages": []},
                    headers={"x-trace-id": "trace-empty-msg"},
                )
                assert resp.status_code == 200

    async def test_invalid_json_body_returns_400(self, gateway_app):
        app, _ = gateway_app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=b"not-a-json-string",
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 400
            assert resp.json()["error"]["type"] == "bad_request"

    async def test_missing_trace_id_generates_uuid(self, gateway_app):
        app, gateway = gateway_app
        mock_resp = {"choices": [{"message": {"role": "assistant", "content": "Done"}}]}

        with patch.object(gateway, "forward_upstream", new=AsyncMock(return_value=mock_resp)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Test"}]},
                )
                assert resp.status_code == 200
                assert gateway.session_manager.sessions_active >= 1

    async def test_large_payload_latency_sla(self, gateway_app):
        app, gateway = gateway_app
        # 60KB payload
        large_text = "This is a clean payload sentence without secrets. " * 1200
        mock_resp = {"choices": [{"message": {"role": "assistant", "content": "Processed successfully."}}]}

        with patch.object(gateway, "forward_upstream", new=AsyncMock(return_value=mock_resp)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                t0 = time.perf_counter()
                resp = await client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4o", "messages": [{"role": "user", "content": large_text}]},
                    headers={"x-trace-id": "trace-large"},
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000.0

                assert resp.status_code == 200
                # Inspection overhead must satisfy SLA (< 50ms)
                assert elapsed_ms < 50.0

    async def test_concurrent_sessions_independence(self, gateway_app):
        app, gateway = gateway_app
        mock_resp = {"choices": [{"message": {"role": "assistant", "content": "OK"}}]}

        with patch.object(gateway, "forward_upstream", new=AsyncMock(return_value=mock_resp)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                async def send_req(trace_id: str):
                    return await client.post(
                        "/v1/chat/completions",
                        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
                        headers={"x-trace-id": trace_id},
                    )

                traces = [f"trace-concurrent-{i}" for i in range(10)]
                responses = await asyncio.gather(*(send_req(t) for t in traces))

                for r in responses:
                    assert r.status_code == 200

                assert gateway.session_manager.sessions_active == 10

    async def test_sse_chunk_inspection_boundaries(self, gateway_app):
        _, gateway = gateway_app
        inspector = gateway.response_inspector

        # Clean chunk
        res1 = inspector.inspect_chunk("data: {'content': 'Hello world'}")
        assert res1.action == "allow"

        # Chunk with secret API key
        res2 = inspector.inspect_chunk("data: {'content': 'Key: sk-live1234567890abcdef1234567890'}")
        assert res2.action == "mask"
        assert "[REDACTED_API_KEY]" in (res2.masked_content or "")
