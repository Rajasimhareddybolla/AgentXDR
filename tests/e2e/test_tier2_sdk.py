"""Tier 2 boundary and concurrency tests for AgentXDR In-Process Python SDK (Milestone 6)."""

import threading
import pytest

from agentxdr.sdk.agent_bus import AgentBus
from agentxdr.sdk.context import AgentXDRContext
from agentxdr.sdk.memory import MemoryGuard
from agentxdr.sdk.openai_guard import guard_openai


class SimpleStore:
    def __init__(self):
        self.d = {}

    def set(self, k, v):
        self.d[k] = v


class SimpleOpenAIClient:
    def __init__(self):
        self.base_url = "https://api.openai.com/v1"
        self.default_headers = {}


class TestTier2SdkBoundaries:
    def test_empty_roles_list_in_context(self):
        ctx = AgentXDRContext(user_id="anonymous", user_roles=[], agent_id="agent-zero", trace_id="trace-zero")
        headers = ctx.to_headers()
        assert headers["X-AgentXDR-Roles"] == ""
        assert headers["X-AgentXDR-User-ID"] == "anonymous"

    def test_very_large_payload_signing_and_verification(self):
        key = b"0123456789abcdef0123456789abcdef"
        ctx = AgentXDRContext("u-big", ["analyst"], "agent-big", "trace-big")
        bus = AgentBus(ctx, signing_key=key)

        large_payload = {
            "metrics": [{"id": i, "val": "data-" * 50} for i in range(500)]
        }
        envelope = bus.send(receiver_agent_id="agent-dest", payload=large_payload)
        assert bus.verify(envelope) is True

    def test_concurrent_context_taint_writes(self):
        ctx = AgentXDRContext("u-thread", ["worker"], "agent-thread", "trace-thread")
        labels = [f"TAINT_{i}" for i in range(100)]

        def worker(lbl):
            ctx.add_taint(lbl)

        threads = [threading.Thread(target=worker, args=(l,)) for l in labels]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snapshot = ctx.get_taint_snapshot()
        assert len(snapshot) == 100

    def test_guard_openai_idempotent(self):
        client = SimpleOpenAIClient()
        guard_openai(client, agent_id="my-agent", policy_version="1.0.0", gateway_base_url="http://gw:8000")
        # Call second time with updated version
        guard_openai(client, agent_id="my-agent", policy_version="1.1.0", gateway_base_url="http://gw:8000")

        assert client.base_url == "http://gw:8000"
        assert client.default_headers["X-AgentXDR-Policy-Version"] == "1.1.0"

    def test_memory_guard_wal_high_volume_writes(self):
        ctx = AgentXDRContext("u-scale", ["admin"], "agent-scale", "trace-scale")
        mem = MemoryGuard(ctx)
        store = SimpleStore()

        for i in range(100):
            res = mem.write(store, f"key_{i}", f"val_{i}")
            assert res.allowed is True

        snapshots = mem.get_snapshots()
        assert len(snapshots) == 100
        assert store.d["key_99"] == "val_99"
