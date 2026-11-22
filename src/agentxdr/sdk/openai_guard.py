"""OpenAI client drop-in instrumentation hook."""

from __future__ import annotations

from typing import Any, Optional


class AgentXDRConfigError(Exception):
    """Raised when an agent client cannot be instrumented by AgentXDR."""
    pass


def guard_openai(
    client: Any,
    agent_id: str,
    policy_version: str = "1.0.0",
    gateway_base_url: Optional[str] = None,
) -> Any:
    """Instrument an OpenAI or compatible client to route via AgentXDR gateway.

    Parameters
    ----------
    client:
        Instance of ``openai.OpenAI``, ``openai.AsyncOpenAI``, or any compatible client.
    agent_id:
        Registered agent identifier in AgentXDR control plane.
    policy_version:
        Pinned policy contract version.
    gateway_base_url:
        Optional AgentXDR LLM Gateway proxy base URL. If provided, overrides client base URL.

    Returns
    -------
    The same client instance mutated in-place for drop-in zero-rewrite usage.
    """
    has_headers = hasattr(client, "default_headers") or hasattr(client, "_custom_headers")
    has_base_url = hasattr(client, "base_url") or hasattr(client, "_base_url")

    if not (has_headers or has_base_url):
        raise AgentXDRConfigError(
            f"Client {type(client).__name__} does not appear to be an OpenAI compatible client."
        )

    # 1. Update gateway base URL if specified
    if gateway_base_url is not None:
        if hasattr(client, "base_url"):
            client.base_url = gateway_base_url
        elif hasattr(client, "_base_url"):
            client._base_url = gateway_base_url

    # 2. Inject AgentXDR tracking headers
    headers_dict = getattr(client, "default_headers", None)
    if headers_dict is None:
        headers_dict = getattr(client, "_custom_headers", None)

    if headers_dict is not None and isinstance(headers_dict, dict):
        headers_dict["X-AgentXDR-Agent-ID"] = agent_id
        headers_dict["X-AgentXDR-Policy-Version"] = policy_version
    elif hasattr(client, "default_headers"):
        client.default_headers = {
            "X-AgentXDR-Agent-ID": agent_id,
            "X-AgentXDR-Policy-Version": policy_version,
        }

    return client
