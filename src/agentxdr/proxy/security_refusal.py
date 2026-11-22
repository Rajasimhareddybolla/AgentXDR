"""Security refusal builder for the AgentXDR LLM Gateway Proxy."""

from __future__ import annotations


def build_refusal(
    rule_id: str,
    owasp_id: str,
    trace_id: str,
    verdict: str,
    http_status: int = 403,
) -> dict:
    """Build a standardised security refusal response dict.

    Parameters
    ----------
    rule_id:
        Internal rule identifier that triggered the refusal.
    owasp_id:
        OWASP ASI category associated with the violation.
    trace_id:
        Session trace identifier.
    verdict:
        Human-readable verdict string (e.g. ``"BLOCKED"``).
    http_status:
        HTTP status code to associate with the refusal (default 403).

    Returns
    -------
    dict
        JSON-serialisable refusal payload.
    """
    return {
        "error": {
            "type": "security_refusal",
            "rule_id": rule_id,
            "owasp_id": owasp_id,
            "trace_id": trace_id,
            "verdict": verdict,
            "message": "Request blocked by AgentXDR inline security policy.",
        }
    }
