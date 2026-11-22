"""Request inspector for the AgentXDR LLM Gateway Proxy.

Performs inline prompt-injection detection and DLP masking on inbound
chat message lists before they are forwarded to the upstream LLM.
"""

from __future__ import annotations

import json
import re
from typing import List

from agentxdr.guardrails.dlp import DlpMasker
from agentxdr.policy.evaluator import PolicyEvaluator
from agentxdr.proxy.models import InspectionResult

# Prompt-injection keyword patterns (OWASP ASI01)
_INJECTION_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"ignore previous instructions", re.IGNORECASE),
    re.compile(r"disregard your", re.IGNORECASE),
    re.compile(r"new instructions:", re.IGNORECASE),
    re.compile(r"you are now", re.IGNORECASE),
    re.compile(r"act as if", re.IGNORECASE),
    re.compile(r"forget everything", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
]


class RequestInspector:
    """Inspect inbound LLM chat messages for injection attacks and PII."""

    def __init__(self, dlp: DlpMasker, policy_evaluator: PolicyEvaluator) -> None:
        self.dlp = dlp
        self.policy_evaluator = policy_evaluator

    def inspect(self, messages: List[dict], trace_id: str) -> InspectionResult:
        """Inspect a list of chat messages.

        Order of evaluation
        -------------------
        1. Prompt-injection keyword scan (block).
        2. DLP masking on content fields (mask).
        3. Clean pass-through (allow).

        Parameters
        ----------
        messages:
            OpenAI-style ``[{"role": ..., "content": ...}]`` message list.
        trace_id:
            Session trace identifier (used for audit / logging).

        Returns
        -------
        InspectionResult
        """
        # 1. Prompt-injection detection
        for msg in messages:
            content = msg.get("content") or ""
            if isinstance(content, str):
                for pattern in _INJECTION_PATTERNS:
                    if pattern.search(content):
                        return InspectionResult(
                            action="block",
                            rule_ids=["PROMPT_INJECTION_DETECTED"],
                            owasp_ids=["ASI01"],
                        )

        # 2. DLP masking pass
        masked_messages: List[dict] = []
        any_masked = False

        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                result = self.dlp.mask_text(content)
                new_msg = dict(msg)
                new_msg["content"] = result.text
                masked_messages.append(new_msg)
                if result.has_pii or result.has_secrets:
                    any_masked = True
            else:
                masked_messages.append(dict(msg))

        if any_masked:
            return InspectionResult(
                action="mask",
                rule_ids=["DLP_MASKED"],
                owasp_ids=["ASI02"],
                masked_content=json.dumps(masked_messages),
            )

        return InspectionResult(action="allow", rule_ids=[], owasp_ids=[])
