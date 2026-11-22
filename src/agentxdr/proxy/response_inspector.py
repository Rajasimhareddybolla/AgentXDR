"""Response inspector for the AgentXDR LLM Gateway Proxy.

Performs DLP masking and system-prompt-leakage detection on content
returned by the upstream LLM before it is relayed to the caller.
Supports both full-response and SSE-chunk inspection modes.
"""

from __future__ import annotations

from typing import Optional

from agentxdr.guardrails.dlp import DlpMasker
from agentxdr.proxy.models import InspectionResult


class ResponseInspector:
    """Inspect outbound LLM response content for PII and prompt leakage."""

    def __init__(
        self,
        dlp: DlpMasker,
        system_prompt_hash: Optional[str] = None,
    ) -> None:
        self.dlp = dlp
        # Store the actual system prompt text so DlpMasker can compare it.
        # The parameter is named *hash* per spec, but we treat it as the
        # pinned system prompt string to pass into mask_text's system_prompt
        # parameter (the DlpMasker performs similarity matching internally).
        self._system_prompt: Optional[str] = system_prompt_hash

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, content: str, trace_id: str) -> InspectionResult:
        """Inspect a full response string.

        Order of evaluation
        -------------------
        1. DLP masking (PII / secrets).
        2. System-prompt leakage scan (if ``system_prompt_hash`` was set).
        3. Clean pass-through.

        Parameters
        ----------
        content:
            Raw LLM response text.
        trace_id:
            Session trace identifier (used for audit / logging).

        Returns
        -------
        InspectionResult
        """
        return self._run(content)

    def inspect_chunk(self, chunk: str) -> InspectionResult:
        """Inspect a single SSE streaming chunk.

        Applies identical logic to :meth:`inspect` but does not require a
        trace_id — suitable for tight streaming hot-paths.
        """
        return self._run(chunk)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, content: str) -> InspectionResult:
        """Core inspection logic shared by both public methods."""
        # 1. DLP masking (runs system-prompt leakage check simultaneously)
        dlp_result = self.dlp.mask_text(content, system_prompt=self._system_prompt)

        # 2. System-prompt leakage → block
        if dlp_result.has_prompt_leak:
            return InspectionResult(
                action="block",
                rule_ids=["SYSTEM_PROMPT_LEAK"],
                owasp_ids=["ASI06"],
            )

        # 3. PII / secrets masked
        if dlp_result.has_pii or dlp_result.has_secrets:
            return InspectionResult(
                action="mask",
                rule_ids=["DLP_MASKED"],
                owasp_ids=["ASI02"],
                masked_content=dlp_result.text,
            )

        return InspectionResult(action="allow", rule_ids=[], owasp_ids=[])
