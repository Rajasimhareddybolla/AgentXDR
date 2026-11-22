"""MCP Injection Scanner — detects prompt-injection payloads in tool descriptors and responses."""

from __future__ import annotations

import re
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Compiled injection-pattern set (case-insensitive)
# ---------------------------------------------------------------------------
_RAW_PATTERNS: List[str] = [
    r"ignore (previous|prior|all) instructions",
    r"disregard your",
    r"you are now",
    r"act as",
    r"new role:",
    r"overrides? (your|all)",
    r"forget (everything|your instructions)",
    r"system prompt",
    r"<system>",
    r"</system>",
    r"<!-- ",
    r"\[SYSTEM\]",
]

_COMPILED_PATTERNS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in _RAW_PATTERNS
]


class McpInjectionScanner:
    """Scan MCP tool descriptions and responses for prompt-injection patterns.

    All patterns are matched case-insensitively via pre-compiled regexes.
    The scanner is stateless and thread-safe.
    """

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    @staticmethod
    def _scan(text: str) -> Tuple[bool, List[str]]:
        """Return *(is_malicious, matched_pattern_strings)* for *text*."""
        matched: List[str] = []
        for pattern in _COMPILED_PATTERNS:
            if pattern.search(text):
                matched.append(pattern.pattern)
        return bool(matched), matched

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_tool_description(self, description: str) -> Tuple[bool, List[str]]:
        """Scan a tool description string for prompt-injection patterns.

        Parameters
        ----------
        description:
            The ``description`` field from an MCP tool descriptor.

        Returns
        -------
        (is_malicious, matched_patterns)
            ``is_malicious`` is ``True`` if any pattern matched.
            ``matched_patterns`` lists the regex strings that fired.
        """
        return self._scan(description)

    def scan_tool_response(self, content: str) -> Tuple[bool, List[str]]:
        """Scan a tool response string for prompt-injection patterns.

        Parameters
        ----------
        content:
            String content returned by the MCP tool.

        Returns
        -------
        (is_malicious, matched_patterns)
        """
        return self._scan(content)
