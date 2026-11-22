"""High-performance inline Data Loss Prevention (DLP) masking engine for AgentXDR.

Synchronous hot-path component inspecting unstructured text and recursive JSON
dictionaries/lists for PII, secrets, credentials, API keys, and system prompt leakage.
SLA: <50ms P95 latency (sub-5ms typical).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple


@dataclass
class DlpResult:
    """Result of DLP masking operation."""

    text: str
    has_pii: bool
    has_secrets: bool
    has_prompt_leak: bool
    redaction_count: int
    latency_ms: float


class DlpMasker:
    """Deterministic inline Data Loss Prevention masking engine."""

    # PII Patterns
    RE_EMAIL: Pattern[str] = re.compile(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]{2,}",
    )
    RE_PHONE: Pattern[str] = re.compile(
        r"(?:\+\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s])\d{3,4}[-.\s]\d{3,4}\b",
    )
    RE_SSN: Pattern[str] = re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b",
    )
    RE_CREDIT_CARD: Pattern[str] = re.compile(
        r"\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b",
    )

    # Secrets & Credentials Patterns
    RE_PRIVATE_KEY: Pattern[str] = re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
    )
    RE_JWT: Pattern[str] = re.compile(
        r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    )
    RE_BEARER: Pattern[str] = re.compile(
        r"(?i)\bBearer\s+([A-Za-z0-9_\-\.+=/]{12,})",
    )
    RE_URL_CREDENTIAL: Pattern[str] = re.compile(
        r"""(?P<proto>[a-zA-Z][a-zA-Z0-9+.-]*://[^:\s/@]+:)(?P<pass>[^@\s/]+)(?P<rest>@[^\s]+)""",
    )
    RE_PASSWORD_KV: Pattern[str] = re.compile(
        r"""(?i)(?P<prefix>['"]?(?:password|passwd|pwd|db_pass|user_password|secret|admin_password|service_secret)['"]?\s*[:=]\s*['"])(?P<val>[^'"]+)(?P<suffix>['"])""",
    )
    RE_HASH: Pattern[str] = re.compile(
        r"\$(?:[1-6y]|2[abxy]|argon2(?:id?|d))\$(?:[a-zA-Z0-9./$,=-]+)",
    )

    # API Keys Patterns
    RE_OPENAI_KEY: Pattern[str] = re.compile(
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
    )
    RE_AWS_KEY: Pattern[str] = re.compile(
        r"\bAKIA[0-9A-Z]{16}\b",
    )
    RE_AWS_SECRET_KEY: Pattern[str] = re.compile(
        r"""(?i)(?P<prefix>(?:AWS_SECRET_ACCESS_KEY|SECRET_ACCESS_KEY)\s*=\s*)(?P<val>[A-Za-z0-9/+=]{35,45})\b""",
    )
    RE_GITHUB_TOKEN: Pattern[str] = re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}\b",
    )
    RE_SLACK_TOKEN: Pattern[str] = re.compile(
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    )
    RE_GENERIC_KEY: Pattern[str] = re.compile(
        r"""(?i)(?P<prefix>['"]?(?:api[_-]?key|access[_-]?token|auth[_-]?token|signing[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret)['"]?\s*[:=]\s*['"])(?P<val>[A-Za-z0-9_\-]{16,})(?P<suffix>['"])""",
    )

    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None) -> None:
        """Initialize the DLP Masker with standard and optional custom regex patterns."""
        self.custom_compiled: Dict[str, Pattern[str]] = {}
        if custom_patterns:
            for name, pat in custom_patterns.items():
                clean_name = re.sub(r"[^A-Z0-9_]", "_", name.upper())
                self.custom_compiled[clean_name] = re.compile(pat)

    def mask_text(self, text: str, system_prompt: Optional[str] = None) -> DlpResult:
        """Scan and redact sensitive tokens and prompt leakage in text."""
        start_time = time.perf_counter()

        if not text:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DlpResult(
                text="",
                has_pii=False,
                has_secrets=False,
                has_prompt_leak=False,
                redaction_count=0,
                latency_ms=elapsed_ms,
            )

        current_text = text
        has_pii = False
        has_secrets = False
        has_prompt_leak = False
        redaction_count = 0

        # 1. Custom Patterns
        for token_name, pat in self.custom_compiled.items():
            matches = list(pat.finditer(current_text))
            if matches:
                has_secrets = True
                redaction_count += len(matches)
                current_text = pat.sub(f"[REDACTED_{token_name}]", current_text)

        # 2. Private Keys (Secrets)
        matches = list(self.RE_PRIVATE_KEY.finditer(current_text))
        if matches:
            has_secrets = True
            redaction_count += len(matches)
            current_text = self.RE_PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", current_text)

        # 3. Password Hashes (Secrets)
        matches = list(self.RE_HASH.finditer(current_text))
        if matches:
            has_secrets = True
            redaction_count += len(matches)
            current_text = self.RE_HASH.sub("[REDACTED_PASSWORD_HASH]", current_text)

        # 4. Bearer Tokens (Secrets)
        def _sub_bearer(m: re.Match[str]) -> str:
            nonlocal has_secrets, redaction_count
            has_secrets = True
            redaction_count += 1
            return "Bearer [REDACTED_BEARER_TOKEN]"

        current_text = self.RE_BEARER.sub(_sub_bearer, current_text)

        # 5. URL Embedded Authority Credentials (Secrets)
        def _sub_url_cred(m: re.Match[str]) -> str:
            nonlocal has_secrets, redaction_count
            has_secrets = True
            redaction_count += 1
            proto = m.group("proto")
            rest = m.group("rest")
            return f"{proto}[REDACTED_PASSWORD]{rest}"

        current_text = self.RE_URL_CREDENTIAL.sub(_sub_url_cred, current_text)

        # 6. JWT Tokens (Secrets)
        matches = list(self.RE_JWT.finditer(current_text))
        if matches:
            has_secrets = True
            redaction_count += len(matches)
            current_text = self.RE_JWT.sub("[REDACTED_JWT]", current_text)

        # 7. Specific API Keys (Secrets)
        for pat in (self.RE_OPENAI_KEY, self.RE_AWS_KEY, self.RE_GITHUB_TOKEN, self.RE_SLACK_TOKEN):
            matches = list(pat.finditer(current_text))
            if matches:
                has_secrets = True
                redaction_count += len(matches)
                current_text = pat.sub("[REDACTED_API_KEY]", current_text)

        # 8. AWS Secret Access Key
        def _sub_aws_secret(m: re.Match[str]) -> str:
            nonlocal has_secrets, redaction_count
            has_secrets = True
            redaction_count += 1
            return f"{m.group('prefix')}[REDACTED_API_KEY]"

        current_text = self.RE_AWS_SECRET_KEY.sub(_sub_aws_secret, current_text)

        # 9. Key-Value Passwords & Generic API Keys (Secrets)
        def _sub_kv_secret(m: re.Match[str]) -> str:
            nonlocal has_secrets, redaction_count
            has_secrets = True
            redaction_count += 1
            prefix = m.group("prefix")
            suffix = m.group("suffix")
            token = "[REDACTED_PASSWORD]" if any(k in prefix.lower() for k in ("pass", "secret", "pwd")) else "[REDACTED_API_KEY]"
            return f"{prefix}{token}{suffix}"

        current_text = self.RE_PASSWORD_KV.sub(_sub_kv_secret, current_text)
        current_text = self.RE_GENERIC_KEY.sub(_sub_kv_secret, current_text)

        # 10. PII: Credit Cards (before phone numbers to avoid partial 12-digit prefix matches)
        matches = list(self.RE_CREDIT_CARD.finditer(current_text))
        if matches:
            has_pii = True
            redaction_count += len(matches)
            current_text = self.RE_CREDIT_CARD.sub("[REDACTED_CREDIT_CARD]", current_text)

        # 11. PII: SSNs
        matches = list(self.RE_SSN.finditer(current_text))
        if matches:
            has_pii = True
            redaction_count += len(matches)
            current_text = self.RE_SSN.sub("[REDACTED_SSN]", current_text)

        # 12. PII: Phone Numbers
        matches = list(self.RE_PHONE.finditer(current_text))
        if matches:
            has_pii = True
            redaction_count += len(matches)
            current_text = self.RE_PHONE.sub("[REDACTED_PHONE]", current_text)

        # 13. PII: Emails
        matches = list(self.RE_EMAIL.finditer(current_text))
        if matches:
            has_pii = True
            redaction_count += len(matches)
            current_text = self.RE_EMAIL.sub("[REDACTED_EMAIL]", current_text)

        # 14. Prompt Leakage Guardrail
        if system_prompt and system_prompt.strip():
            sys_clean = system_prompt.strip()

            # Check code blocks in system prompt
            code_blocks = re.findall(r"```[\s\S]*?```", sys_clean)
            for block in code_blocks:
                if block in current_text:
                    has_prompt_leak = True
                    redaction_count += 1
                    current_text = current_text.replace(block, "[REDACTED_SYSTEM_PROMPT]")

            # Exact match
            if sys_clean in current_text:
                has_prompt_leak = True
                redaction_count += 1
                current_text = current_text.replace(sys_clean, "[REDACTED_SYSTEM_PROMPT]")
            elif not has_prompt_leak:
                # N-gram containment / word similarity check
                sys_words = set(re.findall(r"\b[A-Za-z]{3,}\b", sys_clean.lower()))
                if len(sys_words) >= 6:
                    text_words = re.findall(r"\b[A-Za-z]{3,}\b", current_text.lower())
                    if text_words:
                        matching_words = sum(1 for w in text_words if w in sys_words)
                        containment = matching_words / len(sys_words)
                        overlap_ratio = matching_words / len(text_words)
                        if containment >= 0.65 or (overlap_ratio >= 0.70 and len(text_words) >= 10):
                            has_prompt_leak = True
                            redaction_count += 1
                            current_text = f"[REDACTED_SYSTEM_PROMPT] {current_text}"

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return DlpResult(
            text=current_text,
            has_pii=has_pii,
            has_secrets=has_secrets,
            has_prompt_leak=has_prompt_leak,
            redaction_count=redaction_count,
            latency_ms=elapsed_ms,
        )

    def mask_payload(
        self,
        payload: Dict[str, Any],
        system_prompt: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], DlpResult]:
        """Recursively scan and redact dictionary/list structures."""
        start_time = time.perf_counter()

        has_pii = False
        has_secrets = False
        has_prompt_leak = False
        total_redactions = 0

        def _traverse(node: Any) -> Any:
            nonlocal has_pii, has_secrets, has_prompt_leak, total_redactions
            if isinstance(node, str):
                res = self.mask_text(node, system_prompt=system_prompt)
                if res.has_pii:
                    has_pii = True
                if res.has_secrets:
                    has_secrets = True
                if res.has_prompt_leak:
                    has_prompt_leak = True
                total_redactions += res.redaction_count
                return res.text
            elif isinstance(node, dict):
                return {k: _traverse(v) for k, v in node.items()}
            elif isinstance(node, list):
                return [_traverse(item) for item in node]
            return node

        masked_payload = _traverse(payload)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        aggregate_result = DlpResult(
            text="",
            has_pii=has_pii,
            has_secrets=has_secrets,
            has_prompt_leak=has_prompt_leak,
            redaction_count=total_redactions,
            latency_ms=elapsed_ms,
        )

        return masked_payload, aggregate_result
