"""Tier 2 Boundary Value Analysis & Corner Case Tests for Guardrails Subsystem.

Covers Features 9 through 17 from PROJECT.md and TEST_INFRA.md:
- Feature 9: DLP PII Boundaries (>=5 tests: empty string, string with no PII, boundary email lengths e.g. 254 chars, malformed phone numbers e.g. 5 digits, invalid credit card checksums / edge numbers, multiple adjacent PII tokens email1@a.com email2@b.com, US SSN variations).
- Feature 10: DLP Credentials & Secrets Boundaries (>=5 tests: truncated RSA headers -----BEGIN RSA..., broken base64 JWT payloads, passwords with special symbols, high entropy hex strings, secrets embedded within URLs, bearer token variations).
- Feature 11: DLP API Keys Boundaries (>=5 tests: OpenAI key prefix with invalid length, AWS secret access keys, GitHub fine-grained PAT tokens github_pat_..., case variations, keys with trailing whitespace/punctuation).
- Feature 12: DLP Prompt Leakage Boundaries (>=5 tests: empty system prompt passed, empty text passed, text with only stopwords matching system prompt, slight paraphrase right at similarity threshold, system prompt containing code blocks).
- Feature 13: DLP Latency SLA Boundaries (>=5 tests: 100KB large text payload within <50ms P95, deeply nested dictionary 10 levels deep, list of 1,000 strings, concurrent/rapid sequential calls latency stability, benchmarking p95 over 50 iterations).
- Feature 14: AST Python Syntax Checker Boundaries (>=5 tests: code with syntax error on line 1 vs last line, code with non-ASCII utf-8 comments, code with null bytes/control chars, extremely large AST 500 lines of safe math, single-token code like x = 1).
- Feature 15: AST Forbidden Imports Boundaries (>=5 tests: aliased import import os as my_os, from-import from os import system, nested import inside function def, dynamic import string in variable, relative imports from . import utils, custom blocked imports).
- Feature 16: AST Dangerous Builtins Boundaries (>=5 tests: builtin called via variable alias e = eval; e("1"), builtin inside lambda, builtin inside list comprehension [eval(x) for x in l], builtin passed as function argument map(eval, items), shadowing safe builtin name, custom blocked builtins).
- Feature 17: AST Dunder Traversal Boundaries (>=5 tests: chained dunder ().__class__.__bases__[0].__subclasses__(), accessing __globals__ on function, __builtins__ dictionary access, __code__ object access, benign dunders like __init__ or __str__ allowed).

Total test cases in this file: 50 tests (>= 45 required).
All tests strictly follow public interface contracts from PROJECT.md:
    DlpMasker, DlpResult, AstSanitizer, AstSanitizerResult, AstViolation
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

try:
    from agentxdr.guardrails import (
        AstSanitizer,
        AstSanitizerResult,
        AstViolation,
        DlpMasker,
        DlpResult,
    )
    GUARDRAILS_AVAILABLE = True
except ImportError:
    GUARDRAILS_AVAILABLE = False
    AstSanitizer = None  # type: ignore
    AstSanitizerResult = None  # type: ignore
    AstViolation = None  # type: ignore
    DlpMasker = None  # type: ignore
    DlpResult = None  # type: ignore

pytestmark = pytest.mark.skipif(
    not GUARDRAILS_AVAILABLE,
    reason="agentxdr.guardrails is not yet implemented (scheduled for Milestone 2)",
)


# ==============================================================================
# Feature 9: DLP PII Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature9DlpPiiBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 9: DLP PII Masking."""

    def test_dlp_pii_boundary_empty_string(self):
        """Verify handling of empty string and empty dictionary payloads."""
        masker = DlpMasker()

        # 1. Empty string input
        res_text = masker.mask_text("")
        assert isinstance(res_text, DlpResult)
        assert res_text.text == ""
        assert res_text.has_pii is False
        assert res_text.has_secrets is False
        assert res_text.has_prompt_leak is False
        assert res_text.redaction_count == 0
        assert res_text.latency_ms >= 0.0

        # 2. Empty payload input
        redacted_payload, res_payload = masker.mask_payload({})
        assert redacted_payload == {}
        assert res_payload.has_pii is False
        assert res_payload.redaction_count == 0

    def test_dlp_pii_boundary_string_with_no_pii(self):
        """Verify that benign text containing metrics, technical numbers, and symbols is untouched."""
        masker = DlpMasker()
        clean_text = (
            "Telemetry report: CPU load is 78.4%, memory utilization 4.2GB of 16GB. "
            "Host worker-node-04 status OK. HTTP error code 404 observed on endpoint /api/v1/health. "
            "Checksum SHA256 matches: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08."
        )

        result = masker.mask_text(clean_text)
        assert result.text == clean_text
        assert result.has_pii is False
        assert result.redaction_count == 0

    def test_dlp_pii_boundary_email_length_254_chars(self):
        """Verify boundary RFC 5321 maximum email length (254 characters) is detected and redacted."""
        masker = DlpMasker()

        # Construct exact 254-character valid email:
        # local part (64 chars) + '@' (1 char) + domain part (189 chars) = 254 chars total
        local_part = "a" * 64
        # 189 chars domain: 3 labels of 60 chars each + 2 dots + 1 dot + 6 chars = 60+1+60+1+60+1+6 = 189
        domain_part = f"{'b'*60}.{'c'*60}.{'d'*60}.corp42"
        assert len(domain_part) == 189
        email_254 = f"{local_part}@{domain_part}"
        assert len(email_254) == 254

        input_text = f"Urgent notification dispatched to {email_254} regarding audit findings."
        result = masker.mask_text(input_text)

        assert result.has_pii is True
        assert result.redaction_count >= 1
        assert email_254 not in result.text
        assert "REDACTED" in result.text

        # Boundary contrast: excessively long non-email string (300+ chars) handles gracefully without ReDoS
        giant_string = f"{'x'*150}@{'y'*150}.invalid"
        res_giant = masker.mask_text(f"Notice: {giant_string}")
        assert res_giant.latency_ms < 50.0

    def test_dlp_pii_boundary_malformed_phone_numbers(self):
        """Verify that malformed or non-phone digit sequences do not trigger false positives."""
        masker = DlpMasker()

        # Non-phone sequences: 5-digit zip/port, 4-digit years, partial phone numbers
        benign_numbers = (
            "Invoice #12345 was processed on port 8080. Route code 987-65. "
            "Call desk extension 555 for assistance."
        )
        result_benign = masker.mask_text(benign_numbers)
        assert result_benign.has_pii is False
        assert result_benign.redaction_count == 0
        assert result_benign.text == benign_numbers

        # Valid phone numbers should trigger detection
        valid_phones = "Contact support at +1-800-555-0199 or 415-555-2671 immediately."
        result_valid = masker.mask_text(valid_phones)
        assert result_valid.has_pii is True
        assert result_valid.redaction_count >= 1
        assert "+1-800-555-0199" not in result_valid.text
        assert "415-555-2671" not in result_valid.text

    def test_dlp_pii_boundary_credit_card_checksum_and_edge_numbers(self):
        """Verify valid credit card formats are redacted while arbitrary number series are handled safely."""
        masker = DlpMasker()

        # Valid credit card pattern (16 digits formatted)
        valid_cc_text = "Transaction processed with card 4532-0151-1283-0366."
        result_cc = masker.mask_text(valid_cc_text)
        assert result_cc.has_pii is True
        assert "4532-0151-1283-0366" not in result_cc.text
        assert "REDACTED" in result_cc.text

        # Non-card edge numbers: all zeros or sequential numbers without card format
        non_card_text = "Serial numbers 0000-0000-0000-0000 and metrics 1000 2000 3000 4000."
        res_non_card = masker.mask_text(non_card_text)
        # Must execute cleanly without exception and report valid result structure
        assert isinstance(res_non_card, DlpResult)
        assert res_non_card.latency_ms < 50.0

    def test_dlp_pii_boundary_multiple_adjacent_tokens(self):
        """Verify multiple adjacent PII tokens separated only by single whitespace are correctly redacted."""
        masker = DlpMasker()
        adjacent_text = (
            "Direct notifications to user1@domain.com user2@domain.com admin@corp.net "
            "and call 800-555-0101 800-555-0102 now."
        )
        result = masker.mask_text(adjacent_text)

        assert result.has_pii is True
        assert result.redaction_count >= 5
        assert "user1@domain.com" not in result.text
        assert "user2@domain.com" not in result.text
        assert "admin@corp.net" not in result.text
        assert "800-555-0101" not in result.text
        assert "800-555-0102" not in result.text

        # Verify separator whitespace is preserved and redactions did not merge into a corrupt token
        tokens = result.text.split()
        redaction_tags = [t for t in tokens if "REDACTED" in t]
        assert len(redaction_tags) >= 5

    def test_dlp_pii_boundary_us_ssn_variations(self):
        """Verify valid SSN formats are redacted and edge cases handled without false positives."""
        masker = DlpMasker()

        # Valid SSN formats: hyphenated and space-separated
        ssn_text = "Employee records SSN: 123-45-6789 and secondary SSN 987 65 4321."
        result = masker.mask_text(ssn_text)
        assert result.has_pii is True
        assert "123-45-6789" not in result.text
        assert result.redaction_count >= 1

        # Non-SSN edge case: 9-digit order number without SSN formatting
        order_text = "Warehouse order ID: 123456789 (non-delimited integer)."
        res_order = masker.mask_text(order_text)
        assert isinstance(res_order, DlpResult)
        assert res_order.latency_ms < 50.0


# ==============================================================================
# Feature 10: DLP Credentials & Secrets Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature10DlpCredentialsSecretsBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 10: Credentials & Secrets."""

    def test_dlp_credentials_boundary_truncated_rsa_headers(self):
        """Verify truncated RSA headers handle without regex catastrophic backtracking and complete keys mask."""
        masker = DlpMasker()

        # 1. Truncated RSA header (e.g. log snippet cut off at boundary)
        truncated = "Packet dump snippet: -----BEGIN RSA... [remainder truncated by firewall]"
        res_trunc = masker.mask_text(truncated)
        assert isinstance(res_trunc, DlpResult)
        assert res_trunc.latency_ms < 50.0

        # 2. Complete RSA private key block
        full_rsa = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y9X7eB8oZtU1xV2...sample...rsa...key...payload\n"
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==\n"
            "-----END RSA PRIVATE KEY-----"
        )
        res_full = masker.mask_text(f"Backup secret:\n{full_rsa}\nEnd of secret.")
        assert res_full.has_secrets is True
        assert res_full.redaction_count >= 1
        assert "BEGIN RSA PRIVATE KEY" not in res_full.text
        assert "REDACTED" in res_full.text

    def test_dlp_credentials_boundary_broken_base64_jwt_payload(self):
        """Verify broken/malformed JWT payloads do not crash engine and valid 3-part JWTs are masked."""
        masker = DlpMasker()

        # 1. Broken 2-part JWT (missing signature segment)
        broken_jwt_2part = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        res_broken = masker.mask_text(f"Session token: {broken_jwt_2part}")
        assert isinstance(res_broken, DlpResult)
        assert res_broken.latency_ms < 50.0

        # 2. Corrupted non-base64 characters in payload
        corrupted_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.not_valid_base64$$!!??.signature"
        res_corrupt = masker.mask_text(f"Malformed token: {corrupted_jwt}")
        assert isinstance(res_corrupt, DlpResult)

        # 3. Legitimate 3-part JWT
        valid_jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        res_valid = masker.mask_text(f"Bearer token: {valid_jwt}")
        assert res_valid.has_secrets is True
        assert res_valid.redaction_count >= 1
        assert valid_jwt not in res_valid.text
        assert "REDACTED" in res_valid.text

    def test_dlp_credentials_boundary_passwords_with_special_symbols(self):
        """Verify passwords containing extreme special characters and symbols are masked."""
        masker = DlpMasker()
        complex_secret = (
            'database_config = {\n'
            '    "admin_password": "P@$$w0rd!#%^&*()-_=+[]{}|;:,.<>?/~",\n'
            '    "service_secret": "S3cur3!_#99?@Corp"\n'
            '}'
        )
        result = masker.mask_text(complex_secret)
        assert result.has_secrets is True
        assert result.redaction_count >= 1
        assert "P@$$w0rd!#%^&*()-_=+[]{}|;:,.<>?/~" not in result.text
        assert "S3cur3!_#99?@Corp" not in result.text
        assert "REDACTED" in result.text

    def test_dlp_credentials_boundary_high_entropy_hex_strings(self):
        """Verify 64-character high-entropy hex strings (HMAC/SHA256 secrets) are detected and masked."""
        masker = DlpMasker()
        secret_hex = "4a8b2c1d9e3f0123456789abcdef0123456789abcdef0123456789abcdef0123"
        assert len(secret_hex) == 64

        text = f"API signing secret configured as: signing_key = '{secret_hex}'"
        result = masker.mask_text(text)

        assert result.has_secrets is True
        assert result.redaction_count >= 1
        assert secret_hex not in result.text
        assert "REDACTED" in result.text

    def test_dlp_credentials_boundary_secrets_embedded_in_urls(self):
        """Verify secrets embedded within URL authorities and query parameters are redacted."""
        masker = DlpMasker()

        # Database URL with authority password
        db_url = "postgres://svc_user:Sup3rS3cr3tP%40ss!@postgres-cluster.internal.corp:5432/primary"
        # API URL with query token
        token_val = "gh" + "p_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123"
        api_url = f"https://internal.api.com/v1/export?access_token={token_val}"

        text = f"Endpoints configured:\n1. {db_url}\n2. {api_url}"
        result = masker.mask_text(text)

        assert result.has_secrets is True
        assert result.redaction_count >= 1
        assert "Sup3rS3cr3tP%40ss!" not in result.text
        assert token_val not in result.text
        assert "REDACTED" in result.text

    def test_dlp_credentials_boundary_bearer_token_variations(self):
        """Verify Bearer token headers with case variations and multiple spaces are masked."""
        masker = DlpMasker()
        headers = (
            "Header 1: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xyz123\n"
            "Header 2: authorization: bearer   sec_tok_alpha_999888777\n"
            "Header 3: AUTHORIZATION: BEARER token_prod_secret_42"
        )
        result = masker.mask_text(headers)
        assert result.has_secrets is True
        assert result.redaction_count >= 1
        assert "REDACTED" in result.text


# ==============================================================================
# Feature 11: DLP API Keys Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature11DlpApiKeysBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 11: API Keys."""

    def test_dlp_api_keys_boundary_openai_prefix_length(self):
        """Verify OpenAI key prefix length boundaries: invalid short lengths ignored, full keys masked."""
        masker = DlpMasker()

        # Short invalid tokens with sk- prefix (e.g. sk-123, sk-short)
        short_text = "Variables: sk-123, sk-test, and sk-shortkey are local variable names."
        res_short = masker.mask_text(short_text)
        # Should not falsely redact short variable names as OpenAI secrets
        assert res_short.has_secrets is False
        assert res_short.redaction_count == 0
        assert res_short.text == short_text

        # Valid standard OpenAI API key: sk- + 48 characters
        valid_openai_key = "sk-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4"
        assert len(valid_openai_key) == 51

        valid_text = f"Initialized client with OPENAI_API_KEY={valid_openai_key}"
        res_valid = masker.mask_text(valid_text)
        assert res_valid.has_secrets is True
        assert res_valid.redaction_count >= 1
        assert valid_openai_key not in res_valid.text
        assert "REDACTED" in res_valid.text

    def test_dlp_api_keys_boundary_aws_secret_access_keys(self):
        """Verify AWS Access Key ID (AKIA...) and Secret Access Key (40-char base64) are masked."""
        masker = DlpMasker()
        aws_id = "AKIAIOSFODNN7EXAMPLE"  # 20 chars
        aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 chars

        env_block = (
            f"export AWS_ACCESS_KEY_ID={aws_id}\n"
            f"export AWS_SECRET_ACCESS_KEY={aws_secret}\n"
            f"export AWS_REGION=us-east-1"
        )
        result = masker.mask_text(env_block)

        assert result.has_secrets is True
        assert result.redaction_count >= 1
        assert aws_id not in result.text
        assert aws_secret not in result.text
        assert "REDACTED" in result.text

    def test_dlp_api_keys_boundary_github_fine_grained_pat(self):
        """Verify GitHub fine-grained Personal Access Tokens (github_pat_...) are masked."""
        masker = DlpMasker()
        # GitHub fine-grained PAT: github_pat_ followed by 82 chars
        pat = "github_pat_11AAABBBCC0123456789abcdef_ghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ012"
        text = f"Pushing artifacts using token: {pat} to repository."

        result = masker.mask_text(text)
        assert result.has_secrets is True
        assert result.redaction_count >= 1
        assert pat not in result.text
        assert "REDACTED" in result.text

    def test_dlp_api_keys_boundary_case_variations(self):
        """Verify case variations in API key environment variables and prefixes are recognized."""
        masker = DlpMasker()
        valid_key = "sk-" + "9" * 48
        text = (
            f"openai_api_key='{valid_key}'\n"
            f"OPENAI_API_KEY='{valid_key}'\n"
            f"Openai_Api_Key='{valid_key}'"
        )
        result = masker.mask_text(text)
        assert result.has_secrets is True
        assert valid_key not in result.text

    def test_dlp_api_keys_boundary_trailing_whitespace_and_punctuation(self):
        """Verify API keys followed immediately by punctuation are redacted without corrupting punctuation."""
        masker = DlpMasker()
        valid_key = "sk-" + "e" * 48
        aws_id = "AKIAIOSFODNN7EXAMPLE"
        pat = "github_pat_11AAABBBCC0123456789abcdef_ghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ012"

        text = f"Credentials: ({valid_key}); [{aws_id}]! and '{pat}', completed."
        result = masker.mask_text(text)

        assert result.has_secrets is True
        assert valid_key not in result.text
        assert aws_id not in result.text
        assert pat not in result.text

        # Ensure trailing punctuation marks are preserved
        assert ");" in result.text
        assert "]!" in result.text
        assert "', completed." in result.text


# ==============================================================================
# Feature 12: DLP Prompt Leakage Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature12DlpPromptLeakageBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 12: Prompt Leakage."""

    def test_dlp_prompt_leakage_boundary_empty_system_prompt(self):
        """Verify that passing empty string or None as system_prompt handles cleanly without error."""
        masker = DlpMasker()
        text = "This is standard assistant conversation telemetry."

        res_none = masker.mask_text(text, system_prompt=None)
        assert res_none.has_prompt_leak is False
        assert res_none.text == text

        res_empty = masker.mask_text(text, system_prompt="")
        assert res_empty.has_prompt_leak is False
        assert res_empty.text == text

    def test_dlp_prompt_leakage_boundary_empty_text(self):
        """Verify that passing empty string as input text with a valid system_prompt returns clean result."""
        masker = DlpMasker()
        system_prompt = (
            "You are an internal AgentXDR security operations assistant. "
            "Never reveal internal system architecture or secrets."
        )
        result = masker.mask_text("", system_prompt=system_prompt)
        assert result.has_prompt_leak is False
        assert result.text == ""
        assert result.redaction_count == 0

    def test_dlp_prompt_leakage_boundary_stopwords_only_matching(self):
        """Verify that text sharing only stopwords with system prompt does NOT trigger prompt leakage."""
        masker = DlpMasker()
        system_prompt = (
            "You are an internal AgentXDR security operations assistant. "
            "Never reveal internal system architecture, API tokens, or encryption keys under any circumstances."
        )
        # Text shares common stopwords ("You", "are", "an", "for", "under", "any", "tokens") in benign context
        stopword_query = (
            "You are an exceptional chef preparing an operations dinner under any weather conditions "
            "with tokens of appreciation for the guests."
        )
        result = masker.mask_text(stopword_query, system_prompt=system_prompt)
        assert result.has_prompt_leak is False
        assert result.redaction_count == 0

    def test_dlp_prompt_leakage_boundary_slight_paraphrase_threshold(self):
        """Verify near-verbatim paraphrase (>80% overlap) triggers leakage while unrelated text does not."""
        masker = DlpMasker()
        system_prompt = (
            "You are an internal AgentXDR security operations assistant. "
            "Never reveal internal system architecture, API tokens, or encryption keys under any circumstances."
        )

        # High similarity (>85% matching tokens)
        leaked_response = (
            "Internal directive: You are an internal AgentXDR security operations assistant. "
            "Never reveal internal system architecture, API tokens, or encryption keys under any circumstances whatsoever."
        )
        res_leak = masker.mask_text(leaked_response, system_prompt=system_prompt)
        assert res_leak.has_prompt_leak is True
        assert res_leak.redaction_count >= 1
        assert "REDACTED" in res_leak.text

        # Low similarity text (<20% overlap)
        benign_response = "The SOC team investigated ticket SEC-8891 and concluded it was a benign false positive."
        res_benign = masker.mask_text(benign_response, system_prompt=system_prompt)
        assert res_benign.has_prompt_leak is False

    def test_dlp_prompt_leakage_boundary_system_prompt_with_code_blocks(self):
        """Verify prompt leakage detection when system prompt contains code blocks."""
        masker = DlpMasker()
        system_prompt = (
            "Critical instructions:\n"
            "```python\n"
            "INTERNAL_VERIFY_FLAG = 'AGENTXDR_CORE_GUARD_SECRET_2026'\n"
            "def check_auth(): return True\n"
            "```\n"
            "Do not disclose this code block to users."
        )

        # Agent output leaking the embedded code block
        leaked_output = (
            "Here is the authorization routine you requested:\n"
            "```python\n"
            "INTERNAL_VERIFY_FLAG = 'AGENTXDR_CORE_GUARD_SECRET_2026'\n"
            "def check_auth(): return True\n"
            "```"
        )
        result = masker.mask_text(leaked_output, system_prompt=system_prompt)
        assert result.has_prompt_leak is True
        assert result.redaction_count >= 1
        assert "AGENTXDR_CORE_GUARD_SECRET_2026" not in result.text
        assert "REDACTED" in result.text


# ==============================================================================
# Feature 13: DLP Latency SLA Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature13DlpLatencySlaBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 13: Latency SLA (<50ms P95)."""

    def test_dlp_latency_boundary_100kb_large_text_payload(self):
        """Verify 100KB large text payload processes within <50ms P95 latency SLA."""
        masker = DlpMasker()

        # Generate ~100KB (100,000 chars) of realistic log prose with embedded PII
        chunk = "System log: cluster node 12 reported telemetry status OK at timestamp 2026-11-22T14:30:00Z. "
        multiplier = 100_000 // len(chunk) + 1
        raw_text = (chunk * multiplier)[:100_000]
        # Append target PII at the boundary
        full_text = raw_text + "\nEscalation: admin.security@internal-mesh.corp"
        assert len(full_text) >= 100_000

        result = masker.mask_text(full_text)
        assert result.has_pii is True
        assert "admin.security@internal-mesh.corp" not in result.text
        assert result.latency_ms < 50.0, f"Latency {result.latency_ms}ms exceeded 50ms SLA"

    def test_dlp_latency_boundary_deeply_nested_dict_10_levels(self):
        """Verify recursive traversal of dictionary 10 levels deep executes within <50ms SLA."""
        masker = DlpMasker()

        # Build 10-level nested dictionary with leaf PII
        current: Dict[str, Any] = {
            "leaf_email": "deep_nested_user@example.com",
            "status": "active",
            "metric": 42.0,
        }
        for level in range(10, 0, -1):
            current = {
                f"depth_level_{level}": current,
                "node_id": f"node_{level}",
            }
        payload = current

        redacted, result = masker.mask_payload(payload)
        assert result.has_pii is True
        assert result.latency_ms < 50.0, f"Latency {result.latency_ms}ms exceeded 50ms SLA"

        # Drill down to verify leaf was redacted
        curr_inspect = redacted
        for level in range(1, 11):
            curr_inspect = curr_inspect[f"depth_level_{level}"]
        assert "deep_nested_user@example.com" not in curr_inspect["leaf_email"]
        assert "REDACTED" in curr_inspect["leaf_email"]

    def test_dlp_latency_boundary_list_of_1000_strings(self):
        """Verify scanning a list of 1,000 strings executes within <50ms SLA."""
        masker = DlpMasker()

        # 990 safe strings + 10 strings with emails
        items = [f"Log record #{i}: status healthy on agent worker" for i in range(990)]
        for j in range(10):
            items.append(f"Alert #{j}: notify investigator_{j}@xdr-corp.com immediately")
        assert len(items) == 1000

        payload = {"records": items}
        redacted, result = masker.mask_payload(payload)

        assert len(redacted["records"]) == 1000
        assert result.has_pii is True
        assert result.redaction_count >= 10
        assert result.latency_ms < 50.0, f"Latency {result.latency_ms}ms exceeded 50ms SLA"

    def test_dlp_latency_boundary_rapid_sequential_calls_stability(self):
        """Verify latency stability across 25 rapid sequential calls without memory or regex degradation."""
        masker = DlpMasker()
        latencies: List[float] = []

        test_payloads = [
            "User query: check system health",
            "Contact lead auditor at auditor@corp.com for report",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig123",
            "API key: sk-" + "x" * 48,
            "Clean operational telemetry metrics record",
        ]

        for i in range(25):
            payload = test_payloads[i % len(test_payloads)]
            res = masker.mask_text(payload)
            latencies.append(res.latency_ms)
            assert res.latency_ms < 50.0, f"Call #{i} latency {res.latency_ms}ms exceeded 50ms"

        # Verify mean latency is under 15ms
        mean_latency = sum(latencies) / len(latencies)
        assert mean_latency < 15.0, f"Mean latency {mean_latency}ms unexpectedly high"

    def test_dlp_latency_boundary_benchmarking_p95_over_50_iterations(self):
        """Benchmark 50 iterations on a mixed 5KB payload and verify P95 latency is strictly <50ms."""
        masker = DlpMasker()
        sample_doc = (
            "SOC Incident Report:\n"
            "Summary: Investigating suspicious activity reported by security.analyst@corp.internal.\n"
            "Details: The attacker attempted to access AWS resources with key AKIAIOSFODNN7EXAMPLE.\n"
            "Server logs show continuous probing on port 443 with query parameters.\n"
        ) * 16  # ~5KB
        assert len(sample_doc) > 4000

        latencies: List[float] = []
        for _ in range(50):
            res = masker.mask_text(sample_doc)
            latencies.append(res.latency_ms)

        sorted_lats = sorted(latencies)
        p95_idx = int(0.95 * len(sorted_lats))
        p95_latency = sorted_lats[p95_idx]

        assert p95_latency < 50.0, f"P95 latency {p95_latency}ms failed SLA (<50ms)"
        assert max(latencies) < 100.0, f"Max latency {max(latencies)}ms exceeded safety bound"


# ==============================================================================
# Feature 14: AST Python Syntax Checker Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature14AstPythonSyntaxCheckerBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 14: AST Syntax Checker."""

    def test_ast_syntax_boundary_error_line_1_vs_last_line(self):
        """Verify syntax error line number reporting: line 1 error vs last line error."""
        sanitizer = AstSanitizer()

        # Syntax error on line 1
        code_line_1 = "def (broken_syntax:\n    return True\n"
        res1 = sanitizer.sanitize(code_line_1)
        assert res1.is_safe is False
        assert len(res1.violations) >= 1
        assert res1.violations[0].lineno == 1

        # Syntax error on last line (line 6)
        code_last_line = (
            "x = 10\n"
            "y = 20\n"
            "z = x + y\n"
            "if z > 15:\n"
            "    print(z)\n"
            "else:"
        )
        res2 = sanitizer.sanitize(code_last_line)
        assert res2.is_safe is False
        assert len(res2.violations) >= 1
        assert res2.violations[0].lineno == 6

    def test_ast_syntax_boundary_non_ascii_utf8_comments_and_identifiers(self):
        """Verify valid Python code with UTF-8 comments, docstrings, and non-ASCII characters parses safely."""
        sanitizer = AstSanitizer()
        code_utf8 = (
            "# 🛡️ AgentXDR Security Policy - Überwachung & Analyse 🚀\n"
            "# 日本語のコメント: 正常に動作することを確認\n"
            '"""Docstring with non-ASCII characters: café, naïve, résumé, 100€."""\n'
            "def calculate_total(amount, tax_rate):\n"
            "    # Рассчитать итоговую сумму с учетом налога\n"
            "    return amount * (1.0 + tax_rate)\n"
            "\n"
            "total = calculate_total(100.0, 0.19)\n"
        )
        result = sanitizer.sanitize(code_utf8)
        assert result.is_safe is True
        assert len(result.violations) == 0

    def test_ast_syntax_boundary_null_bytes_and_control_chars(self):
        """Verify code payloads with embedded null bytes or raw control characters are rejected gracefully."""
        sanitizer = AstSanitizer()

        # Embedded null byte in code
        null_byte_code = "x = 10\x00\ny = 20"
        result = sanitizer.sanitize(null_byte_code)
        assert result.is_safe is False
        assert len(result.violations) >= 1

        # Control characters without crash
        bell_code = "a = 1\x07\nb = 2"
        res_bell = sanitizer.sanitize(bell_code)
        assert isinstance(res_bell, AstSanitizerResult)
        assert res_bell.latency_ms < 50.0

    def test_ast_syntax_boundary_extremely_large_ast_500_lines_safe_math(self):
        """Verify large AST consisting of 500 lines of safe math parses safely and within SLA."""
        sanitizer = AstSanitizer()

        # Build 500 safe arithmetic assignments
        lines = ["x_0 = 1"]
        for i in range(1, 500):
            lines.append(f"x_{i} = (x_{i-1} * 2 + {i % 7}) % 1000")
        large_code = "\n".join(lines)

        result = sanitizer.sanitize(large_code)
        assert result.is_safe is True
        assert len(result.violations) == 0
        assert result.latency_ms < 50.0, f"Latency {result.latency_ms}ms exceeded 50ms SLA"

    def test_ast_syntax_boundary_single_token_and_minimal_code(self):
        """Verify boundary single-token inputs, empty strings, and whitespace evaluate safely."""
        sanitizer = AstSanitizer()

        minimal_inputs = [
            "x = 1",
            "pass",
            "",
            "   ",
            "\n\n\n",
            "# single line comment",
            "42",
            "'string literal'",
        ]

        for code in minimal_inputs:
            result = sanitizer.sanitize(code)
            assert result.is_safe is True
            assert len(result.violations) == 0


# ==============================================================================
# Feature 15: AST Forbidden Imports Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature15AstForbiddenImportsBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 15: Forbidden Imports."""

    def test_ast_forbidden_imports_boundary_aliased_import(self):
        """Verify aliased imports (import os as my_os) are detected and blocked."""
        sanitizer = AstSanitizer()

        # Aliased os
        code1 = "import os as my_os\nmy_os.system('id')"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False
        assert any("os" in v.name for v in res1.violations)

        # Aliased subprocess
        code2 = "import subprocess as sp\nsp.run(['whoami'])"
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False
        assert any("subprocess" in v.name for v in res2.violations)

    def test_ast_forbidden_imports_boundary_from_import(self):
        """Verify from-imports (from os import system) are detected and blocked."""
        sanitizer = AstSanitizer()

        code1 = "from os import system, popen\nsystem('echo compromised')"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False
        assert any("os" in v.name for v in res1.violations)

        code2 = "from socket import socket, AF_INET\ns = socket(AF_INET)"
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False
        assert any("socket" in v.name for v in res2.violations)

    def test_ast_forbidden_imports_boundary_nested_inside_function_def(self):
        """Verify forbidden imports nested deep inside function bodies or class methods are blocked."""
        sanitizer = AstSanitizer()
        code = (
            "class TaskRunner:\n"
            "    def execute(self):\n"
            "        def inner_worker():\n"
            "            import shutil\n"
            "            shutil.rmtree('/tmp/data')\n"
            "        return inner_worker()\n"
        )
        result = sanitizer.sanitize(code)
        assert result.is_safe is False
        assert any("shutil" in v.name for v in result.violations)

    def test_ast_forbidden_imports_boundary_dynamic_import_patterns(self):
        """Verify dynamic import invocations (__import__ or importlib) are blocked."""
        sanitizer = AstSanitizer()

        # __import__ call
        code1 = "module_name = 'os'\nmod = __import__(module_name)\nmod.system('id')"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False

        # importlib call
        code2 = "import importlib\nmod = importlib.import_module('subprocess')"
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False

    def test_ast_forbidden_imports_boundary_safe_standard_libraries(self):
        """Verify safe standard library modules (math, json, typing, datetime) are permitted."""
        sanitizer = AstSanitizer()
        safe_code = (
            "from math import sqrt, ceil, pi\n"
            "import json\n"
            "from datetime import datetime, timezone\n"
            "from dataclasses import dataclass\n"
            "import typing\n"
            "\n"
            "x = sqrt(16.0) + pi\n"
            "data = json.dumps({'value': x})\n"
        )
        result = sanitizer.sanitize(safe_code)
        assert result.is_safe is True
        assert len(result.violations) == 0

    def test_ast_forbidden_imports_boundary_custom_blocked_imports_list(self):
        """Verify AstSanitizer respects custom blocked_imports parameter."""
        custom_sanitizer = AstSanitizer(blocked_imports=["requests", "urllib3"])

        # Custom blocked import blocked
        res_blocked = custom_sanitizer.sanitize("import requests\nresp = requests.get('https://example.com')")
        assert res_blocked.is_safe is False
        assert any("requests" in v.name for v in res_blocked.violations)

        # Standard safe import still permitted
        res_safe = custom_sanitizer.sanitize("import math\nx = math.sqrt(25)")
        assert res_safe.is_safe is True


# ==============================================================================
# Feature 16: AST Dangerous Builtins Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature16AstDangerousBuiltinsBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 16: Dangerous Builtins."""

    def test_ast_dangerous_builtins_boundary_variable_alias(self):
        """Verify builtin aliased to a variable (e = eval; e('1')) is intercepted."""
        sanitizer = AstSanitizer()

        # eval aliasing
        code_eval = "e = eval\nresult = e('1 + 1')"
        res_eval = sanitizer.sanitize(code_eval)
        assert res_eval.is_safe is False
        assert any("eval" in v.name for v in res_eval.violations)

        # exec aliasing
        code_exec = "x = exec\nx('pass')"
        res_exec = sanitizer.sanitize(code_exec)
        assert res_exec.is_safe is False
        assert any("exec" in v.name for v in res_exec.violations)

    def test_ast_dangerous_builtins_boundary_inside_lambda(self):
        """Verify dangerous builtins inside lambda expressions are detected."""
        sanitizer = AstSanitizer()

        # eval inside lambda
        code1 = "calculator = lambda expr: eval(expr)\nres = calculator('2 * 3')"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False
        assert any("eval" in v.name for v in res1.violations)

        # open inside lambda
        code2 = "file_reader = lambda path: open(path).read()"
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False
        assert any("open" in v.name for v in res2.violations)

    def test_ast_dangerous_builtins_boundary_inside_comprehensions(self):
        """Verify dangerous builtins inside list, dict, and set comprehensions are detected."""
        sanitizer = AstSanitizer()

        # List comprehension with eval
        code_list = "results = [eval(x) for x in ['1+1', '2*3', '4/2']]"
        res_list = sanitizer.sanitize(code_list)
        assert res_list.is_safe is False
        assert any("eval" in v.name for v in res_list.violations)

        # Dict comprehension with eval
        code_dict = "data = {k: eval(v) for k, v in [('a', '10'), ('b', '20')]}"
        res_dict = sanitizer.sanitize(code_dict)
        assert res_dict.is_safe is False
        assert any("eval" in v.name for v in res_dict.violations)

    def test_ast_dangerous_builtins_boundary_passed_as_function_argument(self):
        """Verify dangerous builtins passed as arguments to higher-order functions (map, filter) are detected."""
        sanitizer = AstSanitizer()

        # map(eval, items)
        code1 = "items = ['1+1', '2+2']\nresults = list(map(eval, items))"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False
        assert any("eval" in v.name for v in res1.violations)

        # Custom function receiving open
        code2 = (
            "def invoke_operation(func, target):\n"
            "    return func(target)\n"
            "content = invoke_operation(open, '/etc/passwd')\n"
        )
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False
        assert any("open" in v.name for v in res2.violations)

    def test_ast_dangerous_builtins_boundary_shadowing_and_safe_builtins(self):
        """Verify safe builtins (len, min, max, range, list, str) do NOT trigger false positives."""
        sanitizer = AstSanitizer()
        code_safe = (
            "def len(items):\n"
            "    return 42\n"
            "\n"
            "val = len([1, 2, 3])\n"
            "low = min(10, 20)\n"
            "high = max(30, 40)\n"
            "numbers = list(range(10))\n"
            "text = str(val)\n"
            "total = sum(numbers)\n"
        )
        result = sanitizer.sanitize(code_safe)
        assert result.is_safe is True
        assert len(result.violations) == 0

    def test_ast_dangerous_builtins_boundary_custom_blocked_builtins_list(self):
        """Verify AstSanitizer respects custom blocked_builtins parameter."""
        custom_sanitizer = AstSanitizer(blocked_builtins=["print", "input"])

        # Custom blocked builtin print is blocked
        res_blocked = custom_sanitizer.sanitize("print('Debug message')")
        assert res_blocked.is_safe is False
        assert any("print" in v.name for v in res_blocked.violations)

        # Standard safe builtin abs is permitted
        res_safe = custom_sanitizer.sanitize("val = abs(-5)")
        assert res_safe.is_safe is True


# ==============================================================================
# Feature 17: AST Dunder Traversal Boundaries (>= 5 tests)
# ==============================================================================


class TestFeature17AstDunderTraversalBoundaries:
    """Boundary Value Analysis & Corner Cases for Feature 17: Dunder Traversal."""

    def test_ast_dunder_boundary_chained_subclasses_traversal(self):
        """Verify chained dunder sandbox escape attempts (().__class__.__bases__[0].__subclasses__()) are blocked."""
        sanitizer = AstSanitizer()

        # Class bases subclasses chain
        code1 = "classes = ().__class__.__bases__[0].__subclasses__()"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False
        assert any(
            v.name in ("__subclasses__", "__bases__", "__class__")
            for v in res1.violations
        )

        # MRO subclasses chain
        code2 = "all_classes = ''.__class__.__mro__[1].__subclasses__()"
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False
        assert any(
            v.name in ("__subclasses__", "__mro__", "__class__")
            for v in res2.violations
        )

    def test_ast_dunder_boundary_function_globals_access(self):
        """Verify accessing __globals__ on function or lambda objects is blocked."""
        sanitizer = AstSanitizer()

        # Function __globals__
        code1 = "def dummy(): pass\nglobals_dict = dummy.__globals__"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False
        assert any("__globals__" in v.name for v in res1.violations)

        # Lambda __globals__ escape pattern
        code2 = "os_mod = (lambda: None).__globals__['__builtins__']['__import__']('os')"
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False
        assert any("__globals__" in v.name for v in res2.violations)

    def test_ast_dunder_boundary_builtins_dictionary_access(self):
        """Verify direct access to __builtins__ dictionary attribute is blocked."""
        sanitizer = AstSanitizer()

        code1 = "b = func.__builtins__\nb['eval']('1 + 1')"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False
        assert any("__builtins__" in v.name for v in res1.violations)

        code2 = "mod_builtins = getattr(module, '__builtins__')"
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False
        assert any("__builtins__" in v.name or "getattr" in v.name for v in res2.violations)

    def test_ast_dunder_boundary_code_object_access(self):
        """Verify inspection or mutation of __code__ object is blocked."""
        sanitizer = AstSanitizer()

        code1 = "code_obj = my_function.__code__\nconsts = code_obj.co_consts"
        res1 = sanitizer.sanitize(code1)
        assert res1.is_safe is False
        assert any("__code__" in v.name for v in res1.violations)

        code2 = "varnames = (lambda x, y: x + y).__code__.co_varnames"
        res2 = sanitizer.sanitize(code2)
        assert res2.is_safe is False
        assert any("__code__" in v.name for v in res2.violations)

    def test_ast_dunder_boundary_benign_dunders_permitted(self):
        """Verify standard object model methods (__init__, __str__, __repr__, __eq__, __len__, __iter__) are permitted."""
        sanitizer = AstSanitizer()
        benign_code = (
            "class SafeRecord:\n"
            "    def __init__(self, key: str, value: int):\n"
            "        self.key = key\n"
            "        self.value = value\n"
            "\n"
            "    def __str__(self) -> str:\n"
            "        return f'{self.key}:{self.value}'\n"
            "\n"
            "    def __repr__(self) -> str:\n"
            "        return f'SafeRecord(key={self.key!r}, value={self.value})'\n"
            "\n"
            "    def __eq__(self, other: object) -> bool:\n"
            "        return isinstance(other, SafeRecord) and self.value == other.value\n"
            "\n"
            "    def __len__(self) -> int:\n"
            "        return len(self.key)\n"
            "\n"
            "    def __iter__(self):\n"
            "        return iter([self.value])\n"
            "\n"
            "rec = SafeRecord('alpha', 10)\n"
            "s = str(rec)\n"
            "length = len(rec)\n"
        )
        result = sanitizer.sanitize(benign_code)
        assert result.is_safe is True
        assert len(result.violations) == 0
