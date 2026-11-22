"""Tier 1 Feature Coverage Tests: Guardrails Subsystem (Features 9-17).

Comprehensive opaque-box Tier 1 Feature Coverage tests verifying the deterministic
inline guardrails layer external to the LLM reasoning loop:
- Feature 9:  DLP PII Masking Engine (emails, phone numbers US/intl, SSN redaction,
              credit card numbers, redaction token replacement [REDACTED_...], clean text untouched)
- Feature 10: DLP Credentials & Secrets Masking (private keys RSA/PEM, passwords in strings/JSON,
              JWT tokens, Bearer tokens, hash strings)
- Feature 11: DLP API Keys Masking (OpenAI sk-..., AWS access keys AKIA..., GitHub tokens ghp_...,
              Slack tokens xoxb-..., generic API keys)
- Feature 12: DLP Prompt Leakage Guardrail (verbatim system prompt match, n-gram high-similarity paraphrase,
              non-leaking query passing, jaccard/similarity scoring, prompt leakage flag has_prompt_leak set)
- Feature 13: DLP Latency SLA (<50ms P95) (small string latency <5ms, medium payload latency <20ms,
              payload dictionary masking, redaction count accuracy, latency_ms reporting)
- Feature 14: AST Python Syntax Checker (valid python code passing is_safe=True, invalid syntax gracefully
              caught with is_safe=False and violation description, empty code string, comments only,
              multi-line functions)
- Feature 15: AST Forbidden Imports Blocker (import os, import subprocess, import socket,
              import ctypes, import shutil, import pickle, from os import system)
- Feature 16: AST Dangerous Builtins Blocker (eval("1+1"), exec("pass"), __import__("os"),
              open("file.txt"), compile("code", "", "exec"))
- Feature 17: AST Dunder Traversal Blocker (__subclasses__(), __bases__, __mro__, __globals__,
              chained dunders ().__class__.__base__)

Total test cases: 50 tests (>= 45 tests required).
Interfaces tested strictly from PROJECT.md:
    DlpMasker, DlpResult, AstSanitizer, AstSanitizerResult, AstViolation
"""

import re
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
# Feature 9: DLP PII Masking Engine (>= 5 tests)
# ==============================================================================


class TestFeature09DlpPiiMaskingEngine:
    """Opaque-box tests for Feature 9: DLP PII Masking Engine."""

    def test_dlp_pii_masks_email_addresses(self):
        """Verifies that multiple standard email address formats are redacted with [REDACTED_...]."""
        masker = DlpMasker()
        text = (
            "Contact primary engineer alice.smith@enterprise.com or "
            "escalate to soc-lead@corp.internal for incident triage."
        )
        result: DlpResult = masker.mask_text(text)

        assert isinstance(result, DlpResult)
        assert result.has_pii is True
        assert "alice.smith@enterprise.com" not in result.text
        assert "soc-lead@corp.internal" not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 2

    def test_dlp_pii_masks_us_and_intl_phone_numbers(self):
        """Verifies that both US and international phone numbers are redacted."""
        masker = DlpMasker()
        text = (
            "Reach US dispatch at +1-555-234-5678 or London operations at "
            "+44-20-7946-0958 regarding ticket #9021."
        )
        result: DlpResult = masker.mask_text(text)

        assert result.has_pii is True
        assert "+1-555-234-5678" not in result.text
        assert "+44-20-7946-0958" not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 2

    def test_dlp_pii_masks_social_security_numbers(self):
        """Verifies that standard US Social Security Numbers (SSNs) are identified and redacted."""
        masker = DlpMasker()
        text = "Employee record contains SSN 123-45-6789 and secondary identifier 987-65-4321."
        result: DlpResult = masker.mask_text(text)

        assert result.has_pii is True
        assert "123-45-6789" not in result.text
        assert "987-65-4321" not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 2

    def test_dlp_pii_masks_credit_card_numbers(self):
        """Verifies that major credit card numbers (Visa, Mastercard, Amex) are redacted."""
        masker = DlpMasker()
        text = (
            "Billing transactions: Visa 4532-1234-5678-9010, "
            "Mastercard 5424 0000 0000 0001, and Amex 3782 822463 10005."
        )
        result: DlpResult = masker.mask_text(text)

        assert result.has_pii is True
        assert "4532-1234-5678-9010" not in result.text
        assert "5424 0000 0000 0001" not in result.text
        assert "3782 822463 10005" not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 3

    def test_dlp_pii_redaction_token_replacement_pattern(self):
        """Verifies that redaction replacement tokens strictly follow the [REDACTED_...] pattern."""
        masker = DlpMasker()
        text = "Send confirmation to user@example.org and verify card 4111 2222 3333 4444."
        result: DlpResult = masker.mask_text(text)

        token_pattern = re.compile(r"\[REDACTED_[A-Z0-9_]+\]")
        matches = token_pattern.findall(result.text)
        assert len(matches) >= 2, f"Expected [REDACTED_...] tokens, got: {result.text}"
        assert result.has_pii is True

    def test_dlp_pii_clean_text_untouched(self):
        """Verifies that clean text containing no sensitive data passes through completely untouched."""
        masker = DlpMasker()
        text = "Cluster telemetry: 42 worker nodes active in region eu-west-1. No latency spikes detected."
        result: DlpResult = masker.mask_text(text)

        assert result.text == text
        assert result.has_pii is False
        assert result.has_secrets is False
        assert result.has_prompt_leak is False
        assert result.redaction_count == 0


# ==============================================================================
# Feature 10: DLP Credentials & Secrets Masking (>= 5 tests)
# ==============================================================================


class TestFeature10DlpCredentialsSecretsMasking:
    """Opaque-box tests for Feature 10: DLP Credentials & Secrets Masking."""

    def test_dlp_secrets_masks_rsa_pem_private_keys(self):
        """Verifies that RSA / PEM private key blocks are identified and redacted."""
        masker = DlpMasker()
        fake_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1+r6PqZ0J9xZ8mYV5cQ1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8\n"
            "R9S0T1U2V3W4X5Y6Z7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0x1y2z3==\n"
            "-----END RSA PRIVATE KEY-----"
        )
        text = f"Deployment configuration:\n{fake_key}\nHost: api.internal"
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert "-----BEGIN RSA PRIVATE KEY-----" not in result.text
        assert "-----END RSA PRIVATE KEY-----" not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1

    def test_dlp_secrets_masks_passwords_in_strings_and_json(self):
        """Verifies that password assignments in configuration strings and JSON are redacted."""
        masker = DlpMasker()
        text = (
            "Configuration string: password='SuperSecretPass!99' and "
            "JSON payload: {\"password\": \"ProdAdminPass#2026\", \"user\": \"root\"}"
        )
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert "SuperSecretPass!99" not in result.text
        assert "ProdAdminPass#2026" not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 2

    def test_dlp_secrets_masks_jwt_tokens(self):
        """Verifies that JSON Web Tokens (JWT) are identified and redacted."""
        masker = DlpMasker()
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        text = f"Authenticated session token: {jwt} for user 12345."
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert jwt not in result.text
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1

    def test_dlp_secrets_masks_bearer_tokens(self):
        """Verifies that HTTP Bearer authorization headers/tokens are redacted."""
        masker = DlpMasker()
        bearer_token = "sec_bearer_token_9876543210abcdeffedcba0987654321"
        text = f"Outgoing HTTP header: Authorization: Bearer {bearer_token}"
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert bearer_token not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1

    def test_dlp_secrets_masks_hash_strings(self):
        """Verifies that sensitive password hashes (e.g. SHA-512 crypt) are redacted."""
        masker = DlpMasker()
        pw_hash = "$6$rounds=5000$saltsalt$xyz123abc456def789ghi012jkl345mno678pqr"
        text = f"Stored user record: password_hash='{pw_hash}' for user admin."
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert pw_hash not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1


# ==============================================================================
# Feature 11: DLP API Keys Masking (>= 5 tests)
# ==============================================================================


class TestFeature11DlpApiKeysMasking:
    """Opaque-box tests for Feature 11: DLP API Keys Masking."""

    def test_dlp_api_keys_masks_openai_keys(self):
        """Verifies that OpenAI API keys starting with sk- are identified and redacted."""
        masker = DlpMasker()
        openai_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        text = f"Initialize OpenAI model client with api_key='{openai_key}'"
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert openai_key not in result.text
        assert "sk-proj-" not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1

    def test_dlp_api_keys_masks_aws_access_keys(self):
        """Verifies that AWS access key IDs starting with AKIA are redacted."""
        masker = DlpMasker()
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        text = f"Upload dump to S3 bucket using AWS_ACCESS_KEY_ID={aws_key}"
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert aws_key not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1

    def test_dlp_api_keys_masks_github_tokens(self):
        """Verifies that GitHub personal access tokens (ghp_...) are redacted."""
        masker = DlpMasker()
        github_token = "gh" + "p_16charactersOrMoreGitHubTokenHere123"
        text = f"Clone repository with git credential: {github_token}"
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert github_token not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1

    def test_dlp_api_keys_masks_slack_tokens(self):
        """Verifies that Slack bot/user tokens (xoxb-... / xoxp-...) are redacted."""
        masker = DlpMasker()
        slack_token = "xox" + "b-123456789012-1234567890123-4567890abcdef1234567890a"
        text = f"Post alert to Slack channel using token: {slack_token}"
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert slack_token not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1

    def test_dlp_api_keys_masks_generic_api_keys(self):
        """Verifies that labeled generic high-entropy API keys are redacted."""
        masker = DlpMasker()
        generic_key = "abcdef0123456789abcdef0123456789"
        text = f"Service client config: api_key = '{generic_key}'"
        result: DlpResult = masker.mask_text(text)

        assert result.has_secrets is True
        assert generic_key not in result.text
        assert "[REDACTED_" in result.text
        assert result.redaction_count >= 1


# ==============================================================================
# Feature 12: DLP Prompt Leakage Guardrail (>= 5 tests)
# ==============================================================================


class TestFeature12DlpPromptLeakageGuardrail:
    """Opaque-box tests for Feature 12: DLP Prompt Leakage Guardrail."""

    def test_dlp_prompt_leakage_verbatim_system_prompt_match(self, pinned_system_prompt):
        """Verifies that exact verbatim repetition of the system prompt trips has_prompt_leak."""
        masker = DlpMasker()
        text = pinned_system_prompt
        result: DlpResult = masker.mask_text(text, system_prompt=pinned_system_prompt)

        assert result.has_prompt_leak is True

    def test_dlp_prompt_leakage_high_ngram_similarity_paraphrase(self, pinned_system_prompt):
        """Verifies that high-similarity n-gram paraphrase of system prompt trips has_prompt_leak."""
        masker = DlpMasker()
        # High n-gram overlap paraphrase
        paraphrase = (
            "I am an internal AgentXDR security operations assistant. "
            "I must never reveal internal system architecture, API tokens, or encryption "
            "keys under any circumstances."
        )
        result: DlpResult = masker.mask_text(paraphrase, system_prompt=pinned_system_prompt)

        assert result.has_prompt_leak is True

    def test_dlp_prompt_leakage_non_leaking_query_passes(self, pinned_system_prompt):
        """Verifies that standard, benign agent responses do not trip has_prompt_leak."""
        masker = DlpMasker()
        safe_response = (
            "The database server CPU utilization is currently at 43% with "
            "normal query latency across all 8 read replicas."
        )
        result: DlpResult = masker.mask_text(safe_response, system_prompt=pinned_system_prompt)

        assert result.has_prompt_leak is False

    def test_dlp_prompt_leakage_low_similarity_passing(self, pinned_system_prompt):
        """Verifies that text sharing only common vocabulary does not falsely trip has_prompt_leak."""
        masker = DlpMasker()
        low_sim_text = "The security operations assistant performed an internal audit of file permissions."
        result: DlpResult = masker.mask_text(low_sim_text, system_prompt=pinned_system_prompt)

        assert result.has_prompt_leak is False

    def test_dlp_prompt_leakage_without_system_prompt(self):
        """Verifies that when no system_prompt is provided, has_prompt_leak is cleanly False."""
        masker = DlpMasker()
        text = "You are an internal AgentXDR security operations assistant."
        result: DlpResult = masker.mask_text(text, system_prompt=None)

        assert result.has_prompt_leak is False
        assert isinstance(result.has_prompt_leak, bool)


# ==============================================================================
# Feature 13: DLP Latency SLA (<50ms P95) (>= 5 tests)
# ==============================================================================


class TestFeature13DlpLatencySla:
    """Opaque-box tests for Feature 13: DLP Latency SLA (<50ms P95)."""

    def test_dlp_latency_small_string_under_sla(self):
        """Verifies that small text strings are masked well within the inline latency SLA (<50ms)."""
        masker = DlpMasker()
        text = "User john@example.com reported an issue with token AKIAIOSFODNN7EXAMPLE."
        result: DlpResult = masker.mask_text(text)

        assert result.latency_ms >= 0.0
        assert result.latency_ms < 50.0, f"Latency {result.latency_ms}ms exceeded 50ms SLA"

    def test_dlp_latency_medium_payload_under_sla(self):
        """Verifies that multi-field payload dictionary masking completes within <50ms."""
        masker = DlpMasker()
        payload = {
            "query": "Fetch records for customer",
            "metadata": {
                "user_email": "admin@target.org",
                "phone": "+1-800-555-0199",
                "auth_header": "Bearer tok_1234567890abcdef",
            },
            "environment": "production-us-east",
            "tags": ["critical", "p0", "audit"],
        }
        _, result = masker.mask_payload(payload)

        assert result.latency_ms >= 0.0
        assert result.latency_ms < 50.0, f"Latency {result.latency_ms}ms exceeded 50ms SLA"

    def test_dlp_payload_dictionary_masking(self):
        """Verifies that mask_payload recursively redacts sensitive fields in nested dictionaries."""
        masker = DlpMasker()
        payload = {
            "user": {
                "email": "customer@fintech.co",
                "card": "4111 2222 3333 4444",
                "name": "Jane Smith",
            },
            "status": "APPROVED",
            "attempt": 1,
        }
        masked_dict, result = masker.mask_payload(payload)

        assert isinstance(masked_dict, dict)
        assert isinstance(result, DlpResult)
        assert "customer@fintech.co" not in masked_dict["user"]["email"]
        assert "4111 2222 3333 4444" not in masked_dict["user"]["card"]
        assert "[REDACTED_" in masked_dict["user"]["email"]
        assert "[REDACTED_" in masked_dict["user"]["card"]
        assert masked_dict["user"]["name"] == "Jane Smith"
        assert masked_dict["status"] == "APPROVED"
        assert masked_dict["attempt"] == 1
        assert result.has_pii is True

    def test_dlp_redaction_count_accuracy(self):
        """Verifies that redaction_count accurately reports the total number of redacted tokens."""
        masker = DlpMasker()
        # Exactly 3 sensitive elements: 1 email, 1 SSN, 1 AWS key
        text = "Records: bob@corp.com, SSN 123-45-6789, AWS key AKIAIOSFODNN7EXAMPLE"
        result: DlpResult = masker.mask_text(text)

        assert result.redaction_count == 3
        assert result.has_pii is True
        assert result.has_secrets is True

    def test_dlp_latency_ms_reporting_and_type(self):
        """Verifies that DlpResult reports latency_ms as a non-negative finite float."""
        masker = DlpMasker()
        result: DlpResult = masker.mask_text("Short benign sentence.")

        assert isinstance(result.latency_ms, float)
        assert result.latency_ms >= 0.0


# ==============================================================================
# Feature 14: AST Python Syntax Checker (>= 5 tests)
# ==============================================================================


class TestFeature14AstPythonSyntaxChecker:
    """Opaque-box tests for Feature 14: AST Python Syntax Checker."""

    def test_ast_valid_python_code_passes(self):
        """Verifies that syntactically valid safe Python code passes with is_safe=True."""
        sanitizer = AstSanitizer()
        code = (
            "def calculate_tax(amount, rate=0.07):\n"
            "    tax = amount * rate\n"
            "    return round(tax, 2)\n"
            "result = calculate_tax(100.0)\n"
        )
        res: AstSanitizerResult = sanitizer.sanitize(code)

        assert isinstance(res, AstSanitizerResult)
        assert res.is_safe is True
        assert len(res.violations) == 0
        assert res.latency_ms >= 0.0

    def test_ast_syntax_error_handled_gracefully(self):
        """Verifies that malformed Python syntax returns is_safe=False without crashing."""
        sanitizer = AstSanitizer()
        broken_code = "def invalid_func(:\n    return 42"
        res: AstSanitizerResult = sanitizer.sanitize(broken_code)

        assert res.is_safe is False
        assert len(res.violations) >= 1
        violation = res.violations[0]
        assert isinstance(violation, AstViolation)
        assert any(
            token in violation.rule.lower() or token in violation.description.lower()
            for token in ("syntax", "syntaxerror", "parse")
        )

    def test_ast_empty_code_string(self):
        """Verifies that an empty code string or whitespace-only code returns is_safe=True."""
        sanitizer = AstSanitizer()

        res_empty = sanitizer.sanitize("")
        assert res_empty.is_safe is True
        assert len(res_empty.violations) == 0

        res_whitespace = sanitizer.sanitize("   \n\t  \n  ")
        assert res_whitespace.is_safe is True
        assert len(res_whitespace.violations) == 0

    def test_ast_comments_and_docstrings_only(self):
        """Verifies that code containing only comments and docstrings passes cleanly."""
        sanitizer = AstSanitizer()
        code = (
            "# Top level architectural comment\n"
            "\"\"\"Multi-line docstring explaining module behavior.\"\"\"\n"
            "# Trailing comment\n"
        )
        res = sanitizer.sanitize(code)

        assert res.is_safe is True
        assert len(res.violations) == 0

    def test_ast_multiline_safe_function(self):
        """Verifies that complex multiline algorithmic code with loops and branching passes."""
        sanitizer = AstSanitizer()
        code = (
            "def binary_search(arr, target):\n"
            "    left, right = 0, len(arr) - 1\n"
            "    while left <= right:\n"
            "        mid = (left + right) // 2\n"
            "        if arr[mid] == target:\n"
            "            return mid\n"
            "        elif arr[mid] < target:\n"
            "            left = mid + 1\n"
            "        else:\n"
            "            right = mid - 1\n"
            "    return -1\n"
            "nums = [1, 3, 5, 7, 9]\n"
            "idx = binary_search(nums, 7)\n"
        )
        res = sanitizer.sanitize(code)

        assert res.is_safe is True
        assert len(res.violations) == 0


# ==============================================================================
# Feature 15: AST Forbidden Imports Blocker (>= 5 tests)
# ==============================================================================


class TestFeature15AstForbiddenImportsBlocker:
    """Opaque-box tests for Feature 15: AST Forbidden Imports Blocker."""

    def test_ast_blocks_import_os(self):
        """Verifies that direct import of 'os' is blocked."""
        sanitizer = AstSanitizer()
        code = "import os\nos.system('echo pwned')"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "os" or "os" in v.description.lower() for v in res.violations
        )

    def test_ast_blocks_import_subprocess(self):
        """Verifies that import of 'subprocess' is blocked."""
        sanitizer = AstSanitizer()
        code = "import subprocess\nsubprocess.run(['cat', '/etc/passwd'])"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "subprocess" or "subprocess" in v.description.lower()
            for v in res.violations
        )

    def test_ast_blocks_import_socket(self):
        """Verifies that import of 'socket' (network egress/reverse shell) is blocked."""
        sanitizer = AstSanitizer()
        code = "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "socket" or "socket" in v.description.lower()
            for v in res.violations
        )

    def test_ast_blocks_import_ctypes(self):
        """Verifies that import of 'ctypes' (memory manipulation) is blocked."""
        sanitizer = AstSanitizer()
        code = "import ctypes\nlibc = ctypes.CDLL(None)"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "ctypes" or "ctypes" in v.description.lower()
            for v in res.violations
        )

    def test_ast_blocks_import_shutil_and_pickle(self):
        """Verifies that multiple forbidden imports ('shutil', 'pickle') are blocked and reported."""
        sanitizer = AstSanitizer()
        code = "import shutil\nimport pickle\ndata = pickle.loads(b'cos\\nsystem\\n...')"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert len(res.violations) >= 2
        names = {v.name for v in res.violations}
        assert "shutil" in names or any("shutil" in v.description.lower() for v in res.violations)
        assert "pickle" in names or any("pickle" in v.description.lower() for v in res.violations)

    def test_ast_blocks_from_import_forbidden(self):
        """Verifies that 'from os import system' syntax is blocked."""
        sanitizer = AstSanitizer()
        code = "from os import system\nsystem('whoami')"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name in ("os", "system") or "os" in v.description.lower()
            for v in res.violations
        )


# ==============================================================================
# Feature 16: AST Dangerous Builtins Blocker (>= 5 tests)
# ==============================================================================


class TestFeature16AstDangerousBuiltinsBlocker:
    """Opaque-box tests for Feature 16: AST Dangerous Builtins Blocker."""

    def test_ast_blocks_eval_call(self):
        """Verifies that calling builtin 'eval' is blocked."""
        sanitizer = AstSanitizer()
        code = "output = eval('1 + 1')"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "eval" or "eval" in v.description.lower() for v in res.violations
        )

    def test_ast_blocks_exec_call(self):
        """Verifies that calling builtin 'exec' is blocked."""
        sanitizer = AstSanitizer()
        code = "exec('secret_state = 100')"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "exec" or "exec" in v.description.lower() for v in res.violations
        )

    def test_ast_blocks_dunder_import_call(self):
        """Verifies that calling builtin '__import__' is blocked."""
        sanitizer = AstSanitizer()
        code = "mod = __import__('os')\nmod.system('id')"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "__import__" or "__import__" in v.description.lower()
            for v in res.violations
        )

    def test_ast_blocks_open_call(self):
        """Verifies that calling builtin 'open' is blocked."""
        sanitizer = AstSanitizer()
        code = "with open('/etc/shadow', 'r') as fd:\n    content = fd.read()"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "open" or "open" in v.description.lower() for v in res.violations
        )

    def test_ast_blocks_compile_call(self):
        """Verifies that calling builtin 'compile' is blocked."""
        sanitizer = AstSanitizer()
        code = "compiled_bytecode = compile('x = 1', '<string>', 'exec')"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "compile" or "compile" in v.description.lower()
            for v in res.violations
        )


# ==============================================================================
# Feature 17: AST Dunder Traversal Blocker (>= 5 tests)
# ==============================================================================


class TestFeature17AstDunderTraversalBlocker:
    """Opaque-box tests for Feature 17: AST Dunder Traversal Blocker."""

    def test_ast_blocks_dunder_subclasses(self):
        """Verifies that accessing '__subclasses__' attribute/call is blocked."""
        sanitizer = AstSanitizer()
        code = "classes = ().__class__.__bases__[0].__subclasses__()"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "__subclasses__" or "__subclasses__" in v.description.lower()
            for v in res.violations
        )

    def test_ast_blocks_dunder_bases(self):
        """Verifies that accessing '__bases__' attribute is blocked."""
        sanitizer = AstSanitizer()
        code = "base_classes = object.__bases__"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "__bases__" or "__bases__" in v.description.lower()
            for v in res.violations
        )

    def test_ast_blocks_dunder_mro(self):
        """Verifies that accessing '__mro__' attribute is blocked."""
        sanitizer = AstSanitizer()
        code = "resolution_order = str.__mro__"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "__mro__" or "__mro__" in v.description.lower()
            for v in res.violations
        )

    def test_ast_blocks_dunder_globals(self):
        """Verifies that accessing '__globals__' attribute on functions is blocked."""
        sanitizer = AstSanitizer()
        code = "global_namespace = (lambda: None).__globals__"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert any(
            v.name == "__globals__" or "__globals__" in v.description.lower()
            for v in res.violations
        )

    def test_ast_blocks_chained_dunder_traversal(self):
        """Verifies that chained sandbox-escape dunders (().__class__.__base__) are blocked."""
        sanitizer = AstSanitizer()
        code = "parent_class = ().__class__.__base__"
        res = sanitizer.sanitize(code)

        assert res.is_safe is False
        assert len(res.violations) >= 1
        assert any(
            "__" in v.name or "dunder" in v.rule.lower() or "dunder" in v.description.lower()
            for v in res.violations
        )


# ==============================================================================
# Interface Contracts & Configuration Extensibility Tests
# ==============================================================================


class TestGuardrailsInterfaceContracts:
    """Opaque-box tests verifying interface contracts, dataclass attributes, and custom configuration."""

    def test_ast_sanitizer_custom_blocklists(self):
        """Verifies that AstSanitizer respects custom blocked_imports and blocked_builtins."""
        custom_sanitizer = AstSanitizer(
            blocked_imports=["math", "json"],
            blocked_builtins=["abs", "len"],
        )

        res_import = custom_sanitizer.sanitize("import math\nx = math.sqrt(4)")
        assert res_import.is_safe is False
        assert any(v.name == "math" for v in res_import.violations)

        res_builtin = custom_sanitizer.sanitize("val = abs(-5)")
        assert res_builtin.is_safe is False
        assert any(v.name == "abs" for v in res_builtin.violations)

    def test_ast_violation_metadata_fields(self):
        """Verifies that AstViolation instances contain typed rule, name, lineno, col_offset, description."""
        sanitizer = AstSanitizer()
        res = sanitizer.sanitize("eval('42')")

        assert res.is_safe is False
        assert len(res.violations) >= 1
        v = res.violations[0]
        assert isinstance(v.rule, str)
        assert isinstance(v.name, str)
        assert isinstance(v.lineno, int)
        assert isinstance(v.col_offset, int)
        assert isinstance(v.description, str)

    def test_dlp_result_dataclass_contract(self):
        """Verifies that DlpResult implements all required fields from PROJECT.md Interface Contracts."""
        masker = DlpMasker()
        result = masker.mask_text("Sample telemetry text.")

        assert hasattr(result, "text") and isinstance(result.text, str)
        assert hasattr(result, "has_pii") and isinstance(result.has_pii, bool)
        assert hasattr(result, "has_secrets") and isinstance(result.has_secrets, bool)
        assert hasattr(result, "has_prompt_leak") and isinstance(result.has_prompt_leak, bool)
        assert hasattr(result, "redaction_count") and isinstance(result.redaction_count, int)
        assert hasattr(result, "latency_ms") and isinstance(result.latency_ms, float)
