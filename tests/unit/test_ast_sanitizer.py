"""Comprehensive unit tests for AgentXDR static Python AST code sanitizer."""

import pytest

from agentxdr.guardrails.ast_sanitizer import (
    AstSanitizer,
    AstSanitizerResult,
    AstViolation,
)


class TestAstSanitizerUnit:
    """Unit tests for AstSanitizer."""

    @pytest.fixture
    def sanitizer(self) -> AstSanitizer:
        return AstSanitizer()

    def test_empty_and_whitespace_code(self, sanitizer: AstSanitizer) -> None:
        res = sanitizer.sanitize("")
        assert res.is_safe is True
        assert len(res.violations) == 0

        res_ws = sanitizer.sanitize("   \n\t  ")
        assert res_ws.is_safe is True
        assert len(res_ws.violations) == 0

    def test_syntax_error_handled_gracefully(self, sanitizer: AstSanitizer) -> None:
        broken_code = "def foo(:\n    return 1"
        res = sanitizer.sanitize(broken_code)
        assert res.is_safe is False
        assert len(res.violations) == 1
        assert res.violations[0].rule == "SYNTAX_ERROR"
        assert res.violations[0].lineno >= 1

    def test_safe_algorithmic_code(self, sanitizer: AstSanitizer) -> None:
        code = (
            "def fib(n):\n"
            "    a, b = 0, 1\n"
            "    for _ in range(n):\n"
            "        a, b = b, a + b\n"
            "    return a\n"
            "val = fib(10)\n"
        )
        res = sanitizer.sanitize(code)
        assert res.is_safe is True
        assert len(res.violations) == 0

    def test_blocks_os_import(self, sanitizer: AstSanitizer) -> None:
        code = "import os\nos.system('ls')"
        res = sanitizer.sanitize(code)
        assert res.is_safe is False
        assert any(v.name == "os" and v.rule == "FORBIDDEN_IMPORT" for v in res.violations)

    def test_blocks_subprocess_import(self, sanitizer: AstSanitizer) -> None:
        code = "import subprocess as sp\nsp.call(['ls'])"
        res = sanitizer.sanitize(code)
        assert res.is_safe is False
        assert any("subprocess" in v.name for v in res.violations)

    def test_blocks_from_import(self, sanitizer: AstSanitizer) -> None:
        code = "from socket import socket, AF_INET"
        res = sanitizer.sanitize(code)
        assert res.is_safe is False
        assert any("socket" in v.name for v in res.violations)

    def test_blocks_eval_exec(self, sanitizer: AstSanitizer) -> None:
        code = "eval('1 + 1'); exec('pass')"
        res = sanitizer.sanitize(code)
        assert res.is_safe is False
        names = {v.name for v in res.violations}
        assert "eval" in names
        assert "exec" in names

    def test_blocks_open_call(self, sanitizer: AstSanitizer) -> None:
        code = "with open('secret.txt') as f: data = f.read()"
        res = sanitizer.sanitize(code)
        assert res.is_safe is False
        assert any(v.name == "open" for v in res.violations)

    def test_blocks_dunder_import(self, sanitizer: AstSanitizer) -> None:
        code = "m = __import__('os')"
        res = sanitizer.sanitize(code)
        assert res.is_safe is False
        assert any(v.name == "__import__" for v in res.violations)

    def test_blocks_dunder_subclasses_traversal(self, sanitizer: AstSanitizer) -> None:
        code = "sub = ().__class__.__bases__[0].__subclasses__()"
        res = sanitizer.sanitize(code)
        assert res.is_safe is False
        names = {v.name for v in res.violations}
        assert "__subclasses__" in names or "__bases__" in names or "__class__" in names

    def test_blocks_dunder_globals(self, sanitizer: AstSanitizer) -> None:
        code = "def f(): pass\ng = f.__globals__"
        res = sanitizer.sanitize(code)
        assert res.is_safe is False
        assert any(v.name == "__globals__" for v in res.violations)

    def test_allows_safe_dunders(self, sanitizer: AstSanitizer) -> None:
        code = (
            "class MyObj:\n"
            "    def __init__(self, val):\n"
            "        self.val = val\n"
            "    def __str__(self):\n"
            "        return str(self.val)\n"
            "o = MyObj(5)\n"
            "s = str(o)\n"
        )
        res = sanitizer.sanitize(code)
        assert res.is_safe is True
        assert len(res.violations) == 0

    def test_custom_blocked_imports(self) -> None:
        custom = AstSanitizer(blocked_imports=["numpy", "pandas"])
        res_numpy = custom.sanitize("import numpy as np")
        assert res_numpy.is_safe is False
        assert any("numpy" in v.name for v in res_numpy.violations)

        res_os = custom.sanitize("import math\nx = math.cos(0)")
        assert res_os.is_safe is True
