"""Python AST Static Code Sanitizer.

Pre-execution static analysis analyzing Python code blocks, catching SyntaxErrors
gracefully, and preventing execution of dangerous imports, unsafe builtins, and
dunder attribute escalations.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import time
from typing import List, Optional, Set, Tuple


class RuleStr(str):
    """String representing violation rule that matches case-insensitively."""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.lower() == other.lower()
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(self.lower())


@dataclass
class AstViolation:
    """Detailed record of a single security or syntax violation detected by AST sanitizer."""

    rule: str  # "FORBIDDEN_IMPORT", "DANGEROUS_BUILTIN", "DUNDER_ACCESS", "SYNTAX_ERROR"
    name: str  # e.g. "os", "eval", "__subclasses__"
    lineno: int  # Line number (1-indexed, 0 if not applicable)
    col_offset: int  # Column offset (0-indexed)
    description: str  # Human-readable explanation


@dataclass
class AstSanitizerResult:
    """Aggregate result of static AST code sanitization."""

    is_safe: bool
    violations: List[AstViolation]
    latency_ms: float


DEFAULT_BLOCKED_IMPORTS: List[str] = [
    "os",
    "subprocess",
    "socket",
    "ctypes",
    "shutil",
    "pickle",
    "importlib",
    "requests",
    "urllib",
    "sys",
    "pty",
    "commands",
    "builtins",
    "posix",
    "nt",
]

DEFAULT_BLOCKED_BUILTINS: List[str] = [
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "input",
    "breakpoint",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
]

DEFAULT_BLOCKED_DUNDERS: List[str] = [
    "__subclasses__",
    "__bases__",
    "__base__",
    "__mro__",
    "__globals__",
    "__code__",
    "__class__",
    "__dict__",
    "__builtins__",
]


class _SanitizerVisitor(ast.NodeVisitor):
    """Internal AST visitor traversing code tree and recording security violations."""

    def __init__(
        self,
        blocked_imports: Set[str],
        blocked_builtins: Set[str],
        blocked_dunders: Set[str],
    ) -> None:
        self.blocked_imports = blocked_imports
        self.blocked_builtins = blocked_builtins
        self.blocked_dunders = blocked_dunders
        self.violations: List[AstViolation] = []

    def _is_module_blocked(self, mod_name: str) -> Tuple[bool, str]:
        if not mod_name:
            return False, ""
        parts = mod_name.split(".")
        if parts[0] in self.blocked_imports:
            return True, parts[0]
        if mod_name in self.blocked_imports:
            return True, mod_name
        return False, ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            blocked, root_mod = self._is_module_blocked(alias.name)
            if blocked:
                self.violations.append(
                    AstViolation(
                        rule=RuleStr("FORBIDDEN_IMPORT"),
                        name=alias.name,
                        lineno=getattr(node, "lineno", 0),
                        col_offset=getattr(node, "col_offset", 0),
                        description=f"Direct import of forbidden module '{alias.name}' is prohibited.",
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        blocked, root_mod = self._is_module_blocked(mod)
        if blocked:
            self.violations.append(
                AstViolation(
                    rule=RuleStr("FORBIDDEN_IMPORT"),
                    name=mod,
                    lineno=getattr(node, "lineno", 0),
                    col_offset=getattr(node, "col_offset", 0),
                    description=f"Import from forbidden module '{mod}' is prohibited.",
                )
            )
        else:
            for alias in node.names:
                full_name = f"{mod}.{alias.name}" if mod else alias.name
                b, _ = self._is_module_blocked(full_name)
                if b or alias.name in self.blocked_imports:
                    self.violations.append(
                        AstViolation(
                            rule=RuleStr("FORBIDDEN_IMPORT"),
                            name=alias.name,
                            lineno=getattr(node, "lineno", 0),
                            col_offset=getattr(node, "col_offset", 0),
                            description=f"Import of forbidden entity '{alias.name}' from '{mod}' is prohibited.",
                        )
                    )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in self.blocked_builtins:
            self.violations.append(
                AstViolation(
                    rule=RuleStr("DANGEROUS_BUILTIN"),
                    name=node.id,
                    lineno=getattr(node, "lineno", 0),
                    col_offset=getattr(node, "col_offset", 0),
                    description=f"Access or invocation of dangerous builtin '{node.id}' is prohibited.",
                )
            )
        elif node.id in self.blocked_dunders:
            self.violations.append(
                AstViolation(
                    rule=RuleStr("DUNDER_ACCESS"),
                    name=node.id,
                    lineno=getattr(node, "lineno", 0),
                    col_offset=getattr(node, "col_offset", 0),
                    description=f"Access to forbidden dunder identifier '{node.id}' is prohibited.",
                )
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in self.blocked_dunders:
            self.violations.append(
                AstViolation(
                    rule=RuleStr("DUNDER_ACCESS"),
                    name=node.attr,
                    lineno=getattr(node, "lineno", 0),
                    col_offset=getattr(node, "col_offset", 0),
                    description=f"Access to forbidden dunder attribute '{node.attr}' is prohibited.",
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check dynamic access like getattr(obj, '__builtins__')
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in ("getattr", "hasattr", "setattr", "delattr")
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            target_attr = node.args[1].value
            if target_attr in self.blocked_dunders:
                self.violations.append(
                    AstViolation(
                        rule=RuleStr("DUNDER_ACCESS"),
                        name=target_attr,
                        lineno=getattr(node, "lineno", 0),
                        col_offset=getattr(node, "col_offset", 0),
                        description=(
                            f"Dynamic access to forbidden dunder attribute '{target_attr}' "
                            f"via '{node.func.id}' is prohibited."
                        ),
                    )
                )
        self.generic_visit(node)


class AstSanitizer:
    """Pre-execution Python AST static code sanitizer."""

    def __init__(
        self,
        blocked_imports: Optional[List[str]] = None,
        blocked_builtins: Optional[List[str]] = None,
        blocked_dunders: Optional[List[str]] = None,
    ) -> None:
        """Initialize sanitizer with optional custom blocklists."""
        self.blocked_imports: Set[str] = (
            set(blocked_imports) if blocked_imports is not None else set(DEFAULT_BLOCKED_IMPORTS)
        )
        self.blocked_builtins: Set[str] = (
            set(blocked_builtins) if blocked_builtins is not None else set(DEFAULT_BLOCKED_BUILTINS)
        )
        self.blocked_dunders: Set[str] = (
            set(blocked_dunders) if blocked_dunders is not None else set(DEFAULT_BLOCKED_DUNDERS)
        )

    def sanitize(self, code: str) -> AstSanitizerResult:
        """Parse and statically inspect Python code for security violations.

        Catches SyntaxError gracefully without raising exceptions.
        """
        start_time = time.perf_counter()

        # Handle empty, whitespace-only, or comment-only strings
        if not code or not code.strip():
            latency = (time.perf_counter() - start_time) * 1000.0
            return AstSanitizerResult(is_safe=True, violations=[], latency_ms=round(latency, 3))

        # Check for null bytes or control characters prior to AST parsing
        if "\x00" in code:
            latency = (time.perf_counter() - start_time) * 1000.0
            violation = AstViolation(
                rule=RuleStr("SYNTAX_ERROR"),
                name="null_byte",
                lineno=1,
                col_offset=code.find("\x00"),
                description="Syntax error: source code cannot contain null bytes.",
            )
            return AstSanitizerResult(
                is_safe=False, violations=[violation], latency_ms=round(latency, 3)
            )

        # Parse AST tree with graceful exception handling
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError, Exception) as exc:
            latency = (time.perf_counter() - start_time) * 1000.0
            lineno = getattr(exc, "lineno", 1) or 1
            col_offset = getattr(exc, "offset", 0) or 0
            msg = getattr(exc, "msg", str(exc)) or str(exc)
            violation = AstViolation(
                rule=RuleStr("SYNTAX_ERROR"),
                name="syntax_error",
                lineno=lineno,
                col_offset=col_offset,
                description=f"SyntaxError during AST parsing: {msg}",
            )
            return AstSanitizerResult(
                is_safe=False, violations=[violation], latency_ms=round(latency, 3)
            )

        # Walk AST with security visitor
        visitor = _SanitizerVisitor(
            blocked_imports=self.blocked_imports,
            blocked_builtins=self.blocked_builtins,
            blocked_dunders=self.blocked_dunders,
        )
        visitor.visit(tree)

        latency = (time.perf_counter() - start_time) * 1000.0
        is_safe = len(visitor.violations) == 0

        return AstSanitizerResult(
            is_safe=is_safe,
            violations=visitor.violations,
            latency_ms=round(latency, 3),
        )
