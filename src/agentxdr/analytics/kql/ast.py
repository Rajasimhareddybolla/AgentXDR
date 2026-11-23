"""
KQL-Lite AST node definitions.

Represents the abstract syntax tree for a KQL tabular pipeline:

    <table> | <operator> | <operator> | ...

Supported operators:
  - where   <predicate>
  - project <col>, <col>, ...
  - summarize <agg>() [by <col>, ...]
  - take    <n>
  - sort    by <col> [asc|desc], ...
  - top     <n> by <col> [asc|desc]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Predicate / Expression AST
# ---------------------------------------------------------------------------


@dataclass
class Literal:
    """A scalar literal value (string, integer, float, bool, None)."""

    value: Any

    def __repr__(self) -> str:
        return f"Literal({self.value!r})"


@dataclass
class ColumnRef:
    """A reference to a column by name (may be dotted, e.g. payload_redacted.tool_name)."""

    name: str

    def __repr__(self) -> str:
        return f"Col({self.name})"


@dataclass
class FunctionCall:
    """A function invocation expression, such as ago(4h)."""

    name: str
    args: List[Any] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"FunctionCall({self.name!r}, {self.args!r})"


@dataclass
class BinaryOp:
    """
    A binary comparison or logical expression.

    op is one of: ==, !=, >, <, >=, <=, =~, !~, has, !has, contains, !contains,
                  startswith, !startswith, endswith, !endswith, in, and, or
    """

    op: str
    left: Any   # ColumnRef | Literal | BinaryOp | UnaryOp | FunctionCall
    right: Any  # ColumnRef | Literal | BinaryOp | List[Literal] | FunctionCall

    def __repr__(self) -> str:
        return f"BinaryOp({self.op!r}, {self.left!r}, {self.right!r})"


@dataclass
class UnaryOp:
    """A unary logical expression (not)."""

    op: str   # "not"
    operand: Any

    def __repr__(self) -> str:
        return f"UnaryOp({self.op!r}, {self.operand!r})"


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


@dataclass
class AggFunction:
    """
    An aggregation call in a summarize clause.

    name     : e.g. "count", "sum", "avg", "min", "max", "dcount"
    column   : operand column (None for count())
    alias    : output column alias (defaults to "<name>_<col>" or "<name>_")
    """

    name: str
    column: Optional[str] = None
    alias: Optional[str] = None


# ---------------------------------------------------------------------------
# Pipeline step clauses
# ---------------------------------------------------------------------------


@dataclass
class TableSource:
    """The source table (first token in a KQL pipeline)."""

    name: str


@dataclass
class WhereClause:
    """| where <predicate>"""

    predicate: Any  # BinaryOp | UnaryOp | Literal | FunctionCall


@dataclass
class ProjectClause:
    """| project <col>, <col>, ..."""

    columns: List[str]


@dataclass
class SummarizeClause:
    """| summarize <agg()> [by <col>, ...]"""

    aggregations: List[AggFunction]
    by_columns: List[str] = field(default_factory=list)


@dataclass
class TakeClause:
    """| take <n>"""

    count: int


@dataclass
class SortClause:
    """| sort by <col> [asc|desc], ..."""

    # List of (column_name, ascending: bool)
    keys: List[Tuple[str, bool]] = field(default_factory=list)


@dataclass
class TopClause:
    """| top <n> by <col> [asc|desc]"""

    count: int
    by_column: str
    ascending: bool = False


# ---------------------------------------------------------------------------
# Top-level pipeline
# ---------------------------------------------------------------------------


@dataclass
class KqlPipeline:
    """
    A complete KQL tabular pipeline.

    source   : the table that feeds the pipeline
    operators: ordered list of clause nodes
    """

    source: TableSource
    operators: List[Any] = field(default_factory=list)


# Type alias per SCOPE.md interface contract
KqlQuery = KqlPipeline
