"""
KQL-Lite → DuckDB SQL compiler.

Compiles a :class:`KqlPipeline` AST to a parameterized DuckDB SQL query
and a matching list of bind parameters.

SQL injection safety: all literal values are passed as positional
parameters (?), never interpolated into the query string.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Iterator, List, NamedTuple, Optional, Sequence, Tuple

from agentxdr.analytics.kql.ast import (
    AggFunction,
    BinaryOp,
    ColumnRef,
    FunctionCall,
    KqlPipeline,
    Literal,
    ProjectClause,
    SortClause,
    SummarizeClause,
    TableSource,
    TakeClause,
    TopClause,
    UnaryOp,
    WhereClause,
)


class CompiledQuery(NamedTuple):
    """Result of compiling a KQL-Lite pipeline to SQL."""

    sql: str
    params: List[Any]


@dataclass
class KqlQueryResult:
    """Result of executing a compiled KQL query against DuckDB."""

    columns: List[str]
    rows: List[dict]
    execution_time_ms: float

    def __iter__(self) -> Iterator[dict]:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: Any) -> Any:
        return self.rows[index]


# Type alias per SCOPE.md interface contract
KqlQuery = KqlPipeline


# ---------------------------------------------------------------------------
# Identifier validation & Quoting
# ---------------------------------------------------------------------------

_SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([a-zA-Z]+)$")


def _safe_col(name: str) -> str:
    """Return a safely quoted column or JSON path expression."""
    parts = name.split(".")
    for p in parts:
        if not _SAFE_IDENT_RE.match(p):
            raise ValueError(f"Invalid column name: {name!r}")
    if len(parts) == 1:
        return f'"{parts[0]}"'
    col = f'"{parts[0]}"'
    json_path = ".".join(parts[1:])
    return f"{col}->>'$.{json_path}'"


# ---------------------------------------------------------------------------
# Expression Compiler
# ---------------------------------------------------------------------------


class _ExprCompiler:
    """Compile a predicate expression to SQL, accumulating bind params."""

    def __init__(self) -> None:
        self.params: List[Any] = []

    def compile(self, node: Any) -> str:
        if isinstance(node, Literal):
            self.params.append(node.value)
            return "?"
        if isinstance(node, ColumnRef):
            return _safe_col(node.name)
        if isinstance(node, FunctionCall):
            return self._compile_function(node)
        if isinstance(node, UnaryOp):
            if node.op == "not":
                return f"NOT ({self.compile(node.operand)})"
            raise ValueError(f"Unknown unary op: {node.op!r}")
        if isinstance(node, BinaryOp):
            return self._compile_binary(node)
        raise ValueError(f"Unknown expression node: {type(node).__name__}")

    def _compile_function(self, node: FunctionCall) -> str:
        fname = node.name.lower()
        if fname == "ago":
            if not node.args:
                raise ValueError("ago() requires a duration argument")
            dur = node.args[0].value if isinstance(node.args[0], Literal) else str(node.args[0])
            dur = str(dur).strip("\"'")
            m = _DURATION_RE.match(dur)
            if not m:
                raise ValueError(f"Invalid duration format for ago(): {dur!r}")
            num = m.group(1)
            raw_unit = m.group(2).lower()
            unit_map = {
                "s": "SECOND", "sec": "SECOND", "second": "SECOND", "seconds": "SECOND",
                "m": "MINUTE", "min": "MINUTE", "minute": "MINUTE", "minutes": "MINUTE",
                "h": "HOUR", "hr": "HOUR", "hour": "HOUR", "hours": "HOUR",
                "d": "DAY", "day": "DAY", "days": "DAY",
            }
            if raw_unit not in unit_map:
                raise ValueError(f"Unsupported duration unit in ago(): {raw_unit!r}")
            unit = unit_map[raw_unit]
            return f"(CURRENT_TIMESTAMP - INTERVAL {num} {unit})"
        raise ValueError(f"Unknown function call: {node.name!r}")

    def _compile_binary(self, node: BinaryOp) -> str:
        op = node.op.lower()

        if op == "and":
            return f"({self.compile(node.left)} AND {self.compile(node.right)})"
        if op == "or":
            return f"({self.compile(node.left)} OR {self.compile(node.right)})"

        if op == "in":
            left_sql = self.compile(node.left)
            placeholders = []
            for lit in node.right:  # type: ignore[union-attr]
                self.params.append(lit.value)
                placeholders.append("?")
            return f"({left_sql} IN ({', '.join(placeholders)}))"

        if op == "has":
            left_sql = self.compile(node.left)
            self.params.append(f"%{node.right.value}%")  # type: ignore[union-attr]
            return f"({left_sql} ILIKE ?)"

        if op == "!has":
            left_sql = self.compile(node.left)
            self.params.append(f"%{node.right.value}%")  # type: ignore[union-attr]
            return f"(NOT ({left_sql} ILIKE ?))"

        if op == "contains":
            left_sql = self.compile(node.left)
            self.params.append(f"%{node.right.value}%")  # type: ignore[union-attr]
            return f"(CAST({left_sql} AS VARCHAR) ILIKE ?)"

        if op == "!contains":
            left_sql = self.compile(node.left)
            self.params.append(f"%{node.right.value}%")  # type: ignore[union-attr]
            return f"(NOT (CAST({left_sql} AS VARCHAR) ILIKE ?))"

        if op == "startswith":
            left_sql = self.compile(node.left)
            self.params.append(f"{node.right.value}%")  # type: ignore[union-attr]
            return f"(CAST({left_sql} AS VARCHAR) ILIKE ?)"

        if op == "!startswith":
            left_sql = self.compile(node.left)
            self.params.append(f"{node.right.value}%")  # type: ignore[union-attr]
            return f"(NOT (CAST({left_sql} AS VARCHAR) ILIKE ?))"

        if op == "endswith":
            left_sql = self.compile(node.left)
            self.params.append(f"%{node.right.value}")  # type: ignore[union-attr]
            return f"(CAST({left_sql} AS VARCHAR) ILIKE ?)"

        if op == "!endswith":
            left_sql = self.compile(node.left)
            self.params.append(f"%{node.right.value}")  # type: ignore[union-attr]
            return f"(NOT (CAST({left_sql} AS VARCHAR) ILIKE ?))"

        if op == "=~":
            left_sql = self.compile(node.left)
            self.params.append(str(node.right.value))  # type: ignore[union-attr]
            return f"(CAST({left_sql} AS VARCHAR) ILIKE ?)"

        if op == "!~":
            left_sql = self.compile(node.left)
            self.params.append(str(node.right.value))  # type: ignore[union-attr]
            return f"(NOT (CAST({left_sql} AS VARCHAR) ILIKE ?))"

        # Standard comparison operators
        _STANDARD_OPS = {"==": "=", "!=": "!=", ">": ">", "<": "<", ">=": ">=", "<=": "<="}
        if op in _STANDARD_OPS:
            sql_op = _STANDARD_OPS[op]
            left_sql = self.compile(node.left)

            # DuckDB JSON arrow extractor (->>) returns VARCHAR text.
            # If comparing against a numeric value or using relative inequality,
            # cast to DOUBLE to avoid BinderError on type mismatch.
            is_numeric_comparison = op in (">", "<", ">=", "<=") or (
                isinstance(node.right, Literal) and isinstance(node.right.value, (int, float))
            )
            if "->>" in left_sql and is_numeric_comparison:
                left_sql = f"TRY_CAST({left_sql} AS DOUBLE)"

            right_sql = self.compile(node.right)
            return f"({left_sql} {sql_op} {right_sql})"

        raise ValueError(f"Unknown binary op: {op!r}")


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------


class KqlCompiler:
    """
    Compiles a :class:`KqlPipeline` to a :class:`CompiledQuery`.

    Usage::

        pipeline = parse("events | where verdict == 'BLOCK' | take 10")
        result = KqlCompiler().compile(pipeline)
        # result.sql  → SELECT * FROM "events" WHERE "verdict" = ? LIMIT 10
        # result.params → ['BLOCK']
        # sql, params = result  (unpackable as 2-tuple)
    """

    def compile(self, pipeline: KqlPipeline) -> CompiledQuery:  # noqa: A003
        table = _safe_col(pipeline.source.name)

        # Detect if a where clause occurs AFTER a summarize clause
        summarize_idx: Optional[int] = None
        where_after_summarize: List[WhereClause] = []
        where_before_summarize: List[WhereClause] = []

        for idx, op in enumerate(pipeline.operators):
            if isinstance(op, SummarizeClause):
                summarize_idx = idx
            elif isinstance(op, WhereClause):
                if summarize_idx is not None and idx > summarize_idx:
                    where_after_summarize.append(op)
                else:
                    where_before_summarize.append(op)

        # Collect primary clause types
        project_clause: Optional[ProjectClause] = next(
            (op for op in pipeline.operators if isinstance(op, ProjectClause)), None
        )
        summarize_clause: Optional[SummarizeClause] = next(
            (op for op in pipeline.operators if isinstance(op, SummarizeClause)), None
        )
        sort_clause: Optional[SortClause] = next(
            (op for op in pipeline.operators if isinstance(op, SortClause)), None
        )
        take_clause: Optional[TakeClause] = next(
            (op for op in pipeline.operators if isinstance(op, TakeClause)), None
        )
        top_clause: Optional[TopClause] = next(
            (op for op in pipeline.operators if isinstance(op, TopClause)), None
        )

        expr_compiler = _ExprCompiler()

        # SELECT clause
        if summarize_clause:
            select_parts: List[str] = []
            for agg in summarize_clause.aggregations:
                select_parts.append(self._compile_agg(agg))
            for col in summarize_clause.by_columns:
                select_parts.append(_safe_col(col))
            select_sql = ", ".join(select_parts) if select_parts else "*"
        elif project_clause:
            select_sql = ", ".join(_safe_col(c) for c in project_clause.columns)
        else:
            select_sql = "*"

        # FROM clause
        from_sql = table

        # WHERE clause (before aggregation)
        where_parts: List[str] = []
        for wc in where_before_summarize:
            p_sql = expr_compiler.compile(wc.predicate)
            if len(where_before_summarize) > 1 and not (p_sql.startswith("(") and p_sql.endswith(")")):
                where_parts.append(f"({p_sql})")
            else:
                where_parts.append(p_sql)
        where_sql = " AND ".join(where_parts) if where_parts else ""

        # GROUP BY clause
        group_by_sql = ""
        if summarize_clause and summarize_clause.by_columns:
            group_by_sql = "GROUP BY " + ", ".join(
                _safe_col(c) for c in summarize_clause.by_columns
            )

        # ORDER BY clause
        order_by_sql = ""
        if sort_clause and sort_clause.keys:
            parts = []
            for col, asc in sort_clause.keys:
                direction = "ASC" if asc else "DESC"
                parts.append(f"{_safe_col(col)} {direction}")
            order_by_sql = "ORDER BY " + ", ".join(parts)
        elif top_clause:
            direction = "ASC" if top_clause.ascending else "DESC"
            order_by_sql = f"ORDER BY {_safe_col(top_clause.by_column)} {direction}"

        # LIMIT clause
        limit_sql = ""
        if take_clause:
            limit_sql = f"LIMIT {take_clause.count}"
        elif top_clause:
            limit_sql = f"LIMIT {top_clause.count}"

        # Assemble primary query
        parts_ordered = [
            f"SELECT {select_sql}",
            f"FROM {from_sql}",
        ]
        if where_sql:
            parts_ordered.append(f"WHERE {where_sql}")
        if group_by_sql:
            parts_ordered.append(group_by_sql)
        if order_by_sql:
            parts_ordered.append(order_by_sql)
        if limit_sql:
            parts_ordered.append(limit_sql)

        inner_sql = " ".join(parts_ordered)

        # Handle subquery wrapping if filtering after summarize
        if where_after_summarize:
            outer_where_parts: List[str] = []
            for wc in where_after_summarize:
                outer_where_parts.append(expr_compiler.compile(wc.predicate))
            outer_where_sql = " AND ".join(outer_where_parts)
            final_sql = f"SELECT * FROM ({inner_sql}) AS _sub WHERE {outer_where_sql}"
        else:
            final_sql = inner_sql

        return CompiledQuery(sql=final_sql, params=expr_compiler.params)

    @staticmethod
    def _compile_agg(agg: AggFunction) -> str:
        name = agg.name.lower()
        alias = agg.alias or f"{name}_"

        agg_map = {
            "count": "count(*)",
            "sum": f"sum({_safe_col(agg.column)})" if agg.column else "sum(*)",
            "avg": f"avg({_safe_col(agg.column)})" if agg.column else "avg(*)",
            "min": f"min({_safe_col(agg.column)})" if agg.column else "min(*)",
            "max": f"max({_safe_col(agg.column)})" if agg.column else "max(*)",
            "dcount": f"count(DISTINCT {_safe_col(agg.column)})" if agg.column else "count(DISTINCT *)",
        }
        if name not in agg_map:
            raise ValueError(f"Unknown aggregation function: {name!r}")

        return f'{agg_map[name]} AS "{alias}"'
