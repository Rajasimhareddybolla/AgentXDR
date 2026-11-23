"""
KQL-Lite pure-Python recursive-descent tokenizer and parser.

Grammar (simplified EBNF):

    pipeline      ::= table_name ("|" operator)*
    operator      ::= where_op | project_op | summarize_op | take_op | sort_op | top_op
    where_op      ::= "where" predicate
    project_op    ::= "project" col_list
    summarize_op  ::= "summarize" agg_list ("by" col_list)?
    take_op       ::= "take" INTEGER
    sort_op       ::= "sort" "by" sort_key ("," sort_key)*
    top_op        ::= "top" INTEGER "by" col_name ("asc" | "desc")?

    predicate     ::= or_expr
    or_expr       ::= and_expr ("or" and_expr)*
    and_expr      ::= not_expr ("and" not_expr)*
    not_expr      ::= "not" not_expr | comparison
    comparison    ::= atom op atom | atom "in" "(" literal_list ")"
    atom          ::= IDENTIFIER | STRING | INTEGER | FLOAT | "true" | "false" | "null"
                    | function_call | "(" or_expr ")"

    op            ::= "==" | "!=" | "=~" | "!~" | ">" | "<" | ">=" | "<="
                    | "has" | "!has" | "contains" | "!contains"
                    | "startswith" | "!startswith" | "endswith" | "!endswith"
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

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


# ===========================================================================
# Tokenizer
# ===========================================================================


@dataclass
class Token:
    kind: str   # IDENT, INT, FLOAT, STRING, PIPE, COMMA, LPAREN, RPAREN, DOT, OP, EOF
    value: str
    pos: int


_TOKEN_RE = re.compile(
    r"""
    (?P<COMMENT>   //[^\r\n]*|--[^\r\n]* )                |
    (?P<FLOAT>     -?\d+\.\d+ )                           |
    (?P<INT>       -?\d+ )                                |
    (?P<STRING>    "(?:[^"\\]|\\.|"")*"  |
                   '(?:[^'\\]|\\.|'')*'  )                |
    (?P<PIPE>      \| )                                   |
    (?P<COMMA>     , )                                    |
    (?P<LPAREN>    \( )                                   |
    (?P<RPAREN>    \) )                                   |
    (?P<DOT>       \. )                                   |
    (?P<OP>        ==|!=|=~|!~|>=|<=|!contains|!has|!startswith|!endswith|>|<|=|\+|-|\*|/|! ) |
    (?P<IDENT>     [A-Za-z_][A-Za-z0-9_]* )               |
    (?P<WS>        \s+ )                                  |
    (?P<MISMATCH>  . )
    """,
    re.VERBOSE,
)

_BINARY_OPS = frozenset(
    {
        "==", "!=", "=~", "!~", ">", "<", ">=", "<=",
        "has", "!has", "contains", "!contains",
        "startswith", "!startswith", "endswith", "!endswith",
    }
)

_AGG_FUNCTIONS = frozenset({"count", "sum", "avg", "min", "max", "dcount"})

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([a-zA-Z]+)$")

_VALID_DURATION_UNITS = frozenset(
    {
        "s", "sec", "second", "seconds",
        "m", "min", "minute", "minutes",
        "h", "hr", "hour", "hours",
        "d", "day", "days",
    }
)

_KEYWORDS = frozenset(
    {
        "where", "project", "summarize", "by", "take", "sort", "top",
        "and", "or", "not", "in", "asc", "desc",
        "count", "sum", "avg", "min", "max", "dcount",
        "true", "false", "null",
    }
)


def tokenize(text: str) -> List[Token]:
    """Tokenize a KQL query string into a list of Token objects."""
    tokens: List[Token] = []
    for m in _TOKEN_RE.finditer(text):
        kind = m.lastgroup
        if kind in ("WS", "COMMENT"):
            continue
        if kind == "MISMATCH":
            raise ParseError(f"Unexpected character {m.group()!r} at pos {m.start()}")
        tokens.append(Token(kind=kind, value=m.group(), pos=m.start()))  # type: ignore[arg-type]
    tokens.append(Token(kind="EOF", value="", pos=len(text)))
    return tokens


# ===========================================================================
# Parser
# ===========================================================================


class ParseError(Exception):
    """Raised when parsing invalid KQL query syntax."""


class _Parser:
    def __init__(self, tokens: List[Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    # ------------------------------------------------------------------
    # Primitive helpers
    # ------------------------------------------------------------------

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        if tok.kind != "EOF":
            self._pos += 1
        return tok

    def _expect_kind(self, kind: str) -> Token:
        tok = self._advance()
        if tok.kind != kind:
            raise ParseError(
                f"Expected token kind {kind!r}, got {tok.kind!r}={tok.value!r} at pos {tok.pos}"
            )
        return tok

    def _expect_ident(self, word: str) -> Token:
        tok = self._advance()
        if tok.kind != "IDENT" or tok.value.lower() != word.lower():
            raise ParseError(
                f"Expected keyword {word!r}, got {tok.value!r} at pos {tok.pos}"
            )
        return tok

    def _peek_ident(self, *words: str) -> bool:
        tok = self._peek()
        return tok.kind == "IDENT" and tok.value.lower() in {w.lower() for w in words}

    def _peek_kind(self, *kinds: str) -> bool:
        return self._peek().kind in kinds

    # ------------------------------------------------------------------
    # Column identifier (supports dotted paths: a.b.c)
    # ------------------------------------------------------------------

    def _parse_col_name(self) -> str:
        tok = self._expect_kind("IDENT")
        name = tok.value
        while self._peek_kind("DOT"):
            self._advance()  # consume dot
            next_tok = self._expect_kind("IDENT")
            name += f".{next_tok.value}"
        return name

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def parse_pipeline(self) -> KqlPipeline:
        source_tok = self._expect_kind("IDENT")
        source = TableSource(name=source_tok.value)
        operators = []
        while self._peek().kind == "PIPE":
            self._advance()  # consume |
            op = self._parse_operator()
            operators.append(op)
        if self._peek().kind != "EOF":
            raise ParseError(
                f"Unexpected token {self._peek().value!r} at pos {self._peek().pos}"
            )
        return KqlPipeline(source=source, operators=operators)

    def _parse_operator(self) -> Any:
        kw = self._peek()
        if kw.kind != "IDENT":
            raise ParseError(f"Expected operator keyword, got {kw.value!r} at pos {kw.pos}")
        kw_lower = kw.value.lower()
        if kw_lower == "where":
            return self._parse_where()
        if kw_lower == "project":
            return self._parse_project()
        if kw_lower == "summarize":
            return self._parse_summarize()
        if kw_lower == "take":
            return self._parse_take()
        if kw_lower == "sort":
            return self._parse_sort()
        if kw_lower == "top":
            return self._parse_top()
        raise ParseError(f"Unknown operator {kw.value!r} at pos {kw.pos}")

    # ------------------------------------------------------------------
    # Operators
    # ------------------------------------------------------------------

    def _parse_where(self) -> WhereClause:
        self._expect_ident("where")
        pred = self._parse_or_expr()
        return WhereClause(predicate=pred)

    def _parse_project(self) -> ProjectClause:
        proj_tok = self._expect_ident("project")
        cols = self._parse_col_list()
        if not cols:
            raise ParseError(
                f"Expected at least one column after 'project' at pos {proj_tok.pos}"
            )
        return ProjectClause(columns=cols)

    def _parse_summarize(self) -> SummarizeClause:
        self._expect_ident("summarize")
        aggs = self._parse_agg_list()
        by_cols: List[str] = []
        if self._peek_ident("by"):
            by_tok = self._advance()  # consume "by"
            by_cols = self._parse_col_list()
            if not by_cols:
                raise ParseError(
                    f"Expected at least one column after 'by' at pos {by_tok.pos}"
                )
        return SummarizeClause(aggregations=aggs, by_columns=by_cols)

    def _parse_take(self) -> TakeClause:
        self._expect_ident("take")
        n_tok = self._expect_kind("INT")
        return TakeClause(count=int(n_tok.value))

    def _parse_sort(self) -> SortClause:
        self._expect_ident("sort")
        self._expect_ident("by")
        keys: List[Tuple[str, bool]] = []
        while True:
            col = self._parse_col_name()
            ascending = True
            if self._peek_ident("asc", "desc"):
                dir_tok = self._advance()
                ascending = dir_tok.value.lower() == "asc"
            keys.append((col, ascending))
            if self._peek_kind("COMMA"):
                self._advance()
                continue
            break
        return SortClause(keys=keys)

    def _parse_top(self) -> TopClause:
        self._expect_ident("top")
        count_tok = self._expect_kind("INT")
        self._expect_ident("by")
        col = self._parse_col_name()
        ascending = False
        if self._peek_ident("asc", "desc"):
            dir_tok = self._advance()
            ascending = dir_tok.value.lower() == "asc"
        return TopClause(count=int(count_tok.value), by_column=col, ascending=ascending)

    # ------------------------------------------------------------------
    # Column list
    # ------------------------------------------------------------------

    def _parse_col_list(self) -> List[str]:
        cols: List[str] = []
        tok = self._peek()
        if tok.kind != "IDENT" or tok.value.lower() in (_KEYWORDS - {"by"}):
            return cols

        cols.append(self._parse_col_name())
        while self._peek_kind("COMMA"):
            comma_tok = self._advance()
            next_tok = self._peek()
            if next_tok.kind != "IDENT" or next_tok.value.lower() in (_KEYWORDS - {"by"}):
                raise ParseError(
                    f"Expected column identifier after comma at pos {comma_tok.pos}"
                )
            cols.append(self._parse_col_name())
        return cols

    # ------------------------------------------------------------------
    # Aggregation list (supports alias = agg() and agg() as alias)
    # ------------------------------------------------------------------

    def _parse_agg_list(self) -> List[AggFunction]:
        aggs: List[AggFunction] = []
        agg = self._parse_agg_function()
        aggs.append(agg)
        while self._peek_kind("COMMA"):
            comma_tok = self._advance()
            if self._peek_ident("by") or self._peek_kind("PIPE", "EOF"):
                raise ParseError(
                    f"Expected aggregation function after comma at pos {comma_tok.pos}"
                )
            agg = self._parse_agg_function()
            aggs.append(agg)
        return aggs

    def _parse_agg_function(self) -> AggFunction:
        alias: Optional[str] = None

        # Check for assignment syntax: alias = agg(...)
        if self._peek().kind == "IDENT" and self._pos + 1 < len(self._tokens):
            next_tok = self._tokens[self._pos + 1]
            if next_tok.kind == "OP" and next_tok.value == "=":
                alias = self._advance().value
                self._advance()  # consume "="

        name_tok = self._expect_kind("IDENT")
        name = name_tok.value.lower()
        if name not in _AGG_FUNCTIONS:
            raise ParseError(
                f"Unknown aggregation function {name!r} at pos {name_tok.pos}"
            )

        col: Optional[str] = None
        self._expect_kind("LPAREN")
        if not self._peek_kind("RPAREN"):
            col = self._parse_col_name()
        self._expect_kind("RPAREN")

        # Check for trailing alias syntax: agg(...) as alias
        if alias is None and self._peek_ident("as"):
            self._advance()
            alias_tok = self._expect_kind("IDENT")
            alias = alias_tok.value

        # Default alias if none was specified
        if alias is None:
            alias = f"{name}_" if col is None else f"{name}_{col}"

        return AggFunction(name=name, column=col, alias=alias)

    # ------------------------------------------------------------------
    # Predicate parsing (recursive descent with precedence)
    # ------------------------------------------------------------------

    def _parse_or_expr(self) -> Any:
        left = self._parse_and_expr()
        while self._peek_ident("or"):
            self._advance()
            right = self._parse_and_expr()
            left = BinaryOp(op="or", left=left, right=right)
        return left

    def _parse_and_expr(self) -> Any:
        left = self._parse_not_expr()
        while self._peek_ident("and"):
            self._advance()
            right = self._parse_not_expr()
            left = BinaryOp(op="and", left=left, right=right)
        return left

    def _parse_not_expr(self) -> Any:
        if self._peek_ident("not"):
            self._advance()
            operand = self._parse_not_expr()
            return UnaryOp(op="not", operand=operand)
        return self._parse_comparison()

    def _parse_comparison(self) -> Any:
        left = self._parse_atom()

        # "in" operator: col in (val, val, ...)
        if self._peek_ident("in"):
            self._advance()
            self._expect_kind("LPAREN")
            values = self._parse_literal_list()
            self._expect_kind("RPAREN")
            return BinaryOp(op="in", left=left, right=values)

        # Binary comparison operators
        tok = self._peek()
        if tok.kind == "OP":
            if tok.value == "=":
                raise ParseError(
                    f"Unexpected operator '=' at pos {tok.pos}; did you mean '=='?"
                )
            if tok.value.lower() not in _BINARY_OPS:
                raise ParseError(f"Unexpected operator {tok.value!r} at pos {tok.pos}")
            op_tok = self._advance()
            right = self._parse_atom()
            return BinaryOp(op=op_tok.value.lower(), left=left, right=right)

        if tok.kind == "IDENT" and tok.value.lower() in _BINARY_OPS:
            op_tok = self._advance()
            right = self._parse_atom()
            return BinaryOp(op=op_tok.value.lower(), left=left, right=right)

        return left

    def _parse_atom(self) -> Any:
        tok = self._peek()

        if tok.kind == "STRING":
            self._advance()
            raw = tok.value
            # Strip surrounding quotes
            if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
                quote_char = raw[0]
                raw = raw[1:-1]
                # Unescape doubled quotes
                if quote_char == '"':
                    raw = raw.replace('""', '"')
                else:
                    raw = raw.replace("''", "'")
            # Unescape backslash escape sequences
            raw = (
                raw.replace('\\"', '"')
                .replace("\\'", "'")
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\r", "\r")
                .replace("\\\\", "\\")
            )
            return Literal(value=raw)

        if tok.kind == "FLOAT":
            self._advance()
            return Literal(value=float(tok.value))

        if tok.kind == "INT":
            self._advance()
            return Literal(value=int(tok.value))

        if tok.kind == "IDENT":
            lv = tok.value.lower()
            # ago(...) relative time function
            if lv == "ago" and self._pos + 1 < len(self._tokens) and self._tokens[self._pos + 1].kind == "LPAREN":
                ago_tok = self._advance()  # consume "ago"
                self._expect_kind("LPAREN")
                dur_parts = []
                while not self._peek_kind("RPAREN", "EOF"):
                    dur_tok = self._advance()
                    dur_parts.append(dur_tok.value)
                self._expect_kind("RPAREN")
                duration_str = "".join(dur_parts).strip("\"'")
                m = _DURATION_RE.match(duration_str) if duration_str else None
                if not m or m.group(2).lower() not in _VALID_DURATION_UNITS:
                    raise ParseError(
                        f"Invalid duration format for ago(): {duration_str!r} at pos {ago_tok.pos}"
                    )
                return FunctionCall(name="ago", args=[Literal(value=duration_str)])

            # Boolean & Null literals (only if not dotted identifier)
            if self._pos + 1 < len(self._tokens) and self._tokens[self._pos + 1].kind != "DOT":
                if lv == "true":
                    self._advance()
                    return Literal(value=True)
                if lv == "false":
                    self._advance()
                    return Literal(value=False)
                if lv == "null":
                    self._advance()
                    return Literal(value=None)

            name = self._parse_col_name()
            return ColumnRef(name=name)

        if tok.kind == "LPAREN":
            self._advance()
            expr = self._parse_or_expr()
            self._expect_kind("RPAREN")
            return expr

        raise ParseError(f"Unexpected token {tok.value!r} at pos {tok.pos}")

    def _parse_literal_list(self) -> List[Literal]:
        literals: List[Literal] = []
        if self._peek_kind("RPAREN"):
            raise ParseError("Expected at least one literal value inside in(...)")

        while True:
            atom = self._parse_atom()
            if not isinstance(atom, Literal):
                raise ParseError(
                    f"Only literals are allowed inside in(...), got {atom!r}"
                )
            literals.append(atom)
            if self._peek_kind("COMMA"):
                comma_tok = self._advance()
                if self._peek_kind("RPAREN", "EOF"):
                    raise ParseError(
                        f"Expected literal value after comma at pos {comma_tok.pos}"
                    )
                continue
            break

        if not literals:
            raise ParseError("Expected at least one literal value inside in(...)")
        return literals


class KqlParser:
    """Entry point for parsing KQL-Lite pipeline strings."""

    @classmethod
    def parse(cls, kql_text: str) -> KqlPipeline:
        tokens = tokenize(kql_text)
        parser = _Parser(tokens)
        return parser.parse_pipeline()


def parse(query: str) -> KqlPipeline:
    """
    Parse a KQL-Lite query string into a :class:`KqlPipeline` AST.

    Raises :class:`ParseError` on syntax errors.
    """
    return KqlParser.parse(query)
