"""
agentxdr.analytics.kql — KQL-Lite tokenizer, parser, and compiler.
"""
from agentxdr.analytics.kql.ast import (
    AggFunction,
    BinaryOp,
    ColumnRef,
    FunctionCall,
    KqlPipeline,
    KqlQuery,
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
from agentxdr.analytics.kql.compiler import (
    CompiledQuery,
    KqlCompiler,
    KqlQueryResult,
)
from agentxdr.analytics.kql.parser import KqlParser, ParseError, parse, tokenize

__all__ = [
    # AST
    "TableSource",
    "WhereClause",
    "ProjectClause",
    "SummarizeClause",
    "TakeClause",
    "SortClause",
    "TopClause",
    "KqlPipeline",
    "KqlQuery",
    "BinaryOp",
    "UnaryOp",
    "ColumnRef",
    "Literal",
    "FunctionCall",
    "AggFunction",
    # Parser
    "tokenize",
    "parse",
    "ParseError",
    "KqlParser",
    # Compiler
    "KqlCompiler",
    "CompiledQuery",
    "KqlQueryResult",
]
