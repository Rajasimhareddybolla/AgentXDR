"""
tests/unit/test_kql_compiler.py

Unit tests for the KQL-Lite tokenizer, parser, and compiler.
"""
from __future__ import annotations

import pytest

from agentxdr.analytics.kql.ast import (
    BinaryOp,
    ColumnRef,
    KqlPipeline,
    Literal,
    ProjectClause,
    SortClause,
    SummarizeClause,
    TableSource,
    TakeClause,
    UnaryOp,
    WhereClause,
)
from agentxdr.analytics.kql.compiler import KqlCompiler, CompiledQuery
from agentxdr.analytics.kql.parser import ParseError, parse, tokenize


# ===========================================================================
# Tokenizer
# ===========================================================================


class TestTokenizer:
    def test_simple_identifier(self):
        tokens = tokenize("events")
        kinds = [t.kind for t in tokens if t.kind != "EOF"]
        assert kinds == ["IDENT"]

    def test_pipe_separated(self):
        tokens = tokenize("events | take 10")
        kinds = [t.kind for t in tokens if t.kind != "EOF"]
        assert "PIPE" in kinds
        assert "IDENT" in kinds
        assert "INT" in kinds

    def test_string_double_quoted(self):
        tokens = tokenize('"hello world"')
        t = [t for t in tokens if t.kind == "STRING"][0]
        assert t.value == '"hello world"'

    def test_string_single_quoted(self):
        tokens = tokenize("'hello'")
        t = [t for t in tokens if t.kind == "STRING"][0]
        assert t.value == "'hello'"

    def test_operators_tokenized(self):
        tokens = tokenize("== != > < >= <=")
        ops = [t.value for t in tokens if t.kind == "OP"]
        assert set(ops) == {"==", "!=", ">", "<", ">=", "<="}

    def test_integer_negative(self):
        tokens = tokenize("-42")
        t = [t for t in tokens if t.kind == "INT"][0]
        assert t.value == "-42"

    def test_float_tokenized(self):
        tokens = tokenize("3.14")
        t = [t for t in tokens if t.kind == "FLOAT"][0]
        assert t.value == "3.14"

    def test_whitespace_skipped(self):
        tokens = tokenize("  events   ")
        kinds = [t.kind for t in tokens if t.kind != "EOF"]
        assert kinds == ["IDENT"]


# ===========================================================================
# Parser — basic pipeline structure
# ===========================================================================


class TestParserStructure:
    def test_table_only(self):
        p = parse("events")
        assert isinstance(p, KqlPipeline)
        assert p.source.name == "events"
        assert p.operators == []

    def test_where_clause_parsed(self):
        p = parse("events | where verdict == 'BLOCK'")
        assert len(p.operators) == 1
        wc = p.operators[0]
        assert isinstance(wc, WhereClause)
        pred = wc.predicate
        assert isinstance(pred, BinaryOp)
        assert pred.op == "=="
        assert isinstance(pred.left, ColumnRef)
        assert pred.left.name == "verdict"
        assert isinstance(pred.right, Literal)
        assert pred.right.value == "BLOCK"

    def test_take_clause_parsed(self):
        p = parse("events | take 20")
        tc = p.operators[0]
        assert isinstance(tc, TakeClause)
        assert tc.count == 20

    def test_project_clause_parsed(self):
        p = parse("events | project event_id, verdict, tool_name")
        pc = p.operators[0]
        assert isinstance(pc, ProjectClause)
        assert pc.columns == ["event_id", "verdict", "tool_name"]

    def test_sort_asc_desc(self):
        p = parse("events | sort by risk_score desc, event_id asc")
        sc = p.operators[0]
        assert isinstance(sc, SortClause)
        assert sc.keys[0] == ("risk_score", False)
        assert sc.keys[1] == ("event_id", True)

    def test_summarize_by(self):
        p = parse("events | summarize count() by verdict")
        sc = p.operators[0]
        assert isinstance(sc, SummarizeClause)
        assert sc.aggregations[0].name == "count"
        assert sc.by_columns == ["verdict"]

    def test_multiple_operators(self):
        p = parse("events | where verdict == 'BLOCK' | sort by risk_score desc | take 5")
        assert len(p.operators) == 3
        assert isinstance(p.operators[0], WhereClause)
        assert isinstance(p.operators[1], SortClause)
        assert isinstance(p.operators[2], TakeClause)

    def test_and_predicate(self):
        p = parse("events | where verdict == 'BLOCK' and owasp_id == 'ASI01'")
        wc = p.operators[0]
        pred = wc.predicate
        assert isinstance(pred, BinaryOp)
        assert pred.op == "and"

    def test_or_predicate(self):
        p = parse("events | where verdict == 'BLOCK' or verdict == 'ALERT'")
        wc = p.operators[0]
        pred = wc.predicate
        assert pred.op == "or"

    def test_not_predicate(self):
        p = parse("events | where not verdict == 'ALLOW'")
        wc = p.operators[0]
        pred = wc.predicate
        assert isinstance(pred, UnaryOp)
        assert pred.op == "not"

    def test_in_predicate(self):
        p = parse("events | where verdict in ('BLOCK', 'ALERT')")
        wc = p.operators[0]
        pred = wc.predicate
        assert isinstance(pred, BinaryOp)
        assert pred.op == "in"
        assert len(pred.right) == 2

    def test_has_predicate(self):
        p = parse("events | where tool_name has 'write'")
        wc = p.operators[0]
        pred = wc.predicate
        assert pred.op == "has"

    def test_contains_predicate(self):
        p = parse("events | where tool_name contains 'file'")
        wc = p.operators[0]
        pred = wc.predicate
        assert pred.op == "contains"

    def test_integer_literal(self):
        p = parse("events | where step_index > 5")
        pred = p.operators[0].predicate
        assert pred.right.value == 5

    def test_boolean_literal_true(self):
        p = parse("events | where is_flagged == true")
        pred = p.operators[0].predicate
        assert pred.right.value is True

    def test_boolean_literal_false(self):
        p = parse("events | where is_active == false")
        pred = p.operators[0].predicate
        assert pred.right.value is False


# ===========================================================================
# Parser — error cases
# ===========================================================================


class TestParserErrors:
    def test_unknown_operator_raises(self):
        with pytest.raises(ParseError, match="Unknown operator"):
            parse("events | explode col")

    def test_missing_take_count_raises(self):
        with pytest.raises(ParseError):
            parse("events | take abc")

    def test_in_with_non_literal_raises(self):
        with pytest.raises(ParseError):
            parse("events | where col in (other_col)")


class TestParserHardeningValidations:
    """Tests for the 5 parser validations requested in Challenger 1 audit."""

    # 1. Comparison Operator Validation
    def test_single_equals_operator_raises_parse_error(self):
        with pytest.raises(ParseError, match="did you mean '=='"):
            parse('events | where severity = "CRITICAL"')

    def test_arithmetic_plus_operator_raises_parse_error(self):
        with pytest.raises(ParseError, match="Unexpected operator"):
            parse("events | where x + 1")

    def test_arithmetic_minus_operator_raises_parse_error(self):
        with pytest.raises(ParseError, match="Unexpected operator"):
            parse("events | where x - 1")

    def test_arithmetic_multiply_operator_raises_parse_error(self):
        with pytest.raises(ParseError, match="Unexpected operator"):
            parse("events | where x * 2")

    def test_arithmetic_divide_operator_raises_parse_error(self):
        with pytest.raises(ParseError, match="Unexpected operator"):
            parse("events | where x / 2")

    def test_negation_exclamation_operator_raises_parse_error(self):
        with pytest.raises(ParseError, match="Unexpected operator"):
            parse("events | where x ! y")

    # 2. Aggregation Function Whitelist
    def test_unknown_agg_function_raises_parse_error(self):
        with pytest.raises(ParseError, match="Unknown aggregation function 'cout'"):
            parse("events | summarize cout() by agent_id")

    def test_unknown_agg_function_with_alias_raises_parse_error(self):
        with pytest.raises(ParseError, match="Unknown aggregation function 'ckunt'"):
            parse("events | summarize failure_count = ckunt() by agent_id")

    def test_unknown_agg_function_mx_raises_parse_error(self):
        with pytest.raises(ParseError, match="Unknown aggregation function 'mx'"):
            parse("events | summarize mx(risk_score) by agent_id")

    @pytest.mark.parametrize("agg", ["count", "sum", "avg", "min", "max", "dcount"])
    def test_whitelisted_agg_functions_succeed(self, agg):
        col_arg = "" if agg == "count" else "risk_score"
        p = parse(f"events | summarize {agg}({col_arg}) by agent_id")
        assert len(p.operators) == 1

    # 3. ago(...) Duration Validation
    def test_malformed_ago_characters_raises_parse_error(self):
        with pytest.raises(ParseError, match="Invalid duration format for ago"):
            parse("AgentEvents | where timestamp > ago(||4h)")

    def test_empty_ago_raises_parse_error(self):
        with pytest.raises(ParseError, match="Invalid duration format for ago"):
            parse("AgentEvents | where timestamp > ago()")

    def test_ago_missing_unit_raises_parse_error(self):
        with pytest.raises(ParseError, match="Invalid duration format for ago"):
            parse("AgentEvents | where timestamp > ago(100)")

    def test_ago_invalid_unit_raises_parse_error(self):
        with pytest.raises(ParseError, match="Invalid duration format for ago"):
            parse("AgentEvents | where timestamp > ago(5xyz)")

    def test_ago_missing_number_raises_parse_error(self):
        with pytest.raises(ParseError, match="Invalid duration format for ago"):
            parse("AgentEvents | where timestamp > ago(hours)")

    # 4. Non-Empty Clause Enforcements
    def test_empty_project_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected at least one column after 'project'"):
            parse("events | project")

    def test_project_trailing_comma_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected column identifier after comma"):
            parse("events | project col,")

    def test_project_trailing_comma_before_pipe_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected column identifier after comma"):
            parse("events | project col, | where x == 1")

    def test_empty_summarize_by_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected at least one column after 'by'"):
            parse("events | summarize count() by")

    def test_summarize_by_trailing_comma_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected column identifier after comma"):
            parse("events | summarize count() by agent_id,")

    def test_summarize_comma_before_by_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected aggregation function after comma"):
            parse("events | summarize count(), by agent_id")

    def test_summarize_trailing_comma_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected aggregation function after comma"):
            parse("events | summarize count(),")

    # 5. Non-Empty IN Clause Enforcement
    def test_empty_in_clause_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected at least one literal value inside in"):
            parse("events | where x in ()")

    def test_empty_in_clause_with_whitespace_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected at least one literal value inside in"):
            parse("events | where x in (   )")

    def test_in_clause_trailing_comma_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected literal value after comma"):
            parse("events | where x in ('a', 'b',)")

    def test_in_clause_single_trailing_comma_raises_parse_error(self):
        with pytest.raises(ParseError, match="Expected literal value after comma"):
            parse("events | where x in (1,)")


# ===========================================================================
# Compiler — SQL generation
# ===========================================================================


class TestCompilerSql:
    def _compile(self, kql: str) -> CompiledQuery:
        return KqlCompiler().compile(parse(kql))

    def test_simple_select_all(self):
        c = self._compile("events")
        assert c.sql == 'SELECT * FROM "events"'
        assert c.params == []

    def test_where_eq(self):
        c = self._compile("events | where verdict == 'BLOCK'")
        assert "WHERE" in c.sql
        assert '"verdict" = ?' in c.sql
        assert c.params == ["BLOCK"]

    def test_where_neq(self):
        c = self._compile("events | where verdict != 'ALLOW'")
        assert '"verdict" != ?' in c.sql

    def test_where_gt(self):
        c = self._compile("events | where risk_score > 0.5")
        assert '"risk_score" > ?' in c.sql
        assert c.params == [0.5]

    def test_where_lt(self):
        c = self._compile("events | where step_index < 10")
        assert '"step_index" < ?' in c.sql

    def test_take_generates_limit(self):
        c = self._compile("events | take 25")
        assert "LIMIT 25" in c.sql

    def test_project_generates_select_cols(self):
        c = self._compile("events | project event_id, verdict")
        assert '"event_id"' in c.sql
        assert '"verdict"' in c.sql
        assert "*" not in c.sql

    def test_sort_desc(self):
        c = self._compile("events | sort by risk_score desc")
        assert "ORDER BY" in c.sql
        assert '"risk_score" DESC' in c.sql

    def test_sort_asc_default(self):
        c = self._compile("events | sort by event_id asc")
        assert '"event_id" ASC' in c.sql

    def test_summarize_count(self):
        c = self._compile("events | summarize count() by verdict")
        assert "count(*)" in c.sql
        assert "GROUP BY" in c.sql
        assert '"verdict"' in c.sql

    def test_summarize_sum(self):
        c = self._compile("events | summarize sum(risk_score) by agent_id")
        assert "sum(" in c.sql
        assert '"risk_score"' in c.sql

    def test_summarize_dcount(self):
        c = self._compile("events | summarize dcount(agent_id)")
        assert "count(DISTINCT" in c.sql

    def test_and_generates_and(self):
        c = self._compile("events | where verdict == 'BLOCK' and owasp_id == 'ASI01'")
        assert "AND" in c.sql
        assert c.params == ["BLOCK", "ASI01"]

    def test_or_generates_or(self):
        c = self._compile("events | where verdict == 'BLOCK' or verdict == 'ALERT'")
        assert "OR" in c.sql

    def test_not_generates_not(self):
        c = self._compile("events | where not verdict == 'ALLOW'")
        assert "NOT" in c.sql

    def test_in_generates_in_clause(self):
        c = self._compile("events | where verdict in ('BLOCK', 'ALERT')")
        assert "IN (" in c.sql
        assert "BLOCK" in c.params
        assert "ALERT" in c.params

    def test_has_generates_ilike(self):
        c = self._compile("events | where tool_name has 'write'")
        assert "ILIKE" in c.sql
        assert c.params == ["%write%"]

    def test_contains_generates_ilike(self):
        c = self._compile("events | where tool_name contains 'file'")
        assert "ILIKE" in c.sql
        assert c.params == ["%file%"]


# ===========================================================================
# SQL injection safety
# ===========================================================================


class TestSqlInjectionSafety:
    def _compile(self, kql: str) -> CompiledQuery:
        return KqlCompiler().compile(parse(kql))

    def test_string_literal_not_interpolated(self):
        """Malicious literal must appear as a bind param, never in SQL text."""
        payload = "'; DROP TABLE events; --"
        c = self._compile(f'events | where verdict == "{payload}"')
        # The payload must NOT appear verbatim in the SQL string
        assert payload not in c.sql
        # It must appear in params
        assert payload in c.params

    def test_integer_literal_not_interpolated(self):
        c = self._compile("events | where step_index > 42")
        assert "42" not in c.sql
        assert 42 in c.params

    def test_invalid_column_name_raises(self):
        from agentxdr.analytics.kql.compiler import _safe_col
        with pytest.raises(ValueError, match="Invalid column name"):
            _safe_col("col; DROP TABLE events")

    def test_multiple_params_ordered_correctly(self):
        c = self._compile(
            "events | where verdict == 'BLOCK' and owasp_id == 'ASI01' and risk_score > 0.5"
        )
        assert c.params == ["BLOCK", "ASI01", 0.5]

    def test_in_list_all_parameterised(self):
        c = self._compile("events | where verdict in ('BLOCK', 'ALERT', 'DENY')")
        assert c.params == ["BLOCK", "ALERT", "DENY"]
        assert "BLOCK" not in c.sql
        assert "ALERT" not in c.sql
        assert "DENY" not in c.sql


# ===========================================================================
# Interface Contracts & Compiler Enhancements
# ===========================================================================


class TestCompilerInterfaceContracts:
    def test_tuple_unpacking(self):
        pipeline = parse("events | where verdict == 'BLOCK' | take 10")
        compiler = KqlCompiler()
        compiled = compiler.compile(pipeline)
        sql, params = compiled
        assert isinstance(compiled, tuple)
        assert sql == compiled.sql
        assert params == compiled.params
        assert params == ["BLOCK"]
        assert "LIMIT 10" in sql

    def test_kql_parser_class_interface(self):
        from agentxdr.analytics.kql.parser import KqlParser
        pipeline = KqlParser.parse("events | take 5")
        assert pipeline.source.name == "events"
        assert len(pipeline.operators) == 1

    def test_dotted_identifier_and_json_arrow(self):
        pipeline = parse("AgentEvents | where payload_redacted.tool_name == 'send_email'")
        c = KqlCompiler().compile(pipeline)
        assert '"payload_redacted"->>\'$.tool_name\'' in c.sql
        assert c.params == ["send_email"]

    def test_ago_function_compiled_to_interval(self):
        pipeline = parse("events | where timestamp > ago(4h)")
        c = KqlCompiler().compile(pipeline)
        assert "(CURRENT_TIMESTAMP - INTERVAL 4 HOUR)" in c.sql
        assert c.params == []

    def test_summarize_alias_assignment(self):
        pipeline = parse("events | summarize failure_count = count() by agent_id")
        c = KqlCompiler().compile(pipeline)
        assert 'count(*) AS "failure_count"' in c.sql
        assert 'GROUP BY "agent_id"' in c.sql

    def test_top_clause_compilation(self):
        pipeline = parse("events | top 25 by risk_score desc")
        c = KqlCompiler().compile(pipeline)
        assert 'ORDER BY "risk_score" DESC' in c.sql
        assert "LIMIT 25" in c.sql

    def test_where_after_summarize_subquery_wrapping(self):
        pipeline = parse("events | summarize cnt = count() by agent_id | where cnt > 5")
        c = KqlCompiler().compile(pipeline)
        assert "SELECT * FROM (" in c.sql
        assert ") AS _sub WHERE" in c.sql
        assert '"cnt" > ?' in c.sql
        assert c.params == [5]

    def test_extended_comparison_operators(self):
        compiler = KqlCompiler()

        c1 = compiler.compile(parse("events | where tool_name startswith 'read_'"))
        assert "ILIKE ?" in c1.sql
        assert c1.params == ["read_%"]

        c2 = compiler.compile(parse("events | where tool_name endswith '_file'"))
        assert "ILIKE ?" in c2.sql
        assert c2.params == ["%_file"]

        c3 = compiler.compile(parse("events | where verdict =~ 'block'"))
        assert "ILIKE ?" in c3.sql
        assert c3.params == ["block"]

        c4 = compiler.compile(parse("events | where verdict !~ 'allow'"))
        assert "NOT (CAST(" in c4.sql
        assert c4.params == ["allow"]

        c5 = compiler.compile(parse("events | where taint_labels !has 'SECRET'"))
        assert "NOT (" in c5.sql
        assert c5.params == ["%SECRET%"]

        c6 = compiler.compile(parse("events | where tool_name !contains 'bash'"))
        assert "NOT (CAST(" in c6.sql
        assert c6.params == ["%bash%"]


# ===========================================================================
# 5 Enterprise Threat Hunting Playbooks
# ===========================================================================


class TestEnterpriseThreatHuntingPlaybooks:
    """Validates the 5 canonical Threat-Hunting Playbooks documented in docs/kql-hunting.md."""

    def test_playbook_1_untrusted_data_egress(self):
        """PB-01: Hunting Untrusted Data Egress (OWASP ASI02 / ASI10)."""
        kql = """
        AgentEvents
        | where timestamp > ago(4h)
        | where taint_labels has "UNTRUSTED_EXTERNAL"
        | where payload_redacted.tool_name in ("send_email", "post_webhook", "http_request")
        | project timestamp, trace_id, agent_id, payload_redacted.tool_name, decision.verdict, drift_snapshot.composite_score
        | sort by timestamp desc
        """
        pipeline = parse(kql)
        assert pipeline.source.name == "AgentEvents"
        assert len(pipeline.operators) == 5

        c = KqlCompiler().compile(pipeline)
        assert "(CURRENT_TIMESTAMP - INTERVAL 4 HOUR)" in c.sql
        assert '"taint_labels" ILIKE ?' in c.sql
        assert '"payload_redacted"->>\'$.tool_name\' IN (?, ?, ?)' in c.sql
        assert 'ORDER BY "timestamp" DESC' in c.sql
        assert "%UNTRUSTED_EXTERNAL%" in c.params
        assert "send_email" in c.params
        assert "post_webhook" in c.params
        assert "http_request" in c.params

    def test_playbook_2_mcp_schema_rug_pulls(self):
        """PB-02: Detecting MCP Schema Rug-Pulls & Shadow MCP Servers (OWASP ASI04)."""
        kql = """
        AgentEvents
        | where timestamp > ago(24h)
        | where event_type == "TOOL_INVOCATION"
        | where decision.rule_id in ("MCP-HASH-MISMATCH", "SHADOW-MCP-DETECTED")
        | summarize failure_count = count(), impacted_traces = dcount(trace_id) by agent_id, payload_redacted.mcp_server, payload_redacted.tool_name
        | sort by failure_count desc
        """
        pipeline = parse(kql)
        c = KqlCompiler().compile(pipeline)

        assert 'count(*) AS "failure_count"' in c.sql
        assert 'count(DISTINCT "trace_id") AS "impacted_traces"' in c.sql
        assert 'GROUP BY "agent_id", "payload_redacted"->>\'$.mcp_server\', "payload_redacted"->>\'$.tool_name\'' in c.sql
        assert 'ORDER BY "failure_count" DESC' in c.sql
        assert "TOOL_INVOCATION" in c.params
        assert "MCP-HASH-MISMATCH" in c.params
        assert "SHADOW-MCP-DETECTED" in c.params

    def test_playbook_3_loop_runaway_detection(self):
        """PB-03: Cascading Failure & Loop Runaway Detection (OWASP ASI08)."""
        kql = """
        AgentEvents
        | where timestamp > ago(2h)
        | where drift_snapshot.s_velocity > 0.70 or decision.rule_id == "ASI08_CIRCUIT_BREAKER_TRIPPED"
        | project timestamp, trace_id, agent_id, drift_snapshot.composite_score, drift_snapshot.s_velocity
        | sort by drift_snapshot.composite_score desc
        | top 25 by drift_snapshot.composite_score
        """
        pipeline = parse(kql)
        c = KqlCompiler().compile(pipeline)

        assert "TRY_CAST(\"drift_snapshot\"->>'$.s_velocity' AS DOUBLE) > ?" in c.sql
        assert '"decision"->>\'$.rule_id\' = ?' in c.sql
        assert "LIMIT 25" in c.sql
        assert 0.70 in c.params
        assert "ASI08_CIRCUIT_BREAKER_TRIPPED" in c.params

    def test_playbook_4_code_sandbox_violations(self):
        """PB-04: Code Execution Sandbox Violations (OWASP ASI05)."""
        kql = """
        AgentEvents
        | where timestamp > ago(12h)
        | where event_type == "SANDBOX_EXEC"
        | where decision.verdict == "BLOCK" or payload_redacted.exit_code != 0
        | project timestamp, trace_id, agent_id, payload_redacted.blocked_import, payload_redacted.error_message
        | sort by timestamp desc
        """
        pipeline = parse(kql)
        c = KqlCompiler().compile(pipeline)

        assert '"event_type" = ?' in c.sql
        assert '"decision"->>\'$.verdict\' = ?' in c.sql
        assert 'TRY_CAST("payload_redacted"->>\'$.exit_code\' AS DOUBLE) != ?' in c.sql
        assert "SANDBOX_EXEC" in c.params
        assert "BLOCK" in c.params
        assert 0 in c.params

    def test_playbook_5_hitl_persuasion_flags(self):
        """PB-05: HITL Approvals with Persuasion Flags (OWASP ASI09)."""
        kql = """
        AgentEvents
        | where timestamp > ago(7d)
        | where event_type == "HITL_DECISION"
        | where payload_redacted.persuasion_score > 0.75
        | project timestamp, trace_id, agent_id, principal.user_id, payload_redacted.tool_name, payload_redacted.decision, payload_redacted.persuasion_score
        | sort by payload_redacted.persuasion_score desc
        """
        pipeline = parse(kql)
        c = KqlCompiler().compile(pipeline)

        assert "TRY_CAST(\"payload_redacted\"->>'$.persuasion_score' AS DOUBLE) > ?" in c.sql
        assert "HITL_DECISION" in c.params
        assert 0.75 in c.params

    def test_playbooks_end_to_end_execution(self):
        """Verify that all 5 playbooks execute against DuckDbAnalyticsStore without errors."""
        import json
        from agentxdr.analytics.duckdb_store import DuckDbAnalyticsStore

        store = DuckDbAnalyticsStore(":memory:")

        # Seed realistic telemetry rows
        for i in range(10):
            p = {"tool_name": "send_email", "mcp_server": "srv-1", "exit_code": 0, "persuasion_score": 0.85}
            d = {"verdict": "BLOCK", "rule_id": "MCP-HASH-MISMATCH", "owasp_ids": ["ASI02"]}
            dr = {"composite_score": 0.88, "s_velocity": 0.75}
            pr = {"user_id": f"usr-{i}"}

            store.execute_query(
                """
                INSERT INTO events (
                    event_id, trace_id, agent_id, event_type,
                    tool_name, verdict, owasp_id, rule_id,
                    risk_score, taint_labels, timestamp_utc, metadata_json,
                    payload_redacted, decision, drift_snapshot, principal
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now(), '{}', ?, ?, ?, ?)
                """,
                [
                    f"e-{i}", f"tr-{i}", "agent-1", "TOOL_INVOCATION",
                    "send_email", "BLOCK", "ASI02", "MCP-HASH-MISMATCH",
                    0.88, "UNTRUSTED_EXTERNAL",
                    json.dumps(p), json.dumps(d), json.dumps(dr), json.dumps(pr),
                ],
            )

        playbooks = [
            # PB 1
            """AgentEvents
            | where timestamp > ago(4h)
            | where taint_labels has "UNTRUSTED_EXTERNAL"
            | where payload_redacted.tool_name in ("send_email", "post_webhook")
            | project timestamp, trace_id, agent_id, payload_redacted.tool_name, decision.verdict
            | sort by timestamp desc""",
            # PB 2
            """AgentEvents
            | where timestamp > ago(24h)
            | where event_type == "TOOL_INVOCATION"
            | where decision.rule_id in ("MCP-HASH-MISMATCH", "SHADOW-MCP-DETECTED")
            | summarize failure_count = count(), impacted_traces = dcount(trace_id) by agent_id, payload_redacted.mcp_server, payload_redacted.tool_name
            | sort by failure_count desc""",
            # PB 3
            """AgentEvents
            | where timestamp > ago(2h)
            | where drift_snapshot.s_velocity > 0.70 or decision.rule_id == "ASI08_CIRCUIT_BREAKER_TRIPPED"
            | project timestamp, trace_id, agent_id, drift_snapshot.composite_score
            | top 25 by drift_snapshot.composite_score""",
            # PB 4
            """AgentEvents
            | where timestamp > ago(12h)
            | where decision.verdict == "BLOCK" or payload_redacted.exit_code != 0
            | project timestamp, trace_id, agent_id
            | sort by timestamp desc""",
            # PB 5
            """AgentEvents
            | where timestamp > ago(7d)
            | where payload_redacted.persuasion_score > 0.75
            | project timestamp, trace_id, agent_id, principal.user_id, payload_redacted.tool_name
            | sort by payload_redacted.persuasion_score desc""",
        ]

        compiler = KqlCompiler()
        for idx, pb in enumerate(playbooks, 1):
            ast = parse(pb)
            c = compiler.compile(ast)
            res = store.execute_query(c.sql, c.params)
            assert isinstance(res, list)
            assert len(res) > 0, f"Playbook {idx} returned empty result"

