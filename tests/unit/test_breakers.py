"""Unit tests for agentxdr.breakers: execution ceilings and loop circuit breakers."""

from __future__ import annotations

import time
import pytest
from pydantic import ValidationError

from agentxdr.breakers import CircuitBreaker, CircuitBreakerVerdict
from agentxdr.models import BudgetsConfig


@pytest.fixture
def budgets() -> BudgetsConfig:
    return BudgetsConfig(
        max_turns=3,
        max_tool_calls=5,
        max_identical_calls=2,
        max_session_duration_sec=0.1,
        max_session_cost_usd=1.0,
    )


class TestCircuitBreaker:
    """Unit tests for CircuitBreaker."""

    def test_turn_budget_enforcement(self, budgets: BudgetsConfig):
        cb = CircuitBreaker(budgets)
        trace_id = "trace-turns"

        # Turns 1, 2, 3 allowed
        for i in range(1, 4):
            v = cb.record_turn(trace_id)
            assert v.is_tripped is False
            assert v.current_value == i

        # Turn 4 trips
        v4 = cb.record_turn(trace_id)
        assert v4.is_tripped is True
        assert v4.limit_name == "max_turns"
        assert v4.current_value == 4

        # Turn 5 remains tripped
        v5 = cb.record_turn(trace_id)
        assert v5.is_tripped is True

    def test_cumulative_tool_calls_enforcement(self, budgets: BudgetsConfig):
        cb = CircuitBreaker(budgets)
        trace_id = "trace-tools"

        for i in range(1, 6):
            v = cb.record_tool_call(trace_id, f"tool_{i}", {"arg": i})
            assert v.is_tripped is False
            assert v.current_value == i

        # Call 6 trips
        v6 = cb.record_tool_call(trace_id, "tool_6", {"arg": 6})
        assert v6.is_tripped is True
        assert v6.limit_name == "max_tool_calls"

    def test_identical_call_loop_breaker(self, budgets: BudgetsConfig):
        cb = CircuitBreaker(budgets)  # max_identical_calls = 2
        trace_id = "trace-loop"

        # 1st call
        v1 = cb.record_tool_call(trace_id, "search", {"q": "term"})
        assert v1.is_tripped is False

        # 2nd call (identical)
        v2 = cb.record_tool_call(trace_id, "search", {"q": "term"})
        assert v2.is_tripped is False

        # 3rd call (identical) trips
        v3 = cb.record_tool_call(trace_id, "search", {"q": "term"})
        assert v3.is_tripped is True
        assert v3.limit_name == "max_identical_calls"

    def test_interleaved_call_resets_identical_streak(self, budgets: BudgetsConfig):
        cb = CircuitBreaker(budgets)
        trace_id = "trace-reset-streak"

        cb.record_tool_call(trace_id, "search", {"q": "term"})
        cb.record_tool_call(trace_id, "search", {"q": "term"})

        # Different call resets streak
        cb.record_tool_call(trace_id, "other_tool", {})

        # Same search call again starts at count 1 -> passes
        v = cb.record_tool_call(trace_id, "search", {"q": "term"})
        assert v.is_tripped is False

    def test_duration_breaker(self, budgets: BudgetsConfig):
        cb = CircuitBreaker(budgets)  # duration = 0.1s
        trace_id = "trace-duration"

        cb.record_turn(trace_id)
        time.sleep(0.15)

        v = cb.check_duration(trace_id)
        assert v.is_tripped is True
        assert v.limit_name == "max_session_duration_sec"

    def test_cost_breaker(self, budgets: BudgetsConfig):
        cb = CircuitBreaker(budgets)  # cost = $1.00
        trace_id = "trace-cost"

        v1 = cb.record_cost(trace_id, 0.40)
        assert v1.is_tripped is False
        assert pytest.approx(v1.current_value) == 0.40

        v2 = cb.record_cost(trace_id, 0.40)
        assert v2.is_tripped is False
        assert pytest.approx(v2.current_value) == 0.80

        # Exceeds $1.00
        v3 = cb.record_cost(trace_id, 0.30)
        assert v3.is_tripped is True
        assert v3.limit_name == "max_session_cost_usd"
        assert pytest.approx(v3.current_value) == 1.10

    def test_negative_cost_raises_value_error(self, budgets: BudgetsConfig):
        cb = CircuitBreaker(budgets)
        with pytest.raises(ValueError):
            cb.record_cost("trace-neg", -0.50)

    def test_reset_trace(self, budgets: BudgetsConfig):
        cb = CircuitBreaker(budgets)
        trace_id = "trace-to-reset"

        for _ in range(4):
            cb.record_turn(trace_id)
        assert cb.record_turn(trace_id).is_tripped is True

        cb.reset(trace_id)
        fresh_v = cb.record_turn(trace_id)
        assert fresh_v.is_tripped is False
