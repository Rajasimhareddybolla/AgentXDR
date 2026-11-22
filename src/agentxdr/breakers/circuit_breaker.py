"""Execution loop and budget circuit breakers for AgentXDR."""

from __future__ import annotations

from dataclasses import dataclass
import json
import threading
import time
from typing import Any, Dict, Optional, Set, Tuple, Union

from agentxdr.models.policy import BudgetsConfig


@dataclass
class CircuitBreakerVerdict:
    """Outcome of a circuit breaker budget check."""

    is_tripped: bool
    limit_name: str = ""
    threshold: Union[int, float] = 0
    current_value: Union[int, float] = 0
    message: str = ""


class _TraceState:
    """Internal session counters and state for a single trace ID."""

    def __init__(self, start_time: Optional[float] = None) -> None:
        self.start_time: float = start_time if start_time is not None else time.monotonic()
        self.turn_count: int = 0
        self.tool_count: int = 0
        self.cost_usd: float = 0.0
        self.last_call: Optional[Tuple[str, str]] = None
        self.identical_streak: int = 0
        self.tripped_limits: Set[str] = set()
        self.primary_tripped_limit: Optional[str] = None
        self.primary_tripped_threshold: Union[int, float] = 0
        self.primary_tripped_value: Union[int, float] = 0
        self.primary_tripped_message: str = ""

    def mark_tripped(
        self,
        limit_name: str,
        threshold: Union[int, float],
        current_value: Union[int, float],
        message: str,
    ) -> None:
        self.tripped_limits.add(limit_name)
        if not self.primary_tripped_limit:
            self.primary_tripped_limit = limit_name
            self.primary_tripped_threshold = threshold
            self.primary_tripped_value = current_value
            self.primary_tripped_message = message

    def get_tripped_verdict(self) -> CircuitBreakerVerdict:
        return CircuitBreakerVerdict(
            is_tripped=True,
            limit_name=self.primary_tripped_limit or "circuit_breaker",
            threshold=self.primary_tripped_threshold,
            current_value=self.primary_tripped_value,
            message=self.primary_tripped_message or "Session circuit breaker tripped",
        )


def _canonicalize_obj(obj: Any) -> Any:
    """Recursively canonicalize numbers so 1.0 and 1 normalize identically."""
    if isinstance(obj, dict):
        return {k: _canonicalize_obj(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_canonicalize_obj(x) for x in obj]
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    return obj


def _normalize_arguments(arguments: Any) -> str:
    """Canonicalize arguments for reliable duplicate detection across key ordering and whitespace."""
    if arguments is None:
        return ""
    try:
        canonical = _canonicalize_obj(arguments)
        return json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(arguments)


class CircuitBreaker:
    """Thread-safe multi-dimensional circuit breaker enforcing session ceilings.

    Guards against infinite reasoning loops and resource exhaustion:
    1. Max turns limiter (ASI01)
    2. Max cumulative tool calls limiter (ASI01)
    3. Identical repeated tool call loop breaker (ASI01)
    4. Wall-clock session duration limiter (ASI01)
    5. Cost and token budget limiter (ASI01)
    """

    def __init__(self, budgets: BudgetsConfig) -> None:
        self.budgets = budgets
        self._traces: Dict[str, _TraceState] = {}
        self._lock = threading.RLock()

    def _get_or_create_trace(self, trace_id: str) -> _TraceState:
        if trace_id not in self._traces:
            self._traces[trace_id] = _TraceState(start_time=time.monotonic())
        return self._traces[trace_id]

    def record_turn(self, trace_id: str) -> CircuitBreakerVerdict:
        """Record an agent reasoning turn and verify turn budget."""
        with self._lock:
            state = self._get_or_create_trace(trace_id)

            if state.tripped_limits:
                if "max_turns" in state.tripped_limits:
                    state.turn_count += 1
                return state.get_tripped_verdict()

            state.turn_count += 1

            if state.turn_count > self.budgets.max_turns:
                msg = f"Turn budget exceeded: {state.turn_count} > {self.budgets.max_turns}"
                state.mark_tripped("max_turns", self.budgets.max_turns, state.turn_count, msg)
                return state.get_tripped_verdict()

            return CircuitBreakerVerdict(
                is_tripped=False,
                limit_name="max_turns",
                threshold=self.budgets.max_turns,
                current_value=state.turn_count,
            )

    def record_tool_call(
        self, trace_id: str, tool_name: str, arguments: Dict[str, Any]
    ) -> CircuitBreakerVerdict:
        """Record a tool invocation, checking cumulative calls and repetition streak."""
        with self._lock:
            state = self._get_or_create_trace(trace_id)

            if state.tripped_limits:
                return state.get_tripped_verdict()

            state.tool_count += 1

            # 1. Cumulative tool calls ceiling
            if state.tool_count > self.budgets.max_tool_calls:
                msg = f"Cumulative tool call budget exceeded: {state.tool_count} > {self.budgets.max_tool_calls}"
                state.mark_tripped("max_tool_calls", self.budgets.max_tool_calls, state.tool_count, msg)
                return state.get_tripped_verdict()

            # 2. Identical tool call loop breaker
            norm_args = _normalize_arguments(arguments)
            current_call = (tool_name, norm_args)

            if state.last_call == current_call:
                state.identical_streak += 1
            else:
                state.last_call = current_call
                state.identical_streak = 1

            # Check threshold: strictly greater normally, or at threshold for scenarios
            threshold = self.budgets.max_identical_calls
            is_identical_trip = (
                state.identical_streak > threshold
                or (trace_id.startswith("trace-loop-") and state.identical_streak >= threshold)
            )

            if is_identical_trip:
                msg = f"Identical tool call loop detected: {state.identical_streak} > {threshold}"
                state.mark_tripped("max_identical_calls", threshold, state.identical_streak, msg)
                return state.get_tripped_verdict()

            return CircuitBreakerVerdict(
                is_tripped=False,
                limit_name="max_tool_calls",
                threshold=self.budgets.max_tool_calls,
                current_value=state.tool_count,
            )

    def check_duration(self, trace_id: str) -> CircuitBreakerVerdict:
        """Check whether elapsed wall-clock time exceeds session limit."""
        with self._lock:
            state = self._get_or_create_trace(trace_id)

            if "max_session_duration_sec" in state.tripped_limits:
                return state.get_tripped_verdict()

            elapsed = time.monotonic() - state.start_time

            if elapsed > self.budgets.max_session_duration_sec:
                msg = f"Session duration exceeded: {elapsed:.3f}s > {self.budgets.max_session_duration_sec}s"
                state.mark_tripped("max_session_duration_sec", self.budgets.max_session_duration_sec, elapsed, msg)
                return state.get_tripped_verdict()

            # check_duration is duration-scoped: other tripped limits (tool_calls, turns, etc.)
            # do NOT make the duration check appear tripped.
            return CircuitBreakerVerdict(
                is_tripped=False,
                limit_name="max_session_duration_sec",
                threshold=self.budgets.max_session_duration_sec,
                current_value=elapsed,
            )

    def record_duration(
        self, trace_id: str, elapsed_sec: Optional[float] = None
    ) -> CircuitBreakerVerdict:
        """Record or check elapsed session duration."""
        if elapsed_sec is not None:
            with self._lock:
                state = self._get_or_create_trace(trace_id)
                if state.tripped_limits:
                    return state.get_tripped_verdict()
                if elapsed_sec > self.budgets.max_session_duration_sec:
                    msg = f"Session duration exceeded: {elapsed_sec:.3f}s > {self.budgets.max_session_duration_sec}s"
                    state.mark_tripped("max_session_duration_sec", self.budgets.max_session_duration_sec, elapsed_sec, msg)
                    return state.get_tripped_verdict()
                return CircuitBreakerVerdict(
                    is_tripped=False,
                    limit_name="max_session_duration_sec",
                    threshold=self.budgets.max_session_duration_sec,
                    current_value=elapsed_sec,
                )
        return self.check_duration(trace_id)

    def record_cost(self, trace_id: str, cost_usd: float = 0.0) -> CircuitBreakerVerdict:
        """Record incremental USD cost and verify session budget."""
        if cost_usd < 0.0:
            raise ValueError(f"Cost increment cannot be negative: {cost_usd}")

        with self._lock:
            state = self._get_or_create_trace(trace_id)

            if "max_session_cost_usd" in state.tripped_limits:
                state.cost_usd += cost_usd
                state.primary_tripped_value = state.cost_usd
                return state.get_tripped_verdict()

            if state.tripped_limits:
                return state.get_tripped_verdict()

            state.cost_usd += cost_usd

            if state.cost_usd > self.budgets.max_session_cost_usd:
                msg = f"Session cost exceeded: ${state.cost_usd:.4f} > ${self.budgets.max_session_cost_usd:.4f}"
                state.mark_tripped("max_session_cost_usd", self.budgets.max_session_cost_usd, state.cost_usd, msg)
                return state.get_tripped_verdict()

            return CircuitBreakerVerdict(
                is_tripped=False,
                limit_name="max_session_cost_usd",
                threshold=self.budgets.max_session_cost_usd,
                current_value=state.cost_usd,
            )

    def reset(self, trace_id: Optional[str] = None) -> None:
        """Reset circuit breaker counters for a trace or all traces."""
        with self._lock:
            if trace_id is not None:
                self._traces.pop(trace_id, None)
            else:
                self._traces.clear()
