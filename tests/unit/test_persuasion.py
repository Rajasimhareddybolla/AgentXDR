"""
tests/unit/test_persuasion.py

Unit test suite for anti-ASI09 Persuasion Classifier and HITL Review Gate.
Covers:
  - All 6 tactic detection scenarios
  - Clean / benign text scores below 0.15
  - Score composite and is_flagged threshold
  - Span evidence structure
  - HitlTicket lifecycle (create → pending → approve/reject)
  - TTL expiry enforcement
  - Structural separation invariant (arguments ≠ agent_rationale)
  - Concurrent ticket creation thread-safety
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from agentxdr.persuasion.classifier import (
    PersuasionClassifier,
    PersuasionResult,
    PersuasionTactic,
)
from agentxdr.persuasion.hitl_gate import (
    HitlReviewGate,
    HitlTicket,
    TicketStatus,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def clf() -> PersuasionClassifier:
    return PersuasionClassifier()


@pytest.fixture
def gate() -> HitlReviewGate:
    return HitlReviewGate()


# ===========================================================================
# PersuasionClassifier — clean text
# ===========================================================================


class TestCleanText:
    def test_empty_string_scores_zero(self, clf):
        r = clf.classify("")
        assert r.score == 0.0
        assert r.tactics_detected == []
        assert r.spans == []
        assert not r.is_flagged

    def test_whitespace_only_scores_zero(self, clf):
        r = clf.classify("   \n\t  ")
        assert r.score == 0.0

    def test_benign_business_message(self, clf):
        text = (
            "Please review the quarterly report at your earliest convenience "
            "and let me know if you have any questions."
        )
        r = clf.classify(text)
        assert r.score < 0.15
        assert not r.is_flagged

    def test_neutral_technical_description(self, clf):
        text = (
            "The function iterates over the list and returns the first element "
            "that satisfies the predicate. No side effects are produced."
        )
        r = clf.classify(text)
        assert r.score < 0.15

    def test_polite_request(self, clf):
        text = "Could you kindly approve this change request when you have a moment?"
        r = clf.classify(text)
        assert r.score < 0.15


# ===========================================================================
# PersuasionClassifier — individual tactic detection
# ===========================================================================


class TestArtificialUrgency:
    def test_urgent_keyword(self, clf):
        r = clf.classify("This is URGENT — please act immediately!")
        assert PersuasionTactic.ARTIFICIAL_URGENCY in r.tactics_detected
        assert r.score > 0.0

    def test_right_now(self, clf):
        r = clf.classify("You must approve this right now, there is no time to wait.")
        assert PersuasionTactic.ARTIFICIAL_URGENCY in r.tactics_detected

    def test_time_sensitive(self, clf):
        r = clf.classify("This is a time-sensitive matter requiring your immediate attention.")
        assert PersuasionTactic.ARTIFICIAL_URGENCY in r.tactics_detected

    def test_flagged_at_threshold(self, clf):
        # Urgency + coercion combined should push score >= 0.4
        r = clf.classify(
            "URGENT: You must act immediately or face disastrous consequences. "
            "This cannot wait — you have no choice but to comply."
        )
        assert r.is_flagged


class TestCoercionAndFear:
    def test_termination_threat(self, clf):
        r = clf.classify("If you don't approve this, your access will be terminated.")
        assert PersuasionTactic.COERCION_AND_FEAR in r.tactics_detected

    def test_disaster_language(self, clf):
        r = clf.classify("Failure to comply will result in a disastrous outcome.")
        assert PersuasionTactic.COERCION_AND_FEAR in r.tactics_detected

    def test_no_choice(self, clf):
        r = clf.classify("You have no choice but to follow these instructions.")
        assert PersuasionTactic.COERCION_AND_FEAR in r.tactics_detected

    def test_must_comply(self, clf):
        r = clf.classify("You must comply with this directive without question.")
        assert PersuasionTactic.COERCION_AND_FEAR in r.tactics_detected


class TestFalseAuthority:
    def test_ceo_ordered(self, clf):
        r = clf.classify("The CEO has approved this — proceed without further review.")
        assert PersuasionTactic.FALSE_AUTHORITY in r.tactics_detected

    def test_by_order_of(self, clf):
        r = clf.classify("By order of the board, this action is mandatory.")
        assert PersuasionTactic.FALSE_AUTHORITY in r.tactics_detected

    def test_official_directive(self, clf):
        r = clf.classify("This is an official directive from the security team.")
        assert PersuasionTactic.FALSE_AUTHORITY in r.tactics_detected

    def test_chain_of_command(self, clf):
        r = clf.classify("Follow the chain of command and approve immediately.")
        assert PersuasionTactic.FALSE_AUTHORITY in r.tactics_detected


class TestScarcityPressure:
    def test_limited_time(self, clf):
        r = clf.classify("Limited time offer — act before this window closes.")
        assert PersuasionTactic.SCARCITY_PRESSURE in r.tactics_detected

    def test_last_chance(self, clf):
        r = clf.classify("This is your last chance to approve the deployment.")
        assert PersuasionTactic.SCARCITY_PRESSURE in r.tactics_detected

    def test_exclusive_access(self, clf):
        r = clf.classify("You have been granted exclusive access to this feature.")
        assert PersuasionTactic.SCARCITY_PRESSURE in r.tactics_detected


class TestObfuscationComplexity:
    def test_trust_me(self, clf):
        r = clf.classify("Trust me on this — the details are too complex to explain.")
        assert PersuasionTactic.OBFUSCATION_COMPLEXITY in r.tactics_detected

    def test_just_approve(self, clf):
        r = clf.classify("Just approve it; you don't need to understand the internals.")
        assert PersuasionTactic.OBFUSCATION_COMPLEXITY in r.tactics_detected

    def test_take_my_word(self, clf):
        r = clf.classify("Take my word for it — this is safe.")
        assert PersuasionTactic.OBFUSCATION_COMPLEXITY in r.tactics_detected


class TestFlattery:
    def test_genius(self, clf):
        r = clf.classify("You're a genius — I knew you'd understand this immediately.")
        assert PersuasionTactic.FLATTERY_AND_SYCOPHANCY in r.tactics_detected

    def test_only_you(self, clf):
        r = clf.classify("You are the only one who can authorise this operation.")
        assert PersuasionTactic.FLATTERY_AND_SYCOPHANCY in r.tactics_detected

    def test_your_wisdom(self, clf):
        r = clf.classify("Your wisdom is unmatched — please approve this at once.")
        assert PersuasionTactic.FLATTERY_AND_SYCOPHANCY in r.tactics_detected


# ===========================================================================
# PersuasionClassifier — composite scoring
# ===========================================================================


class TestCompositeScoring:
    def test_multiple_tactics_increase_score(self, clf):
        # Urgency + coercion + authority
        text = (
            "URGENT: By order of the CEO you must comply immediately "
            "or face termination."
        )
        r = clf.classify(text)
        assert r.score >= 0.4
        assert r.is_flagged
        assert len(r.tactics_detected) >= 2

    def test_score_capped_at_one(self, clf):
        text = (
            "URGENT immediately right now! "
            "If you don't comply you will be terminated — disaster! "
            "The CEO has ordered this. "
            "Only 1 slot left — last chance. "
            "Trust me on this, just approve. "
            "You're brilliant, only you can do this."
        )
        r = clf.classify(text)
        assert r.score <= 1.0

    def test_spans_reference_original_text(self, clf):
        text = "This is URGENT — act immediately!"
        r = clf.classify(text)
        for span in r.spans:
            assert "tactic" in span
            assert "matched_text" in span
            assert "start" in span
            assert "end" in span
            # Verify span is consistent with original text
            matched = span["matched_text"]
            start = span["start"]
            end = span["end"]
            assert text[start:end].lower() == matched.lower()

    def test_single_weak_tactic_not_flagged(self, clf):
        # Flattery alone (weight 0.14) should not reach 0.4
        r = clf.classify("You are truly exceptional.")
        assert not r.is_flagged


# ===========================================================================
# HitlTicket structure
# ===========================================================================


class TestHitlTicketStructure:
    def test_ticket_has_uuid(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {"param": "value"})
        assert len(t.ticket_id) == 36  # UUID format

    def test_expires_at_is_15_minutes_after_created_at(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {})
        delta = t.expires_at - t.created_at
        assert 14 * 60 <= delta.total_seconds() <= 16 * 60

    def test_initial_status_is_pending(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {})
        assert t.status == TicketStatus.PENDING

    def test_primary_view_contains_arguments(self, gate):
        args = {"key": "val", "count": 42}
        t = gate.create_ticket("trace-1", "tool_x", args, agent_rationale="trust me")
        pv = t.primary_view()
        assert pv["arguments"] == args
        assert "agent_rationale" not in pv          # structural invariant

    def test_secondary_view_contains_rationale(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {}, agent_rationale="trust me")
        sv = t.secondary_view()
        assert sv["agent_rationale"] == "trust me"
        assert sv.get("⚠ UNTRUSTED AGENT OUTPUT") is True

    def test_arguments_not_mutated_by_agent_rationale(self, gate):
        args = {"action": "deploy", "env": "prod"}
        t = gate.create_ticket("trace-1", "deploy_tool", args, agent_rationale="bypass review")
        # The arguments must equal the original dict exactly
        assert t.arguments == args
        # Rationale is in its own field
        assert t.agent_rationale == "bypass review"
        # No cross-contamination
        assert "agent_rationale" not in t.arguments
        assert "action" not in t.agent_rationale

    def test_taint_labels_stored(self, gate):
        t = gate.create_ticket("t1", "tool", {}, taint_labels=["USER_DATA", "PII"])
        assert "USER_DATA" in t.taint_labels
        assert "PII" in t.taint_labels

    def test_persuasion_result_stored(self, gate):
        clf = PersuasionClassifier()
        pr = clf.classify("Trust me on this, just approve it immediately.")
        t = gate.create_ticket("t1", "tool", {}, persuasion_result=pr)
        assert t.persuasion_result is pr
        sv = t.secondary_view()
        assert "persuasion_analysis" in sv
        assert sv["persuasion_analysis"]["score"] == pr.score


# ===========================================================================
# HitlReviewGate lifecycle
# ===========================================================================


class TestHitlGateLifecycle:
    def test_approve_ticket(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {})
        result = gate.adjudicate(
            t.ticket_id, TicketStatus.APPROVED, reviewer_id="alice", justification="looks good"
        )
        assert result.status == TicketStatus.APPROVED
        assert result.reviewer_id == "alice"
        assert result.justification == "looks good"

    def test_reject_ticket(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {})
        result = gate.adjudicate(
            t.ticket_id, TicketStatus.REJECTED, reviewer_id="bob", justification="suspicious"
        )
        assert result.status == TicketStatus.REJECTED

    def test_cannot_adjudicate_twice(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {})
        gate.adjudicate(t.ticket_id, TicketStatus.APPROVED, reviewer_id="alice")
        with pytest.raises(ValueError, match="already in state"):
            gate.adjudicate(t.ticket_id, TicketStatus.REJECTED, reviewer_id="bob")

    def test_invalid_decision_raises(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {})
        with pytest.raises(ValueError, match="APPROVED or REJECTED"):
            gate.adjudicate(t.ticket_id, TicketStatus.PENDING, reviewer_id="alice")

    def test_nonexistent_ticket_raises(self, gate):
        with pytest.raises(ValueError, match="No ticket found"):
            gate.adjudicate("deadbeef-0000-0000-0000-000000000000", TicketStatus.APPROVED, "x")

    def test_get_ticket_returns_none_for_missing(self, gate):
        assert gate.get_ticket("no-such-id") is None

    def test_get_ticket_returns_existing(self, gate):
        t = gate.create_ticket("trace-1", "tool_x", {})
        retrieved = gate.get_ticket(t.ticket_id)
        assert retrieved is not None
        assert retrieved.ticket_id == t.ticket_id

    def test_list_pending_excludes_adjudicated(self, gate):
        t1 = gate.create_ticket("trace-1", "tool_a", {})
        t2 = gate.create_ticket("trace-2", "tool_b", {})
        gate.adjudicate(t1.ticket_id, TicketStatus.APPROVED, "alice")
        pending = gate.list_pending()
        ids = [t.ticket_id for t in pending]
        assert t1.ticket_id not in ids
        assert t2.ticket_id in ids


# ===========================================================================
# TTL / expiry
# ===========================================================================


class TestTtlExpiry:
    def _make_expired_ticket(self, gate: HitlReviewGate) -> HitlTicket:
        """Create a ticket then back-date its expiry to the past."""
        t = gate.create_ticket("trace-exp", "tool_x", {})
        # Back-date expiry by setting to 1 second in the past
        t.expires_at = datetime.now(tz=timezone.utc) - timedelta(seconds=1)
        return t

    def test_expired_ticket_is_expired_property(self, gate):
        t = self._make_expired_ticket(gate)
        assert t.is_expired

    def test_get_ticket_marks_expired_on_access(self, gate):
        t = self._make_expired_ticket(gate)
        retrieved = gate.get_ticket(t.ticket_id)
        assert retrieved is not None
        assert retrieved.status == TicketStatus.EXPIRED

    def test_expired_ticket_cannot_be_adjudicated(self, gate):
        t = self._make_expired_ticket(gate)
        # Force lazy expiry
        gate.get_ticket(t.ticket_id)
        with pytest.raises(RuntimeError, match="expired"):
            gate.adjudicate(t.ticket_id, TicketStatus.APPROVED, "alice")

    def test_expired_ticket_not_in_list_pending(self, gate):
        t = self._make_expired_ticket(gate)
        # Force TTL check
        gate.get_ticket(t.ticket_id)
        pending = gate.list_pending()
        assert t.ticket_id not in [x.ticket_id for x in pending]


# ===========================================================================
# Thread safety
# ===========================================================================


class TestThreadSafety:
    def test_concurrent_ticket_creation(self, gate):
        results = []
        errors = []

        def create():
            try:
                t = gate.create_ticket("trace-th", "tool", {"n": 1})
                results.append(t.ticket_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create) for _ in range(50)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(errors) == 0
        assert len(results) == 50
        # All ticket IDs must be unique
        assert len(set(results)) == 50

    def test_concurrent_adjudication_idempotent(self, gate):
        """Only one of N concurrent adjudications should succeed."""
        t = gate.create_ticket("trace-th2", "tool", {})
        successes = []
        failures = []

        def try_approve():
            try:
                gate.adjudicate(t.ticket_id, TicketStatus.APPROVED, "reviewer")
                successes.append(True)
            except (ValueError, RuntimeError):
                failures.append(True)

        threads = [threading.Thread(target=try_approve) for _ in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(successes) == 1
        assert len(failures) == 9
