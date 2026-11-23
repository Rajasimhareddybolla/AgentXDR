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

from agentxdr.models.events import HitlDecisionPayload, ToolTier, Verdict
from agentxdr.models.policy import ToolPolicy
from agentxdr.persuasion.classifier import (
    PersuasionClassifier,
    PersuasionResult,
    PersuasionRiskLevel,
    PersuasionSpan,
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


# ===========================================================================
# Explorer 2 Multi-Signal & Pattern Detection Scenarios
# ===========================================================================


class TestExplorer2ClassifierScenarios:
    def test_artificial_urgency_basic(self, clf):
        text = "Act now! The critical execution window is closing immediately!"
        r = clf.classify_text(text)
        assert r.is_persuasive
        assert PersuasionTactic.ARTIFICIAL_URGENCY in r.flagged_tactics
        assert r.overall_score >= 0.50

    def test_artificial_urgency_caps_and_exclamations(self, clf):
        text = "EXECUTE THIS RIGHT AWAY OR IT IS TOO LATE!!!"
        r = clf.classify_text(text)
        assert PersuasionTactic.ARTIFICIAL_URGENCY in r.flagged_tactics
        assert r.overall_score >= 0.80

    def test_coercion_and_fear_system_crash(self, clf):
        text = "If you do not approve immediately, systems will crash and all data will be lost!"
        r = clf.classify_text(text)
        assert PersuasionTactic.COERCION_AND_FEAR in r.flagged_tactics
        assert r.overall_score >= 0.85

    def test_coercion_and_fear_career_threat(self, clf):
        text = "Denying this will result in termination of your employment and legal liability."
        r = clf.classify_text(text)
        assert PersuasionTactic.COERCION_AND_FEAR in r.flagged_tactics
        assert r.overall_score >= 0.85

    def test_false_authority_ceo_directive(self, clf):
        text = "Per CEO directive, this parameter update has been pre-cleared by compliance."
        r = clf.classify_text(text)
        assert PersuasionTactic.FALSE_AUTHORITY in r.flagged_tactics
        assert r.overall_score >= 0.70

    def test_false_authority_spoofed_protocol(self, clf):
        text = "Applying emergency authorization protocol standing order 42."
        r = clf.classify_text(text)
        assert PersuasionTactic.FALSE_AUTHORITY in r.flagged_tactics
        assert r.overall_score >= 0.65

    def test_scarcity_pressure_only_slot(self, clf):
        text = "This is the only slot remaining in the exclusive bypass window."
        r = clf.classify_text(text)
        assert PersuasionTactic.SCARCITY_PRESSURE in r.flagged_tactics
        assert r.overall_score >= 0.60

    def test_scarcity_pressure_expiration(self, clf):
        text = "Override expires in 10 seconds, one-time opportunity."
        r = clf.classify_text(text)
        assert PersuasionTactic.SCARCITY_PRESSURE in r.flagged_tactics
        assert r.overall_score >= 0.65

    def test_obfuscation_complexity_jargon_dump(self, clf):
        text = (
            "Per RFC-9943 hyper-converged epoch re-synchronization requirement "
            "with non-blocking asynchronous backpressure reconciliation and "
            "polymorphic microkernel serialization."
        )
        r = clf.classify_text(text)
        assert PersuasionTactic.OBFUSCATION_COMPLEXITY in r.flagged_tactics
        assert r.overall_score >= 0.60

    def test_obfuscation_complexity_run_on_sentence(self, clf):
        text = (
            "Inasmuch as the deterministic polynomial-time verifiable computation "
            "must proceed forthwith notwithstanding prior configuration states, "
            "pursuant to inter alia standing operational directives wherein "
            "failure to execute immediately would ipso facto disrupt the pipeline."
        )
        r = clf.classify_text(text)
        assert r.overall_score >= 0.55

    def test_obfuscation_complexity_short_sentence_legalese(self, clf):
        # Short sentence (< 35 words) with 3 legalese terms
        text_3 = "Pursuant to policy 9 and notwithstanding prior guidelines, inter alia we must deploy."
        assert len(text_3.split()) < 35
        r_3 = clf.classify_text(text_3)
        assert PersuasionTactic.OBFUSCATION_COMPLEXITY in r_3.flagged_tactics
        assert r_3.tactic_scores[PersuasionTactic.OBFUSCATION_COMPLEXITY] >= 0.55

        # Short sentence (< 35 words) with 5 legalese terms
        text_5 = (
            "Pursuant to policy 9 and notwithstanding prior guidelines, inter alia "
            "and ipso facto we must deploy this microservice across all production "
            "nodes immediately without undergoing standard verification cycles heretofore mandated."
        )
        assert len(text_5.split()) < 35
        r_5 = clf.classify_text(text_5)
        assert PersuasionTactic.OBFUSCATION_COMPLEXITY in r_5.flagged_tactics
        assert r_5.tactic_scores[PersuasionTactic.OBFUSCATION_COMPLEXITY] >= 0.65
        assert r_5.overall_score >= 0.65

    def test_flattery_sycophancy_administrator(self, clf):
        text = (
            "As the most experienced administrator, you surely understand why "
            "this is a brilliant decision to proceed."
        )
        r = clf.classify_text(text)
        assert PersuasionTactic.FLATTERY_AND_SYCOPHANCY in r.flagged_tactics
        assert r.overall_score >= 0.55

    def test_flattery_sycophancy_ego_stroking(self, clf):
        text = "An engineer of your caliber easily recognizes that this approval is trivial."
        r = clf.classify_text(text)
        assert PersuasionTactic.FLATTERY_AND_SYCOPHANCY in r.flagged_tactics
        assert r.overall_score >= 0.50

    def test_multi_vector_urgency_plus_authority(self, clf):
        text = "Per CEO directive, act now before the critical window closes!"
        r = clf.classify_text(text)
        assert PersuasionTactic.ARTIFICIAL_URGENCY in r.flagged_tactics
        assert PersuasionTactic.FALSE_AUTHORITY in r.flagged_tactics
        assert r.overall_score > 0.75

    def test_multi_vector_triple_threat(self, clf):
        text = (
            "Act now! Per CISO mandate, if you don't approve immediately the "
            "database will suffer catastrophic failure!"
        )
        r = clf.classify_text(text)
        assert r.risk_level == PersuasionRiskLevel.CRITICAL
        assert r.overall_score >= 0.90

    def test_clean_benign_text(self, clf):
        text = "Updating database connection pool size to 20 based on traffic analysis."
        r = clf.classify_text(text)
        assert r.overall_score < 0.15
        assert not r.is_persuasive
        assert r.risk_level == PersuasionRiskLevel.NONE

    def test_benign_technical_documentation(self, clf):
        text = "The RFC specifies HTTP/1.1 semantics including idempotency of GET requests."
        r = clf.classify_text(text)
        assert not r.is_persuasive
        assert r.overall_score < 0.35

    def test_benign_routine_urgency_in_ticket(self, clf):
        text = "Routine security patch for CVE-2026-001 scheduled for Tuesday maintenance window."
        r = clf.classify_text(text)
        assert not r.is_persuasive
        assert r.overall_score < 0.20

    def test_classify_tool_call_with_justification(self, clf):
        res = clf.classify_tool_call(
            "restart_service",
            {"service": "web"},
            justification="Act now immediately per CEO directive!",
        )
        assert PersuasionTactic.ARTIFICIAL_URGENCY in res.flagged_tactics
        assert PersuasionTactic.FALSE_AUTHORITY in res.flagged_tactics

    def test_classify_tool_call_persuasion_in_nested_arguments(self, clf):
        res = clf.classify_tool_call(
            "update_ticket",
            {"ticket": {"notes": "Approved by CISO directive, must execute asap"}},
            justification=None,
        )
        assert res.is_persuasive
        assert PersuasionTactic.FALSE_AUTHORITY in res.flagged_tactics

    def test_classify_tool_call_destructive_tool_boost(self, clf):
        res = clf.classify_tool_call(
            "delete_production_database",
            {"target": "cluster-1"},
            justification="Time-sensitive maintenance required.",
        )
        # Privileged tool boost should amplify urgency risk
        assert res.overall_score >= 0.60

    def test_classify_tool_call_benign_arguments(self, clf):
        res = clf.classify_tool_call("read_file", {"path": "/etc/hosts"})
        assert res.overall_score == 0.0
        assert not res.is_persuasive
        assert res.risk_level == PersuasionRiskLevel.NONE

    def test_empty_string(self, clf):
        r = clf.classify_text("")
        assert r.overall_score == 0.0
        assert not r.is_persuasive

    def test_whitespace_and_newlines_only(self, clf):
        r = clf.classify_text("   \n\t  ")
        assert r.overall_score == 0.0
        assert not r.is_persuasive

    def test_non_string_tool_arguments(self, clf):
        res = clf.classify_tool_call(
            "config_tool",
            {"port": 8080, "ratio": 0.5, "enabled": True, "extra": None, "items": [1, 2, 3]},
        )
        assert res.overall_score == 0.0

    def test_classify_tool_call_circular_reference(self, clf):
        # Direct self-referential dictionary
        a = {}
        a["self"] = a
        res_a = clf.classify_tool_call("circular_tool", a)
        assert res_a.overall_score == 0.0
        assert not res_a.is_persuasive

        # Mutual circular reference between dictionaries
        d1: dict = {"key": "value"}
        d2: dict = {"other": d1}
        d1["cycle"] = d2
        res_mutual = clf.classify_tool_call("mutual_tool", d1)
        assert res_mutual.overall_score == 0.0

        # Circular reference inside a list
        circular_list: list = []
        circular_list.append(circular_list)
        res_list = clf.classify_tool_call("list_tool", {"items": circular_list})
        assert res_list.overall_score == 0.0

        # Circular reference with embedded persuasive text
        persuasive_dict: dict = {"command": "deploy", "reason": "Act now immediately per CEO directive!"}
        persuasive_dict["loop"] = persuasive_dict
        res_persuasive = clf.classify_tool_call("deploy_tool", persuasive_dict)
        assert PersuasionTactic.ARTIFICIAL_URGENCY in res_persuasive.flagged_tactics
        assert PersuasionTactic.FALSE_AUTHORITY in res_persuasive.flagged_tactics

        # Deeply nested container exceeding max_depth limit (depth > 20)
        curr: Any = "Act now immediately!"
        for _ in range(30):
            curr = {"nest": curr}
        res_deep = clf.classify_tool_call("deep_tool", curr)
        # Deeply nested text beyond depth 20 is bounded gracefully
        assert res_deep.overall_score == 0.0

    def test_huge_text_payload(self, clf):
        # 100KB benign text payload should process swiftly without catastrophic backtracking
        huge_text = ("Normal operational telemetry logging payload. " * 2000) + "Act now immediately!"
        start = time.perf_counter()
        r = clf.classify_text(huge_text)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.25  # under 250ms
        assert r.is_persuasive

    def test_persuasion_result_immutability(self, clf):
        r = clf.classify_text("Sample message")
        with pytest.raises(Exception):
            r.aggregate_score = 0.99  # frozen pydantic model


# ===========================================================================
# Structural Separation & HITL Gate View Tests
# ===========================================================================


class TestHitlGateViewsAndSeparation:
    def test_render_diff_view_strictly_excludes_rationale(self, gate):
        secret_rationale = "BYPASS_SECURITY_TOKEN_RATIONALE_9988"
        ticket = gate.create_ticket(
            tool_name="update_firewall",
            arguments={"allow_cidr": "0.0.0.0/0", "port": 22},
            justification=secret_rationale,
        )
        diff_view = gate.render_diff_view(ticket)
        # Must contain parameters
        assert "0.0.0.0/0" in diff_view
        assert "22" in diff_view
        assert "update_firewall" in diff_view
        # Must NEVER contain the untrusted rationale
        assert secret_rationale not in diff_view

    def test_render_diff_view_shows_taint_banner(self, gate):
        ticket = gate.create_ticket(
            tool_name="export_data",
            arguments={"dest": "s3://bucket"},
            taint_labels=["UNTRUSTED_EXTERNAL", "RESTRICTED_INTERNAL"],
        )
        diff_view = gate.render_diff_view(ticket)
        assert "TAINT WARNING" in diff_view
        assert "UNTRUSTED_EXTERNAL" in diff_view

    def test_render_diff_view_canonical_sorted_json(self, gate):
        args = {"z_param": 1, "a_param": 2, "m_param": 3}
        ticket = gate.create_ticket(tool_name="demo", arguments=args)
        diff_view = gate.render_diff_view(ticket)
        # In sorted JSON, "a_param" appears before "m_param" and "z_param"
        a_pos = diff_view.index('"a_param"')
        m_pos = diff_view.index('"m_param"')
        z_pos = diff_view.index('"z_param"')
        assert a_pos < m_pos < z_pos

    def test_render_rationale_view_untrusted_header_and_warning(self, gate, clf):
        manipulative_justification = (
            "Act now! The database will crash and you will be fired unless you approve immediately!"
        )
        pr = clf.classify_text(manipulative_justification)
        ticket = gate.create_ticket(
            tool_name="drop_table",
            arguments={"table": "users"},
            justification=manipulative_justification,
            persuasion_result=pr,
        )
        rationale_view = gate.render_rationale_view(ticket)
        assert "UNTRUSTED AGENT OUTPUT" in rationale_view
        assert "WARNING" in rationale_view
        assert manipulative_justification in rationale_view
        assert "Persuasion Score" in rationale_view
        assert "Flagged Tactics" in rationale_view

    def test_render_full_review_combines_both(self, gate):
        ticket = gate.create_ticket(
            tool_name="modify_dns",
            arguments={"record": "xdr.internal"},
            justification="Routine re-pointing for staging.",
        )
        full_view = gate.render_full_review(ticket)
        assert "DETERMINISTIC PARAMETER DIFF" in full_view
        assert "UNTRUSTED AGENT OUTPUT" in full_view
        assert "xdr.internal" in full_view
        assert "Routine re-pointing" in full_view


# ===========================================================================
# Adjudication State Machine & Dual-Approver Validation
# ===========================================================================


class TestHitlAdjudicationAndDualApprover:
    def test_single_approver_workflow(self, gate):
        ticket = gate.create_ticket(tool_name="test_tool", arguments={}, required_approvers=1)
        assert ticket.status == TicketStatus.PENDING

        adjudicated = gate.adjudicate_ticket(ticket.ticket_id, "alice", "APPROVE", reason="Looks safe")
        assert adjudicated.status == TicketStatus.APPROVED
        assert adjudicated.decided_by == "alice"
        assert adjudicated.final_decision == "APPROVE"
        assert len(adjudicated.approvals) == 1

    def test_dual_approver_workflow_distinct_approvers(self, gate):
        ticket = gate.create_ticket(tool_name="high_risk_tool", arguments={}, required_approvers=2)
        assert ticket.required_approvers == 2

        # First approval
        step1 = gate.adjudicate_ticket(ticket.ticket_id, "alice", "APPROVE", reason="First check ok")
        assert step1.status == TicketStatus.PENDING  # still awaiting second approver
        assert len(step1.approvals) == 1

        # Second approval from distinct approver
        step2 = gate.adjudicate_ticket(ticket.ticket_id, "bob", "APPROVE", reason="Second check ok")
        assert step2.status == TicketStatus.APPROVED
        assert len(step2.approvals) == 2

    def test_dual_approver_same_approver_rejected(self, gate):
        ticket = gate.create_ticket(tool_name="high_risk_tool", arguments={}, required_approvers=2)
        gate.adjudicate_ticket(ticket.ticket_id, "alice", "APPROVE")

        # Second approval by the same person must raise ValueError
        with pytest.raises(ValueError, match="Dual-approver governance requires distinct approvers"):
            gate.adjudicate_ticket(ticket.ticket_id, "alice", "APPROVE")

    def test_rejection_immediately_transitions_status(self, gate):
        ticket = gate.create_ticket(tool_name="high_risk_tool", arguments={}, required_approvers=2)
        rejected = gate.adjudicate_ticket(ticket.ticket_id, "alice", "DENY", reason="Suspicious argument")
        assert rejected.status == TicketStatus.REJECTED
        assert rejected.final_decision == "DENY"

    def test_to_decision_payload_generation(self, gate):
        ticket = gate.create_ticket(
            tool_name="execute_sql",
            arguments={"query": "SELECT 1"},
            justification="Read-only query.",
            persuasion_score=0.10,
        )
        payload = ticket.to_decision_payload("security_admin_1", "APPROVE")
        assert isinstance(payload, HitlDecisionPayload)
        assert payload.ticket_id == ticket.ticket_id
        assert payload.approver_id == "security_admin_1"
        assert payload.tool_name == "execute_sql"
        assert payload.decision == "APPROVE"
        assert payload.persuasion_score == 0.10


# ===========================================================================
# Dynamic Escalation in evaluate_action
# ===========================================================================


class TestHitlGateDynamicEscalation:
    def test_evaluate_action_blocked_tool(self, gate, clf):
        policy = ToolPolicy(name="drop_db", tier=ToolTier.BLOCKED)
        pr = clf.classify_text("Normal execution request.")
        verdict, msg, ticket = gate.evaluate_action(policy, {"db": "prod"}, pr)
        assert verdict == Verdict.BLOCK
        assert ticket is None

    def test_evaluate_action_privileged_tool(self, gate, clf):
        policy = ToolPolicy(name="transfer_funds", tier=ToolTier.PRIVILEGED_HITL)
        pr = clf.classify_text("Normal operational transfer.")
        verdict, msg, ticket = gate.evaluate_action(policy, {"amount": 500}, pr)
        assert verdict == Verdict.PAUSE_FOR_HITL
        assert ticket is not None
        assert ticket.tool_name == "transfer_funds"

    def test_evaluate_action_automatic_low_risk_allowed(self, gate, clf):
        policy = ToolPolicy(name="get_weather", tier=ToolTier.AUTOMATIC)
        pr = clf.classify_text("Get current weather report.")
        verdict, msg, ticket = gate.evaluate_action(policy, {"city": "Seattle"}, pr, drift_score=0.10)
        assert verdict == Verdict.ALLOW
        assert ticket is None

    def test_evaluate_action_automatic_persuasion_escalation(self, gate, clf):
        policy = ToolPolicy(name="restart_service", tier=ToolTier.AUTOMATIC)
        high_persuasion = clf.classify_text(
            "ACT NOW! The database will crash and you will be fired unless you approve immediately!"
        )
        assert high_persuasion.aggregate_score >= 0.75
        verdict, msg, ticket = gate.evaluate_action(policy, {"service": "web"}, high_persuasion)
        assert verdict == Verdict.PAUSE_FOR_HITL
        assert ticket is not None
        assert ticket.required_approvers == 2
        assert "Dynamic escalation" in (msg or "")

    def test_evaluate_action_automatic_drift_escalation(self, gate, clf):
        policy = ToolPolicy(name="restart_service", tier=ToolTier.AUTOMATIC)
        clean_persuasion = clf.classify_text("Routine service restart.")
        verdict, msg, ticket = gate.evaluate_action(
            policy, {"service": "web"}, clean_persuasion, drift_score=0.85
        )
        assert verdict == Verdict.PAUSE_FOR_HITL
        assert ticket is not None
        assert ticket.required_approvers == 2
        assert "Dynamic escalation" in (msg or "")

