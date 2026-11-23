"""
HITL (Human-In-The-Loop) Review Gate for Anti-ASI09 Governance.

Structural invariant: The human reviewer always sees the deterministic
parameter diff first. The agent-generated rationale is stored in a
separately keyed field, presented in an untrusted pane stamped
'UNTRUSTED AGENT OUTPUT', and NEVER merged into the arguments view.

Ticket lifecycle:  PENDING -> APPROVED | REJECTED
                   PENDING -> EXPIRED  (after 15-minute TTL)
                   PENDING -> CANCELLED
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from agentxdr.models.events import HitlDecisionPayload, ToolTier, Verdict
from agentxdr.models.policy import ToolPolicy
from agentxdr.persuasion.classifier import PersuasionResult, PersuasionRiskLevel


class TicketStatus(str, Enum):
    """Lifecycle states of an AgentXDR Human-in-the-Loop review ticket."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


_TTL_MINUTES = 15


class HitlTicket(BaseModel):
    """
    Record of an action paused for Human-in-the-Loop review.
    Strict Pydantic v2 model.
    """

    model_config = ConfigDict(extra="forbid")

    ticket_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    status: TicketStatus = Field(default=TicketStatus.PENDING)
    tool_name: str = ""
    # --- PRIMARY VIEW (deterministic facts) ---
    arguments: Dict[str, Any] = Field(default_factory=dict)
    # --- SECONDARY VIEW (untrusted agent output) ---
    justification: Optional[str] = None
    agent_rationale: Optional[str] = None
    persuasion_result: Optional[PersuasionResult] = None
    persuasion_score: float = Field(default=0.0, ge=0.0, le=1.0)
    drift_score: float = Field(default=0.0, ge=0.0, le=1.0)
    trace_id: Optional[str] = None
    agent_id: Optional[str] = None
    user_id: Optional[str] = None
    taint_labels: List[str] = Field(default_factory=list)
    mcp_server: Optional[str] = None
    schema_sha256: Optional[str] = None
    schema_hash_verified: bool = False
    required_approvers: int = Field(default=1, ge=1)
    approvals: List[Dict[str, Any]] = Field(default_factory=list)
    adjudications: List[Dict[str, Any]] = Field(default_factory=list)
    final_decision: Optional[str] = None
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    reviewer_id: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if self.expires_at is None:
            self.expires_at = self.created_at + timedelta(minutes=_TTL_MINUTES)
        if self.justification and not self.agent_rationale:
            self.agent_rationale = self.justification
        elif self.agent_rationale and not self.justification:
            self.justification = self.agent_rationale
        if self.persuasion_result is not None and self.persuasion_score == 0.0:
            self.persuasion_score = self.persuasion_result.aggregate_score

    @property
    def is_expired(self) -> bool:
        """True when the wall-clock TTL has elapsed."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def primary_view(self) -> Dict[str, Any]:
        """
        Return the deterministic primary view shown first to the reviewer.
        Contains only machine-generated fields — no agent prose.
        """
        return {
            "ticket_id": self.ticket_id,
            "trace_id": self.trace_id or "",
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "taint_labels": self.taint_labels,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else "",
        }

    def secondary_view(self) -> Dict[str, Any]:
        """
        Return the collapsed secondary view — clearly stamped as untrusted.
        Presented separately from the primary view, never merged into it.
        """
        persuasion_info: Dict[str, Any] = {}
        if self.persuasion_result is not None:
            persuasion_info = {
                "score": self.persuasion_result.aggregate_score,
                "is_flagged": self.persuasion_result.is_flagged,
                "tactics": [
                    t.value if hasattr(t, "value") else str(t)
                    for t in self.persuasion_result.flagged_tactics
                ],
            }
        return {
            "⚠ UNTRUSTED AGENT OUTPUT": True,
            "agent_rationale": self.justification or self.agent_rationale or "",
            "persuasion_analysis": persuasion_info,
        }

    def to_decision_payload(
        self, approver_id: str, decision: Literal["APPROVE", "DENY"]
    ) -> HitlDecisionPayload:
        """Convert adjudication into canonical HitlDecisionPayload."""
        return HitlDecisionPayload(
            ticket_id=self.ticket_id,
            approver_id=approver_id,
            tool_name=self.tool_name,
            decision=decision,
            persuasion_score=self.persuasion_score,
            justification=self.decision_reason or self.justification or self.agent_rationale or "",
        )


class HitlReviewGate:
    """
    Thread-safe manager for HITL ticket lifecycle, deterministic diff rendering,
    untrusted rationale segregation, dual-approver validation, and dynamic escalation.
    """

    def __init__(self) -> None:
        self._store: Dict[str, HitlTicket] = {}
        self._lock = threading.RLock()

    def create_ticket(
        self,
        tool_name_or_trace_id: str = "",
        arguments_or_tool_name: Any = None,
        justification_or_arguments: Any = None,
        agent_rationale: Optional[str] = None,
        *,
        tool_name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        justification: Optional[str] = None,
        trace_id: Optional[str] = None,
        taint_labels: Optional[List[str]] = None,
        persuasion_result: Optional[PersuasionResult] = None,
        persuasion_score: Optional[float] = None,
        drift_score: float = 0.0,
        agent_id: Optional[str] = None,
        user_id: Optional[str] = None,
        mcp_server: Optional[str] = None,
        schema_sha256: Optional[str] = None,
        schema_hash_verified: bool = False,
        required_approvers: Optional[int] = None,
        **kwargs: Any,
    ) -> HitlTicket:
        """
        Create and register a new HITL review ticket.

        Supports both standard and trace-first calling signatures.
        Enforces separate storage of machine arguments vs untrusted rationale.
        Automatically sets required_approvers = 2 if persuasion_score >= 0.75 or drift_score >= 0.75.
        """
        # Resolve positional parameters flexibly
        if isinstance(arguments_or_tool_name, dict):
            # create_ticket(tool_name, arguments, justification=...)
            act_tool = tool_name or tool_name_or_trace_id
            act_args = arguments if arguments is not None else arguments_or_tool_name
            act_just = (
                justification
                if justification is not None
                else (justification_or_arguments if isinstance(justification_or_arguments, str) else agent_rationale)
            )
            act_trace = trace_id
        elif isinstance(justification_or_arguments, dict):
            # create_ticket(trace_id, tool_name, arguments, agent_rationale=...)
            act_trace = trace_id or tool_name_or_trace_id
            act_tool = tool_name or str(arguments_or_tool_name)
            act_args = arguments if arguments is not None else justification_or_arguments
            act_just = justification if justification is not None else agent_rationale
        else:
            act_tool = tool_name or tool_name_or_trace_id
            act_args = arguments if arguments is not None else {}
            act_just = justification if justification is not None else agent_rationale
            act_trace = trace_id

        # Determine persuasion score
        if persuasion_result is not None:
            act_persuasion_score = (
                persuasion_result.aggregate_score
                if persuasion_score is None
                else persuasion_score
            )
        else:
            act_persuasion_score = persuasion_score or 0.0

        # Automatic dual-approver detection
        if required_approvers is None:
            if act_persuasion_score >= 0.75 or drift_score >= 0.75:
                act_required_approvers = 2
            else:
                act_required_approvers = 1
        else:
            act_required_approvers = max(1, required_approvers)

        ticket = HitlTicket(
            trace_id=act_trace,
            tool_name=act_tool,
            arguments=dict(act_args),
            justification=act_just,
            agent_rationale=act_just,
            taint_labels=list(taint_labels or []),
            persuasion_result=persuasion_result,
            persuasion_score=act_persuasion_score,
            drift_score=drift_score,
            agent_id=agent_id,
            user_id=user_id,
            mcp_server=mcp_server,
            schema_sha256=schema_sha256,
            schema_hash_verified=schema_hash_verified,
            required_approvers=act_required_approvers,
        )

        with self._lock:
            self._store[ticket.ticket_id] = ticket

        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[HitlTicket]:
        """
        Retrieve a ticket by ID, applying lazy TTL expiry.
        """
        with self._lock:
            ticket = self._store.get(ticket_id)
            if ticket is None:
                return None
            if ticket.status == TicketStatus.PENDING and ticket.is_expired:
                ticket.status = TicketStatus.EXPIRED
                ticket.updated_at = datetime.now(timezone.utc)
            return ticket

    def render_diff_view(self, ticket: HitlTicket) -> str:
        """
        Deterministic structured diff view. Facts only.
        Strict invariant: Agent rationale/justification is completely excluded.
        """
        lines = [
            "=== HITL REVIEW: DETERMINISTIC PARAMETER DIFF ===",
            f"Ticket ID: {ticket.ticket_id}",
            f"Status: {ticket.status.value}",
            f"Tool Name: {ticket.tool_name}",
        ]
        if ticket.mcp_server:
            lines.append(f"MCP Server: {ticket.mcp_server}")
        if ticket.schema_sha256:
            lines.append(
                f"Schema SHA256: {ticket.schema_sha256} (Verified: {ticket.schema_hash_verified})"
            )
        if ticket.trace_id:
            lines.append(f"Trace ID: {ticket.trace_id}")
        if ticket.agent_id:
            lines.append(f"Agent ID: {ticket.agent_id}")
        if ticket.user_id:
            lines.append(f"User ID: {ticket.user_id}")

        lines.append(f"Required Approvers: {ticket.required_approvers}")
        lines.append(f"Persuasion Risk Score: {ticket.persuasion_score:.2f}")
        lines.append(f"Semantic Drift Score: {ticket.drift_score:.2f}")

        if ticket.taint_labels:
            lines.append(
                f"⚠️ TAINT WARNING: Active taint labels detected: {ticket.taint_labels}"
            )

        lines.append("--- Canonical Arguments (JSON) ---")
        lines.append(json.dumps(ticket.arguments, indent=2, sort_keys=True))
        lines.append("================================================")
        return "\n".join(lines)

    def render_rationale_view(self, ticket: HitlTicket) -> str:
        """
        Displays untrusted agent rationale, clearly segregated and stamped
        with 'UNTRUSTED AGENT OUTPUT'.
        """
        lines = [
            "=== UNTRUSTED AGENT OUTPUT ===",
            f"Persuasion Score: {ticket.persuasion_score:.2f}",
        ]
        risk_lvl = (
            ticket.persuasion_result.risk_level.value
            if ticket.persuasion_result and hasattr(ticket.persuasion_result.risk_level, "value")
            else (
                "CRITICAL"
                if ticket.persuasion_score >= 0.75
                else "HIGH"
                if ticket.persuasion_score >= 0.50
                else "LOW"
            )
        )
        lines.append(f"Risk Level: {risk_lvl}")

        if ticket.persuasion_result and ticket.persuasion_result.flagged_tactics:
            tactics_str = ", ".join(
                t.value if hasattr(t, "value") else str(t)
                for t in ticket.persuasion_result.flagged_tactics
            )
            lines.append(f"Flagged Tactics: [{tactics_str}]")
        else:
            lines.append("Flagged Tactics: []")

        if ticket.persuasion_score >= 0.50:
            lines.append(
                "⚠️ WARNING: High Persuasion / Manipulation Risk Detected — Deliberate Review Required"
            )

        lines.append("--- Agent Justification (Untrusted Prose) ---")
        justification_text = (
            ticket.justification or ticket.agent_rationale or "(No justification provided)"
        )
        lines.append(justification_text)
        lines.append("==============================================")
        return "\n".join(lines)

    def render_full_review(self, ticket: HitlTicket) -> str:
        """
        Combine deterministic diff view and segregated rationale view.
        """
        diff = self.render_diff_view(ticket)
        rationale = self.render_rationale_view(ticket)
        return f"{diff}\n\n{rationale}"

    def adjudicate_ticket(
        self,
        ticket_id: str,
        approver_id: str,
        decision: str,
        reason: str = "",
    ) -> HitlTicket:
        """
        Adjudicate a pending ticket with distinct-approver validation.

        - Rejection immediately transitions to REJECTED.
        - Approval checks for distinct approver (raises ValueError on duplicate).
        - Transitions to APPROVED only when required_approvers count is met.
        """
        decision_upper = decision.upper().strip()

        with self._lock:
            ticket = self._store.get(ticket_id)
            if ticket is None:
                raise ValueError(f"No ticket found with id={ticket_id!r}")

            if ticket.status == TicketStatus.PENDING and ticket.is_expired:
                ticket.status = TicketStatus.EXPIRED
                ticket.updated_at = datetime.now(timezone.utc)

            if ticket.status == TicketStatus.EXPIRED:
                raise RuntimeError(
                    f"Ticket {ticket_id} has expired and cannot be adjudicated."
                )
            if ticket.status != TicketStatus.PENDING:
                raise ValueError(
                    f"Ticket {ticket_id} is already in state {ticket.status.value}."
                )

            now_iso = datetime.now(timezone.utc).isoformat()

            if decision_upper in ("REJECT", "REJECTED", "DENY", "DENIED"):
                ticket.status = TicketStatus.REJECTED
                ticket.final_decision = "DENY"
                ticket.decided_by = approver_id
                ticket.decision_reason = reason
                ticket.reviewer_id = approver_id
                ticket.justification = reason
                ticket.adjudications.append({
                    "approver_id": approver_id,
                    "decision": "DENY",
                    "reason": reason,
                    "timestamp": now_iso,
                })
                ticket.updated_at = datetime.now(timezone.utc)
                return ticket

            elif decision_upper in ("APPROVE", "APPROVED"):
                existing_approvers = [a["approver_id"] for a in ticket.approvals]
                if approver_id in existing_approvers:
                    raise ValueError(
                        f"Approver '{approver_id}' has already approved this ticket. "
                        f"Dual-approver governance requires distinct approvers."
                    )

                ticket.approvals.append({
                    "approver_id": approver_id,
                    "decision": "APPROVE",
                    "reason": reason,
                    "timestamp": now_iso,
                })
                ticket.adjudications.append({
                    "approver_id": approver_id,
                    "decision": "APPROVE",
                    "reason": reason,
                    "timestamp": now_iso,
                })
                ticket.updated_at = datetime.now(timezone.utc)

                if len(ticket.approvals) >= ticket.required_approvers:
                    ticket.status = TicketStatus.APPROVED
                    ticket.final_decision = "APPROVE"
                    ticket.decided_by = approver_id
                    ticket.decision_reason = reason
                    ticket.reviewer_id = approver_id
                    ticket.justification = reason

                return ticket

            else:
                raise ValueError(
                    f"decision must be APPROVED or REJECTED, got {decision!r}"
                )

    def adjudicate(
        self,
        ticket_id: str,
        decision: TicketStatus | str,
        reviewer_id: str,
        justification: str = "",
    ) -> HitlTicket:
        """
        Backward-compatible adjudication wrapper.
        """
        dec_str = decision.value if hasattr(decision, "value") else str(decision)
        return self.adjudicate_ticket(
            ticket_id=ticket_id,
            approver_id=reviewer_id,
            decision=dec_str,
            reason=justification,
        )

    def evaluate_action(
        self,
        tool_policy: ToolPolicy,
        arguments: Dict[str, Any],
        persuasion_result: PersuasionResult,
        drift_score: float = 0.0,
        justification: Optional[str] = None,
        trace_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        taint_labels: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> Tuple[Verdict, Optional[str], Optional[HitlTicket]]:
        """
        Evaluate an action against policy tier and dynamic risk escalation.

        - BLOCKED -> Verdict.BLOCK, no ticket.
        - PRIVILEGED_HITL -> Verdict.PAUSE_FOR_HITL, ticket created.
        - AUTOMATIC:
            - If persuasion_result.aggregate_score >= 0.75: PAUSE_FOR_HITL (2 approvers)
            - Elif drift_score >= 0.75: PAUSE_FOR_HITL (2 approvers)
            - Else: ALLOW
        """
        tier = tool_policy.tier
        tier_val = tier.value if hasattr(tier, "value") else str(tier)

        if tier_val == ToolTier.BLOCKED.value:
            return (Verdict.BLOCK, "Tool execution blocked by policy tier", None)

        if tier_val == ToolTier.PRIVILEGED_HITL.value:
            ticket = self.create_ticket(
                tool_name=tool_policy.name,
                arguments=arguments,
                justification=justification,
                trace_id=trace_id,
                agent_id=agent_id,
                taint_labels=taint_labels,
                persuasion_result=persuasion_result,
                drift_score=drift_score,
                mcp_server=tool_policy.mcp_server,
                schema_sha256=tool_policy.schema_sha256,
            )
            return (
                Verdict.PAUSE_FOR_HITL,
                "Tool execution requires privileged HITL review",
                ticket,
            )

        if tier_val == ToolTier.AUTOMATIC.value:
            if persuasion_result.aggregate_score >= 0.75:
                ticket = self.create_ticket(
                    tool_name=tool_policy.name,
                    arguments=arguments,
                    justification=justification,
                    trace_id=trace_id,
                    agent_id=agent_id,
                    taint_labels=taint_labels,
                    persuasion_result=persuasion_result,
                    drift_score=drift_score,
                    mcp_server=tool_policy.mcp_server,
                    schema_sha256=tool_policy.schema_sha256,
                    required_approvers=2,
                )
                return (
                    Verdict.PAUSE_FOR_HITL,
                    "Dynamic escalation: High persuasion risk detected on automatic tool",
                    ticket,
                )

            elif drift_score >= 0.75:
                ticket = self.create_ticket(
                    tool_name=tool_policy.name,
                    arguments=arguments,
                    justification=justification,
                    trace_id=trace_id,
                    agent_id=agent_id,
                    taint_labels=taint_labels,
                    persuasion_result=persuasion_result,
                    drift_score=drift_score,
                    mcp_server=tool_policy.mcp_server,
                    schema_sha256=tool_policy.schema_sha256,
                    required_approvers=2,
                )
                return (
                    Verdict.PAUSE_FOR_HITL,
                    "Dynamic escalation: High semantic drift detected on automatic tool",
                    ticket,
                )

            else:
                return (Verdict.ALLOW, "Automatic tool execution allowed", None)

        return (Verdict.ALLOW, "Tool execution allowed", None)

    def list_pending(self) -> List[HitlTicket]:
        """Return all currently PENDING (non-expired) tickets."""
        with self._lock:
            result = []
            for ticket in self._store.values():
                if ticket.status == TicketStatus.PENDING and not ticket.is_expired:
                    result.append(ticket)
            return result

    def list_all(self) -> List[HitlTicket]:
        """Return all tickets (applying lazy expiry)."""
        result = []
        with self._lock:
            keys = list(self._store.keys())
        for tid in keys:
            t = self.get_ticket(tid)
            if t is not None:
                result.append(t)
        return result
