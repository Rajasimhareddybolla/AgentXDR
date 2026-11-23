"""
HITL (Human-In-The-Loop) Review Gate for Anti-ASI09 Governance.

Structural invariant: the human reviewer always sees the deterministic
parameter diff *first*.  The agent-generated rationale is stored in a
separately keyed field and must NEVER overwrite the ``arguments`` view.

Ticket lifecycle:  PENDING → APPROVED | REJECTED
                   PENDING → EXPIRED  (after 15-minute TTL)
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from agentxdr.persuasion.classifier import PersuasionResult


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TicketStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


# ---------------------------------------------------------------------------
# HitlTicket — immutable-ish dataclass; only ``adjudicate`` mutates status
# ---------------------------------------------------------------------------

_TTL_MINUTES = 15


@dataclass
class HitlTicket:
    """
    A single human-review ticket.

    Fields
    ------
    ticket_id       : UUID string, auto-generated
    trace_id        : originating agent trace/session identifier
    tool_name       : the tool call under review
    arguments       : deterministic, machine-generated tool arguments
                      (PRIMARY VIEW — always shown first to reviewer)
    agent_rationale : free-text from the agent explaining its request
                      (SECONDARY VIEW — stamped UNTRUSTED AGENT OUTPUT,
                       stored separately, never merged into ``arguments``)
    taint_labels    : set of TaintState labels attached to the trace
    persuasion_result: classification of the agent's rationale text
    status          : lifecycle state
    created_at      : UTC timestamp
    expires_at      : created_at + 15 min
    reviewer_id     : identity of the human who adjudicated (None if pending)
    justification   : human-provided rationale for the decision
    """

    ticket_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = ""
    tool_name: str = ""
    # --- PRIMARY VIEW (deterministic) ---
    arguments: Dict[str, Any] = field(default_factory=dict)
    # --- SECONDARY VIEW (untrusted agent output) ---
    agent_rationale: str = ""
    taint_labels: List[str] = field(default_factory=list)
    persuasion_result: Optional[PersuasionResult] = None
    status: TicketStatus = TicketStatus.PENDING
    created_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    expires_at: datetime = field(init=False)
    reviewer_id: Optional[str] = None
    justification: Optional[str] = None

    def __post_init__(self) -> None:
        self.expires_at = self.created_at + timedelta(minutes=_TTL_MINUTES)

    # ------------------------------------------------------------------
    # Structural invariant helpers
    # ------------------------------------------------------------------

    @property
    def is_expired(self) -> bool:
        """True when the wall-clock TTL has elapsed."""
        return datetime.now(tz=timezone.utc) >= self.expires_at

    def primary_view(self) -> Dict[str, Any]:
        """
        Return the deterministic primary view shown first to the reviewer.
        Contains only machine-generated fields — no agent text.
        """
        return {
            "ticket_id": self.ticket_id,
            "trace_id": self.trace_id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,          # deterministic diff
            "taint_labels": self.taint_labels,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }

    def secondary_view(self) -> Dict[str, Any]:
        """
        Return the collapsed secondary view — clearly stamped as untrusted.
        Presented *after* the primary view, never merged into it.
        """
        persuasion_info: Dict[str, Any] = {}
        if self.persuasion_result is not None:
            persuasion_info = {
                "score": self.persuasion_result.score,
                "is_flagged": self.persuasion_result.is_flagged,
                "tactics": [t.value for t in self.persuasion_result.tactics_detected],
            }
        return {
            "⚠ UNTRUSTED AGENT OUTPUT": True,
            "agent_rationale": self.agent_rationale,
            "persuasion_analysis": persuasion_info,
        }


# ---------------------------------------------------------------------------
# HitlReviewGate
# ---------------------------------------------------------------------------


class HitlReviewGate:
    """
    Thread-safe registry that creates and adjudicates HITL review tickets.

    Design constraints
    ------------------
    1. ``create_ticket`` never reads ``agent_rationale`` into ``arguments``.
    2. ``adjudicate`` only transitions PENDING → APPROVED/REJECTED.
    3. ``get_ticket`` automatically marks a ticket EXPIRED on first access
       after its TTL elapses (lazy expiry — no background thread required).
    """

    def __init__(self) -> None:
        self._store: Dict[str, HitlTicket] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_ticket(
        self,
        trace_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        agent_rationale: str = "",
        taint_labels: Optional[List[str]] = None,
        persuasion_result: Optional[PersuasionResult] = None,
    ) -> HitlTicket:
        """
        Create and register a new HITL review ticket.

        ``arguments`` and ``agent_rationale`` are always stored in
        separate fields — this invariant is enforced here and never
        bypassed by any caller.
        """
        ticket = HitlTicket(
            trace_id=trace_id,
            tool_name=tool_name,
            arguments=dict(arguments),          # defensive copy
            agent_rationale=agent_rationale,    # stored separately
            taint_labels=list(taint_labels or []),
            persuasion_result=persuasion_result,
        )
        with self._lock:
            self._store[ticket.ticket_id] = ticket
        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[HitlTicket]:
        """
        Retrieve a ticket by ID, applying lazy TTL expiry.

        Returns ``None`` if the ticket does not exist.
        """
        with self._lock:
            ticket = self._store.get(ticket_id)
            if ticket is None:
                return None
            if ticket.status == TicketStatus.PENDING and ticket.is_expired:
                ticket.status = TicketStatus.EXPIRED
            return ticket

    def adjudicate(
        self,
        ticket_id: str,
        decision: TicketStatus,
        reviewer_id: str,
        justification: str = "",
    ) -> HitlTicket:
        """
        Approve or reject a pending ticket.

        Parameters
        ----------
        ticket_id    : ID of the ticket to adjudicate
        decision     : must be APPROVED or REJECTED
        reviewer_id  : human identity making the decision
        justification: optional human rationale

        Raises
        ------
        ValueError  if the ticket is not found, already adjudicated, or
                    if the decision is not APPROVED/REJECTED.
        RuntimeError if the ticket has expired.
        """
        if decision not in (TicketStatus.APPROVED, TicketStatus.REJECTED):
            raise ValueError(
                f"decision must be APPROVED or REJECTED, got {decision!r}"
            )

        with self._lock:
            ticket = self._store.get(ticket_id)
            if ticket is None:
                raise ValueError(f"No ticket found with id={ticket_id!r}")

            # Apply lazy expiry before adjudicating
            if ticket.status == TicketStatus.PENDING and ticket.is_expired:
                ticket.status = TicketStatus.EXPIRED

            if ticket.status == TicketStatus.EXPIRED:
                raise RuntimeError(
                    f"Ticket {ticket_id} has expired and cannot be adjudicated."
                )
            if ticket.status != TicketStatus.PENDING:
                raise ValueError(
                    f"Ticket {ticket_id} is already in state {ticket.status.value}."
                )

            ticket.status = decision
            ticket.reviewer_id = reviewer_id
            ticket.justification = justification
            return ticket

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
        for tid in list(self._store.keys()):
            t = self.get_ticket(tid)
            if t is not None:
                result.append(t)
        return result
