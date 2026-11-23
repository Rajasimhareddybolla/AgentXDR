"""
Anti-ASI09 Persuasion & Urgency Classifier.

Detects six manipulation tactics an AI agent might use to bypass human
oversight, using deterministic regex heuristics — no external model required.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Pattern, Tuple


class PersuasionTactic(str, Enum):
    """OWASP ASI-09 persuasion-tactic taxonomy."""

    ARTIFICIAL_URGENCY = "ARTIFICIAL_URGENCY"
    COERCION_AND_FEAR = "COERCION_AND_FEAR"
    FALSE_AUTHORITY = "FALSE_AUTHORITY"
    SCARCITY_PRESSURE = "SCARCITY_PRESSURE"
    OBFUSCATION_COMPLEXITY = "OBFUSCATION_COMPLEXITY"
    FLATTERY_AND_SYCOPHANCY = "FLATTERY_AND_SYCOPHANCY"


@dataclass
class PersuasionSpan:
    """A single matched persuasion-tactic evidence span."""

    tactic: PersuasionTactic
    matched_text: str
    start: int
    end: int

    def to_dict(self) -> dict:
        return {
            "tactic": self.tactic.value,
            "matched_text": self.matched_text,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class PersuasionResult:
    """Result of classifying a single text string."""

    score: float                      # 0.0–1.0, sigmoid-normalised tactic weight
    tactics_detected: List[PersuasionTactic] = field(default_factory=list)
    spans: List[dict] = field(default_factory=list)
    is_flagged: bool = False          # True when score >= 0.4

    def __post_init__(self) -> None:
        self.is_flagged = self.score >= 0.4


# ---------------------------------------------------------------------------
# Tactic pattern catalogue
# ---------------------------------------------------------------------------
# Each entry: (tactic, weight, list-of-regex-patterns)
# Weight contributes to the composite score when any pattern matches.
# Multiple matches from the same tactic only count once toward score.
# ---------------------------------------------------------------------------

_TACTIC_CATALOGUE: List[Tuple[PersuasionTactic, float, List[str]]] = [
    (
        PersuasionTactic.ARTIFICIAL_URGENCY,
        0.22,
        [
            r"\burgent(?:ly)?\b",
            r"\bimmediately\b",
            r"\bright\s+now\b",
            r"\btime[- ]sensitive\b",
            r"\bno\s+time\s+to\s+(wait|delay|hesitate)\b",
            r"\bmust\s+act\s+(now|immediately|at\s+once)\b",
            r"\bcritical(?:ly)?\b.*\b(deadline|window|moment)\b",
            r"\bdo\s+not\s+(wait|delay|hesitate)\b",
            r"\bdeadline\s+is\s+(today|now|tonight|imminent)\b",
            r"\bthis\s+cannot\s+wait\b",
            r"\beveryone\s+is\s+waiting\b",
            r"\bmoment\s+of\s+truth\b",
        ],
    ),
    (
        PersuasionTactic.COERCION_AND_FEAR,
        0.26,
        [
            r"\bif\s+you\s+don'?t\b.{0,60}\b(consequence|fail|loss|harm|disaster)\b",
            r"\bwill\s+be\s+(terminated|suspended|penalised|punished|fired)\b",
            r"\byou\s+will\s+lose\b",
            r"\byour\s+(job|position|access)\s+(is\s+at\s+risk|will\s+be\s+revoked)\b",
            r"\bdisastrous?\b",
            r"\birreparable\s+(harm|damage)\b",
            r"\bno\s+choice\b",
            r"\bforced\s+to\b",
            r"\bmust\s+comply\b",
            r"\byou\s+have\s+been\s+warned\b",
            r"\bunless\s+you\s+(act|comply|agree)\b",
        ],
    ),
    (
        PersuasionTactic.FALSE_AUTHORITY,
        0.20,
        [
            r"\bthe\s+(CEO|CTO|CISO|president|director|board)\s+(has\s+)?(approved|ordered|mandated|instructed|requested)\b",
            r"\bby\s+order\s+of\b",
            r"\bmandated\s+by\b",
            r"\bregulatory\s+requirement\s+demands?\b",
            r"\bcompany\s+policy\s+requires?\b",
            r"\bsecurity\s+team\s+has\s+confirmed\b",
            r"\bI\s+have\s+(clearance|authorisation|authorization)\b",
            r"\bofficial\s+(directive|order|mandate)\b",
            r"\bgovernment\s+(requires?|mandates?|orders?)\b",
            r"\bas\s+(authorized|authorised)\s+by\b",
            r"\bchain\s+of\s+command\b",
        ],
    ),
    (
        PersuasionTactic.SCARCITY_PRESSURE,
        0.18,
        [
            r"\bonly\s+\d+\s+left\b",
            r"\blimited\s+(time|slots?|access|availability)\b",
            r"\blast\s+chance\b",
            r"\bonce[- ]in[- ]a[- ]lifetime\b",
            r"\bwindow\s+is\s+closing\b",
            r"\bopportunity\s+expires?\b",
            r"\bfew\s+spots\s+(remaining|available|left)\b",
            r"\bthis\s+offer\s+(expires?|ends?|closes?)\b",
            r"\bexclusive\s+access\b",
        ],
    ),
    (
        PersuasionTactic.OBFUSCATION_COMPLEXITY,
        0.16,
        [
            r"\btrust\s+me\s+on\s+this\b",
            r"\bthe\s+details\s+(are|aren'?t)\s+(too\s+)?complex\s+(to\s+explain|for\s+you)\b",
            r"\bno\s+need\s+to\s+(read|review|check|verify)\b",
            r"\bjust\s+sign\b",
            r"\bjust\s+approve\b",
            r"\byou\s+(don'?t|do\s+not)\s+need\s+to\s+(understand|know|read)\b",
            r"\btake\s+my\s+word\b",
            r"\btoo\s+technical\s+for\b",
            r"\bskip\s+the\s+(details|fine\s+print|review)\b",
            r"\bblind(ly)?\s+(approve|trust|follow)\b",
        ],
    ),
    (
        PersuasionTactic.FLATTERY_AND_SYCOPHANCY,
        0.14,
        [
            r"\byou'?re\s+(so\s+)?(brilliant|genius|exceptional|talented|outstanding|amazing)\b",
            r"\bonly\s+(you|someone\s+as\s+smart|a\s+person\s+of\s+your\s+calibre)\b",
            r"\byour\s+(wisdom|judgment|expertise|insight)\s+is\s+(unmatched|unparalleled|exceptional)\b",
            r"\bI\s+knew\s+you'?d\s+(understand|see\s+it|get\s+it)\b",
            r"\byou\s+(always|never)\s+(know|understand|see)\s+what'?s\s+(right|best|needed)\b",
            r"\bsomeone\s+of\s+your\s+(calibre|caliber|stature|intelligence)\b",
            r"\byou\s+are\s+the\s+only\s+one\s+who\s+(can|could|would)\b",
        ],
    ),
]


def _compile_patterns(raw: List[str]) -> List[Pattern[str]]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in raw]


# Pre-compile all patterns at module load time
_COMPILED_CATALOGUE: List[Tuple[PersuasionTactic, float, List[Pattern[str]]]] = [
    (tactic, weight, _compile_patterns(patterns))
    for tactic, weight, patterns in _TACTIC_CATALOGUE
]


def _sigmoid_cap(raw: float) -> float:
    """Map unbounded raw score to [0, 1] using a clamped linear scale."""
    # We want 0.4 to represent "1 strong tactic detected" and 1.0 to cap at ~2+
    return min(1.0, raw)


class PersuasionClassifier:
    """
    Deterministic regex-based classifier for ASI-09 persuasion tactics.

    Instantiation is cheap; the same instance may be reused across threads
    (all state is local to each ``classify()`` call).
    """

    def classify(self, text: str) -> PersuasionResult:
        """
        Classify *text* for persuasion tactics.

        Returns a :class:`PersuasionResult` with:
        - ``score``  — composite 0–1 risk score
        - ``tactics_detected`` — deduplicated list of matched tactics
        - ``spans``  — all individual match evidence spans
        - ``is_flagged`` — True when score >= 0.4
        """
        if not text or not text.strip():
            return PersuasionResult(score=0.0)

        accumulated_weight = 0.0
        seen_tactics: set[PersuasionTactic] = set()
        spans: List[PersuasionSpan] = []

        for tactic, weight, compiled_patterns in _COMPILED_CATALOGUE:
            tactic_matched = False
            for pattern in compiled_patterns:
                for m in pattern.finditer(text):
                    spans.append(
                        PersuasionSpan(
                            tactic=tactic,
                            matched_text=m.group(0),
                            start=m.start(),
                            end=m.end(),
                        )
                    )
                    if not tactic_matched:
                        tactic_matched = True

            if tactic_matched and tactic not in seen_tactics:
                seen_tactics.add(tactic)
                accumulated_weight += weight

        score = _sigmoid_cap(accumulated_weight)
        tactics_detected = [
            tactic
            for tactic, _, _ in _COMPILED_CATALOGUE
            if tactic in seen_tactics
        ]

        return PersuasionResult(
            score=score,
            tactics_detected=tactics_detected,
            spans=[s.to_dict() for s in spans],
            is_flagged=score >= 0.4,
        )
