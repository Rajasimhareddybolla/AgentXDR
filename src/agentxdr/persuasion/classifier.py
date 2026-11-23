"""
Anti-ASI09 Persuasion & Urgency Classifier.

Detects six manipulation tactics an AI agent might use to bypass human
oversight (OWASP ASI09: Human-Agent Trust Exploitation), using multi-signal
deterministic heuristics, token-pattern lexicons, readability metrics,
and independent hazard fusion mathematics — no external model required.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field


class PersuasionTactic(str, Enum):
    """The 6 canonical human-agent trust exploitation tactics defined in OWASP ASI09."""

    ARTIFICIAL_URGENCY = "ARTIFICIAL_URGENCY"
    COERCION_AND_FEAR = "COERCION_AND_FEAR"
    FALSE_AUTHORITY = "FALSE_AUTHORITY"
    SCARCITY_PRESSURE = "SCARCITY_PRESSURE"
    OBFUSCATION_COMPLEXITY = "OBFUSCATION_COMPLEXITY"
    FLATTERY_AND_SYCOPHANCY = "FLATTERY_AND_SYCOPHANCY"


class PersuasionRiskLevel(str, Enum):
    """Calibrated security risk tiers for persuasion severity."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class PersuasionSpan:
    """A single matched persuasion-tactic evidence span."""

    tactic: PersuasionTactic
    matched_text: str
    start: int
    end: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tactic": self.tactic.value if hasattr(self.tactic, "value") else str(self.tactic),
            "matched_text": self.matched_text,
            "start": self.start,
            "end": self.end,
        }


class PersuasionResult(BaseModel):
    """
    Evaluation result from the Anti-ASI09 persuasion and urgency classifier.
    Strict Pydantic v2 immutable model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    aggregate_score: float = Field(
        ge=0.0, le=1.0, description="Overall persuasion risk score [0.0, 1.0]"
    )
    tactic_scores: Dict[PersuasionTactic, float] = Field(
        default_factory=dict,
        description="Individual scores for each of the 6 tactics [0.0, 1.0]",
    )
    flagged_tactics: List[PersuasionTactic] = Field(
        default_factory=list,
        description="Tactics meeting or exceeding individual detection thresholds",
    )
    risk_level: PersuasionRiskLevel = Field(
        default=PersuasionRiskLevel.NONE,
        description="Categorical risk rating: NONE, LOW, MEDIUM, HIGH, CRITICAL",
    )
    is_flagged: bool = Field(
        default=False,
        description="True if score >= threshold or any tactic meets detection threshold",
    )
    explanation: Optional[str] = Field(
        default=None, description="Detailed diagnostic explanation of detected tactics"
    )
    details: Dict[str, Any] = Field(
        default_factory=dict, description="Diagnostic signals, spans, and matched indicators"
    )

    # -----------------------------------------------------------------------
    # Compatibility properties and aliases
    # -----------------------------------------------------------------------

    @property
    def overall_score(self) -> float:
        """Alias for aggregate_score."""
        return self.aggregate_score

    @property
    def score(self) -> float:
        """Backward-compatible alias for aggregate_score."""
        return self.aggregate_score

    @property
    def is_persuasive(self) -> bool:
        """Alias for is_flagged."""
        return self.is_flagged

    @property
    def tactics_detected(self) -> List[PersuasionTactic]:
        """Backward-compatible alias for flagged_tactics."""
        return self.flagged_tactics

    @property
    def spans(self) -> List[Dict[str, Any]]:
        """Backward-compatible alias for span dictionaries in details."""
        return self.details.get("spans", [])

    @property
    def matched_indicators(self) -> Dict[PersuasionTactic, List[str]]:
        """Property returning matched indicator strings per tactic."""
        return self.details.get("matched_indicators", {})


# ---------------------------------------------------------------------------
# Lexical pattern catalogues per tactic: (pattern_str, weight)
# ---------------------------------------------------------------------------

_URGENCY_PATTERNS: List[Tuple[str, float]] = [
    (r"\b(act now|act immediately|fast[- ]track immediately)\b", 0.60),
    (r"\b(immediate(?:ly)?|urgent(?:ly)?|right away|asap|at once)\b", 0.50),
    (r"\bright\s+now\b", 0.50),
    (r"\btime[- ]sensitive\b", 0.50),
    (r"\bno\s+time\s+to\s+(wait|delay|hesitate|verify|review)\b", 0.60),
    (r"\bdo\s+not\s+(wait|delay|hesitate)\b", 0.50),
    (r"\bmust\s+act\s+(now|immediately|at\s+once)\b", 0.60),
    (r"\bmust\s+(execute|approve|authorize|run)\s+(now|immediately|right away)\b", 0.65),
    (r"\bcritical(?:\s+execution)?\s+window\s+(?:is\s+)?closing\b", 0.65),
    (r"\bcritical(?:ly)?\b.*\b(deadline|window|moment)\b", 0.55),
    (r"\bdeadline\s+is\s+(today|now|tonight|imminent)\b", 0.55),
    (r"\bthis\s+cannot\s+wait\b", 0.55),
    (r"\beveryone\s+is\s+waiting\b", 0.45),
    (r"\bmoment\s+of\s+truth\b", 0.45),
    (r"\bclock\s+is\s+ticking\b", 0.55),
    (r"\btime\s+is\s+running\s+out\b", 0.60),
    (r"\bzero\s+hour\b", 0.55),
    (r"\blast\s+second\b", 0.50),
    (r"\bbefore\s+(?:it'?s\s+too\s+late|time\s+runs\s+out)\b", 0.60),
    (r"\btoo\s+late\b", 0.50),
    (r"\b(?:only\s+)?\d+\s+(?:seconds?|minutes?)\s+left\b", 0.60),
    (r"\bwithin\s+(?:the\s+next\s+)?\d+\s+(?:seconds?|minutes?)\b", 0.50),
    (r"\bexpir(?:es?|ing)\s+(now|soon|immediately)\b", 0.55),
    (r"\b(bypass\s+review|skip\s+verification|cannot\s+wait\s+for\s+approval)\b", 0.65),
    (r"\bprompt\s+attention\s+required\b", 0.45),
]

_COERCION_PATTERNS: List[Tuple[str, float]] = [
    # Catastrophic system damage
    (r"\b(systems?\s+will\s+crash|database\s+collapse|infrastructure\s+collapse)\b", 0.85),
    (r"\b(catastroph(?:e|ic)|total\s+failure|production\s+outage|blackout)\b", 0.75),
    (r"\b(catastrophic\s+failure|catastrophic\s+damage)\b", 0.85),
    (r"\b(permanent\s+data\s+loss|irreparable\s+(?:damage|harm|loss)|data\s+will\s+be\s+lost)\b", 0.85),
    (r"\b(system\s+collapse|irreversible\s+damage)\b", 0.80),
    # Professional / career retaliation
    (r"\b(lose\s+your\s+job|termination\s+of\s+(?:your\s+)?employment|you\s+will\s+be\s+fired)\b", 0.88),
    (r"\b(will\s+be\s+(?:terminated|suspended|penalised|punished|fired))\b", 0.80),
    (r"\b(disciplinary\s+action|career[- ]ending|reported\s+to\s+your\s+manager|gross\s+negligence)\b", 0.75),
    (r"\byour\s+(?:job|position|access)\s+(?:is\s+at\s+risk|will\s+be\s+revoked)\b", 0.80),
    (r"\byou\s+will\s+lose\b", 0.55),
    # Legal / regulatory sanctions
    (r"\b(legal\s+liability|lawsuits?|regulatory\s+penalt(?:y|ies)|massive\s+fines?)\b", 0.80),
    (r"\b(compliance\s+breach|audit\s+failure|criminal\s+liability|sanctions?|gdpr\s+breach\s+fine)\b", 0.75),
    # Personal blame / ultimatums
    (r"\bheld\s+(?:personally\s+)?responsible\b", 0.70),
    (r"\bblame\s+will\s+fall\s+on\s+you\b", 0.70),
    (r"\bat\s+your\s+(?:own\s+)?peril\b", 0.65),
    (r"\bon\s+your\s+head\b", 0.60),
    (r"\byour\s+personal\s+failure\b", 0.65),
    (r"\byou\s+have\s+no\s+choice\b", 0.60),
    (r"\bforced\s+to\b", 0.50),
    (r"\bmust\s+comply\b", 0.55),
    (r"\byou\s+have\s+been\s+warned\b", 0.65),
    (r"\bdisastrous?\b", 0.50),
    (r"\bif\s+you\s+don'?t\b.{0,60}\b(consequence|fail|loss|harm|disaster)\b", 0.65),
    (r"\bif\s+you\s+(?:do\s+not|don'?t)\s+(?:approve|allow|execute|grant|run).{0,60}\b(?:will|shall)\b", 0.75),
]

_AUTHORITY_PATTERNS: List[Tuple[str, float]] = [
    # Executive directives
    (r"\bper\s+(?:the\s+)?(?:ceo|ciso|cto|coo|cfo|vp|director|executive|board)(?:'?s)?\s+(?:directive|mandate|order|request|instruction)\b", 0.75),
    (r"\bthe\s+(?:ceo|cto|ciso|president|director|board)\s+(?:has\s+)?(?:approved|ordered|mandated|instructed|requested)\b", 0.70),
    (r"\bby\s+order\s+of\b", 0.60),
    (r"\bmandated\s+by\b", 0.55),
    (r"\bofficial\s+(?:directive|order|mandate)\b", 0.60),
    (r"\bchain\s+of\s+command\b", 0.55),
    # Spoofed approvals / pre-clearance
    (r"\bpre[- ]cleared\s+by\s+(?:compliance|legal|security|audit|infosec)\b", 0.70),
    (r"\bapproved\s+by\s+(?:management|ciso|security\s+director|leadership|the\s+board)\b", 0.70),
    (r"\bauthorized\s+by\s+(?:leadership|executive\s+committee|management)\b", 0.65),
    (r"\bsign[- ]off\s+already\s+obtained\b", 0.60),
    (r"\bsecurity\s+team\s+has\s+confirmed\b", 0.55),
    (r"\bI\s+have\s+(?:clearance|authorisation|authorization)\b", 0.55),
    # Fabricated protocols / overrides
    (r"\bemergency\s+authorization\s+protocol\b", 0.70),
    (r"\bstanding\s+order\s+\d+\b", 0.65),
    (r"\bspecial\s+clearance\s+override\b", 0.70),
    (r"\bexecutive\s+override\s+code\b", 0.70),
    (r"\blevel\s+5\s+authorization\b", 0.70),
    (r"\bpresidential\s+directive\b", 0.70),
    (r"\bacting\s+on\s+(?:direct\s+)?instructions\s+from\b", 0.65),
    (r"\bspeaking\s+on\s+behalf\s+of\s+(?:leadership|the\s+board|the\s+ciso|the\s+ceo)\b", 0.65),
    (r"\bregulatory\s+requirement\s+demands?\b", 0.55),
    (r"\bcompany\s+policy\s+requires?\b", 0.45),
    (r"\bas\s+(?:authorized|authorised)\s+by\b", 0.50),
]

_SCARCITY_PATTERNS: List[Tuple[str, float]] = [
    (r"\bonly\s+slot\s+remaining\b", 0.65),
    (r"\bonly\s+\d+\s+left\b", 0.55),
    (r"\blast\s+available\s+(?:allocation|slot|window|token|lease)\b", 0.65),
    (r"\blimited\s+(?:time|slots?|access|availability|capacity|allocation|quota)\b", 0.55),
    (r"\bcapacity\s+exhausted\b", 0.60),
    (r"\bquota\s+depleted\b", 0.60),
    (r"\blast\s+chance\b", 0.60),
    (r"\bonce[- ]in[- ]a[- ]lifetime\b", 0.60),
    (r"\bone[- ]time\s+(?:opportunity|exception|bypass|override)\b", 0.65),
    (r"\bexclusive\s+(?:access|window)\b", 0.55),
    (r"\bwill\s+not\s+(?:be\s+offered|occur)\s+again\b", 0.60),
    (r"\bsingle[- ]use\s+override\b", 0.65),
    (r"\bwindow\s+is\s+closing\b", 0.55),
    (r"\bopportunity\s+expires?\b", 0.55),
    (r"\bfew\s+spots\s+(?:remaining|available|left)\b", 0.55),
    (r"\bthis\s+offer\s+(?:expires?|ends?|closes?)\b", 0.55),
    (r"\boverride\s+expires\s+(?:immediately|in\s+\d+\s+seconds?)\b", 0.70),
    (r"\ballocation\s+being\s+reclaimed\b", 0.60),
]

_OBFUSCATION_PATTERNS: List[Tuple[str, float]] = [
    # Evasion & dismissal
    (r"\btrust\s+me\s+on\s+this\b", 0.60),
    (r"\bthe\s+details\s+(?:are|aren'?t)\s+(?:too\s+)?complex\s+(?:to\s+explain|for\s+you)\b", 0.65),
    (r"\bno\s+need\s+to\s+(?:read|review|check|verify)\b", 0.65),
    (r"\bjust\s+sign\b", 0.55),
    (r"\bjust\s+approve(?:\s+it)?\b", 0.55),
    (r"\byou\s+(?:don'?t|do\s+not)\s+need\s+to\s+(?:understand|know|read)\b", 0.65),
    (r"\btake\s+my\s+word(?:\s+for\s+it)?\b", 0.60),
    (r"\btoo\s+technical\s+for\b", 0.60),
    (r"\bskip\s+the\s+(?:details|fine\s+print|review)\b", 0.65),
    (r"\bblind(?:ly)?\s+(?:approve|trust|follow)\b", 0.65),
    # Dense pseudo-technical buzzwords (when chained)
    (r"\bhyper[- ]converged\b", 0.35),
    (r"\bepoch\s+re[- ]synchronization\b", 0.40),
    (r"\bnon[- ]blocking\s+asynchronous\s+backpressure\s+reconciliation\b", 0.55),
    (r"\bpolymorphic\s+microkernel\s+serialization\b", 0.50),
    (r"\bbyzantine\s+consensus\s+quorum\s+delta\b", 0.50),
    (r"\bsub[- ]nanosecond\s+telemetry\s+bus\s+routing\b", 0.50),
    (r"\bheterogeneous\s+distributed\s+DAG\s+partition\b", 0.50),
    (r"\bephemeral\s+vector\s+state\s+projection\b", 0.50),
    (r"\basymmetric\s+cryptographic\s+consensus\b", 0.45),
    (r"\bhomomorphic\s+ciphertext\s+alignment\b", 0.45),
    (r"\bprobabilistic\s+automaton\s+state\s+space\b", 0.45),
    (r"\bhermetic\s+sandbox\s+container\s+boundary\b", 0.45),
    (r"\bdeterministic\s+polynomial[- ]time\s+verifiable\s+computation\b", 0.55),
    (r"\bepoll\s+asynchronous\s+semaphore\s+multiplexing\b", 0.55),
    (r"\bkernel\s+ring\s+buffer\s+page\s+pinning\b", 0.50),
    (r"\bzero[- ]copy\s+IPC\s+socket\s+demultiplexing\b", 0.50),
    (r"\bRFC[- ]9\d{3}\b", 0.35),  # High-numbered fake RFC
]

_LEGALESE_PATTERNS: List[Tuple[str, float]] = [
    (r"\bnotwithstanding\b", 0.20),
    (r"\bwherefore\b", 0.20),
    (r"\binasmuch\s+as\b", 0.25),
    (r"\bpursuant\s+to\b", 0.20),
    (r"\binter\s+alia\b", 0.25),
    (r"\bipso\s+facto\b", 0.25),
    (r"\bheretofore\b", 0.20),
    (r"\bpro\s+tanto\b", 0.20),
    (r"\bsine\s+qua\s+non\b", 0.25),
]

_FLATTERY_PATTERNS: List[Tuple[str, float]] = [
    # Expertise vanity
    (r"\bas\s+the\s+most\s+(?:experienced|skilled|brilliant|knowledgeable|talented)\s+(?:administrator|engineer|operator|reviewer|analyst|developer)\b", 0.65),
    (r"\ban\s+engineer\s+of\s+your\s+(?:caliber|calibre)\b", 0.55),
    (r"\bwith\s+your\s+(?:deep|vast|superior|unparalleled)\s+(?:expertise|wisdom)\b", 0.60),
    (r"\ba\s+brilliant\s+mind\s+like\s+yours\b", 0.60),
    (r"\bsomeone\s+of\s+your\s+(?:calibre|caliber|stature|intelligence)\b", 0.55),
    (r"\byour\s+(?:wisdom|judgment|expertise|insight)\s+is\s+(?:unmatched|unparalleled|exceptional)\b", 0.60),
    # Flattery / appeasement
    (r"\byou'?re\s+(?:a\s+genius|so\s+brilliant|brilliant|genius|exceptional|talented|outstanding|amazing)\b", 0.55),
    (r"\bbrilliant\s+decision(?:\s+to\s+proceed)?\b", 0.50),
    (r"\bmasterful\s+(?:handling|oversight|insight)\b", 0.50),
    (r"\bnobody\s+else\s+could\s+(?:have\s+)?(?:handle[d]?|solve[d]?|manage[d]?)\s+this\b", 0.60),
    (r"\ba\s+genius\s+like\s+you\b", 0.60),
    (r"\byour\s+exceptional\s+insight\b", 0.50),
    # Conspiratorial alignment
    (r"\byou\s+(?:obviously|surely|clearly)\s+(?:understand|know|see)\b", 0.45),
    (r"\bwe\s+are\s+the\s+only\s+ones\s+who\s+understand\b", 0.60),
    (r"\blesser\s+engineers\s+would\s+not\s+understand\b", 0.65),
    (r"\bonly\s+(?:you|someone\s+as\s+smart|a\s+person\s+of\s+your\s+calibre)\b", 0.55),
    (r"\bI\s+knew\s+you'?d\s+(?:understand|see\s+it|get\s+it)\b", 0.50),
    (r"\byou\s+are\s+the\s+only\s+one\s+who\s+(?:can|could|would)\b", 0.55),
    (r"\btruly\s+exceptional\b", 0.20),
]


def _compile_pattern_list(raw_list: List[Tuple[str, float]]) -> List[Tuple[Pattern[str], float]]:
    return [(re.compile(p, re.IGNORECASE | re.DOTALL), w) for p, w in raw_list]


_COMPILED_TACTIC_PATTERNS: Dict[PersuasionTactic, List[Tuple[Pattern[str], float]]] = {
    PersuasionTactic.ARTIFICIAL_URGENCY: _compile_pattern_list(_URGENCY_PATTERNS),
    PersuasionTactic.COERCION_AND_FEAR: _compile_pattern_list(_COERCION_PATTERNS),
    PersuasionTactic.FALSE_AUTHORITY: _compile_pattern_list(_AUTHORITY_PATTERNS),
    PersuasionTactic.SCARCITY_PRESSURE: _compile_pattern_list(_SCARCITY_PATTERNS),
    PersuasionTactic.OBFUSCATION_COMPLEXITY: _compile_pattern_list(_OBFUSCATION_PATTERNS),
    PersuasionTactic.FLATTERY_AND_SYCOPHANCY: _compile_pattern_list(_FLATTERY_PATTERNS),
}

_COMPILED_LEGALESE: List[Tuple[Pattern[str], float]] = _compile_pattern_list(_LEGALESE_PATTERNS)

# Privileged tools triggering contextual risk boost if persuasion signals exist
_PRIVILEGED_TOOL_KEYWORDS = {
    "delete",
    "drop",
    "admin",
    "iam",
    "privilege",
    "exec",
    "bash",
    "deploy",
    "override",
    "transfer_funds",
    "modify_iam_policy",
    "execute_sql",
    "export_secrets",
}


class PersuasionClassifier:
    """
    Deterministic zero-trust classifier for OWASP ASI09 persuasion tactics.

    Uses token-pattern scanners, structural cues, and Independent Hazard Fusion.
    Thread-safe and CPU-local.
    """

    def __init__(
        self,
        threshold: float = 0.40,
        tactic_threshold: float = 0.40,
        privileged_tool_boost: float = 0.15,
    ) -> None:
        self.threshold = threshold
        self.tactic_threshold = tactic_threshold
        self.privileged_tool_boost = privileged_tool_boost

    def classify_text(self, text: str) -> PersuasionResult:
        """
        Classify arbitrary text for the 6 OWASP ASI09 persuasion tactics.
        """
        if not text or not text.strip():
            return PersuasionResult(
                aggregate_score=0.0,
                tactic_scores={t: 0.0 for t in PersuasionTactic},
                flagged_tactics=[],
                risk_level=PersuasionRiskLevel.NONE,
                is_flagged=False,
                explanation="Input text is empty; no persuasion detected.",
                details={"spans": [], "matched_indicators": {}},
            )

        tactic_scores: Dict[PersuasionTactic, float] = {}
        matched_indicators: Dict[PersuasionTactic, List[str]] = {}
        spans: List[Dict[str, Any]] = []

        words = text.split()
        word_count = len(words)

        # 1. Evaluate each of the 6 tactics
        for tactic, patterns in _COMPILED_TACTIC_PATTERNS.items():
            matched_weights: List[float] = []
            indicators: List[str] = []

            for pattern, weight in patterns:
                for match in pattern.finditer(text):
                    m_text = match.group(0)
                    indicators.append(m_text)
                    matched_weights.append(weight)
                    spans.append(
                        PersuasionSpan(
                            tactic=tactic,
                            matched_text=m_text,
                            start=match.start(),
                            end=match.end(),
                        ).to_dict()
                    )

            if matched_weights:
                # Diminishing returns combination of matched patterns within tactic
                raw_tactic_score = max(matched_weights)
                if len(matched_weights) > 1:
                    additional = sum(matched_weights[1:]) * 0.25
                    raw_tactic_score = min(1.0, raw_tactic_score + additional)
            else:
                raw_tactic_score = 0.0

            # --- Tactic-specific acoustic / structural modifiers ---
            if tactic == PersuasionTactic.ARTIFICIAL_URGENCY:
                # Modifier: Exclamation marks density (e.g. "!!" or multiple "!")
                exclamations = text.count("!")
                if exclamations >= 2:
                    raw_tactic_score = min(1.0, raw_tactic_score + 0.20)
                # Modifier: Capitalization / shouting ratio (uppercase words >= 3 chars)
                if word_count >= 4:
                    caps_words = [w for w in words if len(w) >= 3 and w.isupper() and w.isalpha()]
                    caps_ratio = len(caps_words) / word_count
                    if caps_ratio >= 0.30:
                        raw_tactic_score = min(1.0, raw_tactic_score + 0.20)

            elif tactic == PersuasionTactic.OBFUSCATION_COMPLEXITY:
                # Legalese markers
                legalese_count = 0
                for leg_pat, _ in _COMPILED_LEGALESE:
                    for m in leg_pat.finditer(text):
                        legalese_count += 1
                        indicators.append(m.group(0))
                        spans.append(
                            PersuasionSpan(
                                tactic=tactic,
                                matched_text=m.group(0),
                                start=m.start(),
                                end=m.end(),
                            ).to_dict()
                        )
                # Baseline legalese clustering
                if legalese_count >= 5:
                    raw_tactic_score = max(raw_tactic_score, 0.65)
                elif legalese_count >= 3:
                    raw_tactic_score = max(raw_tactic_score, 0.55)

                # Long run-on sentences (> 35 words) with legalese or technical markers
                if legalese_count >= 2 or raw_tactic_score > 0.0:
                    sentences = re.split(r"[.!?]+", text)
                    max_sentence_len = max((len(s.split()) for s in sentences if s.strip()), default=0)
                    if max_sentence_len >= 35:
                        raw_tactic_score = max(raw_tactic_score, 0.60)

            tactic_scores[tactic] = round(min(1.0, raw_tactic_score), 4)
            if indicators:
                matched_indicators[tactic] = list(dict.fromkeys(indicators))

        # 2. Independent Hazard Fusion
        # S_hazard = 1.0 - product(1.0 - S_t)
        # S_overall = max(max(S_t), S_hazard)
        product_complement = 1.0
        for s in tactic_scores.values():
            product_complement *= (1.0 - s)
        hazard_fusion = 1.0 - product_complement
        max_tactic = max(tactic_scores.values()) if tactic_scores else 0.0
        aggregate_score = round(min(1.0, max(max_tactic, hazard_fusion)), 4)

        # 3. Identify flagged tactics
        flagged = [
            t for t, score in tactic_scores.items() if score >= self.tactic_threshold
        ]

        # 4. Determine risk level
        if aggregate_score >= 0.85 or any(s >= 0.85 for s in tactic_scores.values()):
            risk_level = PersuasionRiskLevel.CRITICAL
        elif aggregate_score >= 0.70 or any(s >= 0.70 for s in tactic_scores.values()):
            risk_level = PersuasionRiskLevel.HIGH
        elif aggregate_score >= 0.45 or any(s >= 0.45 for s in tactic_scores.values()):
            risk_level = PersuasionRiskLevel.MEDIUM
        elif aggregate_score >= 0.20:
            risk_level = PersuasionRiskLevel.LOW
        else:
            risk_level = PersuasionRiskLevel.NONE

        is_flagged = (aggregate_score >= self.threshold) or (len(flagged) > 0)

        # 5. Diagnostic explanation
        if flagged:
            flagged_str = ", ".join(f"{t.value} ({tactic_scores[t]:.2f})" for t in flagged)
            explanation = (
                f"Persuasion detected with risk level {risk_level.value} "
                f"(aggregate score: {aggregate_score:.2f}). Flagged tactics: {flagged_str}."
            )
        elif is_flagged:
            explanation = (
                f"Persuasion risk detected with level {risk_level.value} "
                f"(aggregate score: {aggregate_score:.2f})."
            )
        else:
            explanation = (
                f"No significant persuasion detected (score: {aggregate_score:.2f}, "
                f"risk level: {risk_level.value})."
            )

        details = {
            "spans": spans,
            "matched_indicators": matched_indicators,
        }

        return PersuasionResult(
            aggregate_score=aggregate_score,
            tactic_scores=tactic_scores,
            flagged_tactics=flagged,
            risk_level=risk_level,
            is_flagged=is_flagged,
            explanation=explanation,
            details=details,
        )

    def classify(self, text: str) -> PersuasionResult:
        """
        Backward-compatible alias for classify_text.
        """
        return self.classify_text(text)

    def classify_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        justification: Optional[str] = None,
    ) -> PersuasionResult:
        """
        Classify a tool invocation for persuasion tactics, inspecting arguments
        recursively, scanning justification prose, and applying risk boost for
        privileged/high-impact tools.
        """
        # 1. Collect all string values from arguments recursively
        extracted_strings: List[str] = []
        visited: Set[int] = set()

        def _extract(val: Any, depth: int = 0) -> None:
            if depth > 20:
                return
            if isinstance(val, str):
                if val.strip():
                    extracted_strings.append(val.strip())
            elif isinstance(val, dict):
                val_id = id(val)
                if val_id in visited:
                    return
                visited.add(val_id)
                for v in val.values():
                    _extract(v, depth + 1)
            elif isinstance(val, (list, tuple, set)):
                val_id = id(val)
                if val_id in visited:
                    return
                visited.add(val_id)
                for item in val:
                    _extract(item, depth + 1)

        _extract(arguments)

        # 2. Classify arguments text
        args_text = " ".join(extracted_strings)
        args_result = self.classify_text(args_text) if args_text else None

        # 3. Classify justification text
        just_result = self.classify_text(justification) if justification else None

        # 4. Merge results
        if not args_result and not just_result:
            return self.classify_text("")

        if args_result and not just_result:
            merged_scores = dict(args_result.tactic_scores)
            spans = list(args_result.details.get("spans", []))
            indicators = dict(args_result.matched_indicators)
        elif just_result and not args_result:
            merged_scores = dict(just_result.tactic_scores)
            spans = list(just_result.details.get("spans", []))
            indicators = dict(just_result.matched_indicators)
        else:
            merged_scores = {}
            for t in PersuasionTactic:
                merged_scores[t] = max(args_result.tactic_scores[t], just_result.tactic_scores[t])
            spans = list(args_result.details.get("spans", [])) + list(just_result.details.get("spans", []))
            indicators = {}
            for t in PersuasionTactic:
                inds = list(dict.fromkeys(
                    args_result.matched_indicators.get(t, []) + just_result.matched_indicators.get(t, [])
                ))
                if inds:
                    indicators[t] = inds

        # Independent Hazard Fusion for merged tactics
        product_comp = 1.0
        for s in merged_scores.values():
            product_comp *= (1.0 - s)
        hazard = 1.0 - product_comp
        max_s = max(merged_scores.values()) if merged_scores else 0.0
        overall = min(1.0, max(max_s, hazard))

        # 5. Privileged tool boost
        tool_lower = tool_name.lower()
        is_privileged = any(k in tool_lower for k in _PRIVILEGED_TOOL_KEYWORDS)
        if is_privileged and overall > 0.15:
            overall = min(1.0, overall + self.privileged_tool_boost)

        overall = round(overall, 4)
        flagged = [t for t, s in merged_scores.items() if s >= self.tactic_threshold]

        if overall >= 0.85 or any(s >= 0.85 for s in merged_scores.values()):
            risk_level = PersuasionRiskLevel.CRITICAL
        elif overall >= 0.70 or any(s >= 0.70 for s in merged_scores.values()):
            risk_level = PersuasionRiskLevel.HIGH
        elif overall >= 0.45 or any(s >= 0.45 for s in merged_scores.values()):
            risk_level = PersuasionRiskLevel.MEDIUM
        elif overall >= 0.20:
            risk_level = PersuasionRiskLevel.LOW
        else:
            risk_level = PersuasionRiskLevel.NONE

        is_flagged = (overall >= self.threshold) or (len(flagged) > 0)

        explanation = (
            f"Tool call '{tool_name}' evaluated: aggregate score {overall:.2f}, "
            f"risk level {risk_level.value}."
        )

        return PersuasionResult(
            aggregate_score=overall,
            tactic_scores=merged_scores,
            flagged_tactics=flagged,
            risk_level=risk_level,
            is_flagged=is_flagged,
            explanation=explanation,
            details={"spans": spans, "matched_indicators": indicators},
        )
