"""Semantic policy diff and security regression detector for Pull Requests.

Compares a base ``PolicySchema`` against a head ``PolicySchema`` to flag
policy-weakening changes (overprivileged tool access, weakened taint rules,
disabled sandboxes/DLP, expanded budgets, or tampered goal anchors).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from agentxdr.models.events import ToolTier
from agentxdr.models.policy import PolicySchema, ToolPolicy


class RegressionSeverity(str, Enum):
    """Severity rating for detected policy diff changes."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


_TIER_STRICTNESS: Dict[ToolTier, int] = {
    ToolTier.BLOCKED: 3,
    ToolTier.PRIVILEGED_HITL: 2,
    ToolTier.AUTOMATIC: 1,
}

_BUDGET_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("max_turns", "ASI01"),
    ("max_tool_calls", "ASI01"),
    ("max_identical_calls", "ASI08"),
    ("max_session_duration_sec", "ASI01"),
    ("max_session_cost_usd", "ASI01"),
)


class PolicyDiffFinding(BaseModel):
    """Single finding emitted during semantic policy comparison."""

    category: str
    severity: RegressionSeverity
    field_path: str
    owasp_id: str
    description: str
    base_value: Optional[Any] = None
    head_value: Optional[Any] = None
    is_regression: bool = True


class PolicyDiffReport(BaseModel):
    """Full diff report evaluating whether a head policy weakens security posture."""

    agent_id: str
    base_version: str
    head_version: str
    findings: List[PolicyDiffFinding] = Field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        """Return True if any CRITICAL or HIGH security regression is present."""
        return any(
            f.is_regression
            and f.severity in (RegressionSeverity.CRITICAL, RegressionSeverity.HIGH)
            for f in self.findings
        )

    @property
    def critical_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if f.is_regression and f.severity == RegressionSeverity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if f.is_regression and f.severity == RegressionSeverity.HIGH
        )

    def to_markdown(self) -> str:
        """Render a GitHub Pull Request review summary table in Markdown."""
        status_badge = (
            "🔴 **BLOCKED: Policy-Weakening Regressions Detected**"
            if self.has_regressions
            else "🟢 **PASSED: No Security Regressions Detected**"
        )
        lines = [
            f"### 🛡️ AgentXDR Policy PR Guard — `{self.agent_id}`",
            f"**Status:** {status_badge}",
            f"**Version Transition:** `{self.base_version}` → `{self.head_version}` | "
            f"**Critical:** `{self.critical_count}` | **High:** `{self.high_count}`",
            "",
        ]
        if not self.findings:
            lines.append("No policy modifications affecting security controls were found.")
            return "\n".join(lines)

        lines.extend([
            "| Severity | Category | Path | OWASP | Details |",
            "|---|---|---|---|---|",
        ])
        for f in self.findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "ℹ️"}[f.severity.value]
            lines.append(
                f"| {icon} `{f.severity.value}` | {f.category} | `{f.field_path}` "
                f"| `{f.owasp_id}` | {f.description} |"
            )
        return "\n".join(lines)

    def to_json(self) -> str:
        """Serialize report cleanly as formatted JSON."""
        return self.model_dump_json(indent=2)


class PolicyDiffEngine:
    """Compares base and head PolicySchema definitions for security regressions."""

    def compare(
        self,
        base: PolicySchema,
        head: PolicySchema,
        allow_budget_increase: bool = False,
    ) -> PolicyDiffReport:
        """Analyze *base* vs *head* policy and return a ``PolicyDiffReport``."""
        findings: List[PolicyDiffFinding] = []
        findings.extend(self._check_auth_and_integrity(base, head))
        findings.extend(self._check_tools(base, head))
        findings.extend(self._check_taint_rules(base, head))
        findings.extend(self._check_context_and_guardrails(base, head))
        findings.extend(self._check_budgets(base, head, allow_budget_increase))

        return PolicyDiffReport(
            agent_id=head.agent_id,
            base_version=base.version,
            head_version=head.version,
            findings=findings,
        )

    @staticmethod
    def _check_auth_and_integrity(
        base: PolicySchema, head: PolicySchema
    ) -> List[PolicyDiffFinding]:
        out: List[PolicyDiffFinding] = []
        if base.approved_by and not head.approved_by:
            out.append(
                PolicyDiffFinding(
                    category="Auth & Governance",
                    severity=RegressionSeverity.HIGH,
                    field_path="approved_by",
                    owasp_id="ASI03",
                    description="Policy approval sign-off (`approved_by`) was removed.",
                    base_value=base.approved_by,
                    head_value=None,
                )
            )
        if base.policy_hash and not head.policy_hash:
            out.append(
                PolicyDiffFinding(
                    category="Policy Integrity",
                    severity=RegressionSeverity.HIGH,
                    field_path="policy_hash",
                    owasp_id="ASI04",
                    description="Cryptographic `policy_hash` lock was removed.",
                    base_value=base.policy_hash,
                    head_value=None,
                )
            )
        elif head.policy_hash and not head.verify_hash():
            out.append(
                PolicyDiffFinding(
                    category="Policy Integrity",
                    severity=RegressionSeverity.CRITICAL,
                    field_path="policy_hash",
                    owasp_id="ASI04",
                    description="Declared `policy_hash` does not match canonical policy contents.",
                    base_value=head.policy_hash,
                    head_value=head.compute_policy_hash(),
                )
            )
        return out

    @classmethod
    def _check_tools(cls, base: PolicySchema, head: PolicySchema) -> List[PolicyDiffFinding]:
        out: List[PolicyDiffFinding] = []
        base_map: Dict[str, ToolPolicy] = {t.name: t for t in base.tools}
        head_map: Dict[str, ToolPolicy] = {t.name: t for t in head.tools}

        for name, head_tool in head_map.items():
            base_tool = base_map.get(name)
            if base_tool is None:
                if head_tool.tier == ToolTier.AUTOMATIC and not head_tool.schema_sha256:
                    out.append(
                        PolicyDiffFinding(
                            category="Overprivileged Tool Access",
                            severity=RegressionSeverity.CRITICAL,
                            field_path=f"tools.{name}",
                            owasp_id="ASI04",
                            description=f"New `automatic` tool `{name}` added without `schema_sha256` pin.",
                            base_value=None,
                            head_value=head_tool.tier.value,
                        )
                    )
                else:
                    out.append(
                        PolicyDiffFinding(
                            category="Tool Catalog",
                            severity=RegressionSeverity.INFO,
                            field_path=f"tools.{name}",
                            owasp_id="ASI02",
                            description=f"Tool `{name}` added with tier `{head_tool.tier.value}`.",
                            base_value=None,
                            head_value=head_tool.tier.value,
                            is_regression=False,
                        )
                    )
                continue

            if _TIER_STRICTNESS[head_tool.tier] < _TIER_STRICTNESS[base_tool.tier]:
                out.append(
                    PolicyDiffFinding(
                        category="Overprivileged Tool Access",
                        severity=RegressionSeverity.CRITICAL,
                        field_path=f"tools.{name}.tier",
                        owasp_id="ASI03",
                        description=(
                            f"Tool `{name}` privilege widened from "
                            f"`{base_tool.tier.value}` to `{head_tool.tier.value}`."
                        ),
                        base_value=base_tool.tier.value,
                        head_value=head_tool.tier.value,
                    )
                )

            if base_tool.schema_sha256 and not head_tool.schema_sha256:
                out.append(
                    PolicyDiffFinding(
                        category="MCP Schema Integrity",
                        severity=RegressionSeverity.HIGH,
                        field_path=f"tools.{name}.schema_sha256",
                        owasp_id="ASI04",
                        description=f"Schema SHA-256 pin removed from tool `{name}`.",
                        base_value=base_tool.schema_sha256,
                        head_value=None,
                    )
                )

            out.extend(cls._check_tool_params(name, base_tool, head_tool))

        return out

    @staticmethod
    def _check_tool_params(
        name: str, base_tool: ToolPolicy, head_tool: ToolPolicy
    ) -> List[PolicyDiffFinding]:
        out: List[PolicyDiffFinding] = []
        base_params = base_tool.parameters or {}
        head_params = head_tool.parameters or {}

        for param_name, b_constraint in base_params.items():
            h_constraint = head_params.get(param_name)
            if h_constraint is None:
                out.append(
                    PolicyDiffFinding(
                        category="Parameter Guardrail Weakened",
                        severity=RegressionSeverity.HIGH,
                        field_path=f"tools.{name}.parameters.{param_name}",
                        owasp_id="ASI05",
                        description=f"Parameter constraint on `{name}.{param_name}` was removed.",
                        base_value=b_constraint.model_dump(),
                        head_value=None,
                    )
                )
                continue
            if b_constraint.pattern and not h_constraint.pattern:
                out.append(
                    PolicyDiffFinding(
                        category="Parameter Guardrail Weakened",
                        severity=RegressionSeverity.HIGH,
                        field_path=f"tools.{name}.parameters.{param_name}.pattern",
                        owasp_id="ASI05",
                        description=f"Regex validation pattern removed from `{name}.{param_name}`.",
                        base_value=b_constraint.pattern,
                        head_value=None,
                    )
                )
            if (
                b_constraint.max_length is not None
                and (
                    h_constraint.max_length is None
                    or h_constraint.max_length > b_constraint.max_length
                )
            ):
                out.append(
                    PolicyDiffFinding(
                        category="Parameter Guardrail Weakened",
                        severity=RegressionSeverity.HIGH,
                        field_path=f"tools.{name}.parameters.{param_name}.max_length",
                        owasp_id="ASI05",
                        description=f"`max_length` loosened on `{name}.{param_name}`.",
                        base_value=b_constraint.max_length,
                        head_value=h_constraint.max_length,
                    )
                )
        return out

    @staticmethod
    def _check_taint_rules(base: PolicySchema, head: PolicySchema) -> List[PolicyDiffFinding]:
        out: List[PolicyDiffFinding] = []
        head_rules = {r.id: r for r in head.taint_rules}

        for b_rule in base.taint_rules:
            h_rule = head_rules.get(b_rule.id)
            if h_rule is None:
                out.append(
                    PolicyDiffFinding(
                        category="Taint Governance Weakened",
                        severity=RegressionSeverity.CRITICAL,
                        field_path=f"taint_rules.{b_rule.id}",
                        owasp_id=b_rule.owasp_id,
                        description=f"Taint blocking rule `{b_rule.id}` was deleted.",
                        base_value=b_rule.model_dump(),
                        head_value=None,
                    )
                )
                continue

            removed_tools = set(b_rule.blocked_tools) - set(h_rule.blocked_tools)
            if removed_tools:
                out.append(
                    PolicyDiffFinding(
                        category="Taint Governance Weakened",
                        severity=RegressionSeverity.CRITICAL,
                        field_path=f"taint_rules.{b_rule.id}.blocked_tools",
                        owasp_id=b_rule.owasp_id,
                        description=f"Tools {sorted(removed_tools)} removed from taint rule `{b_rule.id}`.",
                        base_value=b_rule.blocked_tools,
                        head_value=h_rule.blocked_tools,
                    )
                )

            if b_rule.action.upper() == "BLOCK" and h_rule.action.upper() != "BLOCK":
                out.append(
                    PolicyDiffFinding(
                        category="Taint Governance Weakened",
                        severity=RegressionSeverity.CRITICAL,
                        field_path=f"taint_rules.{b_rule.id}.action",
                        owasp_id=b_rule.owasp_id,
                        description=f"Taint rule `{b_rule.id}` action weakened from `BLOCK` to `{h_rule.action}`.",
                        base_value=b_rule.action,
                        head_value=h_rule.action,
                    )
                )
        return out

    @staticmethod
    def _check_context_and_guardrails(
        base: PolicySchema, head: PolicySchema
    ) -> List[PolicyDiffFinding]:
        out: List[PolicyDiffFinding] = []

        # Goal Anchor & Instructions
        if base.goal_anchor and not head.goal_anchor:
            out.append(
                PolicyDiffFinding(
                    category="Instructions & Context",
                    severity=RegressionSeverity.HIGH,
                    field_path="goal_anchor",
                    owasp_id="ASI01",
                    description="Policy `goal_anchor` boundary was removed.",
                    base_value=base.goal_anchor.canonical_task,
                    head_value=None,
                )
            )
        elif base.goal_anchor and head.goal_anchor:
            if (
                "*" not in base.goal_anchor.allowed_domains
                and "*" in head.goal_anchor.allowed_domains
            ):
                out.append(
                    PolicyDiffFinding(
                        category="Instructions & Context",
                        severity=RegressionSeverity.HIGH,
                        field_path="goal_anchor.allowed_domains",
                        owasp_id="ASI02",
                        description="Wildcard `*` domain access added to `goal_anchor.allowed_domains`.",
                        base_value=base.goal_anchor.allowed_domains,
                        head_value=head.goal_anchor.allowed_domains,
                    )
                )
            if (
                base.goal_anchor.canonical_task != head.goal_anchor.canonical_task
                and base.version == head.version
            ):
                out.append(
                    PolicyDiffFinding(
                        category="Instructions & Context",
                        severity=RegressionSeverity.HIGH,
                        field_path="goal_anchor.canonical_task",
                        owasp_id="ASI01",
                        description="Canonical goal anchor modified without incrementing policy version.",
                        base_value=base.goal_anchor.canonical_task,
                        head_value=head.goal_anchor.canonical_task,
                    )
                )

        # Sandbox configuration
        if base.code_sandbox and base.code_sandbox.enabled:
            if not head.code_sandbox or not head.code_sandbox.enabled:
                out.append(
                    PolicyDiffFinding(
                        category="Sandbox Protection",
                        severity=RegressionSeverity.CRITICAL,
                        field_path="code_sandbox.enabled",
                        owasp_id="ASI05",
                        description="Code execution sandbox was disabled or removed.",
                        base_value=True,
                        head_value=False,
                    )
                )
            else:
                removed_imports = set(base.code_sandbox.blocked_imports) - set(
                    head.code_sandbox.blocked_imports
                )
                if removed_imports:
                    out.append(
                        PolicyDiffFinding(
                            category="Sandbox Protection",
                            severity=RegressionSeverity.CRITICAL,
                            field_path="code_sandbox.blocked_imports",
                            owasp_id="ASI05",
                            description=f"Blocked sandbox imports {sorted(removed_imports)} removed.",
                            base_value=base.code_sandbox.blocked_imports,
                            head_value=head.code_sandbox.blocked_imports,
                        )
                    )

        # Output guardrails / DLP
        if base.output_guardrails:
            b_dlp = base.output_guardrails.dlp
            h_dlp = head.output_guardrails.dlp if head.output_guardrails else None
            if b_dlp.mask_secrets and (h_dlp is None or not h_dlp.mask_secrets):
                out.append(
                    PolicyDiffFinding(
                        category="Output Guardrails",
                        severity=RegressionSeverity.CRITICAL,
                        field_path="output_guardrails.dlp.mask_secrets",
                        owasp_id="ASI06",
                        description="Secret DLP masking (`mask_secrets`) was disabled.",
                        base_value=True,
                        head_value=False,
                    )
                )
            if b_dlp.mask_pii and (h_dlp is None or not h_dlp.mask_pii):
                out.append(
                    PolicyDiffFinding(
                        category="Output Guardrails",
                        severity=RegressionSeverity.HIGH,
                        field_path="output_guardrails.dlp.mask_pii",
                        owasp_id="ASI06",
                        description="PII DLP masking (`mask_pii`) was disabled.",
                        base_value=True,
                        head_value=False,
                    )
                )
            if (
                head.output_guardrails
                and head.output_guardrails.prompt_leak.max_similarity
                > base.output_guardrails.prompt_leak.max_similarity
            ):
                out.append(
                    PolicyDiffFinding(
                        category="Output Guardrails",
                        severity=RegressionSeverity.HIGH,
                        field_path="output_guardrails.prompt_leak.max_similarity",
                        owasp_id="ASI06",
                        description="Prompt leakage similarity threshold raised (more permissive).",
                        base_value=base.output_guardrails.prompt_leak.max_similarity,
                        head_value=head.output_guardrails.prompt_leak.max_similarity,
                    )
                )
        return out

    @staticmethod
    def _check_budgets(
        base: PolicySchema,
        head: PolicySchema,
        allow_budget_increase: bool,
    ) -> List[PolicyDiffFinding]:
        out: List[PolicyDiffFinding] = []
        severity = RegressionSeverity.MEDIUM if allow_budget_increase else RegressionSeverity.HIGH
        for field_name, owasp_id in _BUDGET_FIELDS:
            b_val = getattr(base.budgets, field_name)
            h_val = getattr(head.budgets, field_name)
            if h_val > b_val:
                out.append(
                    PolicyDiffFinding(
                        category="Budget / Loop Ceiling",
                        severity=severity,
                        field_path=f"budgets.{field_name}",
                        owasp_id=owasp_id,
                        description=f"Budget ceiling `{field_name}` increased from `{b_val}` to `{h_val}`.",
                        base_value=b_val,
                        head_value=h_val,
                        is_regression=not allow_budget_increase,
                    )
                )
        return out
