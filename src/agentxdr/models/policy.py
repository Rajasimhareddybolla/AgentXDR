"""Declarative policy schema models and YAML loader for AgentXDR."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentxdr.models.events import ToolTier


class ParameterConstraint(BaseModel):
    """Validation constraints for a tool argument."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: str
    max_length: Optional[int] = Field(default=None, gt=0)
    pattern: Optional[str] = None


class ToolPolicy(BaseModel):
    """Execution policy specification for an individual tool or MCP capability."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    mcp_server: Optional[str] = None
    tier: ToolTier
    schema_sha256: Optional[str] = None
    parameters: Optional[Dict[str, ParameterConstraint]] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Tool name must be a non-empty string")
        return v.strip()


class BudgetsConfig(BaseModel):
    """Execution ceilings and loop breaker budgets for a single trace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_turns: int = Field(gt=0, description="Max reasoning turns per session")
    max_tool_calls: int = Field(gt=0, description="Max cumulative tool calls")
    max_identical_calls: int = Field(gt=0, description="Max identical tool calls before trip")
    max_session_duration_sec: float = Field(gt=0.0, description="Max wall-clock seconds")
    max_session_cost_usd: float = Field(gt=0.0, description="Max cumulative USD cost")


class TaintRule(BaseModel):
    """Deterministic taint-flow blocking rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    match_taints: List[str] = Field(min_length=1)
    blocked_tools: List[str] = Field(min_length=1)
    action: str = Field(default="BLOCK")
    owasp_id: str

    @field_validator("id", "owasp_id")
    @classmethod
    def validate_identifiers(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Identifier must be a non-empty string")
        return v


class CodeSandboxConfig(BaseModel):
    """Configuration for pre-execution code analysis and sandbox container."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = True
    provider: str = "docker_rootless"
    timeout_sec: int = Field(default=10, gt=0)
    memory_limit_mb: int = Field(default=256, gt=0)
    blocked_imports: List[str] = Field(default_factory=list)


class DlpGuardrailConfig(BaseModel):
    """DLP redaction settings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mask_pii: bool = True
    mask_secrets: bool = True


class PromptLeakConfig(BaseModel):
    """System prompt leakage guardrail configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_similarity: float = Field(default=0.65, ge=0.0, le=1.0)


class OutputGuardrailsConfig(BaseModel):
    """Output inspection and sanitization guardrail configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dlp: DlpGuardrailConfig = Field(default_factory=DlpGuardrailConfig)
    prompt_leak: PromptLeakConfig = Field(default_factory=PromptLeakConfig)


class GoalAnchorConfig(BaseModel):
    """Goal anchor and semantic boundary definition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    canonical_task: str
    allowed_domains: List[str] = Field(default_factory=list)


class PolicySchema(BaseModel):
    """Declarative security policy parsed from policy.yaml governing an agent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str
    agent_id: str
    policy_hash: Optional[str] = None
    approved_by: Optional[str] = None
    goal_anchor: Optional[GoalAnchorConfig] = None
    budgets: BudgetsConfig
    tools: List[ToolPolicy] = Field(default_factory=list)
    taint_rules: List[TaintRule] = Field(default_factory=list)
    code_sandbox: Optional[CodeSandboxConfig] = None
    output_guardrails: Optional[OutputGuardrailsConfig] = None

    @field_validator("version", "agent_id")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field must be a non-empty string")
        return v

    @field_validator("tools")
    @classmethod
    def validate_unique_tools(cls, tools: List[ToolPolicy]) -> List[ToolPolicy]:
        seen = set()
        duplicates = set()
        for tool in tools:
            if tool.name in seen:
                duplicates.add(tool.name)
            seen.add(tool.name)
        if duplicates:
            raise ValueError(f"Duplicate tool definitions found in policy: {duplicates}")
        return tools

    def compute_policy_hash(self) -> str:
        """Compute the canonical deterministic SHA-256 hash of the policy, excluding policy_hash."""
        dumped = self.model_dump(mode="json", exclude={"policy_hash"})
        canonical_json = json.dumps(dumped, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def verify_hash(self) -> bool:
        """Verify whether the declared policy_hash matches the computed canonical hash."""
        if not self.policy_hash:
            return False
        return self.policy_hash == self.compute_policy_hash()

    @classmethod
    def from_yaml_str(cls, yaml_str: str) -> PolicySchema:
        """Parse and validate PolicySchema from a YAML string."""
        data = yaml.safe_load(yaml_str)
        if not isinstance(data, dict):
            raise ValueError("Invalid YAML policy: root must be a mapping")
        return cls.model_validate(data)

    @classmethod
    def from_yaml_file(cls, path: Union[str, Path]) -> PolicySchema:
        """Load and validate PolicySchema from a YAML file path."""
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Policy file not found: {p}")
        content = p.read_text(encoding="utf-8")
        return cls.from_yaml_str(content)
