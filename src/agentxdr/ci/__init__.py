"""CI/CD security gates for AgentXDR: policy regression diffing and dependency auditing."""

from agentxdr.ci.dependency_audit import (
    DependencyAuditReport,
    DependencyAuditor,
    DependencyFinding,
)
from agentxdr.ci.policy_diff import (
    PolicyDiffEngine,
    PolicyDiffFinding,
    PolicyDiffReport,
    RegressionSeverity,
)

__all__ = [
    "PolicyDiffEngine",
    "PolicyDiffFinding",
    "PolicyDiffReport",
    "RegressionSeverity",
    "DependencyAuditor",
    "DependencyAuditReport",
    "DependencyFinding",
]
