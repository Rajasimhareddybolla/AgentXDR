"""Dependency and external MCP package vulnerability scanner for AgentXDR CI."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

from agentxdr.ci.policy_diff import RegressionSeverity

# Curated offline CVE / advisory rules: (ecosystem, package_lower) -> list of advisories
_OFFLINE_ADVISORIES: Dict[Tuple[str, str], List[Dict[str, str]]] = {
    ("PyPI", "starlette"): [
        {
            "fixed": "0.40.0",
            "cve": "CVE-2024-47874",
            "severity": "HIGH",
            "title": "Multipart form DoS vulnerability in Starlette < 0.40.0",
        }
    ],
    ("PyPI", "cryptography"): [
        {
            "fixed": "42.0.0",
            "cve": "CVE-2024-26130",
            "severity": "HIGH",
            "title": "NULL pointer dereference in cryptography < 42.0.0",
        }
    ],
    ("PyPI", "pyyaml"): [
        {
            "fixed": "5.4.0",
            "cve": "CVE-2020-14343",
            "severity": "CRITICAL",
            "title": "Arbitrary code execution via FullLoader in PyYAML < 5.4.0",
        }
    ],
    ("PyPI", "mcp"): [
        {
            "fixed": "1.2.0",
            "cve": "ADV-MCP-2025-01",
            "severity": "HIGH",
            "title": "Outdated MCP SDK missing strict stdio origin hardening",
        }
    ],
    ("npm", "@modelcontextprotocol/server-filesystem"): [
        {
            "fixed": "0.6.3",
            "cve": "ADV-MCP-FS-001",
            "severity": "CRITICAL",
            "title": "Symlink path traversal outside allowed directories in < 0.6.3",
        }
    ],
    ("npm", "@modelcontextprotocol/server-git"): [
        {
            "fixed": "0.6.2",
            "cve": "ADV-MCP-GIT-001",
            "severity": "HIGH",
            "title": "Command argument injection in MCP git server < 0.6.2",
        }
    ],
}

_DEP_SPEC_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(.*)$")
_VERSION_EXTRACT_RE = re.compile(r"(\d+(?:\.\d+)+)")


class DependencyFinding(BaseModel):
    """Security or hygiene finding on a Python or external MCP dependency."""

    package: str
    ecosystem: str
    version_spec: str
    severity: RegressionSeverity
    cve_id: str
    title: str
    remediation: str
    source_file: str


class DependencyAuditReport(BaseModel):
    """Aggregate report from scanning dependencies and MCP tool packages."""

    scanned_files: List[str] = Field(default_factory=list)
    packages_checked: int = 0
    findings: List[DependencyFinding] = Field(default_factory=list)

    @property
    def has_blocking_findings(self) -> bool:
        return any(
            f.severity in (RegressionSeverity.CRITICAL, RegressionSeverity.HIGH)
            for f in self.findings
        )

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def to_text(self) -> str:
        lines = [
            f"AgentXDR Dependency Audit: {self.packages_checked} packages checked across "
            f"{len(self.scanned_files)} file(s)",
            f"Findings: {len(self.findings)} (Blocking: {self.has_blocking_findings})",
        ]
        for f in self.findings:
            lines.append(
                f"  [{f.severity.value}] {f.ecosystem}:{f.package} ({f.version_spec}) "
                f"- {f.cve_id}: {f.title} ({f.source_file})"
            )
        return "\n".join(lines)


def _parse_version_tuple(ver_str: str) -> Optional[Tuple[int, ...]]:
    match = _VERSION_EXTRACT_RE.search(ver_str)
    if not match:
        return None
    return tuple(int(p) for p in match.group(1).split("."))


def _is_version_below(version_spec: str, fixed_version: str) -> bool:
    """Return True if a concrete minimum/pinned version is strictly below fixed_version."""
    if not version_spec or "*" in version_spec:
        return False
    # Check lower-bound / pinned operators (`==`, `>=`, `^`, `~`, bare version)
    v_tuple = _parse_version_tuple(version_spec)
    f_tuple = _parse_version_tuple(fixed_version)
    if v_tuple is None or f_tuple is None:
        return False
    max_len = max(len(v_tuple), len(f_tuple))
    v_pad = v_tuple + (0,) * (max_len - len(v_tuple))
    f_pad = f_tuple + (0,) * (max_len - len(f_tuple))
    return v_pad < f_pad


class DependencyAuditor:
    """Audits project dependencies and MCP external server definitions."""

    def scan(
        self,
        root_path: Path | str = ".",
        mcp_config_path: Optional[Path | str] = None,
        offline: bool = True,
    ) -> DependencyAuditReport:
        """Scan pyproject/requirements and MCP configs under *root_path*."""
        root = Path(root_path)
        scanned_files: List[str] = []
        packages: List[Tuple[str, str, str, str]] = []  # (eco, pkg, spec, source)

        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            scanned_files.append(str(pyproject))
            packages.extend(self._parse_pyproject(pyproject))

        for req_file in sorted(root.glob("requirements*.txt")):
            scanned_files.append(str(req_file))
            packages.extend(self._parse_requirements(req_file))

        mcp_candidates: List[Path] = []
        if mcp_config_path:
            mcp_candidates.append(Path(mcp_config_path))
        else:
            for name in (".mcp.json", "mcp.json"):
                cand = root / name
                if cand.is_file():
                    mcp_candidates.append(cand)

        for mcp_file in mcp_candidates:
            if mcp_file.is_file():
                scanned_files.append(str(mcp_file))
                packages.extend(self._parse_mcp_config(mcp_file))

        findings: List[DependencyFinding] = []
        for eco, pkg, spec, src in packages:
            findings.extend(self._evaluate_package(eco, pkg, spec, src))

        if not offline and packages:
            findings.extend(self._query_osv_batch(packages))

        return DependencyAuditReport(
            scanned_files=scanned_files,
            packages_checked=len(packages),
            findings=findings,
        )

    @staticmethod
    def _parse_pyproject(path: Path) -> List[Tuple[str, str, str, str]]:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        project = data.get("project", {})
        raw_deps: List[str] = list(project.get("dependencies", []))
        for group_deps in project.get("optional-dependencies", {}).values():
            raw_deps.extend(group_deps)
        out: List[Tuple[str, str, str, str]] = []
        for raw in raw_deps:
            m = _DEP_SPEC_RE.match(raw)
            if m:
                out.append(("PyPI", m.group(1).strip(), m.group(2).strip() or "*", str(path)))
        return out

    @staticmethod
    def _parse_requirements(path: Path) -> List[Tuple[str, str, str, str]]:
        out: List[Tuple[str, str, str, str]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            clean = line.split("#", 1)[0].strip()
            if not clean or clean.startswith("-"):
                continue
            m = _DEP_SPEC_RE.match(clean)
            if m:
                out.append(("PyPI", m.group(1).strip(), m.group(2).strip() or "*", str(path)))
        return out

    @staticmethod
    def _parse_mcp_config(path: Path) -> List[Tuple[str, str, str, str]]:
        out: List[Tuple[str, str, str, str]] = []
        data = json.loads(path.read_text(encoding="utf-8"))
        servers = data.get("mcpServers", data.get("servers", {}))
        if not isinstance(servers, dict):
            return out

        for _, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = str(cfg.get("command", ""))
            args = [str(a) for a in cfg.get("args", [])]
            eco = "npm" if "npx" in cmd else ("PyPI" if "uvx" in cmd or "python" in cmd else "generic")
            for arg in args:
                if arg.startswith("-") or arg in ("-y", "run"):
                    continue
                if "@" in arg and not arg.startswith("@"):
                    pkg, ver = arg.rsplit("@", 1)
                    out.append((eco, pkg, f"=={ver}", str(path)))
                    break
                if arg.startswith("@") and arg.count("@") >= 2:
                    idx = arg.rfind("@")
                    out.append((eco, arg[:idx], f"=={arg[idx + 1:]}", str(path)))
                    break
                if eco in ("npm", "PyPI"):
                    out.append((eco, arg, "*", str(path)))
                    break
        return out

    @staticmethod
    def _evaluate_package(
        eco: str, pkg: str, spec: str, src: str
    ) -> List[DependencyFinding]:
        findings: List[DependencyFinding] = []
        pkg_key = pkg.lower()

        # 1. Unpinned / wildcard specifiers on external MCP servers or dependencies
        if spec in ("", "*", "latest") or spec.endswith("@latest"):
            sev = RegressionSeverity.HIGH if eco == "npm" else RegressionSeverity.MEDIUM
            findings.append(
                DependencyFinding(
                    package=pkg,
                    ecosystem=eco,
                    version_spec=spec or "*",
                    severity=sev,
                    cve_id="HYGIENE-UNPINNED-DEP",
                    title="Unpinned or wildcard package specifier can allow supply-chain drift.",
                    remediation=f"Pin `{pkg}` to an explicit minimum or exact immutable version.",
                    source_file=src,
                )
            )

        # 2. Offline known CVE advisories
        for adv in _OFFLINE_ADVISORIES.get((eco, pkg_key), []):
            if _is_version_below(spec, adv["fixed"]):
                findings.append(
                    DependencyFinding(
                        package=pkg,
                        ecosystem=eco,
                        version_spec=spec,
                        severity=RegressionSeverity(adv["severity"]),
                        cve_id=adv["cve"],
                        title=adv["title"],
                        remediation=f"Upgrade `{pkg}` to >= {adv['fixed']}.",
                        source_file=src,
                    )
                )
        return findings

    @staticmethod
    def _query_osv_batch(
        packages: List[Tuple[str, str, str, str]],
    ) -> List[DependencyFinding]:
        queries = []
        meta = []
        for eco, pkg, spec, src in packages:
            if eco not in ("PyPI", "npm"):
                continue
            ver_match = _VERSION_EXTRACT_RE.search(spec)
            if not ver_match:
                continue
            queries.append({"package": {"name": pkg, "ecosystem": eco}, "version": ver_match.group(1)})
            meta.append((eco, pkg, spec, src))

        if not queries:
            return []

        findings: List[DependencyFinding] = []
        try:
            resp = httpx.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": queries},
                timeout=10.0,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            for idx, entry in enumerate(results):
                vulns = entry.get("vulns", [])
                if vulns and idx < len(meta):
                    eco, pkg, spec, src = meta[idx]
                    for v in vulns[:3]:
                        findings.append(
                            DependencyFinding(
                                package=pkg,
                                ecosystem=eco,
                                version_spec=spec,
                                severity=RegressionSeverity.HIGH,
                                cve_id=v.get("id", "OSV-UNKNOWN"),
                                title=v.get("summary", "Vulnerability reported by OSV."),
                                remediation=f"Upgrade `{pkg}` to a non-vulnerable release.",
                                source_file=src,
                            )
                        )
        except Exception:
            # Fail gracefully if network/OSV is unreachable during scan
            return []
        return findings
