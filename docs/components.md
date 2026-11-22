# AgentXDR: Subsystem & Component Specifications

This document defines the technical specifications, execution contracts, and interfaces for the seven core subsystems composing AgentXDR.

---

## 1. Subsystem 1: Shift-Left CI/CD Security & Pre-Deployment Red Teaming

### 1.1 GitHub PR & Push Security Analyzers (`agentxdr-ci`)
Evaluates every pull request and commit against five deterministic static analyzers:
1. **Overprivileged Tool Access Analyzer:** Scans diffs in `policy.yaml` and tool definitions. Flags widening permissions (`blocked -> privileged_hitl` or `privileged_hitl -> automatic`), wildcard tool assignments (`*`), or loosened egress URL patterns.
2. **Authentication & Authorization Analyzer:** Detects hardcoded secrets, disabled delegation flags, bypassed RAG ACL checks, or shared master API keys.
3. **Dependencies & Supply Chain Monitor:** Audits Python dependencies (`requirements.txt`, `pyproject.toml`) and MCP declarations (`mcp.json`) against known CVE databases and enforces approved tool vendor lists.
4. **System Instructions & Guardrail Diff Monitor:** Parses system prompt templates to detect weakening of security boundaries, constraint deletions, or conflicting directives.
5. **Tool & Context Schema Monitor:** Computes SHA-256 hashes of declared MCP tool schemas and verifies alignment with the pinned registry.

### 1.2 Pre-Deployment Adversarial Red Teaming (PyRIT)
* Integrates Microsoft PyRIT to orchestrate single-turn and multi-turn adversarial attack converters (direct jailbreaks, RAG document poisoning, tool-parameter manipulation, and ASI09 persuasion attempts).
* **Gating Policy:** Generates an Attack Success Rate (ASR) scorecard mapped to OWASP ASI01–ASI10. PRs fail automatically if $\text{ASR}_{\text{critical}} > 0\%$.

---

## 2. Subsystem 2: Context, Provenance & Data Governance Layer

### 2.1 The Five Context Sources & Trust Tiers

| Source | Default Provenance Tier | Security Governance |
| :--- | :--- | :--- |
| **1. System Instructions** | `TRUSTED_SYSTEM` | SHA-256 hashed at deploy time; verified immutable at runtime; monitored for outbound prompt leakage. |
| **2. User Input** | `AUTHENTICATED_USER` | Scanned by input guardrails; bound to verified user principal identity and JWT claims. |
| **3. RAG Documents** | `RESTRICTED_INTERNAL` or `UNTRUSTED_EXTERNAL` | Pre-retrieval metadata filtering by user ACL; injection scanning; chunk-level provenance tagging. |
| **4. Persistent Memory** | `VERIFIED_MEMORY` | Gated writes; tainted turns blocked from persisting; all writes recorded in Write-Ahead Snapshot Log. |
| **5. Tool Outputs** | `UNTRUSTED_EXTERNAL` | Tool schemas SHA-256 pinned; returned payloads sanitized; propagates taint labels to session state. |

### 2.2 Session Taint Propagation State Machine
Maintained in Redis as a set of monotonic labels for each active `trace_id`:
* Possible Taints: `UNTRUSTED_EXTERNAL`, `CONFIDENTIAL_RAG`, `CONTAINS_PII`, `SUSPECTED_INJECTION`.
* Taint labels propagate across all intermediate steps, inter-agent messages, and tool invocations.
* **Deterministic Rules:** Evaluated prior to every tool invocation (e.g., if $\text{Taints} \supseteq \{\text{UNTRUSTED\_EXTERNAL}, \text{CONFIDENTIAL\_RAG}\}$, external communication tools are hard-blocked).

---

## 3. Subsystem 3: Inline Guardrails & Tiered Action Policy Engine

### 3.1 Declarative Policy Specification (`policy.yaml`)
Each agent is governed by an immutable, versioned YAML contract:

```yaml
version: "1.0.0"
agent_id: "doc-support-agent"
policy_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
approved_by: "secops-lead@enterprise.com"

goal_anchor:
  canonical_task: "Assist authenticated internal employees with IT documentation and troubleshooting."
  allowed_domains: ["it-kb", "support-tickets"]

budgets:
  max_turns: 15
  max_tool_calls: 20
  max_identical_calls: 3
  max_session_duration_sec: 180
  max_session_cost_usd: 0.50

tools:
  - name: "search_internal_kb"
    mcp_server: "kb-server"
    tier: "automatic"
    schema_sha256: "a1b2c3..."
    parameters:
      query: { type: "string", max_length: 500 }
  - name: "escalate_to_jira"
    mcp_server: "jira-server"
    tier: "privileged_hitl"
    schema_sha256: "d4e5f6..."
  - name: "execute_system_command"
    tier: "blocked"

taint_rules:
  - id: "TAINT-EXFIL-001"
    match_taints: ["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"]
    blocked_tools: ["send_email", "post_webhook"]
    action: "BLOCK"
    owasp_id: "ASI02"

code_sandbox:
  enabled: true
  provider: "docker_rootless"
  timeout_sec: 10
  memory_limit_mb: 256
  blocked_imports: ["os", "subprocess", "socket", "ctypes", "requests"]

output_guardrails:
  dlp:
    mask_pii: true
    mask_secrets: true
  prompt_leak:
    max_similarity: 0.65
```

### 3.2 Tiered Action Execution Model
* **Tier 0 (`automatic`):** Read-only, idempotent actions executed after parameter schema and taint validation.
* **Tier 1 (`privileged_hitl`):** State-mutating, financial, or external communication actions. Execution pauses deterministically; creates a ticket in the Anti-ASI09 HITL Queue with a 15-minute TTL.
* **Tier 2 (`blocked`):** Dangerous capabilities rejected unconditionally with HTTP 403.

---

## 4. Subsystem 4: Identity, Versioned RBAC & Inter-Agent Bus Security

### 4.1 Permission Intersection & Attenuation
* Effective authorization is strictly computed as:
  $$\text{Effective Scope} = \text{Scope}_{\text{User}} \cap \text{Scope}_{\text{Agent Role}} \cap \text{Scope}_{\text{Task Policy}}$$
* Multi-hop delegation narrows permissions monotonically:
  $$\text{Scope}_{A \to B} \subseteq \text{Effective Scope}_{A} \cap \text{Scope}_{\text{Agent } B}$$

### 4.2 Cryptographic Inter-Agent Communication Envelope
All agent-to-agent messages pass through the control plane bus enclosed in a signed envelope:

```json
{
  "message_id": "msg-01934e8f-7c1a-7b3b-8f0a-123456789abc",
  "trace_id": "trace-889102-prod",
  "sender_agent_id": "doc-support-agent",
  "receiver_agent_id": "data-analyst-agent",
  "timestamp_utc": "2026-11-22T14:30:00Z",
  "nonce": "c4ca4238a0b923820dcc509a6f75849b",
  "attenuated_token": "eyJhbGciOi...",
  "taint_labels": ["UNTRUSTED_EXTERNAL"],
  "payload": {
    "action": "query_metrics",
    "parameters": {"date_range": "last_30d"}
  },
  "signature": "30450221008f...edcba"
}
```

---

## 5. Subsystem 5: Unexpected Code Execution (RCE) Containment Sandbox

### 5.1 Three-Stage Execution Boundary
1. **Stage 1 — AST Static Sanitizer:** Parses source code into Python AST; rejects forbidden imports (`os`, `subprocess`, `socket`, `ctypes`, `shutil`), built-ins (`eval`, `exec`), and dunder inspection.
2. **Stage 2 — Escalation Policy:** Pure read-only transformations execute automatically inside the sandbox; code modifying external state or requesting elevated scopes escalates to `privileged_hitl`.
3. **Stage 3 — Ephemeral Rootless Container:**
   * Container flags: `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`.
   * Cgroups caps: 256 MB RAM, 10s CPU timeout, PID limit 32.
   * Container destroyed immediately upon return; stdout/stderr scanned by DLP before returning.

### 5.2 Pluggable Provider Interface
```python
class SandboxProvider(ABC):
    @abstractmethod
    def execute(self, code: str, timeout_sec: int, memory_mb: int) -> SandboxResult:
        pass
```
* **Implementations:** `DockerRootlessProvider` (Production default), `SubprocessRestrictedProvider` (Local development/CI fallback).

---

## 6. Subsystem 6: Behavioral Observability, Action-Graph & Drift Detection

### 6.1 Live Action-Graph (DAG) Construction
For every `trace_id`, an execution graph $G = (V, E)$ is updated in real time:
* **Nodes ($V$):** `USER`, `RAG_DOC`, `LLM_STEP`, `TOOL_CALL`, `MEMORY_STORE`, `SANDBOX`, `PEER_AGENT`.
* **Edges ($E$):** `READS_FROM`, `INVOKES`, `WRITES_TO`, `DELEGATES_TO`, `RETURNS_TO`.
* **Graph Analyzers:** Detects forbidden taint motifs (e.g., `UNTRUSTED_EXTERNAL -> TOOL_CALL -> EGRESS`), Markov transition surprise, and delegation cycle deadlocks.

### 6.2 Composite Drift Scoring Model
Calculates risk score $R_t \in [0.0, 1.0]$ at step $t$:
$$R_t = \min\Big(1.0,\; 0.45\,S_{\text{policy}}(t) + 0.25\,S_{\text{graph}}(t) + 0.15\,S_{\text{velocity}}(t) + 0.15\,S_{\text{semantic}}(t)\Big)$$

* $S_{\text{policy}}(t)$: Severity of deterministic rule violations (critical violations force $R_t = 1.0$).
* $S_{\text{graph}}(t)$: Graph structural anomaly score.
* $S_{\text{velocity}}(t)$: Ratio against turn, call, and token budget ceilings.
* $S_{\text{semantic}}(t)$: Goal-anchor cosine distance computed on CPU via ONNX embeddings (`bge-small-en-v1.5`) over a 3-step sliding window.

---

## 7. Subsystem 7: Active Response, Containment & State Recovery Controller

### 7.1 Hierarchical Kill Switches
* **Tool / Module Kill Switch:** Disables a compromised tool or MCP server instantly across the fleet.
* **Session Kill Switch:** Terminates a specific `trace_id` thread without disrupting other concurrent users.
* **Agent Kill Switch:** Halts all executions for a specific agent instance.
* **Global Flow Kill Switch:** Emergency red button halting all multi-agent workflows.

### 7.2 Write-Ahead Memory & RAG Snapshot Rollback
* Records all intercepted writes in an append-only snapshot log:
  $$\text{Commit} = (\text{commit\_id}, \text{trace\_id}, \text{agent\_id}, \text{key}, \text{prev\_val}, \text{new\_val}, \text{taint\_labels}, \text{timestamp})$$
* **Atomic Rollbacks:**
  * **Session Rollback:** Reverts all writes made during a hijacked trace.
  * **Point-in-Time Rollback:** Restores agent memory to any historical commit ID.
  * **Taint-Based Purge:** Cascading rollback of all writes originating from a poisoned RAG document.

### 7.3 Anti-ASI09 HITL Approval Interface
* **Deterministic Diff Pane (Primary View):** Displays verified tool target, schema hash, raw parameter diffs, and Taint Warning banner.
* **Untrusted Agent Rationale Pane (Secondary View):** Collapsed by default; badged as `UNTRUSTED AGENT OUTPUT`; highlights persuasion and urgency classifier scores.
