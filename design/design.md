I will now generate the complete design.md architectural specification for AgentXDR, defining every system boundary, input/output contract, threat mapping, state machine, data schema, and functional requirement from A to Z.


Integration Targets: OpenAI SDK, Model Context Protocol (MCP), Python Agent Runtimes, GitHub CI/CD

1. Executive Summary & Design Philosophy

1.1 Product Vision

AgentXDR is an enterprise security control plane, inline runtime protection layer, and SOC war-room platform purpose-built for autonomous AI agents. Modeled on the operational paradigm of Endpoint Detection and Response (EDR/XDR) and SIEM/SOAR platforms (such as Cortex XDR and Microsoft Sentinel), AgentXDR observes agent telemetry, enforces deterministic guardrails at runtime, calculates behavioral and semantic drift, isolates cascading failures, and enables surgical state recovery—without requiring enterprises to rebuild existing agents on a proprietary framework.

1.2 Core Architectural Principles

1. Drop-In, Zero-Rewrite Adoption: Security attaches externally via reverse proxies (OpenAI API & MCP JSON-RPC), a thin Python OpenTelemetry sensor wrapper, and a reusable GitHub Action. Existing enterprise agents remain portable.
2. Externalized Deterministic Enforcement: Prompt-level instructions inside an LLM are treated strictly as soft alignment, never as security boundaries. All hard enforcement (RBAC, tool allowlists, taint blocks, DLP masking, loop caps, sandboxing, kill switches) executes in deterministic, non-LLM code outside the model.
3. Dual-Path Latency Architecture: Security checks are strictly partitioned into a Synchronous Hot Path (deterministic prevention, target overhead <50\text{ ms}) and an Asynchronous Warm Path (graph analytics, local CPU semantic drift, persuasion analysis, 200\text{--}800\text{ ms}).
4. Continuous Control Loop: Static permissions and API gateways fail because autonomous systems drift across multi-step plans, memory writes, and tool chains. AgentXDR closes the loop across Shift-Left Prevention -> Inline Enforcement -> Behavioral Detection -> Active Containment & Recovery.
5. Zero-GPU Enterprise Portability: The entire security stack—including local semantic embeddings, DLP scanning, graph analytics, and sandboxed code execution—runs strictly on commodity CPU infrastructure.

1.3 System Scope & Explicit Boundaries

Boundary	In Scope (What AgentXDR Owns)	Out of Scope (Explicit Non-Goals)
Agent Hosting	Inline proxying, telemetry capture, policy enforcement, and sandboxing for external agents.	Hosting, orchestrating, or replacing agent frameworks (LangGraph, CrewAI, custom loops).
Model Layer	Proxying OpenAI-compatible HTTP/SSE traffic; input/output inspection and DLP masking.	Fine-tuning, training, or hosting foundation LLM weights.
Tooling & MCP	Intercepting MCP JSON-RPC (tools/list, tools/call), schema SHA-256 pinning, shadow MCP detection, tiered tool authorization.	Building enterprise SaaS connectors (Jira, Slack, ERP) themselves.
Data & RAG	Retrieval-level RBAC metadata injection, ingestion sanitization, taint tagging, write-ahead memory snapshots and rollback.	Building a proprietary vector database engine (AgentXDR wraps existing vector/memory stores).
Code Execution	Static AST sanitization, ephemeral rootless container sandboxing via a pluggable SandboxProvider interface, approval escalation.	Providing persistent developer workspaces or long-running compute clusters.
CI/CD & Testing	GitHub PR security diffing (code, prompts, policies, tools, dependencies) and automated PyRIT adversarial gating.	General-purpose SAST/DAST for non-agentic enterprise microservices.
SOC Operations	Live Action-Graph visualization, KQL-lite telemetry hunting, OWASP ASI01–10 posture tracking, HITL approvals, kill switches, quarantine.	Replacing enterprise-wide network firewalls or non-AI endpoint EDR agents (integrates alongside them).

2. Threat Model & OWASP Agentic Top 10 Coverage Matrix

AgentXDR guarantees 100% preventative, detective, and responsive coverage across all ten categories of the 2026 OWASP Top 10 for Agentic Applications, explicitly closing structural gaps commonly missed in vendor checklists (such as missing Supply Chain/RCE coverage and the Human-in-the-Loop persuasion paradox).

OWASP ID	Threat Class	Primary Attack Vector	Preventative Control (Hot Path / Shift-Left)	Detective Control (Warm Path / CI)	Active Response Control
ASI01	Agent Goal Hijack	Direct or indirect prompt injection via user input, RAG docs, or tool outputs redirecting agent objectives.	Trust-tier provenance tagging; input/tool-output injection filters; pinned goal anchor; GitHub prompt-diff gate.	Goal-anchor semantic drift scoring; NLI constraint-contradiction alerts; PyRIT injection evals.	Escalate session to HITL; trip session kill switch at risk threshold.
ASI02	Tool Misuse & Exploitation	Coercing an agent into calling legitimate tools out of context or with malicious parameters.	Tiered Action Policy (Auto / HITL / Blocked); parameter schema validation; deterministic taint-flow rules.	Action-Graph transition anomaly scoring; tool velocity and burst detection.	Hard-block tool call inline; revoke module/tool capability via Redis kill switch.
ASI03	Identity & Privilege Abuse	Overprivileged static keys, permission creep, or cross-agent credential inheritance.	Ephemeral workload identity; attenuated token scoping (\text{User} \cap \text{Agent} \cap \text{Task}); versioned RBAC registry.	GitHub PR privilege-escalation gate; continuous elevated-privilege invocation alerts.	Immediately revoke delegated session tokens; freeze offending policy version.
ASI04	Agentic Supply Chain Vulnerabilities	Poisoned tool descriptions, MCP schema rug-pulls, compromised dependencies, or shadow MCP servers.	Cryptographic SHA-256 pinning of MCP schemas at load time; AIBOM/dependency verification; approved MCP registry.	Runtime detection of unregistered ("shadow") MCP endpoints; CI scanning of mcp.json and tool descriptors.	Block unpinned/mutated MCP tool immediately; sever connection to shadow server.
ASI05	Unexpected Code Execution (RCE)	Crafted inputs triggering unsafe code generation, deserialization, or host shell execution.	Python AST static sanitizer; blocked-import policy; rootless network-disabled Docker sandbox; HITL escalation for elevated exec.	Sandbox violation telemetry (blocked syscalls, OOM, timeout, egress attempts).	Terminate ephemeral container immediately; escalate trace to High Severity incident.
ASI06	Memory & Context Poisoning	Planting false facts or dormant triggers into RAG indexes or persistent agent memory.	Retrieval-level RBAC on RAG; ingestion sanitization; gated memory writes blocking untrusted-source persistence.	Memory mutation audit logs; anomaly detection on unexpected long-term context edits.	Atomic rollback of memory/RAG commits via Write-Ahead Snapshot Log.
ASI07	Insecure Inter-Agent Communication	Tampering, replay, protocol downgrade, or unvalidated instruction passing between agents.	Cryptographically signed inter-agent envelopes; strict TLS; anti-replay nonces/timestamps; Pydantic payload validation.	Full inter-agent message bus logging; detection of unauthorized agent-to-agent collusion paths.	Drop invalid/replayed messages; quarantine sending agent on the bus.
ASI08	Cascading Failures	Single fault or injection amplifying across loops, retries, or chained multi-agent workflows.	Composite loop & budget circuit breakers (max turns, repeated-call cycles, token/cost/time caps).	Velocity drift calculation; multi-agent propagation tracking across shared trace_id.	Trip global flow kill switch; halt downstream dependent agents automatically.
ASI09	Human-Agent Trust Exploitation	Manipulative fluency, urgency framing, or fabricated rationales steering humans into unsafe approvals.	Anti-ASI09 HITL UI displaying deterministic raw API diffs & taint warnings while isolating/collapsing agent prose.	Persuasion & urgency classifier scanning outbound agent responses and approval rationales.	Flag HITL ticket with manipulation warning; require dual-approver validation; log forensic attribution.
ASI10	Rogue Agents	Compromised or misaligned agents acting as autonomous insider threats, exfiltrating data, or contacting C2.	Deterministic output DLP masker (PII, secrets, prompts); strict egress allowlists; no-egress sandboxes.	Behavioral baseline deviation; composite drift score R_t; C2/anomalous outbound URL detection.	One-click or automated Agent Quarantine; total credential revocation; isolate from fleet.

3. System Boundaries & High-Level Architecture

3.1 Mediated Multi-Agent Trust Boundary Architecture

Every communication edge entering or leaving an agent's LLM runtime crosses a deterministic Policy Enforcement Point (PEP). Critically, this includes the untrusted return path from the outside world back into the LLM context.

================================================================================
                          SHIFT-LEFT BOUNDARY (CI/CD)
  [ GitHub PR / Push ] ---> [ agentxdr-ci Action ] ---> [ PyRIT Red-Team Gate ]
        (Diffs code, prompts, RBAC, deps, MCP pins)            |
===============================================================|================
                                                               v (Approved Artifacts)
================================================================================
                     AGENTXDR CONTROL PLANE (Trusted Zone)
  +-------------------------+  +----------------------+  +--------------------+
  | Versioned Policy & RBAC |  | Pinned MCP Registry  |  | Active Response    |
  | Store (PostgreSQL)      |  | (SHA-256 + Shadow)   |  | (Kill/Quarantine/  |
  +-------------------------+  +----------------------+  |  Snapshot Rollback)|
  +-------------------------+  +----------------------+  +--------------------+
  | Anti-ASI09 HITL Queue   |  | SOC War-Room API &   |
  | (Deterministic Diff UI) |  | KQL-Lite Query Eng.  |
  +-------------------------+  +----------------------+
=================|=========================================^====================
                 | Control Signals (Redis Pub/Sub)         | Immutable Events
                 | (<5ms propagation)                      | (Redis Streams)
                 v                                         |
======================================    ======================================
 INLINE EDGE (Hot Path <50ms)             ASYNC DETECTION PLANE (Warm Path)
 +----------------------------------+     +------------------------------------+
 | 1. OpenAI-Compatible LLM Proxy   |     | 1. Live Action-Graph (DAG) Builder |
 |    - Input/Output DLP & Masking  |     | 2. Deterministic Taint-Flow Engine |
 |    - Goal Anchor & Loop Caps     |     | 3. CPU ONNX Semantic Drift Scorer  |
 | 2. MCP Security Proxy (JSON-RPC) |     | 4. ASI09 Persuasion Classifier     |
 |    - Schema Hash Verification    |     | 5. OWASP ASI01-10 Alert Correlator |
 |    - Tiered Action PEP           |     +-----------------+------------------+
 |    - Tool Output Sanitization    |                       |
 | 3. Thin Python SDK Hooks         |                       v
 |    - RAG RBAC & Taint Tagging    |     +------------------------------------+
 |    - Gated/Snapshotted Memory    |     | ANALYTICAL SIEM STORE (DuckDB) +   |
 |    - Signed Inter-Agent Bus      |     | SOC DASHBOARD (Next.js/React Flow) |
 |    - SandboxProxy (RCE Enclave)  |     +------------------------------------+
 +--------+---------------+---------+
          |               |
          v               v
====================  ======================    ================================
 AGENT RUNTIME ZONE    RCE SANDBOX ENCLAVE       UNTRUSTED OUTSIDE WORLD
 [ Enterprise Agent ]  [ Ephemeral Rootless ]    [ External APIs / Web / SaaS ]
 [ (OpenAI + MCP)   ]  [ Docker: net=none,  ]    [ External MCP Servers       ]
                       [ ro-fs, AST checked ]    [ External Documents / Users ]
====================  ======================    ================================
       ^                                                       |
       |____________ UNTRUSTED RETURN PATH (Tainted) __________|
              (Must re-enter strictly through Inline Edge PEP)


3.2 Dual-Path Execution Contract

Path	Execution Mode	Target Latency	Responsibilities	Action Authority
Hot Path (Inline Edge)	Synchronous (blocks request/response until verdict)	<50\text{ ms} (P95, excluding upstream LLM/MCP time)	Kill-switch check, AuthN/RBAC scope intersection, loop/budget counters, MCP SHA-256 verification, tiered tool policy (Auto/HITL/Deny), deterministic taint-flow blocks, regex/Presidio DLP masking, AST code sanitization, memory write gating.	ALLOW, MASK_AND_ALLOW, PAUSE_FOR_HITL, BLOCK.
Warm Path (Detection Plane)	Asynchronous (consumes from Redis Streams)	200\text{--}800\text{ ms} per event	Action-Graph DAG construction, graph-transition anomaly analysis, local ONNX (fastembed) semantic drift calculation, NLI/persuasion classification, alert correlation, OWASP ASI mapping, DuckDB ingestion.	Emit alerts; write dynamic state transitions to Redis (auto-escalate to HITL, trip session kill switch, quarantine agent) affecting the very next Hot Path call.

3.3 Fail-Safe & Resilience Boundaries

How the Inline Edge behaves if an internal AgentXDR dependency degrades:

Component Failure	Default Posture	Rationale
Policy Store / Redis Kill-Switch Unreachable	Fail-Closed for privileged_hitl, blocked, and code_sandbox actions; configurable Fail-Closed (default) or Cached-Policy Grace Window (30s) for automatic read-only calls.	Prevents attackers from bypassing security by DoS-ing the Control Plane.
MCP Schema Registry Unreachable	Fail-Closed (reject unknown/unverified tool invocations).	Blocks ASI04 rug-pull exploitation during outages.
Warm Path Detector Lag / Offline	Hot Path Continues Operating (deterministic rules still enforce); Telemetry buffers durably in Redis Streams; SOC raises DETECTOR_DEGRADED health alert.	Preserves availability without dropping deterministic guardrails or losing audit logs.
Sandbox Daemon Unreachable	Fail-Closed (never fall back to host execution).	Guarantees zero accidental host RCE (ASI05).

4. Integration & Onboarding Boundary Specification

AgentXDR exposes four clean, versioned integration contracts so enterprise teams can onboard agents rapidly.

4.1 Touchpoint 1: OpenAI-Compatible Inline LLM Gateway

⚬ Boundary: HTTP/HTTPS reverse proxy implementing the OpenAI /v1/chat/completions and /v1/responses contracts (supporting both standard JSON and Server-Sent Events streaming).
⚬ Required Identity & Context Headers:
  ⚬ X-AgentXDR-Agent-ID: Registered agent identifier.
  ⚬ X-AgentXDR-Policy-Version: Pinned policy version string (or latest-approved).
  ⚬ X-AgentXDR-Trace-ID: Distributed trace identifier linking multi-turn and multi-agent spans.
  ⚬ X-AgentXDR-Principal-Token: Signed JWT representing the originating human user and their roles (for \text{User} \cap \text{Agent} scoping).
⚬ Inputs: Outbound LLM request payload (messages, system prompt, declared tool schemas, temperature/model metadata).
⚬ Inline Transformations:
  1. Verifies agent status (Active vs. Quarantined vs. Kill-Switched).
  2. Increments session turn & budget counters in Redis.
  3. Inspects user inputs and tool-return messages for prompt injection markers and updates session taint labels.
  4. Applies outbound DLP masking to prevent leaking credentials/PII to external LLM providers.
  5. Scans LLM response (buffered per sentence/chunk for SSE or full payload for tool calls) for harmful content, leaked system prompt fragments, API keys/PII, and unauthorized tool call requests.
⚬ Outputs: Sanitized OpenAI-compatible response, or a standardized HTTP 403 Forbidden / 429 Too Many Requests JSON security refusal envelope containing rule_id, owasp_id, and trace_id (plus 202 Accepted / pending state for HITL-paused tool calls).

4.2 Touchpoint 2: MCP Security Proxy

⚬ Boundary: Reverse proxy mediating Model Context Protocol JSON-RPC 2.0 traffic (HTTP/SSE and stdio-bridge modes) between an agent client and external/internal MCP servers.
⚬ Intercepted Methods:
  ⚬ initialize / tools/list:
    ⚬ Input: Raw MCP tool catalog returned by the server.
    ⚬ Validation: Computes canonical SHA-256 hash over each tool's (name, description, inputSchema). Compares against the Pinned MCP Schema Registry. Scans tool descriptions for embedded prompt-injection directives (tool poisoning).
    ⚬ Output: Approved subset of tools permitted by the agent's policy.yaml; unapproved or hash-mismatched tools are stripped and trigger a Critical ASI04 Alert.
  ⚬ tools/call:
    ⚬ Input: JSON-RPC tool invocation (name, arguments) + active session context.
    ⚬ Validation: Evaluates Tiered Policy (Automatic / Privileged HITL / Blocked), checks deterministic taint-flow rules, validates argument schemas, and scrubs outbound sensitive data.
    ⚬ Return-Path Sanitization: Intercepts the MCP server's tool response, tags the session with UNTRUSTED_EXTERNAL taint, scans the returned payload for indirect prompt injection, and masks sensitive artifacts before returning the result to the agent.
⚬ Shadow MCP Detection: Any MCP endpoint URL/server name requested through the proxy or discovered in repository/egress telemetry that is absent from the Control Plane's Approved MCP Registry triggers an immediate SHADOW_MCP_DETECTED alert and blocks execution in enforcing mode.

4.3 Touchpoint 3: Thin Python OTel Sensor SDK (agentxdr-sdk)

⚬ Boundary: In-process lightweight wrapper capturing internal agent operations invisible to network proxies while emitting OpenTelemetry gen_ai.* compliant spans.
⚬ Exposed Hooks:
  ⚬ guard_openai(client, agent_id, policy_version): Injects gateway base URL and tracing/identity headers transparently.
  ⚬ AgentXDRContext(user_id, user_roles, trace_id): Manages trace propagation, principal identity, and local taint context.
  ⚬ ctx.rag_retrieve(store, query, enforce_rbac=True): Injects mandatory user/role ACL filters before vector similarity search; inspects returned chunks for injection patterns; tags provenance and logs chunk IDs.
  ⚬ ctx.memory_write(store, key, value): Gates writes against untrusted-taint policy; logs a Write-Ahead Snapshot commit to the Control Plane before persisting.
  ⚬ ctx.sandbox_exec(code, language="python"): Routes agent-generated code exclusively to the RCE Sandbox service rather than local exec()/subprocess.
  ⚬ ctx.send_agent_message(target_agent_id, payload): Signs, timestamps, attaches anti-replay nonce, attenuates delegated scopes, and routes inter-agent messages through the Control Plane bus.

4.4 Touchpoint 4: GitHub Actions Shift-Left Gate (agentxdr-ci)

⚬ Boundary: CI workflow triggered on pull_request and push events against repositories containing agent source code, prompts, MCP configs, or policy.yaml.
⚬ Inputs: Git commit diff (base..head), repository files, dependency manifests (requirements.txt, pyproject.toml, package.json, mcp.json), and connection to a staging instance for adversarial probing.
⚬ Outputs: GitHub Commit Status Check (PASS / WARN / FAIL), structured PR Security Review comment detailing detected regressions, SARIF security report, and updated AIBOM snapshot pushed to the Control Plane.

5. Detailed Subsystem Design Specifications

5.1 Subsystem 1: Shift-Left CI/CD Security & Pre-Deployment Red Teaming

A. GitHub Push & PR Security Monitors

Every commit/PR is evaluated across five deterministic analyzers:

1. Overprivileged Tool Access Analyzer: Diffs policy.yaml and tool registrations. Flags any transition from blocked -> privileged_hitl or privileged_hitl -> automatic, wildcard tool permissions (*), or broadened egress URL domains.
2. Authentication & Authorization Analyzer: Scans code and policy diffs for hardcoded API keys, disabled require_user_delegation, bypassed RAG RBAC flags, or static shared credentials replacing per-user tokens.
3. Dependencies & External Tool Supply Chain Monitor: Generates an AIBOM/SBOM across Python/JS packages, model identifiers, and MCP server references; checks CVEs and flags unverified third-party tools or unregistered Shadow MCP entries in mcp.json.
4. System Instructions & Guardrail Diff Monitor: Parses system prompt templates and flags deletions/weakening of constraint blocks, role boundary changes, or introduction of conflicting directives.
5. Tools & Context Schema Monitor: Recomputes SHA-256 hashes of declared tool schemas and flags unapproved schema drift.

Privileged Pull Request Gating: Any PR triggering a Privilege Expansion or Guardrail Weakening rule is automatically blocked from merging until a designated Security Reviewer (CODEOWNERS / RBAC Approver) signs off and records an approval justification.

B. External Tool Verification Harness

Before an external MCP server or tool can enter the Approved Registry, it passes through an automated vetting gate:

⚬ Static inspection of JSON tool descriptions and parameter schemas for concealed imperatives, invisible Unicode characters, or exfiltration directives.
⚬ Dynamic contract testing against synthetic boundary inputs to verify deterministic error handling and absence of unexpected outbound side effects.

C. Pre-Deployment Adversarial Red Teaming (PyRIT Integration)

⚬ Input: Staging endpoint of the candidate PR build + targeted attack dataset mapped to OWASP ASI01–ASI10.
⚬ Execution: Orchestrates Microsoft PyRIT automated single-turn and multi-turn adversarial converters (direct jailbreaks, indirect prompt injections embedded in mock RAG docs, tool-parameter manipulation, privilege-escalation coercion, and ASI09 social-engineering prompts).
⚬ Output: Attack Success Rate (ASR) scorecard per OWASP category. Merges fail automatically if any Critical-severity probe (e.g., RCE, Secret Exfiltration, Unauthorized Tool Execution) succeeds (\text{ASR}_{\text{critical}} > 0\%).

5.2 Subsystem 2: Context, Provenance & Data Governance Layer

A. The Five Context Sources & Trust Tiers

All data entering an agent's reasoning loop is classified into one of five typed sources and assigned an immutable provenance tier:

Context Source	Default Provenance Tier	Security Control Applied
1. System Instructions	TRUSTED_SYSTEM	Cryptographically hashed at deploy time; verified immutable at runtime; monitored for leakage in outputs.
2. User Input	AUTHENTICATED_USER	Scanned by input guardrails; bound to verified principal.user_id and role claims.
3. RAG (Semantic Store)	RESTRICTED_INTERNAL or UNTRUSTED_EXTERNAL	Enforced Retrieval-Level RBAC (pre-retrieval metadata filtering by user ACLs); pre-ingestion injection scanning; chunk-level provenance tagging.
4. Persistent Memory	VERIFIED_MEMORY	Read/write access gated by policy; writes from tainted turns blocked unless explicitly sanitized and approved; every write versioned for rollback.
5. Tool Outputs & Descriptions	UNTRUSTED_EXTERNAL (unless allowlisted internal deterministic DB)	Tool descriptions SHA-256 pinned; tool return payloads sanitized for indirect prompt injection and automatically propagate taint labels into session state.

B. Session Taint-Label Propagation State Machine

Every active trace_id maintains a monotonically accumulating set of Taint Labels in Redis (e.g., UNTRUSTED_EXTERNAL, CONFIDENTIAL_RAG, CONTAINS_PII, SUSPECTED_INJECTION).

⚬ When an agent reads a confidential RAG document, CONFIDENTIAL_RAG is added to the trace taint set.
⚬ When an agent fetches an external webpage or third-party MCP tool output, UNTRUSTED_EXTERNAL is added.
⚬ Deterministic Enforcement: Policy taint rules evaluate the session's active taint set before every subsequent tool call and memory write (e.g., if {"UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"} \subseteq \text{Taints}(\text{trace}), any external egress tool like send_email or http_post is deterministically BLOCKED).

5.3 Subsystem 3: Inline Guardrails & Tiered Action Policy Engine

A. Declarative Versioned Policy Schema (policy.yaml)

Every onboarded agent is governed by a strictly typed, immutable policy version specifying:

⚬ agent_id, version (SemVer), policy_hash, approved_by, approval_timestamp.
⚬ goal_anchor: Canonical task definition used as the baseline vector for semantic drift detection.
⚬ rbac: Delegation mode, permitted roles, RAG ACL strictness.
⚬ budgets: Composite loop and resource thresholds.
⚬ tools: Explicit per-tool tier assignments, MCP server bindings, SHA-256 schema pins, and parameter constraints.
⚬ taint_rules: Deterministic data-flow block rules mapped to OWASP ASI IDs.
⚬ memory_policy: Allowed write sources, TTL, snapshot retention, taint write-block rules.
⚬ code_sandbox: Enabled flag, provider (docker_rootless), resource caps, blocked AST imports/calls.
⚬ output_guardrails: Enabled DLP detectors, prompt-leak threshold, harmful/semantic filter settings.

B. Guardrail Pipeline Specification

1. Input Guardrails:
  ⚬ Structural normalization (stripping zero-width obfuscation characters, encoding normalization).
  ⚬ Deterministic signature + lightweight classifier scan for direct prompt injection, role-override directives, and jailbreak framing.
2. Tiered Action Governance:
  ⚬ Tier 0 — automatic: Read-only, idempotent, scoped strictly to effective principal permissions. Executes immediately after parameter and taint validation.
  ⚬ Tier 1 — privileged_hitl: State-mutating, financial, cross-tenant, or external-communication tools. Execution pauses deterministically; an approval ticket is created in the Anti-ASI09 HITL Queue with an expiry TTL (default 15 min, auto-deny on timeout).
  ⚬ Tier 2 — blocked: Hard-denied capabilities (arbitrary shell, IAM mutation, unregistered external hosts). Rejected unconditionally at the proxy; emits a High-Severity security event.
3. Stored Data & Memory Guardrails:
  ⚬ Blocks unverified writes to persistent memory/RAG stores when session taint includes UNTRUSTED_EXTERNAL or SUSPECTED_INJECTION.
  ⚬ Rejects payloads containing embedded instruction templates or unmasked secrets before persistence.
4. Loop & Autonomy Circuit Breakers:
  ⚬ Enforces five independent hard caps per trace_id:
    1. max_turns: Maximum LLM reasoning iterations.
    2. max_tool_calls: Total tool invocations across the trace.
    3. max_identical_calls: Maximum repeated invocations with identical (tool_name, normalized_args) hash (stops infinite retry loops).
    4. max_session_duration_sec: Wall-clock execution cap.
    5. max_session_cost_usd: Real-time token-cost cap.
  ⚬ Breaching any cap immediately terminates the loop (ASI08_CIRCUIT_BREAKER_TRIPPED).
5. Output Guardrails (3-Layer Defense):
  ⚬ Deterministic Data Masker (Hot Path): Redacts API keys/tokens (high-entropy + provider regexes), PII (Presidio/regex for emails, SSNs, phone numbers, credit cards), and system-prompt exfiltration (n-gram/substring overlap against the pinned TRUSTED_SYSTEM prompt).
  ⚬ Harmful Content Guardrail: Blocks prohibited categories (malware generation payloads, credential harvesting templates, destructive system commands).
  ⚬ Semantic Policy Filter: Checks outputs against domain-specific policy constraints and flags persuasive/manipulative framing directed at human operators (ASI09).

5.4 Subsystem 4: Identity, Versioned RBAC & Inter-Agent Bus Security

A. Zero-Trust Agent Identity & Token Attenuation

⚬ Every registered agent receives a distinct short-lived cryptographic workload identity; static shared admin keys are prohibited.
⚬ For every human-initiated or delegated request, effective authorization is computed strictly via Permission Intersection:
  
  $$\text{Effective Scope} = \text{Scope}_{\text{User}} \cap \text{Scope}_{\text{Agent Role}} \cap \text{Scope}_{\text{Task Policy}}$$
⚬ Multi-Agent Delegation Rule: When Agent A delegates a subtask to Agent B, the resulting token is strictly attenuated:
  
  $$\text{Scope}_{A \to B} \subseteq \text{Effective Scope}_{A} \cap \text{Scope}_{\text{Agent } B}$$
  
  Permissions can strictly narrow across hops and can never escalate.

B. Versioned Roles & Permissions Governance Lifecycle

⚬ All agent roles and permission policies are stored as immutable versioned records (append-only version history in PostgreSQL synced with Git).
⚬ State Transitions: DRAFT -> PENDING_SECURITY_APPROVAL -> ACTIVE -> SUPERSEDED / REVOKED.
⚬ Any role holding privileged_hitl tools, cross-tenant RAG scopes, or code execution capabilities is tagged HIGH_PRIVILEGE = true:
  ⚬ Requires explicit multi-field approval metadata (approved_by, ticket_ref, review_expiry_date).
  ⚬ Automatically triggers continuous audit alerts on every invocation and generates weekly permission-creep/unused-scope revocation recommendations.

C. Signed Inter-Agent Communication Bus (ASI07)

All agent-to-agent messages pass through the Control Plane relay using a mandatory signed envelope:

⚬ Fields: message_id, trace_id, sender_agent_id, receiver_agent_id, timestamp_utc, nonce, attenuated_token, taint_labels, schema_version, payload, signature.
⚬ Verification Rules:
  1. Verify cryptographic signature against sender's active workload key.
  2. Verify sender and receiver are neither QUARANTINED nor KILL_SWITCHED.
  3. Reject stale timestamps (|\Delta t| > 30\text{ s}) or replayed nonces (checked in Redis).
  4. Validate payload against strict Pydantic inter-agent schema.
  5. Propagate sender's taint_labels directly into the receiver's session trace so taint cannot be laundered by hopping across agents.

5.5 Subsystem 5: Unexpected Code Execution (RCE) Containment Sandbox

To neutralize ASI05 without breaking legitimate data-analysis or coding agents, all agent-generated code executes exclusively through a three-stage containment boundary:

1. Stage 1 — Static Code Sanitization (Pre-Execution):
  ⚬ Parses candidate Python code into an Abstract Syntax Tree (AST).
  ⚬ Rejects disallowed imports (os, subprocess, socket, ctypes, shutil, importlib, pickle, requests/urllib unless explicitly allowlisted), dangerous built-ins (eval, exec, __import__, open outside /workspace), and obfuscated dunder attribute traversals.
2. Stage 2 — Escalation Policy Check:
  ⚬ Pure data transformations inside /workspace execute automatically inside the sandbox.
  ⚬ Code requesting elevated capabilities (e.g., writing persistent artifacts or accessing an allowlisted internal dataset) escalates to privileged_hitl with the exact sanitized source code rendered in the diff drawer.
3. Stage 3 — Ephemeral Rootless Execution Enclave:
  ⚬ Exposed behind an abstract SandboxProvider interface (default v1 provider: DockerRootlessProvider; swappable with Firecracker/gVisor microVMs without changing callers).
  ⚬ Hard Runtime Constraints:
    ⚬ --network=none (eliminates data exfiltration and C2 callbacks).
    ⚬ --read-only root filesystem with size-capped ephemeral tmpfs scratch directory.
    ⚬ --cap-drop=ALL, --security-opt=no-new-privileges, non-root UID/GID.
    ⚬ Strict cgroups limits: CPU quota, RAM cap (e.g., 256 MB), PID limit (blocks fork bombs), and hard wall-clock timeout (e.g., 10 s).
  ⚬ Container is unconditionally destroyed immediately after capturing bounded stdout/stderr and return exit code; outputs are tagged UNTRUSTED_EXTERNAL and DLP-scanned before returning to the agent.

5.6 Subsystem 6: Behavioral Observability, Action-Graph & Drift Detection Engine

A. Five Mandatory Telemetry Streams

Every state change across an agent's lifecycle emits an immutable AgentEvent record:

1. USER_INPUT: Raw/masked prompt, principal identity, input guardrail scores.
2. RAG_ACCESS: Query hash, applied RBAC ACL filter, retrieved document/chunk IDs, provenance tiers, injection scan verdict.
3. MEMORY_MUTATION: Operation (READ/WRITE/ROLLBACK), key/namespace, previous & new value hashes, commit ID, taint state.
4. TOOL_INVOCATION: MCP server, tool name, SHA-256 schema pin status, redacted arguments, policy tier verdict, return-path taint/DLP outcome, latency.
5. AGENT_COMM: Sender/receiver IDs, attenuated scopes, nonce/signature status, propagated taint labels, payload schema verdict.
   (Plus LLM_GENERATION, SANDBOX_EXEC, HITL_DECISION, and RESPONSE_ACTION lifecycle events.)

B. Live Action-Graph (DAG) Construction & Anomaly Detection

For every trace_id, the Warm Path incrementally builds a directed execution graph G = (V, E):

⚬ Nodes (V): Typed operational entities (USER, RAG_DOC, LLM_STEP, TOOL_CALL, MEMORY_STORE, SANDBOX, PEER_AGENT, EXTERNAL_EGRESS), annotated with provenance tier, taint labels, and policy verdict.
⚬ Edges (E): Causal sequence and data-flow transitions (READS_FROM, INVOKES, WRITES_TO, DELEGATES_TO, RETURNS_TO).
⚬ Graph Anomaly Detectors:
  1. Forbidden Taint-Flow Motifs: Deterministic subgraph matching (e.g., UNTRUSTED_EXTERNAL -> LLM_STEP -> PRIVILEGED_TOOL or CONFIDENTIAL_RAG -> LLM_STEP -> EXTERNAL_EGRESS).
  2. Markov Transition Deviation: Evaluates empirical transition surprise -\log P(\text{Node}_{t} \mid \text{Node}_{t-1}, \text{Agent}) against the agent's baseline behavioral profile.
  3. Cycle & Fan-Out Detection: Identifies repeating sub-loops or unexpected multi-agent fan-out explosions (ASI08).

C. Composite Drift Scoring Model

At every step t of a trace, the Warm Path computes a bounded composite behavioral risk score R_t \in [0, 1]:

$$R_t = \min\Big(1.0,\; w_1 S_{\text{policy}}(t) + w_2 S_{\text{graph}}(t) + w_3 S_{\text{velocity}}(t) + w_4 S_{\text{semantic}}(t)\Big)$$

Default calibrated weights (configurable per agent policy): w_1 = 0.45, w_2 = 0.25, w_3 = 0.15, w_4 = 0.15.

⚬ S_{\text{policy}}(t) \in [0, 1] (Deterministic Policy Signal): Weighted severity of hard rule hits (taint violations, schema hash mismatches, unauthorized scope attempts, DLP hits, sandbox violations). A critical violation sets S_{\text{policy}}(t) = 1.0 and triggers an immediate short-circuit override to R_t = 1.0.
⚬ S_{\text{graph}}(t) \in [0, 1] (Action-Graph Structural Drift): Normalized anomaly score derived from unseen tool transitions, forbidden subgraph motifs, and unexpected multi-agent hops.
⚬ S_{\text{velocity}}(t) \in [0, 1] (Loop & Resource Velocity): Max ratio across turn count, tool call count, repeated identical calls, and token burn relative to configured session budgets.
⚬ S_{\text{semantic}}(t) \in [0, 1] (Goal-Anchor Semantic Drift): Computed on CPU using local ONNX embeddings (fastembed, e.g., BAAI/bge-small-en-v1.5) over a sliding window of k = 3 recent steps to dampen natural conversational variance:

$$S_{\text{semantic}}(t) = \frac{1}{k} \sum_{i = t-k+1}^{t} \left(1 - \frac{\vec{e}_{\text{anchor}} \cdot \vec{e}_{\text{step}, i}}{\|\vec{e}_{\text{anchor}}\|\,\|\vec{e}_{\text{step}, i}\|}\right)$$

Automated Escalation Policy Thresholds:

⚬ R_t \in [0.00, 0.55): NORMAL — log telemetry continuously.
⚬ R_t \in [0.55, 0.75): ELEVATED — open Medium SOC Alert; capture full trace snapshot.
⚬ R_t \in [0.75, 0.90): HIGH_RISK — dynamically tighten session policy (auto-escalate all remaining non-read tools to privileged_hitl).
⚬ R_t \ge 0.90: CRITICAL — automatically trip Session Kill Switch, revoke session delegation token, and quarantine agent if cross-agent propagation is detected.

5.7 Subsystem 7: Active Response, Containment & State Recovery Controller

A. Hierarchical Kill Switches (Sub-Millisecond Enforcement)

Backed by Redis key-value flags + Redis Pub/Sub broadcasts consumed immediately by all Inline Edge proxies:

Kill Switch Scope	Target Granularity	Effect on In-Flight & Future Traffic
1. Tool / Module Kill Switch	(agent_id, tool_name) or global mcp_server_id	Immediately blocks all calls to a compromised tool or MCP server across one or all agents while keeping healthy capabilities online.
2. Session Kill Switch	trace_id	Terminates a single hijacked or looping conversation thread without disrupting other users on the same agent.
3. Agent Kill Switch	agent_id	Halts all LLM, MCP, memory, and sandbox execution for a compromised agent instance.
4. Global Flow / Fleet Kill Switch	workflow_id or * (Emergency Red Button)	Freezes an entire multi-agent pipeline or all enterprise agents during an active cascading incident.

B. Blast-Radius Isolation & Quarantine

⚬ State Machine: HEALTHY -> DEGRADED_HITL_ONLY -> QUARANTINED -> RECOVERED / DECOMMISSIONED.
⚬ Entering QUARANTINED atomically:
  1. Drops all inbound and outbound traffic for the agent on the Inter-Agent Bus (stopping cascading propagation to peer agents).
  2. Revokes the agent's active workload credentials and delegated user tokens.
  3. Terminates any running ephemeral sandbox containers tied to the agent.
  4. Preserves all telemetry, graph state, and memory snapshots in read-only forensic mode.

C. Write-Ahead Memory & RAG Snapshot Rollback

⚬ Every intercepted write to an agent's persistent memory or dynamic RAG collection is recorded as a versioned commit:
  (commit_id, trace_id, agent_id, store_id, target_key_or_doc_id, operation, previous_payload, new_payload, provenance_tier, taint_labels, timestamp, state=[ACTIVE|ROLLED_BACK]).
⚬ Recovery Operations:
  ⚬ Trace Rollback: Reverts all memory/RAG mutations produced by a specific compromised trace_id.
  ⚬ Point-in-Time Agent Rollback: Restores an agent's memory namespace cleanly to any prior commit_id prior to poisoning (ASI06).
  ⚬ Taint-Based Purge: Identifies and rolls back all downstream writes derived from a specific poisoned RAG document ID across multiple sessions.

D. Anti-ASI09 Human-in-the-Loop (HITL) Approval Contract

To prevent compromised agents from socially engineering human approvers, every privileged_hitl escalation enforces strict visual and data separation:

⚬ Trusted Deterministic Diff Pane (Primary View):
  ⚬ Exact target tool, MCP server, and verified schema hash status.
  ⚬ Raw structured JSON arguments and computed state/destination diff (e.g., exact recipient email, external URL, SQL mutation, or sanitized Python code).
  ⚬ Active Session Taint Banner explicitly surfacing untrusted inputs (e.g., "WARNING: This trace ingested an untrusted external PDF 2 steps prior to this request").
  ⚬ Current Composite Drift Score R_t and originating human user identity.
⚬ Untrusted Agent Rationale Pane (Secondary, Collapsed by Default):
  ⚬ Explicitly badged UNTRUSTED AGENT OUTPUT.
  ⚬ Displays persuasion/urgency classifier alerts (e.g., highlighting manipulative pressure or fabricated authority claims).
⚬ Forensic Attribution Log: Persists the approver's identity, timestamp, decision (APPROVE / DENY), exact deterministic payload hash approved, and whether persuasion warnings were active at the time of approval.

6. Data Architecture, Storage Contracts & Query Interface

6.1 Polyglot Persistence Boundaries

Data Store	Role	Stored Artifacts	Retention & Access Pattern
PostgreSQL	Control Plane System of Record (ACID)	Agent Registry, Versioned policy.yaml & RBAC history, Pinned MCP Schemas, HITL Approval Tickets, Incident Cases, Write-Ahead Memory Snapshot Commits, CI/CD Scan Results.	Strict relational integrity; append-only versioning for policies and audit records.
Redis	Real-Time State & High-Speed Bus	Redis Streams (telemetry ingestion queue), Redis Pub/Sub (kill switch & quarantine broadcasts), ephemeral keys (session loop/budget counters, active taint sets, anti-replay nonces).	Sub-millisecond reads/writes; TTL-bounded ephemeral session state.
DuckDB	Analytical SIEM Telemetry Store	Immutable flattened AgentEvent streams, Action-Graph edges, drift score time-series, OWASP alert logs.	Columnar analytical OLAP optimized for fast KQL-lite SOC hunting queries on local CPU.

6.2 Core Entity Schemas (Canonical Contracts)

1. AgentEvent (Immutable Telemetry Envelope)

{
  "event_id": "uuid-v7",
  "timestamp": "ISO-8601 UTC",
  "trace_id": "string",
  "span_id": "string",
  "parent_span_id": "string | null",
  "agent_id": "string",
  "policy_version": "semver",
  "event_type": "USER_INPUT | LLM_GENERATION | RAG_ACCESS | MEMORY_MUTATION | TOOL_INVOCATION | AGENT_COMM | SANDBOX_EXEC | HITL_DECISION | RESPONSE_ACTION",
  "principal": {
    "user_id": "string",
    "roles": ["string"],
    "effective_scopes": ["string"]
  },
  "provenance_tier": "TRUSTED_SYSTEM | AUTHENTICATED_USER | RESTRICTED_INTERNAL | VERIFIED_MEMORY | UNTRUSTED_EXTERNAL",
  "taint_labels": ["string"],
  "payload_redacted": "object",
  "decision": {
    "verdict": "ALLOW | MASK_AND_ALLOW | PAUSE_FOR_HITL | BLOCK | KILL",
    "rule_id": "string | null",
    "owasp_ids": ["ASI01..ASI10"],
    "latency_ms": "float"
  },
  "drift_snapshot": {
    "composite_score": "float (0.0-1.0)",
    "s_policy": "float",
    "s_graph": "float",
    "s_velocity": "float",
    "s_semantic": "float"
  }
}


2. IncidentRecord (SOC Case Object)

⚬ incident_id, created_at, updated_at, severity (LOW | MEDIUM | HIGH | CRITICAL), status (OPEN | INVESTIGATING | CONTAINED | RESOLVED).
⚬ owasp_categories ([ASI01..ASI10]), affected_agent_ids, root_trace_id, peak_drift_score.
⚬ triggering_event_ids, automated_actions_taken, manual_response_audit_log.

6.3 KQL-Lite SOC Hunting Query Interface

The platform exposes a declarative, Sentinel-inspired query language compiled deterministically into parameterized DuckDB SQL (preventing SQL injection on the SIEM itself):

⚬ Supported Tables: AgentEvents, ToolInvocations, DriftMetrics, Incidents, MCPRegistry, PolicyAudit.
⚬ Supported Pipe Operators: where, project, summarize ... by ..., sort by, top, extend, has / contains, ago(15m | 1h | 24h).
⚬ Example Hunt Queries:

  AgentEvents
  | where timestamp > ago(1h)
  | where taint_labels has "UNTRUSTED_EXTERNAL" and decision.verdict == "BLOCK"
  | summarize blocked_count = count(), max_drift = max(drift_snapshot.composite_score) by agent_id, payload_redacted.tool_name
  | sort by blocked_count desc
  


  ToolInvocations
  | where schema_hash_verified == false or is_shadow_mcp == true
  | project timestamp, agent_id, mcp_server, tool_name, trace_id
  


---

## 7. SOC War-Room Dashboard Functional Specification

The Next.js web console is designed around three operational personas: **SOC Incident Responder**, **AI Security Engineer**, and **Governance / Policy Approver**.

| View | Primary Purpose | Key Interactive Components & Data Contracts |
| :--- | :--- | :--- |
| **1. Command Overview & OWASP ASI01–10 Matrix** | Executive & SOC situational awareness across the enterprise fleet. | Real-time 10-tile **OWASP Agentic Top 10 Coverage & Alert Matrix** (Active alerts, blocked attempts, posture health per ASI01–ASI10); live fleet status (`HEALTHY / HITL / QUARANTINED`); global emergency kill switch (double-confirmed). |
| **2. Live Trace & Action-Graph Explorer** | Visual root-cause forensics for multi-step and multi-agent chains. | Interactive **React Flow DAG** color-coded by provenance tier and verdict (`Green=Allow`, `Amber=Tainted/HITL`, `Red=Blocked/Exfil`); step-by-step timeline scrubber showing live drift curve $R_t$ decomposition ($S_{\text{policy}}, S_{\text{graph}}, S_{\text{velocity}}, S_{\text{semantic}}$). |
| **3. KQL-Lite Threat Hunting Console** | Proactive threat hunting and custom detection validation. | Syntax-highlighted query editor with autocomplete for table schemas and OWASP IDs; tabular & chart results; one-click "Pivot to Trace Graph" or "Promote to Alert Rule". |
| **4. Incident & Active Response Drawer** | Rapid containment and recovery without leaving the investigation view. | Contextual 1-click actions: **Kill Session**, **Kill Tool/Module**, **Quarantine Agent**, and **Rollback Memory/RAG** (displaying exact before/after snapshot diffs before executing rollback). |
| **5. Anti-ASI09 HITL Approval Queue** | Safe human adjudication of high-risk agent actions. | Live queue of paused `privileged_hitl` calls; primary deterministic parameter/diff view + Taint Warning banner; collapsed `UNTRUSTED AGENT OUTPUT` rationale pane with persuasion flags; Approve/Deny with mandatory reason logging. |
| **6. Fleet Posture, Versioned RBAC & Supply Chain** | Governance of agents, roles, MCP tools, and CI/CD status. | Onboarded Agent Inventory; Policy Version diff viewer & approval workflow; Pinned MCP Schema SHA-256 Registry & Shadow MCP discovery feed; GitHub PR Security Gate & PyRIT Red-Team scorecard history. |

---

## 8. Enterprise Validation Harness: Reference Demo Fleet & Attack Simulator

To validate every security invariant end-to-end under realistic enterprise conditions, the platform includes a self-contained **3-Agent Enterprise Target Fleet** (onboarded strictly through the drop-in OpenAI SDK + MCP Proxy + Thin SDK) and a scripted **Red-Team Attack Simulator**.

### 8.1 Reference Target Topology
1. **`doc-support-agent` (IT & Knowledge Assistant):** Reads internal RAG docs (RBAC-enforced) and external ticket attachments; maintains session/long-term user memory; delegates analytics requests to `data-analyst-agent`.
2. **`data-analyst-agent` (SQL & Python Analyst):** Queries read-only Postgres via MCP and runs agent-generated Python scripts via the RCE Sandbox; returns summaries to `doc-support-agent` or `ops-comms-agent`.
3. **`ops-comms-agent` (Action & Notifications Agent):** Holds `privileged_hitl` tools (`send_email`, `create_jira_ticket`, `post_webhook`) and `blocked` tools (`shell_exec`).

### 8.2 Five Canonical End-to-End Attack Replay Scenarios

| Scenario | Simulated Attack Chain | OWASP Coverage | Expected AgentXDR Behavior |
| :--- | :--- | :--- | :--- |
| **Scenario 1: Indirect Injection -> Taint Exfiltration -> Memory Poisoning** | External document ingested by `doc-support-agent` contains hidden instructions to read confidential finance RAG chunks, persist a backdoor rule to long-term memory, and instruct `ops-comms-agent` to email secrets externally. | **ASI01, ASI02, ASI06, ASI07, ASI10** | RAG RBAC restricts unauthorized docs; `UNTRUSTED_EXTERNAL` taint propagates across the signed inter-agent bus; Memory write gate blocks untrusted persistence (or demonstrates post-facto Snapshot Rollback); Taint-flow rule `TAINT-EXFIL-001` hard-blocks `send_email` inline; Action-Graph highlights full attack path. |
| **Scenario 2: MCP Schema Rug-Pull & Shadow Server** | External MCP server dynamically mutates a previously approved tool description to inject credential-harvesting instructions; an agent also attempts to invoke an unregistered shadow MCP endpoint. | **ASI04, ASI02** | MCP Proxy detects SHA-256 hash mismatch on `tools/list`, strips compromised tool, raises Critical ASI04 alert; unregistered endpoint triggers `SHADOW_MCP_DETECTED` and fails closed. |
| **Scenario 3: Malicious Code Generation & Sandbox Escape Attempt** | Prompt manipulates `data-analyst-agent` into generating Python code importing `subprocess`/`socket` to read environment secrets and open a reverse shell/C2 callback. | **ASI05, ASI10** | Stage 1 AST Sanitizer blocks forbidden imports immediately; secondary obfuscated payload executing inside rootless Docker fails on `--network=none` and `--read-only` FS; container destroyed and High Severity alert logged. |
| **Scenario 4: Cascading Loop & Multi-Agent Quarantine** | Crafted prompt induces a self-reinforcing delegation loop between `doc-support-agent` and `ops-comms-agent`, driving up tool velocity and token burn while attempting scope escalation. | **ASI03, ASI08, ASI10** | Token attenuation blocks scope widening; Composite Drift $R_t$ crosses $0.90$ via $S_{\text{velocity}}$ and graph cycle detection; Loop Circuit Breaker halts trace; Automated Quarantine isolates rogue agent on the bus without impacting healthy traffic. |
| **Scenario 5: Persuasive HITL Social Engineering & Shift-Left PR Weakening** | Compromised agent crafts an urgent "CFO override" rationale requesting approval for a wire/webhook action; concurrently, a simulated PR attempts to weaken `policy.yaml` from `privileged_hitl` to `automatic`. | **ASI09, ASI03, ASI04** | HITL Queue isolates agent prose under `UNTRUSTED`, flags urgency persuasion, and displays raw external webhook diff + Taint Banner; GitHub Action `agentxdr-ci` flags privilege expansion and fails the PR merge check alongside PyRIT regression results. |

---

## 9. Non-Functional Requirements, Security Invariants & Hardening

### 9.1 Performance & Resource Targets (Single-Node CPU Deployment)
* **Inline Hot Path Overhead:** P50 $<20\text{ ms}$, P95 $<50\text{ ms}$ (excluding upstream LLM/MCP RTT).
* **Warm Path Detection Latency:** P95 $<800\text{ ms}$ from event emission to drift score update and alert visibility.
* **Kill Switch Propagation:** $<10\text{ ms}$ from Control Plane trigger to Inline Edge enforcement across all proxy instances.
* **Hardware Footprint:** Full stack (Gateway, Control Plane, Detector + ONNX embeddings, Postgres, Redis, DuckDB, Sandbox, Dashboard) operable on a single developer workstation ($16\text{ GB}$ RAM, CPU-only, no GPU required).

### 9.2 Hardening the Security Platform Itself (Meta-Security)
* **Log & Prompt Injection Resistance:** Telemetry displayed in the SOC dashboard is strictly HTML/XSS-escaped and structurally separated so malicious agent outputs cannot exploit SOC analysts or inject fake UI controls.
* **Immutable Audit Integrity:** Telemetry records in DuckDB and policy/approval logs in PostgreSQL are append-only; response actions (kill switches, rollbacks, policy approvals) require authenticated operator identity and generate secondary audit trails.
* **Least-Privilege Control Plane:** The Inline Gateway holds *read-only* access to active policies and *write-only* append access to telemetry streams; it cannot approve policies or mutate RBAC versions.
* **Secret Hygiene:** Raw PII and secrets masked by the DLP layer are never stored in cleartext inside telemetry payloads or DuckDB logs (only cryptographic hashes or redaction tokens are persisted for correlation).

### 9.3 Architectural Extensibility Contracts
All volatile external dependencies sit behind explicit internal interfaces to keep the platform future-proof:
* `LLMProxyAdapter`: Default OpenAI-compatible; extensible to Anthropic native / Vertex / Bedrock protocols.
* `SandboxProvider`: Default `DockerRootlessProvider`; swappable with Firecracker, gVisor, or Kubernetes Kata Containers.
* `EmbeddingProvider`: Default local CPU ONNX (`fastembed`); swappable with external embedding endpoints.
* `AlertSink`: Default internal SOC Dashboard + DuckDB; extensible to webhook/SIEM forwarders (Microsoft Sentinel, Splunk, Cortex XDR, PagerDuty, Slack).
```eof

I have written the complete A–Z system specification in `design.md`, covering the product boundaries, full OWASP ASI01–ASI10 threat matrix, dual-path architecture, drop-in integration contracts (OpenAI SDK, MCP proxy, thin Python OTel SDK, GitHub Actions), all seven core subsystems, data schemas, KQL-lite hunt grammar, SOC dashboard views, and the 5-scenario validation harness.

Would you like to review and refine any specific boundary or contract inside `design.md`—such as the Policy YAML schema, the KQL-lite grammar, or the Inter-Agent Bus protocol—before moving on to Phase 1?
