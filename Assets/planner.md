# AgentXDR Implementation Planner

**Status:** Proposed execution plan  
**Date:** 2026-11-23  
**Repository:** AgentXDR  
**Current package version:** `0.1.0`

## 1. Purpose

This document converts the AgentXDR design documents into an executable engineering plan. It separates what already exists from what is still architectural intent, defines milestones and subdivided goals, and establishes the interfaces that must remain stable as the project grows.

The goal is not to build a collection of disconnected security features. The goal is to build a dependable control loop:

```text
Policy + identity
        ↓
Deterministic inline enforcement
        ↓
Canonical security events
        ↓
Warm-path detection and correlation
        ↓
Containment, approval, and recovery
        ↓
Evidence, replay, and policy improvement
```

The most important architectural rule is that every prevention, detection, and response action must be explainable from a versioned policy, a versioned event, and a reproducible decision.

## 2. Current state: what is really present

The repository currently contains a strong, tested Python core. The latest local test run produced:

```text
629 passed, 17 skipped
```

### 2.1 Implemented and usable now

| Area | Current implementation | Maturity |
|---|---|---|
| Policy models | Pydantic policy, tools, budgets, taint rules, hashes | Working core |
| Policy enforcement | Tool registration, tiers, schema hashes, taint rules, parameters, kill switches | Working core |
| DLP | Deterministic masking for secrets, PII, and prompt leakage | Working core |
| AST controls | Static Python code inspection | Working core |
| Circuit breakers | Turn, tool-call, repeated-call, duration, and cost limits | Working core |
| Kill switches | In-process hierarchical kill-switch state | Working prototype |
| LLM gateway | FastAPI OpenAI-compatible request/response inspection and forwarding | Working prototype |
| MCP proxy | `tools/list`, `tools/call`, shadow-tool filtering, injection scanning, schema pinning | Working prototype |
| Taint propagation | In-process monotonic taint state | Working core |
| RAG guard | ACL filter injection, chunk scanning, provenance metadata | Working adapter |
| Memory guard | Tainted-write blocking and in-process write-ahead records | Partial |
| Agent bus | HMAC envelope, nonce generation, role attenuation | Partial |
| SDK telemetry | OpenTelemetry `gen_ai.*` spans | Basic instrumentation |

### 2.2 Designed but not yet implemented

These are described in the README and design documents but are not present as complete subsystems:

- Redis-backed distributed state, streams, and kill switches
- PostgreSQL control-plane persistence
- Durable event ingestion and immutable event storage
- DuckDB analytical store and KQL-Lite compiler
- Action-Graph/DAG construction and graph anomaly detection
- Semantic goal drift using CPU embeddings/ONNX
- Persuasion and urgency analysis for ASI09
- Persistent memory/RAG snapshots and atomic rollback
- Rootless Docker or equivalent sandbox providers
- Production HITL queue, approval verification, and dual control
- Agent quarantine and blast-radius orchestration
- GitHub Action and policy/dependency/prompt diff gates
- PyRIT or equivalent adversarial evaluation harness
- Reference fleet and canonical attack replay runner
- SOC dashboard and live topology/execution canvas
- Production identity validation, tenancy, authentication, and authorization

### 2.3 Important current limitations

The planner must address these before calling the project production-ready:

1. `MemoryGuard` records snapshots only in the Python process and has no rollback operation.
2. `AgentBus` uses HMAC and a base64-encoded role payload, but it does not yet provide full anti-replay validation or independently verifiable workload identity.
3. The gateway and MCP proxy are local application objects; they are not yet distributed or operationally hardened.
4. Telemetry spans are emitted, but no canonical `AgentEvent` pipeline consumes them.
5. The README claims warm-path analytics and response controls that the repository does not yet implement.
6. The system has no durable audit trail, so a security decision cannot yet be reconstructed after process failure.
7. The code has broad unit/e2e coverage, but there is no adversarial corpus, performance benchmark suite, or failure-injection test environment.

## 3. Target architecture

### 3.1 Plane separation

AgentXDR should be implemented as five cooperating planes:

```text
                 ┌─────────────────────────────────────────┐
                 │ Control Plane                           │
                 │ policies, identities, tools, approvals  │
                 │ incidents, snapshots, response commands │
                 └───────────────────┬─────────────────────┘
                                     │ cached state / commands
┌──────────────────────┐             │             ┌───────────────────────┐
│ Agent workload        │             │             │ External systems      │
│ OpenAI SDK, framework │◄────────────┼───────────►│ MCP, RAG, memory, SaaS│
└──────────┬───────────┘             │             └───────────────────────┘
           │                          │
           ▼                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Inline Enforcement Plane                                                  │
│ LLM gateway | MCP proxy | SDK hooks | DLP | policy PEP | taint | breakers│
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ append-only events
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Detection Plane                                                           │
│ Redis Streams | graph builder | velocity rules | drift | persuasion      │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ alerts / response commands
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Response and Recovery Plane                                               │
│ kill | quarantine | HITL | rollback | revoke | evidence and incident case│
└──────────────────────────────────────────────────────────────────────────┘

                         ┌─────────────────────────────┐
                         │ Analytics and operator plane │
                         │ DuckDB/KQL | API | SOC UI    │
                         └─────────────────────────────┘
```

### 3.2 Storage responsibilities

Keep the accepted polyglot storage decision, but assign each store a narrow responsibility:

| Store | Owns | Must not own |
|---|---|---|
| PostgreSQL | Versioned policies, agents, principals, MCP registry, approvals, incidents, snapshot metadata | Per-event high-volume analytics or hot-path locks |
| Redis | Cached policy decisions, active taints, counters, kill/quarantine flags, approval leases, streams | Long-term audit truth |
| DuckDB | Local analytical projections, threat hunting, replay analysis, offline investigations | Authoritative control state |
| Object storage | Large payloads, redacted evidence bundles, exported graphs, replay fixtures | Inline authorization |

For local development, provide Docker Compose profiles for PostgreSQL, Redis, and an optional object-store emulator. The core library must remain usable in an in-memory mode for tests.

### 3.3 The canonical event contract

The existing `AgentEvent` model should become the central integration contract. Every boundary must emit the same envelope, including allowed actions, blocked actions, errors, and operator decisions.

Required event properties:

- `event_id`, `timestamp`, `trace_id`, `span_id`, `parent_span_id`
- `tenant_id`, `agent_id`, `policy_version`, `policy_hash`
- principal identity and effective scopes
- event type and provenance tier
- monotonic taint labels
- redacted payload only
- decision verdict, rule ID, OWASP IDs, and latency
- component and deployment version
- correlation IDs for incident, approval, snapshot, and response command

Sensitive raw payloads must never be written to the event bus by default. If forensic capture is explicitly enabled, it must use a separate encrypted evidence store with retention and access policy.

### 3.4 Enforcement contract

All inline components should return a common decision shape:

```text
DecisionResult:
  verdict: ALLOW | MASK_AND_ALLOW | PAUSE_FOR_HITL | BLOCK | KILL
  rule_id: stable identifier
  owasp_ids: list
  reason_code: stable machine-readable code
  policy_version / policy_hash
  trace_id
  latency_ms
  evidence_refs: list
```

Do not make UI text, exception strings, or natural-language model output the source of truth for authorization.

## 4. Delivery strategy

### 4.1 Recommended order

The safest implementation order is:

1. Freeze contracts and observability boundaries.
2. Productionize the current hot path.
3. Add durable state and distributed coordination.
4. Build the event pipeline and warm-path detection.
5. Implement response and recovery.
6. Add the sandbox.
7. Add CI/red teaming.
8. Build the operator APIs and UI.
9. Validate with a reference fleet and adversarial replay.
10. Harden deployment, performance, and security operations.

This order prevents the common failure mode of building a dashboard before the event and response semantics are reliable.

### 4.2 Delivery modes

Every new detector or response should support three modes:

- **Observe:** calculate and emit evidence, never change behavior.
- **Recommend:** create an alert or approval recommendation.
- **Enforce:** block, kill, quarantine, or rollback.

New controls should default to Observe in production until false-positive rates, latency, and replay behavior are understood.

## 5. Milestones and subdivided goals

## Milestone 0 — Contract freeze and engineering foundation

**Objective:** Turn the current prototype into a stable platform foundation before adding distributed services.

### Goals

#### M0.1 Define public API boundaries

- Mark stable public classes and functions in `agentxdr.__init__`.
- Add explicit versioning rules for policy schema, event schema, decision schema, and MCP envelope.
- Separate internal helpers from supported extension points.
- Add deprecation policy and compatibility tests.

#### M0.2 Normalize decision and error semantics

- Introduce a shared decision/result model used by the gateway, MCP proxy, SDK, and future sandbox.
- Replace component-specific refusal shapes with a common reason-code catalog.
- Preserve backwards-compatible JSON-RPC and OpenAI error responses at the edge.
- Ensure every denial includes policy version, rule ID, trace ID, and safe evidence metadata.

#### M0.3 Complete event schema

- Expand `AgentEvent` to cover all existing event types.
- Add schema version, tenant, deployment, parent/causal references, and evidence references.
- Define redaction rules before serialization.
- Add JSON Schema or equivalent contract artifacts for non-Python producers.

#### M0.4 Build deterministic test fixtures

- Create reusable fixtures for clean flow, direct injection, indirect injection, schema rug-pull, taint exfiltration, loop storm, privilege escalation, and memory poisoning.
- Add golden decision tests: same inputs, policy, and state must produce the same decision.
- Add a redacted-event snapshot suite.

### Exit criteria

- No new subsystem invents its own decision or event shape.
- Contract tests run without external services.
- Existing 629 passing tests remain green.
- A versioned compatibility guide exists for policy and event changes.

## Milestone 1 — Hot-path productionization

**Objective:** Make the current inline gateway, MCP proxy, policy evaluator, DLP, and circuit breaker safe to embed in a real service.

### Goals

#### M1.1 Harden policy evaluation

- Compile a loaded policy into an immutable runtime policy object.
- Validate policy hashes and reject inconsistent version/hash pairs.
- Add explicit tenant and agent scope checks.
- Define fail-open/fail-closed behavior per control; security-critical controls must fail closed.
- Add policy decision caching only for safe, immutable inputs.
- Add policy evaluation benchmarks for normal and worst-case rules.

#### M1.2 Harden the LLM gateway

- Support both `/v1/chat/completions` and the modern `/v1/responses` shape if required by target clients.
- Implement streaming/SSE inspection with bounded buffering and safe partial-output behavior.
- Propagate trace, principal, policy, and taint context consistently.
- Add upstream retries only when idempotency and circuit rules permit them.
- Add request size limits, timeout budgets, concurrency limits, and upstream allowlists.
- Never forward internal AgentXDR headers to untrusted destinations without an explicit allowlist.
- Add structured logs and canonical events for accepted, masked, refused, timeout, and upstream-error paths.

#### M1.3 Harden the MCP proxy

- Validate full JSON-RPC structure and reject malformed requests.
- Track MCP server identity as well as tool identity.
- Normalize schema hashing rules and hash algorithm prefixes.
- Support fail-closed behavior when a pinned tool cannot be verified.
- Add upstream MCP forwarding and connection lifecycle handling.
- Add per-server rate limits and server-level kill switches.
- Preserve refusal metadata while avoiding leakage of sensitive policy internals.

#### M1.4 Improve DLP safely

- Separate detection from masking so policies can choose block, mask, or audit.
- Add deterministic custom pattern configuration with rule IDs.
- Add context-aware false-positive tests for code, dates, IDs, and ordinary emails.
- Add Unicode normalization and hidden-character handling for prompt injection and exfiltration.
- Make redaction idempotent.

#### M1.5 Complete session state semantics

- Define session creation, expiration, idle timeout, and cleanup behavior.
- Make counters atomic when backed by Redis.
- Add trace parent/child relationships for multi-agent calls.
- Add explicit `ACTIVE`, `HITL_PENDING`, `QUARANTINED`, `KILLED`, `COMPLETED`, and `EXPIRED` states.

### Exit criteria

- Gateway and MCP proxy have documented edge contracts and failure modes.
- Hot-path overhead is benchmarked, with a target of less than 50 ms P95 excluding upstream model/tool time.
- Security-critical checks remain functional during upstream failures.
- No sensitive raw content appears in ordinary logs or events.

## Milestone 2 — Durable control plane and distributed state

**Objective:** Move security state from process memory into authoritative and highly available services.

### Goals

#### M2.1 PostgreSQL control-plane schema

Create migrations and repositories for:

- tenants and principals
- agents and agent versions
- policy versions and approvals
- policy bindings
- roles and effective scopes
- MCP servers and tool registry
- tool schema pins
- HITL requests and decisions
- incidents and response actions
- memory/RAG snapshot metadata
- audit records

Every mutable security object needs an immutable version or append-only history.

#### M2.2 Redis runtime state

Implement namespaced keys for:

- active kill switches
- quarantine state
- session taints
- counters and budgets
- policy cache
- approval leases and idempotency keys
- event stream offsets

Use TTLs for ephemeral state. Include tenant, agent, and environment in every key to prevent cross-tenant collisions.

#### M2.3 Configuration distribution

- Publish policy changes as versioned control-plane events.
- Update edge workers through atomic cache swaps.
- Keep the last known-good policy available.
- Reject partial or hash-mismatched configuration updates.
- Record which policy version made each decision.

#### M2.4 Identity and authorization

- Validate incoming principal identity at a trusted edge.
- Compute effective scopes as user ∩ agent role ∩ task policy.
- Replace base64-only delegation tokens with signed, short-lived envelopes or JWTs.
- Add key rotation and key version identifiers.
- Enforce tenant isolation in every repository and cache key.

### Exit criteria

- Restarting a gateway does not lose kill switches, sessions, audit state, or policy versions.
- Two gateway instances make consistent decisions against the same policy and runtime state.
- A policy can be approved, activated, rolled back, and audited.
- Cross-tenant access tests are negative by default.

## Milestone 3 — Canonical telemetry and warm-path pipeline

**Objective:** Create the evidence stream that powers detection, investigations, replay, and the future UI.

### Goals

#### M3.1 Event emission adapters

Emit canonical `AgentEvent` records from:

- user input
- LLM request and response
- tool discovery
- tool invocation
- tool result
- RAG retrieval
- memory mutation
- sandbox execution
- inter-agent message
- HITL request and decision
- kill, quarantine, rollback, and policy changes

#### M3.2 Redis Streams ingestion

- Use tenant/environment partitioning.
- Add consumer groups and replayable offsets.
- Define retry, dead-letter, and poison-event behavior.
- Make event publication non-blocking for normal hot-path requests.
- Provide a bounded local buffer when Redis is temporarily unavailable.
- Decide explicitly which event classes are allowed to block an action when publication fails.

#### M3.3 DuckDB analytical projection

- Create normalized event and incident tables.
- Store nested payloads in a queryable form while preserving redaction.
- Implement retention and compaction.
- Add indexes or partitioning appropriate for trace, agent, tenant, and time.
- Provide deterministic replay from event fixtures into DuckDB.

#### M3.4 KQL-Lite

- Implement a parser with a deliberately small grammar.
- Compile only to parameterized DuckDB SQL.
- Reject unknown fields and unsafe expressions.
- Add query budgets, result limits, and timeouts.
- Provide query explain output for operators.
- Ship the documented threat-hunting playbooks as tested queries.

### Exit criteria

- A complete trace can be reconstructed from canonical events.
- Events survive process restarts and can be replayed into analytics.
- KQL-Lite queries cannot execute arbitrary SQL.
- Ingestion lag, dropped events, dead-letter count, and storage health are observable.

## Milestone 4 — Behavioral detection and drift engine

**Objective:** Detect suspicious behavior that individual inline rules cannot see.

### Goals

#### M4.1 Action-Graph builder

- Model nodes for principal, prompt, context source, LLM step, tool call, memory, sandbox, and peer agent.
- Model causal edges such as `READS_FROM`, `INVOKES`, `WRITES_TO`, `DELEGATES_TO`, and `RETURNS_TO`.
- Preserve parent/child spans and causal IDs.
- Handle late and duplicate events idempotently.
- Bound graph size with trace windows and compaction.

#### M4.2 Deterministic anomaly detectors

Implement first because they are explainable and cheap:

- tool burst and velocity anomalies
- unexpected tool transition
- fan-out explosion
- repeated failure/retry storms
- tainted-context-to-egress path
- cross-agent delegation cycles
- privilege changes during a trace
- tool schema changes during a session

#### M4.3 Composite drift score

Implement the documented formula as a versioned scoring policy:

```text
R_t = min(1.0,
  0.45 * S_policy +
  0.25 * S_graph +
  0.15 * S_velocity +
  0.15 * S_semantic)
```

- Start with `S_semantic = 0` until the embedding scorer is validated.
- Version the coefficients and threshold configuration.
- Emit component scores, not just the composite score.
- Make critical policy violations capable of forcing `R_t = 1.0`.
- Add hysteresis so a score near a threshold does not flap kill switches.

#### M4.4 CPU semantic scorer

- Benchmark a small CPU embedding model against latency and memory targets.
- Compare responses against the policy goal anchor and recent task window.
- Cache embeddings by content hash.
- Never send tenant content to an external embedding service by default.
- Calibrate thresholds using clean and adversarial evaluation sets.

#### M4.5 ASI09 persuasion signals

Start with transparent heuristics:

- urgency language
- authority claims
- pressure to bypass controls
- requests to hide or suppress evidence
- emotional coercion
- unusual approval timing

Add a local classifier only after the heuristic baseline has measurable value. The score should annotate HITL decisions; it must not be the only reason to approve a high-risk action.

### Exit criteria

- Each alert includes evidence paths and explainable contributing signals.
- Warm-path alerts can update runtime state within the agreed operational target.
- Detection results are replayable and threshold changes can be evaluated offline.
- False positives and false negatives are measured on a versioned corpus.

## Milestone 5 — Active response, quarantine, and recovery

**Objective:** Convert detection into safe, auditable containment and recovery.

### Goals

#### M5.1 Response command model

Create idempotent, signed commands for:

- kill trace
- kill tool/server
- quarantine agent
- quarantine tenant or environment
- revoke delegated credentials
- pause new tool calls
- escalate all actions to HITL
- rollback memory/RAG writes
- restore a prior policy

Every command needs issuer, reason, evidence refs, expiration, scope, and execution result.

#### M5.2 Quarantine state machine

Use explicit transitions:

```text
HEALTHY → SUSPECTED → RESTRICTED → QUARANTINED → RECOVERING → HEALTHY
                              └──────────────→ KILLED
```

Define which actions are allowed in each state. Quarantine must be narrower than a global kill and should preserve evidence collection.

#### M5.3 HITL approval service

- Create approval requests with deterministic target, arguments, tool hash, taints, principal, and policy version.
- Use expiring leases to prevent duplicate execution.
- Enforce idempotency keys.
- Require step-up authentication for sensitive actions.
- Add dual approval for high-risk classes.
- Bind the final approval to an exact parameter hash; any change creates a new request.
- Keep agent rationale visually and logically separate from deterministic evidence.

#### M5.4 Durable memory/RAG snapshots

- Record previous and new value hashes, source document IDs, trace ID, taints, actor, and timestamp.
- Store enough encrypted data or references to reverse the mutation.
- Support trace rollback, point-in-time rollback, and taint/source-based purge.
- Use optimistic concurrency and a transaction/outbox pattern.
- Make rollback idempotent and produce its own events.

#### M5.5 Blast-radius calculation

Before quarantine or rollback, calculate affected:

- active traces
- agents and child agents
- tools and MCP servers
- memory namespaces
- tenants and destinations

Show the blast radius to the operator and include it in the response audit record.

### Exit criteria

- A simulated compromise can be stopped, explained, and recovered without manual database edits.
- Response commands are authenticated, scoped, idempotent, and auditable.
- Rollback does not silently overwrite newer legitimate writes.
- The system can contain one trace without unnecessarily stopping unrelated agents.

## Milestone 6 — Code execution sandbox

**Objective:** Complete ASI05 protection from static inspection through isolated execution.

### Goals

#### M6.1 Provider interface

Define a stable provider interface:

```python
execute(
    code: str,
    *,
    timeout_sec: int,
    memory_mb: int,
    network: str,
    filesystem: str,
) -> SandboxResult
```

`SandboxResult` must include exit state, stdout/stderr after DLP, duration, resource usage, violation codes, and evidence references.

#### M6.2 Local restricted provider

- Use only for development and CI.
- Run in a temporary workspace with strict timeout/resource limits.
- Apply AST checks before execution.
- Make the limitations explicit; never present it as equivalent to container isolation.

#### M6.3 Rootless container provider

- Network disabled by default.
- Read-only root filesystem.
- Writable temporary workspace only.
- Drop capabilities and use no-new-privileges.
- Apply CPU, memory, PID, and wall-clock limits.
- Pin the execution image by digest.
- Remove the container and workspace after completion.
- Capture lifecycle events and violations.

#### M6.4 Escalation rules

- Classify code actions as read-only, filesystem-mutating, network-capable, credential-sensitive, or privileged.
- Require HITL for policy-defined high-risk classes.
- Render code diffs and requested capabilities, not persuasive explanations.

### Exit criteria

- Known escape and egress tests fail safely.
- Timeouts, OOM, malformed code, and provider outages produce deterministic results.
- No untrusted generated code executes on the host in production mode.

## Milestone 7 — Shift-left security and adversarial validation

**Objective:** Catch dangerous changes before deployment and continuously measure control effectiveness.

### Goals

#### M7.1 GitHub Action

Analyze pull requests for:

- policy privilege widening
- tool tier changes
- schema hash changes
- prompt/goal-anchor weakening
- disabled ACL or taint checks
- hardcoded credentials
- dependency and container-image changes
- MCP endpoint additions

Produce SARIF and a human-readable report. Separate advisory findings from blocking findings.

#### M7.2 Policy diff analyzer

- Compare effective privileges, not just YAML text.
- Flag `blocked → privileged_hitl` and `privileged_hitl → automatic` transitions.
- Detect wildcard tools, widened egress, weaker parameter constraints, and removed taint rules.
- Require explicit approval metadata for high-risk changes.

#### M7.3 Adversarial evaluation harness

Build a provider-neutral harness first; integrate PyRIT as an adapter rather than making the whole product depend on it.

Attack families should include:

- direct prompt injection
- indirect RAG/tool injection
- tool parameter manipulation
- MCP schema rug-pull
- memory poisoning
- privilege escalation
- inter-agent replay/tampering
- retry storm
- RCE attempts
- HITL persuasion
- DLP/exfiltration attempts

#### M7.4 Security quality gates

Track:

- attack success rate
- block rate
- false-positive rate
- detection latency
- response latency
- rollback success rate
- event loss rate
- P95/P99 hot-path overhead

### Exit criteria

- Pull requests receive reproducible security reports.
- Critical attack classes have explicit pass/fail thresholds.
- Baseline attack fixtures run in CI without external model dependencies.
- Every release has a security regression report.

## Milestone 8 — Reference fleet and replayable demonstrations

**Objective:** Prove that the platform works across realistic multi-agent workflows.

### Goals

Implement the three documented reference agents:

- `doc-support-agent`
- `data-analyst-agent`
- `ops-comms-agent`

Each should use real gateway/MCP/SDK integrations and have:

- versioned policy
- realistic RAG and memory adapter
- at least one automatic, HITL, and blocked tool
- inter-agent delegation
- telemetry and trace propagation
- deterministic attack fixtures

Canonical replay scenarios:

1. A poisoned document attempts to exfiltrate internal content.
2. An MCP tool silently changes schema and description.
3. A compromised agent attempts privilege escalation through delegation.
4. A retry loop causes a multi-agent cascade.
5. An attacker persuades an operator to approve a dangerous external action.

Each replay must show prevention, detection, response, and recovery.

### Exit criteria

- A new developer can run the fleet locally with one documented command.
- Each attack produces a trace, events, incident, response, and final evidence bundle.
- The demonstrations use the same APIs as production code rather than bespoke test shortcuts.

## Milestone 9 — Operator API and SOC war-room UI

**Objective:** Provide operators with safe visibility and controlled response without making the UI a security boundary.

### Goals

#### M9.1 Read APIs

- agents, policies, versions, and effective capabilities
- live sessions and traces
- event search and trace reconstruction
- incidents and evidence
- MCP registry and schema history
- memory/RAG snapshots
- system health and ingestion lag

#### M9.2 Action APIs

- approve/reject HITL request
- kill trace/tool/agent
- quarantine and recover
- rollback snapshot
- acknowledge/resolve incident

All action APIs must call the same response-command service used by automation.

#### M9.3 Topology and execution views

The UI should show:

- originating principal and effective scopes
- agent, policy, model, and state
- context sources and provenance
- tool tiers and schema-pin status
- causal execution graph
- taint propagation
- drift components
- active response controls

#### M9.4 Anti-ASI09 design requirements

- Deterministic diffs are primary.
- Agent explanations are labeled untrusted and collapsed by default.
- Approval buttons display exact target and parameter hash.
- High-risk actions require explicit re-authentication and, where configured, a second approver.

### Exit criteria

- Operators can investigate and contain a replayed incident entirely through APIs/UI.
- The UI never bypasses policy or directly mutates protected state.
- Critical actions remain available through a safe API/CLI path if the UI is unavailable.

## Milestone 10 — Production hardening and operational readiness

**Objective:** Make the platform safe to deploy and operate continuously.

### Goals

- Threat model every service and trust boundary.
- Add service authentication and mTLS where appropriate.
- Rotate encryption, signing, and database credentials.
- Add tenant isolation tests and authorization fuzzing.
- Add rate limits, quotas, circuit breakers, and backpressure across all services.
- Define retention, deletion, legal hold, and evidence access policy.
- Add health checks for stale policy caches, stream lag, dead letters, and response-command failures.
- Add disaster recovery for PostgreSQL, Redis, object storage, and evidence.
- Produce SBOMs and signed container images.
- Pin dependencies and run vulnerability scanning.
- Add SLOs and alerts for enforcement availability, latency, event loss, detection lag, and response completion.
- Run failure-injection tests: Redis outage, PostgreSQL outage, stale policy, duplicate events, clock skew, model timeout, and UI outage.

### Exit criteria

- Documented deployment, upgrade, rollback, and disaster-recovery procedures exist.
- Security decisions remain safe under dependency and infrastructure failures.
- An on-call operator can diagnose the system without reading application source code.

## 6. Cross-cutting engineering practices

### 6.1 Build around evidence, not claims

Every README claim should map to one of:

- a tested implementation
- an integration test requiring a documented service
- a benchmark result
- a design-only statement clearly labeled as planned

Do not describe a component as production-grade until it has persistence, failure behavior, security tests, and operational metrics.

### 6.2 Deterministic core, probabilistic advisory layer

Use deterministic code for:

- authorization
- policy enforcement
- schema verification
- taint blocks
- DLP masking
- loop limits
- response commands
- rollback eligibility

Use probabilistic models only for:

- semantic drift signals
- persuasion signals
- anomaly ranking
- triage assistance

Probabilistic output may escalate or recommend. It should not silently grant permission.

### 6.3 Idempotency everywhere

Events, response commands, HITL decisions, snapshots, and rollbacks must be safe to retry. Use stable idempotency keys derived from the operation, trace, policy version, and parameter hash.

### 6.4 Replay-first development

For every detector or response feature, create:

1. an input event fixture;
2. the expected decision or alert;
3. the expected state transition;
4. the expected evidence;
5. a replay test;
6. a failure/duplicate/retry variant.

This will make the warm path, UI, and incident response testable without a live LLM.

### 6.5 Privacy by construction

- Redact before events leave the inline process.
- Keep raw content out of metrics and ordinary logs.
- Use content hashes and evidence references wherever possible.
- Encrypt sensitive evidence at rest.
- Make tenant and retention boundaries explicit.
- Treat prompts, tool arguments, RAG content, and agent rationale as potentially sensitive.

## 7. Out-of-the-box ideas worth exploring

These should be prototyped only after the event, policy, and response foundations are stable.

### 7.1 Security canary lineage

Insert high-entropy, tenant-specific canary markers into selected sensitive RAG records. Track whether a canary or a robust derived fingerprint appears in outbound tool arguments or model responses. Treat this as a detection signal, not a sole blocking mechanism, because paraphrasing and false matches are possible.

### 7.2 Capability receipts

Before a tool call, issue a short-lived signed capability receipt containing the exact tool, schema hash, parameter hash, principal, taints, policy version, and expiration. The downstream connector accepts the call only if the receipt matches. This closes the gap between approval and execution.

### 7.3 Shadow-mode policy simulation

When changing policy, evaluate live traffic against both the active and candidate policies without changing behavior. Show which calls would newly block, newly allow, or newly escalate. This makes policy rollout measurable and reversible.

### 7.4 Causal evidence bundles

For every incident, automatically package the smallest causal subgraph that explains it: source context, taint propagation, decision points, tool arguments, policy versions, response commands, and recovery actions. This is more useful to an analyst than a giant raw log export.

### 7.5 Deception tools and honey capabilities

Register synthetic high-risk tools or decoy resources that legitimate agents should never call. A call to a honey capability is a high-confidence rogue-behavior signal and can trigger quarantine. Use carefully and disclose it in governance documentation.

### 7.6 Policy mutation testing

Automatically weaken policies in controlled test runs: remove a taint rule, widen a parameter, change a tool tier, or alter a schema hash. Verify that CI gates and test cases detect the mutation. This tests the tests, not only the product.

### 7.7 Multi-agent capability ledger

Maintain a live ledger of who delegated which capability to whom, for what trace, with what attenuation, and until when. Detect capability amplification even when each individual hop appears valid.

### 7.8 Active-learning incident review

Let operators label false positives and true incidents. Use those labels to calibrate thresholds and prioritize new fixtures, while keeping authorization deterministic and avoiding automatic model retraining from unreviewed incident content.

### 7.9 Privacy-preserving fleet analytics

For cross-tenant trends, aggregate event features and hashes rather than raw prompts, tool arguments, or documents. This enables fleet-level anomaly research without centralizing customer content.

## 8. Suggested first execution slice

The next implementation slice should be Milestones 0 and 1, limited to the following deliverables:

1. Shared `DecisionResult` and reason-code catalog.
2. Versioned canonical `AgentEvent` schema and redaction boundary.
3. Policy compilation/validation and immutable runtime policy.
4. Gateway and MCP structured event emission.
5. Streaming-safe gateway behavior.
6. MCP JSON-RPC validation and server identity tracking.
7. Session lifecycle and fail-closed behavior tests.
8. Hot-path benchmark suite.
9. Documentation update that labels warm-path, rollback, sandbox, CI, and UI features as planned until implemented.

This slice creates the contracts that all later milestones consume and gives the project a measurable production baseline.

## 9. Clarifying questions for the next planning revision

These decisions materially affect implementation details. The plan above assumes the recommended option in each case, but the project owner should confirm them:

1. **Primary deployment target:** Should the first production target be local Docker Compose, Kubernetes, or AWS-managed services? The recommended starting point is Docker Compose for development followed by Kubernetes-compatible containers.
2. **First integration:** Should AgentXDR prioritize OpenAI-compatible LLM traffic, MCP traffic, or the Python SDK? The recommended order is gateway + MCP together, with the SDK as the sensor for internal state.
3. **Identity provider:** Should the control plane initially support a simple signed internal identity or a real OIDC provider such as Cognito/Auth0/Entra? The recommended production direction is OIDC, with a local signed-token adapter for tests.
4. **Data retention:** What is the expected tenant/event retention period, and may raw prompt/tool content ever be retained? The recommended default is redacted events only, with opt-in encrypted evidence retention.
5. **Sandbox threat level:** Is the sandbox intended for untrusted arbitrary Python, or only controlled transformation code? The recommended assumption is arbitrary untrusted code, which requires rootless container isolation before production use.
6. **Human approval boundary:** Which tool categories require one approver versus two approvers? The recommended default is dual approval for external communication, financial actions, credential changes, destructive writes, and policy changes.
7. **Latency budget:** Is the stated `<50 ms P95` measured only for AgentXDR overhead, or does it include network and serialization? The recommended metric is AgentXDR-added overhead excluding upstream model/tool time, with separate end-to-end SLOs.
8. **Model strategy:** Must all detection models run locally on CPU, or may a private hosted model be used for triage? The recommended security baseline is local CPU detection with optional private hosted enrichment disabled by default.

## 10. Definition of done for AgentXDR v1

AgentXDR v1 should not be declared complete until it can demonstrate all of the following in a clean local or staging deployment:

- A versioned policy is approved, activated, evaluated, and rolled back.
- An LLM request is traced, inspected, redacted, allowed or blocked, and audited.
- An MCP tool is registered, hash-verified, invoked, and audited.
- A tainted tool/RAG result prevents a forbidden downstream action.
- A loop or cost budget trips without allowing additional work.
- A generated-code request is inspected and runs only inside the approved sandbox provider.
- A memory mutation can be traced and rolled back safely.
- A suspicious trace produces an explainable incident and scoped containment command.
- An HITL approval is bound to exact parameters and cannot be replayed or modified.
- A full attack scenario can be replayed from events and produces the same result.
- Operators can investigate the incident without accessing unredacted production prompts by default.
- Performance, event loss, detection lag, and recovery SLOs are measured and documented.

