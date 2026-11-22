# Architecture Decision Records (ADRs) - AgentXDR

This document serves as the persistent log of key architectural decisions, rationale, trade-offs, and invariants for AgentXDR, as mandated by the project governance rules.

---

## ADR-001: Project Root & Repository Hierarchy Realignment
* **Date:** 2026-11-22
* **Status:** Accepted
* **Context:** Initial workspace inspection revealed that the Git repository and remote origin had been initialized inside the `design/` subdirectory rather than at the project root (`/Users/raja/Desktop/Ai-Learn/AgentXDR`). This left `Assets/`, `docs/`, `specs/`, `channelog/`, and `message-log.md` untracked.
* **Decision:** Realigned the Git repository root to `/Users/raja/Desktop/Ai-Learn/AgentXDR`, moved the root `README.md` to top-level, added a comprehensive `.gitignore` for Python, Node, DuckDB, and OS artifacts, and ensured all future commits encompass the complete project lifecycle.
* **Consequences:** All components, documentation, assets, and specs are now unified under cohesive version control, preventing secrets leakage and enabling clean CI/CD automation.

---

## ADR-002: Drop-In, Zero-Rewrite Security Proxy Integration Model
* **Date:** 2026-11-22
* **Status:** Accepted
* **Context:** Enterprise teams utilize diverse agent frameworks (LangGraph, CrewAI, AutoGen, custom OpenAI loops). Forcing teams to rewrite their agent logic onto a proprietary SDK creates high friction and impedes adoption.
* **Decision:** Implement AgentXDR primarily as an external, drop-in control plane via:
  1. **OpenAI-Compatible Inline HTTP/SSE Gateway:** Intercepts `/v1/chat/completions` and `/v1/responses` by pointing `base_url` to the gateway.
  2. **MCP Security Proxy:** Mediates JSON-RPC 2.0 traffic (`tools/list`, `tools/call`) between clients and external/internal MCP servers.
  3. **Thin Python OTel Sensor SDK (`agentxdr-sdk`):** Lightweight in-process wrapper capturing internal state (RAG ACL metadata injection, memory write gating, signed inter-agent communication).
* **Consequences:** Enterprises can secure existing agents with 1–2 lines of configuration change without vendor lock-in.

---

## ADR-003: Strict Dual-Path Latency Architecture (Hot Path vs. Warm Path)
* **Date:** 2026-11-22
* **Status:** Accepted
* **Context:** Security controls must not introduce unacceptable latency into conversational AI experiences. However, deep behavioral graph analytics, Markov surprise modeling, and semantic embedding drift calculations are computationally intensive.
* **Decision:** Strictly decouple security operations into two asynchronous tiers:
  * **Synchronous Hot Path (<50ms P95 overhead):** Deterministic enforcement executing inline before/after model and tool invocations. Covers kill-switch checks, RBAC intersection, circuit breaker counters, MCP SHA-256 schema verification, deterministic taint-flow rules, regex/Presidio DLP masking, and AST static code sanitization.
  * **Asynchronous Warm Path (200–800ms P95):** Analytical processing driven by Redis Streams. Builds the live Action-Graph (DAG), computes local CPU ONNX semantic drift ($S_{\text{semantic}}$) via `fastembed`, scores ASI09 persuasion metrics, correlates OWASP incidents, and writes columnar telemetry to DuckDB.
* **Consequences:** Protects interactive user experience while maintaining enterprise-grade behavioral threat detection. Any warm-path alert can dynamically flip a Redis flag that halts or escalates subsequent hot-path calls within 5ms.

---

## ADR-004: Anti-ASI09 Structural Human-in-the-Loop (HITL) Interface Paradigm
* **Date:** 2026-11-22
* **Status:** Accepted
* **Context:** Attackers exploit the natural conversational fluency of LLMs to generate compelling, urgent, or deceptive rationales ("CFO authorized emergency payment due to system outage"), successfully socially engineering human approvers into granting dangerous actions (OWASP ASI09).
* **Decision:** The AgentXDR HITL review UI enforces strict physical and cognitive data separation:
  1. **Primary View (Deterministic Parameter Diff):** Displays raw JSON payloads, target MCP endpoints, verified schema hashes, recipient destinations, and an active Taint Warning banner (e.g., "Warning: Session ingested an untrusted PDF 2 steps ago").
  2. **Secondary View (Agent Natural Language Rationale):** Collapsed by default, explicitly badged as `UNTRUSTED AGENT OUTPUT`, and augmented with an automated Persuasion & Urgency classifier score.
* **Consequences:** Humans make decisions based solely on verified, deterministic payload facts rather than AI-generated rhetorical persuasion.

---

## ADR-005: Write-Ahead Memory & Context Snapshot Engine for Atomic Rollback
* **Date:** 2026-11-22
* **Status:** Accepted
* **Context:** OWASP ASI06 (Memory & Context Poisoning) attacks often lay dormant across multiple conversation turns before triggering an exploit. Conventional runtime blocks cannot undo poisoned memory once committed.
* **Decision:** Implement a Write-Ahead Memory & RAG Snapshot Log in the Control Plane. Every SDK/proxy-intercepted write operation to long-term memory or semantic vector collections records a versioned commit `(commit_id, trace_id, agent_id, store_id, key, previous_value, new_value, taint_labels, timestamp)`. The platform exposes atomic Rollback APIs:
  * Trace Rollback (reverts all mutations from a compromised session).
  * Point-in-Time Rollback (restores agent memory namespace to a pre-attack commit).
  * Taint-Based Purge (cascading rollback of all writes derived from a specific poisoned document ID).
* **Consequences:** Grants incident responders full state recovery capabilities, neutralizing persistent memory poisoning.

---

## ADR-006: Abstract Pluggable Sandbox Provider for Code Execution Containment
* **Date:** 2026-11-22
* **Status:** Accepted
* **Context:** Mitigating ASI05 (Unexpected Code Execution) requires sandboxing agent-generated code with zero network access, read-only filesystems, and strict resource limits. However, local developer workstations, lightweight staging servers, and CI environments may lack a configured rootless Docker daemon.
* **Decision:** Establish an abstract `SandboxProvider` Python interface:
  * `DockerRootlessProvider` (Production default: rootless container, `--network=none`, `--read-only`, cgroups limits).
  * `SubprocessRestrictedProvider` (Fallback/dev mode: isolated temporary directory, pre-execution static AST import rejection, execution timeout, resource limits).
  * Extensible to gVisor, Firecracker microVMs, or WebAssembly (Wasm) runtimes.
* **Consequences:** Ensures 100% testability and portability across all host operating systems without compromising production isolation.

---

## ADR-007: Polyglot Storage Architecture with Local CPU Optimization
* **Date:** 2026-11-22
* **Status:** Accepted
* **Context:** AgentXDR requires transactional integrity for policies, sub-millisecond state checks for the hot path, and high-performance analytical aggregation for threat hunting—all while running on commodity CPU hardware without GPU dependencies.
* **Decision:** Adopt a purpose-built polyglot persistence architecture:
  * **PostgreSQL:** Control Plane System of Record for immutable versioned policies, RBAC registries, pinned MCP schemas, HITL tickets, and snapshot commit metadata.
  * **Redis:** In-memory caching, sub-millisecond kill switches, active session taint sets, circuit-breaker counters, and Pub/Sub / Streams bus.
  * **DuckDB:** Embedded analytical columnar OLAP for high-speed KQL-Lite threat hunting queries over millions of immutable `AgentEvent` records on local CPU.
* **Consequences:** Eliminates external GPU requirements, achieves zero-copy columnar analytics, and keeps deployment footprints lightweight.


---

## ADR-008: Comprehensive Agent Topology, User-Principal Mapping, and Live Graphical Execution Cockpit
* **Date:** 2026-11-22
* **Status:** Accepted
* **Context:** Security operators and AI governance teams struggle with the opaque "black-box" nature of autonomous multi-agent systems. Without a visual control plane, operators cannot readily verify: (1) which human user initiated an action and their effective privileges, (2) the complete capability perimeter of an agent (all attached tools, tiers, and context sources), and (3) what the agent is causally doing in real-time as it traverses reasoning loops and tool chains.
* **Decision:** Implement a dual-mode **Visual Control Plane (AgentXDR Canvas)** in the SOC War-Room console:
  1. **Agent Topology & Capability Map (Blueprint View):**
     * **User-Principal Node:** Maps originating human identity (`user_id`, avatar, department, assigned roles, effective token clearance) and authenticated session link.
     * **Agent Digital Twin Node:** Central hub showing agent ID, model, active policy SemVer, goal anchor, live health status (`HEALTHY`, `HITL_PENDING`, `QUARANTINED`, `KILLED`), and composite drift score.
     * **Context Periphery:** Explicitly models all attached context sources (System Instructions with SHA-256 integrity, RAG knowledge collections with RBAC ACL tags, Persistent Memory with snapshot support).
     * **Tool & MCP Periphery:** Visual cards for each attached tool color-coded by tier (🟢 Automatic, 🟡 Privileged HITL, 🔴 Blocked), verified SHA-256 schema pin status, parameter limits, and target egress endpoints.
     * **Sandbox Enclave:** Visual representation of container boundaries (`net=none`, `ro-fs`, resource limits).
  2. **Live Graphical Execution DAG (Cockpit / War-Room View):**
     * Renders a real-time causal Directed Acyclic Graph (DAG) using React Flow / canvas mapping every step of active sessions:
       $$\text{User} \longrightarrow \text{User Prompt} \longrightarrow \text{Inline PEP} \longrightarrow \text{RAG Context} \longrightarrow \text{LLM Reasoning} \longrightarrow \text{Tool Calls} \longrightarrow \text{Response}$$
     * Animated data flow with moving particles, pulsing active nodes, dynamic taint labels badge propagation (e.g., `⚠️ UNTRUSTED_EXTERNAL`), step-by-step drift curve decomposition, and interactive 1-click containment buttons (Kill Trace, Quarantine Agent, Memory Rollback) directly embedded in the graphical canvas.
* **Consequences:** Eliminates black-box opacity. SecOps teams, auditors, and leadership gain full visual clarity, immediate situational awareness, and surgical control over autonomous agent operations.
