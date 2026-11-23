# AgentXDR: Project Status & Operational Guide

**System:** AgentXDR Runtime Security Control Plane & Analytics Plane  
**Status:** FULLY OPERATIONAL (All Milestones Completed & Verified)  
**Test Suite:** 1,058 passed, 0 failures, 17 skipped (100% pass rate)  
**Branch:** `feature/complete-agentxdr-application` (ready for `main`)

---

## 1. Quick Start: Running the Application

### 1.1 Run Live Security Demo
Exercises all 3 phases in a self-contained live run (DLP masking, ActionGraph DAG, Motif Anomaly Detection, Semantic Drift, Anti-ASI09 Persuasion, HITL review, DuckDB SIEM, and Kill Switches):
```bash
agentxdr demo
# Or via python directly:
python3 scripts/run_demo.py
```

### 1.2 Start Unified Runtime Control Plane Server
Launches the full FastAPI control plane hosting both hot-path reverse proxies and warm-path analytical endpoints:
```bash
agentxdr serve --host 0.0.0.0 --port 8000 --policy examples/sample_policy.yaml
```
- **Hot-Path LLM Gateway:** `POST /v1/chat/completions` (DLP masking, injection scanning, circuit breakers)
- **Hot-Path MCP Security Proxy:** `POST /mcp` (Schema hash pinning, shadow tool detection)
- **Interactive OpenAPI Documentation:** `http://localhost:8000/docs`

### 1.3 Threat Hunting with KQL-Lite
Execute analytical queries against warm-path DuckDB telemetry:
```bash
agentxdr kql "events | where verdict == 'BLOCK' | take 5"
```

### 1.4 Policy Validation & Visual Topology Export
```bash
# Validate policy against schema constraints
agentxdr policy validate examples/sample_policy.yaml

# Export visual architecture as Mermaid graph
agentxdr topology examples/sample_policy.yaml --format mermaid

# Export visual architecture as React Flow JSON
agentxdr topology examples/sample_policy.yaml --format json
```

---

## 2. Architecture & Subsystem Matrix

| Subsystem | Components | Primary Responsibilities |
|-----------|------------|--------------------------|
| **1. Policy & Core Engine** | `PolicyEvaluator`, `PolicySchema`, `load_policy_yaml` | Declarative YAML rules, tiered action resolution (`automatic`, `privileged_hitl`, `blocked`), parameter constraints |
| **2. Deterministic Guardrails** | `DlpMasker`, `AstSanitizer` | Zero-GPU PII/secrets masking, AST forbidden import and reflection blocking |
| **3. Circuit Breakers** | `CircuitBreaker` | Hard limits: turns, tool calls, identical loop detection, session duration, token/USD budget |
| **4. Hot-Path Proxies** | `LlmGateway`, `McpProxy`, `McpSchemaRegistry` | Reverse proxy for LLM completions, JSON-RPC MCP proxy with SHA-256 schema hash pinning and shadow detection |
| **5. In-Process SDK** | `AgentXDRContext`, `guard_openai`, `RagGuard`, `MemoryGuard`, `AgentBus` | Client SDK wrapping OpenAI, RAG tenant metadata enforcement, memory mutation write-ahead logs |
| **6. Action-Graph & Motifs** | `ActionGraph`, `MotifAnomalyDetector` | Trace-isolated execution DAG builder, 5 attack motifs: ASI01 indirect taint, execution loops, tool jumping, privilege escalation, fan-out bursts |
| **7. Visual Topology** | `AgentTopologyModel`, `AgentTopologyBuilder` | 5-layer topology model (User, Agent Digital Twin, Context Perimeter, MCP Periphery, Sandbox Enclave) with Mermaid and React Flow export |
| **8. Local CPU Semantic Drift** | `SemanticDriftCalculator`, `DeterministicEmbeddingEngine`, `OnnxEmbeddingEngine` | Cosine distance against goal anchor, 3-step sliding window, calibrated risk classification, composite risk $R_t$ |
| **9. Anti-ASI09 Persuasion & HITL** | `PersuasionClassifier`, `HitlReviewGate`, `HitlTicket` | 6 manipulation tactics detection (`ARTIFICIAL_URGENCY`, `COERCION_AND_FEAR`, `FALSE_AUTHORITY`, `SCARCITY_PRESSURE`, `OBFUSCATION_COMPLEXITY`, `FLATTERY_AND_SYCOPHANCY`), structural diff vs untrusted rationale separation, 15-min TTL |
| **10. Embedded DuckDB SIEM** | `DuckDbAnalyticsStore`, `KqlCompiler`, `KqlParser` | Columnar storage for `events`, `graph_edges`, `drift_snapshots`, `motif_violations`, recursive-descent KQL-Lite compiler with 100% parameterized SQL injection immunity |
| **11. Unified Control Plane** | `create_agentxdr_app`, CLI `agentxdr` | Integrated FastAPI runtime server, CLI tool suite, and live demonstration harness |

---

## 3. API Route Map

```
Hot-Path Endpoints:
  POST /v1/chat/completions                 -> OpenAI-compatible guarded proxy
  POST /mcp                                 -> Guarded JSON-RPC MCP proxy

Warm-Path Analytics & SIEM:
  POST /api/v1/analytics/events             -> Telemetry ingestion into DuckDB & ActionGraph
  POST /api/v1/analytics/kql                -> Analytical KQL pipeline execution
  GET  /api/v1/analytics/stats              -> Columnar store record counters

Visual Topology & Graph:
  GET  /api/v1/topology/mermaid             -> Live topology Mermaid export
  GET  /api/v1/topology/react-flow          -> Live topology React Flow nodes/edges
  GET  /api/v1/graph/{trace_id}             -> Causal execution DAG for trace
  GET  /api/v1/graph/{trace_id}/motifs      -> Motif anomaly detection scan results

Semantic Drift & Governance:
  POST /api/v1/drift/evaluate               -> Step cosine drift evaluation
  GET  /api/v1/drift/{trace_id}/trajectory  -> Step trajectory history

Anti-ASI09 Persuasion & HITL:
  POST /api/v1/persuasion/classify          -> 6-tactic manipulation classifier
  GET  /api/v1/hitl/tickets                 -> List pending review tickets
  GET  /api/v1/hitl/tickets/{ticket_id}     -> Segregated primary diff vs untrusted view
  POST /api/v1/hitl/tickets/{ticket_id}/adjudicate -> Human approval/rejection

Active Response Containment:
  GET  /api/v1/response/kill-switch/status  -> Active kill switch records
  POST /api/v1/response/kill-switch/trip    -> Trip kill switch (Session/Agent/Tool/Global)
  POST /api/v1/response/kill-switch/reset   -> Deactivate kill switch
```

---

## 4. Verification & Quality Gates

```
Automated Test Run Summary:
============================== 1058 passed, 17 skipped in 23.88s ==============================
- Regressions: 0
- Failures: 0
- Code Coverage: Phase 1 (Core Engine), Phase 2 (Proxies & SDK), Phase 3 (Warm-Path Analytics), Unified App & CLI
```
