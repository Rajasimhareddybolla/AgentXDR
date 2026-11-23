# Project: AgentXDR Phase 3 — Warm-Path Analytics Plane & KQL-Lite SIEM Engine

## Architecture
Phase 3 builds the warm-path analytics plane and KQL-Lite SIEM engine for AgentXDR, seamlessly bridging hot-path enforcement with warm-path telemetry analysis, live graph visualization, semantic drift detection, anti-persuasion governance, and analytical querying.

```
+-----------------------------------------------------------------------------------+
|                                 Hot Path (M1-M6)                                  |
|   User / Principal -> FastAPI Gateway / SDK -> PolicyEvaluator & MCP Proxy        |
+-----------------------------------------------------------------------------------+
                                        |  (AgentEvent stream)
                                        v
+-----------------------------------------------------------------------------------+
|                         Warm-Path Analytics Plane (Phase 3)                       |
|                                                                                   |
|  +-----------------------------+       +---------------------------------------+  |
|  | Milestone 7: Graph & Topo   |       | Milestone 8: Semantic Drift           |  |
|  | - ActionGraph (DAG Builder) |       | - SemanticDriftCalculator (Local CPU) |  |
|  | - MotifAnomalyDetector      |       | - Pluggable Embedding Engines         |  |
|  | - AgentTopologyBuilder      |       | - Sliding Window Cosine Distance      |  |
|  | - React Flow & Mermaid Exps |       | - Trajectory Classification           |  |
|  +-----------------------------+       +---------------------------------------+  |
|                                                                                   |
|  +-----------------------------+       +---------------------------------------+  |
|  | Milestone 9: Anti-ASI09     |       | Milestone 10: DuckDB & KQL-Lite       |  |
|  | - PersuasionClassifier      |       | - DuckDbAnalyticsStore                |  |
|  | - 6 ASI09 Tactics Scoring   |       | - KqlParser (Pure AST Recursive Desc) |  |
|  | - HitlReviewGate & Tickets  |       | - KqlCompiler (AST -> DuckDB SQL)     |  |
|  | - Structural Separation     |       | - 5 Enterprise Threat Hunting PB      |  |
|  +-----------------------------+       +---------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

## Code Layout
Existing layout maintained with new Phase 3 packages:
```
src/agentxdr/
├── __init__.py               # Re-exports Phase 3 modules & existing symbols
├── models/                   # Existing event & policy schemas
│   ├── events.py             # AgentEvent, HitlDecisionPayload, DriftSnapshot
│   └── policy.py             # PolicySchema, GoalAnchorConfig, ToolPolicy
├── graph/                    # [M7] Action-Graph & Motif Anomaly Detection
│   ├── __init__.py
│   ├── models.py             # GraphNodeType, GraphEdgeType, GraphNode, GraphEdge, MotifViolation
│   ├── action_graph.py       # ActionGraph (DAG builder wrapping NetworkX DiGraph)
│   └── motif_detector.py     # MotifAnomalyDetector (taint paths, cycles, jumping, escalation, bursts)
├── topology/                 # [M7] Visual Agent Topology
│   ├── __init__.py
│   ├── models.py             # UserPrincipalNode, AgentHubNode, ContextPerimeterNode, McpToolNode, AgentTopologyModel
│   └── builder.py            # AgentTopologyBuilder (from Policy & events -> React Flow JSON & Mermaid)
├── drift/                    # [M8] Local CPU Semantic Drift
│   ├── __init__.py
│   ├── models.py             # DriftClassification, SemanticDriftResult, TrajectoryPoint
│   ├── embeddings.py         # BaseEmbeddingEngine, FastembedEngine, OnnxEmbeddingEngine, DeterministicEmbeddingEngine
│   └── calculator.py         # SemanticDriftCalculator (sliding window cosine drift, composite R_t)
├── persuasion/               # [M9] Anti-ASI09 Persuasion & HITL Governance
│   ├── __init__.py
│   ├── classifier.py         # PersuasionClassifier, PersuasionTactic, PersuasionResult
│   └── hitl_gate.py          # HitlReviewGate, HitlTicket, TicketStatus, structural separation
├── analytics/                # [M10] DuckDB Store & KQL-Lite SIEM Engine
│   ├── __init__.py
│   ├── duckdb_store.py       # DuckDbAnalyticsStore (in-memory & file-based, thread-safe)
│   └── kql/
│       ├── __init__.py
│       ├── ast.py            # AST node definitions
│       ├── parser.py         # Pure Python tokenizer and recursive descent parser
│       └── compiler.py       # AST to DuckDB SQL compiler
tests/
├── unit/
│   ├── test_action_graph.py
│   ├── test_topology.py
│   ├── test_semantic_drift.py
│   ├── test_persuasion.py
│   ├── test_duckdb_store.py
│   └── test_kql_compiler.py
└── e2e/
    ├── test_tier1_phase3_features.py
    ├── test_tier2_phase3_boundaries.py
    ├── test_tier3_phase3_combinations.py
    ├── test_tier4_phase3_scenarios.py
    └── test_tier5_adversarial_hardening.py
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Action-Graph DAG Builder | Constructs execution DAGs from `AgentEvent` streams tracking causality and data flows | M7 | ORIGINAL_REQUEST §R1 |
| 2 | Motif Anomaly Detection | Detects 5 attack motifs: forbidden taint subgraphs, execution loops, tool jumping, privilege escalation, fan-out bursts | M7 | ORIGINAL_REQUEST §R1 |
| 3 | Visual Topology Model | Data model capturing User -> Agent -> Context -> MCP Tools hierarchy | M7 | ORIGINAL_REQUEST §R1, §R2 |
| 4 | Agent Diagram & Active Execution | Visual agent topology showing tools categorized by mode (Automatic, HITL, Blocked), context perimeter, user-principal, active execution highlighting, React Flow JSON & Mermaid export | M7 | ORIGINAL_REQUEST §R2 |
| 5 | Local CPU Semantic Drift Calculator | Evaluates cosine similarity of agent actions against `goal_anchor` via ONNX / fastembed / deterministic engine | M8 | ORIGINAL_REQUEST §R3 |
| 6 | Drift Classification & Composite Risk | Calibrated drift thresholds (`NORMAL`, `ELEVATED`, `HIGH_RISK`, `CRITICAL`), 3-step sliding window, and composite score $R_t$ | M8 | ORIGINAL_REQUEST §R3 |
| 7 | Anti-ASI09 Persuasion & Urgency Classifier | Detects coercive, deceptive, artificial urgency, and authority fabrication signals in agent communications and tool inputs | M9 | ORIGINAL_REQUEST §R4 |
| 8 | Persuasion-Driven HITL Governance | Dynamic escalation of automatic tools to `PAUSE_FOR_HITL`, structural separation of parameters from untrusted prose, dual approver validation | M9 | ORIGINAL_REQUEST §R4 |
| 9 | Embedded DuckDB Analytical Store | Persists and indexes warm-path `AgentEvents`, `Incidents`, `MCPRegistry` in DuckDB with in-memory & file-based support | M10 | ORIGINAL_REQUEST §R5 |
| 10 | KQL-Lite Grammar & AST Parser | Pure Python parser for pipeline-oriented KQL syntax (`where`, `summarize`, `project`, `extend`, `sort by`, `top`, `take`) | M10 | ORIGINAL_REQUEST §R5 |
| 11 | KQL-Lite to DuckDB SQL Compiler | Safely compiles KQL AST into parameterized DuckDB SQL; validates against all 5 threat hunting playbooks | M10 | ORIGINAL_REQUEST §R5 |
| 12 | End-to-End Test Suite & Zero Regression | All existing 629 automated tests pass with 100% success rate, plus full Tiers 1-4 tests for Phase 3 | Final Milestone | ORIGINAL_REQUEST §R6 |
| 13 | Adversarial Coverage Hardening | White-box stress testing, corner cases, and adversarial probe generation (Tier 5) | Final Milestone | Project Pattern Phase 2 |
| 14 | Project Tracking & Repository Rules | `message-log.md` updated with milestone records; conventional commits pushed to `origin/main` | All Milestones | ORIGINAL_REQUEST §R6 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M7 | Action-Graph & Visual Topology | Action-Graph DAG builder, 5 motif anomaly detectors, visual topology data model (User -> Agent -> Context -> MCP Tools), active execution highlighting, React Flow & Mermaid serializers | None | DONE |
| M8 | Local CPU Semantic Drift | Local CPU semantic drift calculator, pluggable embedding engines (ONNX, Fastembed, Deterministic), 3-step sliding window cosine distance, calibrated drift classification, composite $R_t$ | None (uses existing models) | DONE |
| M9 | Anti-ASI09 Persuasion Governance | 6-tactic persuasion & urgency classifier, multi-signal scoring, HitlReviewGate, HitlTicket lifecycle, dynamic HITL escalation, structural parameter separation | None (uses existing models & policy) | DONE |
| M10 | Embedded DuckDB & KQL-Lite Engine | DuckDbAnalyticsStore, AgentEvents/Incidents/MCPRegistry schemas, KqlParser (pure AST recursive descent), KqlCompiler (AST -> DuckDB SQL), 5 hunting playbooks | None (uses existing models & duckdb) | DONE |
| M_E2E | End-to-End Test Suite & Zero Regression | All existing automated tests pass with 100% success rate (>=750 tests), plus full Tiers 1-3 tests for Phase 3 | M7, M8, M9, M10 | IN_PROGRESS |
| E2E | E2E Testing Track | Comprehensive 4-Tier test suite for Phase 3, publishes `TEST_READY.md` | M7-M10 specs | PLANNED |
| MF | Final Milestone | Pass 100% E2E tests (Tiers 1-4), Tier 5 adversarial coverage hardening, docs/message-log update, conventional commits and push to `origin/main` | M7-M10, E2E | PLANNED |

## Interface Contracts

### M7: Graph & Topology ↔ Core System
- `ActionGraph.ingest_event(event: AgentEvent) -> None`
- `ActionGraph.get_subgraph(trace_id: str) -> nx.DiGraph`
- `MotifAnomalyDetector.scan_trace(graph: nx.DiGraph, trace_id: str) -> List[MotifViolation]`
- `AgentTopologyBuilder.build_topology(policy: PolicySchema, active_trace: Optional[str] = None) -> AgentTopologyModel`
- `AgentTopologyModel.to_react_flow() -> Dict[str, Any]`
- `AgentTopologyModel.to_mermaid() -> str`

### M8: Semantic Drift ↔ Policy & Telemetry
- `BaseEmbeddingEngine.encode(texts: List[str]) -> np.ndarray`
- `SemanticDriftCalculator.evaluate_step(trace_id: str, step_text: str, anchor_text: str) -> SemanticDriftResult`
- `SemanticDriftResult.drift_score: float` (0.0 to 1.0)
- `SemanticDriftResult.classification: DriftClassification` (NORMAL, ELEVATED, HIGH_RISK, CRITICAL)
- `SemanticDriftResult.composite_risk: float` ($R_t$)

### M9: Anti-ASI09 Persuasion ↔ HITL Governance
- `PersuasionClassifier.classify_text(text: str) -> PersuasionResult`
- `PersuasionClassifier.classify_tool_call(tool_name: str, arguments: Dict[str, Any], justification: Optional[str] = None) -> PersuasionResult`
- `HitlReviewGate.evaluate_action(tool_policy: ToolPolicy, arguments: Dict[str, Any], persuasion_result: PersuasionResult, drift_score: float = 0.0) -> Tuple[Verdict, Optional[str], Optional[HitlTicket]]`
- `HitlReviewGate.adjudicate_ticket(ticket_id: str, approver_id: str, decision: Literal["APPROVE", "DENY"], justification: str = "") -> HitlDecisionPayload`

### M10: DuckDB Store ↔ KQL-Lite SIEM Engine
- `DuckDbAnalyticsStore(database_path: str = ":memory:", read_only: bool = False)`
- `DuckDbAnalyticsStore.ingest_event(event: AgentEvent) -> None`
- `DuckDbAnalyticsStore.ingest_events(events: Sequence[AgentEvent]) -> int`
- `DuckDbAnalyticsStore.query_sql(sql: str, params: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]`
- `DuckDbAnalyticsStore.query_kql(kql: str) -> List[Dict[str, Any]]`
- `KqlParser.parse(kql_text: str) -> KqlQuery`
- `KqlCompiler.compile(query: KqlQuery) -> Tuple[str, List[Any]]`
