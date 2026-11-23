# E2E Test Infra: AgentXDR Phase 3

## Test Philosophy
- Opaque-box, requirement-driven testing based on user specifications and architecture contracts.
- Strictly offline, deterministic, sub-second execution without external cloud/network calls.
- Zero regressions on existing 629 passing tests.
- Methodology: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Combinatorial + Real-World Workload Testing.

## Feature Inventory
| # | Feature | Source (requirement) | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---|---------|---------------------|:------:|:------:|:------:|:------:|
| 1 | Action-Graph DAG Builder | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| 2 | Motif Anomaly Detection | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| 3 | Visual Topology Model | ORIGINAL_REQUEST §R1, §R2 | 5 | 5 | ✓ | ✓ |
| 4 | Agent Diagram & Active Execution | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| 5 | Local CPU Semantic Drift Calculator | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ | ✓ |
| 6 | Drift Classification & Composite Risk | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ | ✓ |
| 7 | Anti-ASI09 Persuasion & Urgency Classifier | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ | ✓ |
| 8 | Persuasion-Driven HITL Governance | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ | ✓ |
| 9 | Embedded DuckDB Analytical Store | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |
| 10 | KQL-Lite Grammar & AST Parser | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |
| 11 | KQL-Lite to DuckDB SQL Compiler | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |

## Test Architecture
- Test runner: `pytest`
- In-memory execution: DuckDB `:memory:`, Deterministic Embedding Engine, NetworkX in-memory DiGraph.
- Pass/fail semantics: Exit code 0, 100% pass rate.
- Directory layout:
  - `tests/unit/test_action_graph.py`
  - `tests/unit/test_topology.py`
  - `tests/unit/test_semantic_drift.py`
  - `tests/unit/test_persuasion.py`
  - `tests/unit/test_duckdb_store.py`
  - `tests/unit/test_kql_compiler.py`
  - `tests/e2e/test_tier1_phase3_features.py`
  - `tests/e2e/test_tier2_phase3_boundaries.py`
  - `tests/e2e/test_tier3_phase3_combinations.py`
  - `tests/e2e/test_tier4_phase3_scenarios.py`
  - `tests/e2e/test_tier5_adversarial_hardening.py`

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Compromised Agent Exfiltration via Dynamic Egress | F1, F2, F9, F11 | High |
| 2 | Prompt Injection inducing High-Urgency Persuasion & HITL Escalation | F7, F8, F9, F11 | High |
| 3 | Goal Hijacking with Semantic Drift Divergence & Kill-Switch Trip | F5, F6, F1, F4 | High |
| 4 | MCP Schema Rug-Pull & Shadow Tool Anomaly Hunting via KQL | F1, F2, F9, F10, F11 | High |
| 5 | Runaway Loop & Recursive Delegation Cycle Detection & Topology Scrubbing | F1, F2, F3, F4 | High |

## Coverage Thresholds
- Tier 1: ≥5 per feature (≥55 tests)
- Tier 2: ≥5 per feature (≥55 tests)
- Tier 3: Pairwise coverage of major feature interactions (≥11 tests)
- Tier 4: ≥5 realistic multi-feature application scenarios
- Tier 5: Adversarial coverage hardening (white-box gap analysis)
