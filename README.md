# AegisOps — Autonomous DevOps Incident Triage Agent, Step-Level Trajectory Grading Engine & Calibrated LLM-as-a-Judge

> **🌐 Live Interactive Web Application & Trace Replay Player:** [**https://ritwikareddykancharla.github.io/aegis-ops/**](https://ritwikareddykancharla.github.io/aegis-ops/)

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-D94E1F.svg)](https://ritwikareddykancharla.github.io/aegis-ops/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib)-brightgreen.svg)](#quick-start)
[![CI Regression Gate](https://img.shields.io/badge/CI%20Eval%20Gate-PASS%20(%CE%BA%3D0.9167)-success.svg)](#3-calibrated-llm-as-a-judge--statistical-significance)

**`AegisOps`** is a production-grade, standalone Python framework for **autonomous cloud incident triage**, **deterministic DAG-based step-level trajectory evaluation**, **OpenTelemetry cost/latency tracing**, and **human-calibrated LLM-as-a-Judge regression gating**.

It is engineered so that every MCP server, state-machine checkpoint, trajectory evaluator, and statistical significance engine runs deterministically out-of-the-box with **zero external API keys**, while providing a pluggable **AWS Bedrock Converse API (`BedrockAgentClient`)** adapter for live foundation model deployment.

---

## System Architecture

> **Live Interactive Dashboard & Trace Replay Player:** [https://ritwikareddykancharla.github.io/aegis-ops/](https://ritwikareddykancharla.github.io/aegis-ops/)  
> **Excalidraw Source:** [`docs/architecture.excalidraw`](docs/architecture.excalidraw)

![AegisOps Architecture Diagram](docs/architecture.svg)

---

## Core Engineering Highlights

### 1. Deterministic MCP Tool Servers (`aegis_ops/mcp_servers.py`)
Implements three Model Context Protocol (MCP) servers backed by strict Draft-07 JSON-Schema validation (`validate_json_schema`), structured error envelopes (`SCHEMA_VALIDATION_ERROR`, `RESOURCE_NOT_FOUND`, `SAFETY_GATE_VIOLATION`), and per-call token/latency telemetry:
- **`CloudWatchLogsMCP`**: Queries structured service logs by time window, severity, and trace ID (`query_error_logs`) and clusters stack traces into 12 canonical failure signatures (`detect_error_signatures`: `ConnectionPoolExhausted`, `OOMKilled`, `IAMAccessDenied`, `HotPartitionThrottled`, `TLSHandshakeTimeout`, `NATPortExhausted`, `DeadlockDetected`, `BGPFlapDetected`, `DNSResolutionFailure`, `DiskIOPSThrottled`, `RedisEvictionSpike`, `KMSKeyDisabled`).
- **`PrometheusMetricsMCP`**: Queries SRE golden signals (`p99_latency_ms`, `error_rate_pct`, `cpu_saturation_pct`, `memory_saturation_pct`, `db_pool_utilization_pct`, `anomaly_z_score`) via `query_golden_signals` and correlates change events via `get_recent_deployments` (`GetRecentDeployments`).
- **`RunbookRemediationMCP`**: Retrieves standard operating procedures (`get_runbook`) and enforces a **mandatory safety approval gate** on `execute_remediation` when `dry_run=False`—blocking unapproved or forged tokens with `SAFETY_GATE_VIOLATION`.

### 2. Checkpointable State-Machine Triage Agent (`aegis_ops/triage_agent.py`)
- Enforces an explicit diagnostic state machine:
  `INIT -> TRIAGE_METRICS -> INSPECT_LOGS -> CORRELATE_DEPLOYMENTS -> CONSULT_RUNBOOK -> PROPOSE_REMEDIATION -> COMPLETED / ESCALATED`
- **Crash-Recovery Checkpointing**: Supports `save_checkpoint(trajectory, path)` and `resume_from_checkpoint(path, scenario)` so interrupted multi-step investigations resume from the exact state transition without repeating prior tool calls.
- **Cost & Loop Kill-Switches**: Halts execution and transitions to `ESCALATED` immediately if step count reaches `max_steps` (`KILL_SWITCH_MAX_STEPS`) or cumulative token spend reaches `max_budget_usd` (`KILL_SWITCH_BUDGET_EXCEEDED`).
- **Pluggable Policy & Bedrock Adapter**: Includes `BedrockAgentClient` (formatting MCP schemas into AWS Bedrock Converse API `toolConfig`) plus 5 deterministic policies for reproducible evaluation (`OptimalTriagePolicy`, `BaselineTriagePolicy`, `HallucinatingParamPolicy`, `UnsafeMutatingPolicy`, `PrematureConclusionPolicy`).

### 3. Step-Level DAG Trajectory Grading Engine (`aegis_ops/trajectory_eval.py`)
Rather than grading only final text outputs, `StepTrajectoryEvaluator` grades the full tool-call trajectory against each scenario's ground-truth Directed Acyclic Graph (`DAGSpec`):
- **`dag_compliance_score`**: Fraction of satisfied required tool nodes and `must_precede` prerequisite edges (e.g., verifying `query_error_logs` and `get_recent_deployments` precede `execute_remediation`).
- **`parameter_hallucination_rate`**: Fraction of tool calls with JSON-Schema errors, nonexistent service names, or mismatched target resources.
- **`safety_gate_violation_rate`**: Zero-tolerance tracking of unapproved mutating remediation attempts (`dry_run=False` without valid SRE approval token).
- **`tool_efficiency_ratio`**: Diagnostic node coverage penalized for redundant or failed steps.
- **`root_cause_accuracy`**: Exact match verification on diagnosed error signature, suspect deployment/change ID, remediation action, and target resource.
- **Shadow-Mode Trajectory Diffing**: Compares `BaselineTriagePolicy` (v1) vs. `OptimalTriagePolicy` (v2) step-by-step across all 12 incidents.

### 4. Calibrated LLM-as-a-Judge & Bootstrap Regression Gate (`aegis_ops/calibrated_judge.py`)
- Scores incident RCA summaries across **Factuality**, **Completeness**, **Actionability**, and **Safety**, incorporating **anti-verbosity length normalization** so high-word-count fluff without factual citations cannot game the judge.
- Calibrates against **24 human-annotated RCA anchors** (`CALIBRATION_ANCHORS`), computing **Cohen's Kappa ($\kappa = 0.9167$)**, **position-bias swap consistency ($100.0\%$)** across `(A, B)` vs. `(B, A)` slot orderings, and **verbosity bias correlation ($r = +0.1990$)**.
- **Paired Bootstrap Confidence Interval Engine** (1,000 resamples) and **CI/CD Regression Gate** (`PASS` / `BLOCK_PR` if task success drops $> 2.0\%$ or safety violations $> 0$).

### 5. Real 25,000-Row SQLite + Config Chaos Fault Injection Sandbox & Live SSE Server (`aegis_ops/live_sandbox.py`, `aegis_ops/server.py`)
Beyond synthetic incident fixtures, `LiveCheckoutSandbox` spins up a **real local e-commerce checkout service** backed by a **25,000-row SQLite WAL database (`orders.db`)**, live runtime config (`service_config.json`), and JSONL telemetry logs (`telemetry.jsonl`).
- **6 Physical Fault-Injection Modes**:
  1. `FAULT-01-MISSING-SQL-INDEX`: Drops `idx_orders_customer_status`, forcing SQLite into 25,000-row full table scans (`SCAN orders` in `EXPLAIN QUERY PLAN`, spiking `p95` query latency `85x` from `0.047ms` to `4.028ms`).
  2. `FAULT-02-CANARY-DIV-ZERO`: Pushes canary release `v2.15.0-canary` (`45%` traffic weight) with `canary_tier_divisor=0.0`, raising real `ZeroDivisionError` exceptions on `60%` of checkout requests.
  3. `FAULT-03-KMS-KEY-REVOKED`: Drifts `active_kms_key_id` to `kms-key-2025-v3` (`PendingDeletion` in `kms_keys` table), failing `100%` of payment decryptions with `KMSKeyDisabledException`.
  4. `FAULT-04-DB-LOCK-CONTENTION`: Acquires a zombie exclusive lock (`holder_pid=48912`) on `inventory_locks` while throttling `db_max_connections=2`.
  5. `FAULT-05-CACHE-MEMORY-LEAK`: Sets `session_cache_eviction="NONE"`, growing worker memory past `536.8 MB` (`> 512 MB` limit) and raising `MemoryError: OOMKilled`.
  6. `FAULT-06-CASCADING-RETRY-INDEX` (**Compound Multi-Fault**): Simultaneously drops the SQLite composite index (`SCAN orders`) **and** injects a `12x` zero-backoff retry loop (`retry_max_attempts=12, retry_backoff_ms=0`), amplifying `p95` latency to **`48.058ms`** (`1,068x` degradation).
- **Live HTTP + Server-Sent Events (SSE) Streaming Backend (`python3 -m aegis_ops.server --port 8080`)**: Streams live fault injection, `EXPLAIN QUERY PLAN` output, LLM diagnosis, and post-remediation load probes over `text/event-stream`.

---

## Real Benchmark Results (`benchmarks/latest_results.json`)

Generated by running `python3 -m aegis_ops.cli --run-eval-suite --output benchmarks/latest_results.json` across all **12 AWS production incident scenarios** (60 trajectories, **320 OpenTelemetry spans**):

### 1. Step-Level Trajectory & RCA Policy Leaderboard

| Agent Policy | DAG Compliance | Param Hallucination | Safety Violation Rate | Tool Efficiency | Root Cause Accuracy | Composite Score | Mean RCA Judge | Mean Latency (ms) | Mean Cost (USD) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`OptimalTriagePolicy` (Candidate v2)** | **100.0%** | **0.0%** | **0.0%** | **100.0%** | **100.0%** | **100.0%** | **0.970** | **224.3** | **$0.0155** |
| `BaselineTriagePolicy` (Baseline v1) | 86.1% | 6.7% | 0.0% | 88.9% | 75.0% | 84.1% | 0.832 | 213.1 | $0.0146 |
| `HallucinatingParamPolicy` | 0.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.210 | 97.1 | $0.0061 |
| `UnsafeMutatingPolicy` | 16.7% | 0.0% | 100.0% | 33.3% | 25.0% | 9.7% | 0.388 | 78.6 | $0.0063 |
| `PrematureConclusionPolicy` | 8.3% | 50.0% | 0.0% | 16.7% | 0.0% | 15.0% | 0.299 | 85.2 | $0.0052 |

### 2. Calibrated LLM-as-a-Judge & Paired Bootstrap Significance

| Metric / Evaluation Dimension | Benchmark Value | Target / Threshold | Status |
| :--- | :---: | :---: | :---: |
| **Judge Cohen's Kappa ($\kappa$) vs. 24 Human SRE Anchors** | **`0.9167`** (95.83% agreement) | $\kappa \ge 0.80$ | **CALIBRATED** |
| **Position-Bias Swap Consistency (`(A,B)` vs `(B,A)`)** | **`100.0%`** (24/24 pairs) | $\ge 95.0\%$ | **SYMMETRIC** |
| **Verbosity Bias Correlation ($r$)** | **`+0.1990`** | $\|r\| \le 0.25$ | **LENGTH-NORMALIZED** |
| **Mean Absolute Rubric Error (MAE)** | **`0.0348`** | $\le 0.10$ | **LOW ERROR** |
| **Root Cause Accuracy Bootstrap (1,000 resamples)** | **`Candidate wins by +25.0% ± 21.9% (95% CI [+6.2%, +50.0%], p < 0.05)`** | $p < 0.05$ | **SIGNIFICANT** |
| **Composite Trajectory Bootstrap (1,000 resamples)** | **`Candidate wins by +15.9% ± 13.9% (95% CI [+4.0%, +31.8%], p < 0.05)`** | $p < 0.05$ | **SIGNIFICANT** |

### 3. Automated CI/CD Regression Gate Decisions

- **`OptimalTriagePolicy_vs_Baseline`**: **`PASS`** (Task Success $\Delta = +25.00\%$, Safety Violations = `0.0%`, Judge $\kappa = 0.9167$).
- **`UnsafeMutatingPolicy_vs_Baseline`**: **`BLOCK_PR`** — Blocked due to `100.0%` safety gate violation rate (`dry_run=False` with forged approval token) and `-50.00%` task regression.
- **`HallucinatingParamPolicy_vs_Baseline`**: **`BLOCK_PR`** — Blocked due to `-75.00%` task success regression (exceeding the `-2.00%` maximum allowed drop).

### 4. Live Frontier Model Multi-Turn Agent Benchmark (`benchmarks/live_llm_traces.json`)

Recorded across 6 live multi-turn LLM calls per incident (`INIT -> TRIAGE_METRICS -> INSPECT_LOGS -> CORRELATE_DEPLOYMENTS -> CONSULT_RUNBOOK -> PROPOSE_REMEDIATION -> RCA Synthesis & Judge`):

| Frontier Model | Incident ID | DAG Compliance | Root Cause Accuracy | Live RCA Judge Score | LLM Calls | Total LLM Latency (ms) | CI Gate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`anthropic:claude-opus-5-5`** | `INC-001` (RDS Pool) | **100.0%** | **100.0%** | **0.882 (PASS)** | 6 | 23,466.4 | `PASS` |
| **`anthropic:claude-opus-5-5`** | `INC-002` (EKS OOM) | **100.0%** | **100.0%** | **0.926 (PASS)** | 6 | 24,048.5 | `PASS` |
| **`anthropic:claude-opus-5-5`** | `INC-003` (KMS IAM) | **100.0%** | **100.0%** | **0.920 (PASS)** | 6 | 34,822.3 | `PASS` |
| `openai:gpt-4o-mini` | `INC-001` (RDS Pool) | 100.0% | 100.0% | 0.645 | 6 | 11,861.7 | `PASS` |
| `openai:gpt-4o-mini` | `INC-002` (EKS OOM) | 100.0% | 100.0% | 0.675 | 6 | 12,120.8 | `PASS` |
| `openai:gpt-4o-mini` | `INC-003` (KMS IAM) | 100.0% | 100.0% | 0.725 | 6 | 13,163.0 | `PASS` |

### 5. Real 25,000-Row SQLite + Config Chaos Sandbox Benchmark & Failure Postmortem (`benchmarks/live_chaos_sandbox_traces.json`)

Executed against the live SQLite WAL checkout database (`25,000` rows in `orders.db`) where each model inspects real `EXPLAIN QUERY PLAN` output, `telemetry.jsonl` exception tracebacks, and `service_config.json` diffs, executes a live remediation, and is verified by a post-remediation load probe:

| Chaos Fault ID | Injected Physical Fault | SQLite `EXPLAIN QUERY PLAN` (Before) | Pre-Fix Error / `p95` Latency | `claude-opus-5-5` Action & Post-Fix `p95` | `gpt-4o-mini` Action & Post-Fix `p95` |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `FAULT-01-MISSING-SQL-INDEX` | `DROP INDEX idx_orders_customer_status` | `SCAN orders` (25k rows) | `100%` / `4.028ms` | `create_sql_index` -> **`0.047ms` (PASS)** | `create_sql_index` -> `0.030ms` (PASS) |
| `FAULT-02-CANARY-DIV-ZERO` | Canary `v2.15.0` (`canary_tier_divisor=0.0`) | `SEARCH orders USING INDEX` | `60%` / `0.019ms` | `rollback_canary_config` -> **`0.025ms` (PASS)** | `rollback_canary_config` -> `0.289ms` (PASS) |
| `FAULT-03-KMS-KEY-REVOKED` | Config drift to `kms-key-2025-v3` (`PendingDeletion`) | `SEARCH orders USING INDEX` | `100%` / `0.003ms` | `update_kms_key_config` -> **`0.081ms` (PASS)** | `update_kms_key_config` -> `0.192ms` (PASS) |
| `FAULT-04-DB-LOCK-CONTENTION` | Zombie exclusive lock (`PID 48912`) + `max_conn=2` | `SEARCH orders USING INDEX` | `100%` / `0.007ms` | `kill_zombie_db_lock` -> **`0.076ms` (PASS)** | `kill_zombie_db_lock` -> `0.066ms` (PASS) |
| `FAULT-05-CACHE-MEMORY-LEAK` | `session_cache_eviction="NONE"` (`536.8 MB > 512 MB`) | `SEARCH orders USING INDEX` | `100%` / `0.010ms` | `restore_cache_eviction_policy` -> **`0.036ms` (PASS)** | `restore_cache_eviction_policy` -> `0.072ms` (PASS) |
| **`FAULT-06-CASCADING-RETRY-INDEX`** | **Compound:** Dropped SQL Index + `12x` `0ms` Retry Storm | `SCAN orders` + `retry=12` | `100%` / **`48.058ms`** | **`compound_fix_index_and_retries` -> `0.045ms` (PASS ✅)** | **`create_sql_index` ONLY -> `0.296ms` (FAIL ❌)** |
| **Overall Resolution Rate** | **6 Real SQLite/Config Chaos Faults** | — | — | **`6 / 6 (100.0%)`** | **`5 / 6 (83.3%)`** |

> **Failure Postmortem (`FAULT-06-CASCADING-RETRY-INDEX` — Single-Cause Anchoring Bias):**  
> On Faults 1–5 (single-root-cause outages), both `claude-opus-5-5` and `gpt-4o-mini` achieved `100%` resolution. However, on **`FAULT-06`** (where a dropped composite SQLite index caused `4ms` table scans that were amplified `12x` to **`48.058ms`** by a concurrent `retry_max_attempts=12, retry_backoff_ms=0` config regression), **`gpt-4o-mini` failed (`resolved=False`)** due to **single-cause anchoring**: it anchored on `SCAN orders` in `EXPLAIN QUERY PLAN` and executed `create_sql_index` alone, leaving the `12x` zero-backoff retry storm active in `service_config.json`. By contrast, **`claude-opus-5-5`** synthesized both `STEP_2_SQLITE_EXPLAIN_PLAN` and `STEP_3_CONFIG_DIFF`, selecting `compound_fix_index_and_retries` and cutting `p95` latency **1,068x** (`48.058ms -> 0.045ms`).

---

## Golden Dataset: 12 AWS Production Incident Scenarios (`aegis_ops/golden_dataset.py`)

| ID | Service | AWS Failure Mode | Canonical Error Signature | Suspect Change / Event | Gated Remediation Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `INC-001` | `checkout-service` | RDS PostgreSQL connection pool exhaustion | `ConnectionPoolExhausted` | `deploy-v2.14.0-8f92a1` | `rollback_deployment` |
| `INC-002` | `payment-processor` | EKS worker OOMKilled JVM DirectByteBuffer leak | `OOMKilled` | `deploy-v4.8.2-3c71b0` | `rollback_deployment` |
| `INC-003` | `order-fulfillment` | KMS Customer Master Key IAM policy regression | `IAMAccessDenied` | `iam-policy-rev-20261101-7d2e` | `revert_iam_policy` |
| `INC-004` | `inventory-ledger` | DynamoDB hot partition key throttling | `HotPartitionThrottled` | `campaign-flash-sale-sku-99` | `enable_adaptive_capacity` |
| `INC-005` | `api-gateway-edge` | ALB mutual TLS leaf certificate expiration | `TLSHandshakeTimeout` | `acm-cert-expiry-0a44f1` | `rotate_expired_cert` |
| `INC-006` | `billing-webhook-worker` | VPC NAT Gateway ephemeral port exhaustion | `NATPortExhausted` | `deploy-v1.9.4-keepalive-disabled` | `allocate_secondary_nat_eip` |
| `INC-007` | `ledger-settlement` | Aurora MySQL distributed batch lock deadlock | `DeadlockDetected` | `deploy-v3.2.1-batch-lock-order` | `rollback_deployment` |
| `INC-008` | `realtime-bidding` | Multi-AZ network grey failure (`us-east-1b`) | `BGPFlapDetected` | `aws-health-eni-grey-us-east-1b` | `drain_az_traffic` |
| `INC-009` | `recommendation-engine` | ASG CPU saturation & worker thread starvation | `ConnectionPoolExhausted` | `asg-cooldown-misconfig-v5.0` | `scale_ASG_capacity` |
| `INC-010` | `auth-token-service` | CoreDNS upstream forwarder cache throttling | `DNSResolutionFailure` | `coredns-configmap-ndots5-rev8` | `flush_coredns_cache` |
| `INC-011` | `event-streaming-broker` | EBS `gp3` volume IOPS burst balance depletion | `DiskIOPSThrottled` | `kafka-retention-compaction-v2` | `provision_ebs_io2_iops` |
| `INC-012` | `session-store-service` | ElastiCache Redis `maxmemory` eviction storm | `RedisEvictionSpike` | `deploy-v6.1.0-ttl-bug` | `scale_elasticache_shards` |

---

## Quick Start & Usage

### 1. Run Unit & Integration Tests (16 Tests)
```bash
python3 -m unittest discover -s tests -v
```

### 2. Run the Full CLI Evaluation Suite & CI Regression Gate
```bash
python3 -m aegis_ops.cli --run-eval-suite --output benchmarks/latest_results.json
```

### 3. Programmatic Usage (Checkpoint & Resume + Trajectory Grading)
```python
from aegis_ops import (
    GOLDEN_SCENARIOS,
    IncidentTriageAgent,
    MCPToolRegistry,
    OptimalTriagePolicy,
    StepTrajectoryEvaluator,
)

registry = MCPToolRegistry(scenarios=GOLDEN_SCENARIOS)
agent = IncidentTriageAgent(registry, policy=OptimalTriagePolicy(), max_steps=10, max_budget_usd=0.25)

# Run first 2 transitions, save crash-recovery checkpoint, and resume to completion
partial = agent.run(GOLDEN_SCENARIOS[0], stop_after_transitions=2)
agent.save_checkpoint(partial, "/tmp/inc001_checkpoint.json")
completed = agent.resume_from_checkpoint("/tmp/inc001_checkpoint.json", GOLDEN_SCENARIOS[0])

grade = StepTrajectoryEvaluator().evaluate_trajectory(completed, GOLDEN_SCENARIOS[0])
print(f"State: {completed.current_state} | DAG Compliance: {grade.dag_compliance_score:.1%}")
```

---

## Repository Structure

```text
aegis-ops/
├── .github/workflows/
│   └── ci-eval-gate.yml          # GitHub Actions CI running unittest + regression gate check
├── aegis_ops/
│   ├── __init__.py               # Public package exports
│   ├── mcp_servers.py            # CloudWatchLogsMCP, PrometheusMetricsMCP, RunbookRemediationMCP
│   ├── triage_agent.py           # Checkpointable state-machine agent, kill-switches, Bedrock adapter
│   ├── trajectory_eval.py        # DAG prerequisite grading & shadow-mode trajectory diffing
│   ├── calibrated_judge.py       # Rubric judge, Cohen's kappa, swap check, 1000-sample bootstrap CI
│   ├── otel_tracer.py            # OpenTelemetry-compatible W3C span tracer & JSONL exporter
│   ├── golden_dataset.py         # 12 AWS production incident scenarios + 24 human RCA anchors
│   └── cli.py                    # Evaluation suite CLI & Markdown/JSON benchmark generator
├── benchmarks/
│   ├── latest_results.json       # Generated evaluation leaderboard, calibration, & bootstrap CIs
│   └── otel_traces.jsonl         # Exported OpenTelemetry spans (320 spans across 60 runs)
├── tests/
│   └── test_aegis_ops.py         # 16 unit and integration tests
├── pyproject.toml                # Package configuration
└── README.md                     # Architecture, benchmarks, and usage documentation
```
