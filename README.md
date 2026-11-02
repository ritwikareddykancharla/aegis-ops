# AegisOps — Autonomous DevOps Incident Triage Agent, Step-Level Trajectory Grading Engine & Calibrated LLM-as-a-Judge

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

---

## Resume Bullets (Tailored for AWS DevOps Agent & Eva Data Center GenAI Roles)

1. **Autonomous DevOps Incident Triage Agent & MCP Tooling (AWS DevOps Agent #1 / Eva GenAI #2):** Engineered `AegisOps`, a checkpointable finite-state-machine incident triage agent (`INIT -> TRIAGE_METRICS -> INSPECT_LOGS -> CORRELATE_DEPLOYMENTS -> CONSULT_RUNBOOK -> PROPOSE_REMEDIATION`) integrated with 3 JSON-Schema-validated MCP servers (`CloudWatchLogsMCP`, `PrometheusMetricsMCP`, `RunbookRemediationMCP`) and hard approval-token safety gates on mutating remediations.
2. **Step-Level DAG Trajectory Grading Engine:** Built a deterministic Directed Acyclic Graph (DAG) trajectory evaluator measuring prerequisite ordering compliance (`must_precede`), parameter hallucination rate, premature remediation detection, and tool efficiency across 12 AWS production failure modes (RDS pool exhaustion, EKS `OOMKilled`, KMS IAM regression, DynamoDB hot partition, ALB mTLS expiry, NAT port exhaustion).
3. **Calibrated LLM-as-a-Judge & Anti-Verbosity Rubric:** Designed a multi-dimensional RCA Judge (Factuality, Completeness, Actionability, Safety) calibrated against 24 human-annotated SRE anchors, achieving **Cohen's $\kappa = 0.9167$** (95.8% agreement), **100.0% position-bias swap consistency**, and length-normalized verbosity bias correlation ($r = +0.199$).
4. **Statistical Significance & CI/CD Regression Gating:** Implemented shadow-mode trajectory diffing, OpenTelemetry W3C span tracing (latency, token count, USD cost per step), and a 1,000-resample paired bootstrap CI gate that verified a **+25.0% ± 21.9% ($p < 0.05$)** root-cause accuracy gain over baseline while automatically blocking PRs on >2% accuracy drops or any safety-gate violation.
