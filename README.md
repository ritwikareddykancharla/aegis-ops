# AegisOps — CloudWatch & Prometheus Incident Triage Agent

> **Live AWS Endpoint (`us-west-2` Lambda Function URL):** [https://ikvs4adub6fg2ipcn7kxxllgsm0thcja.lambda-url.us-west-2.on.aws/](https://ikvs4adub6fg2ipcn7kxxllgsm0thcja.lambda-url.us-west-2.on.aws/)  
> **Health Check:** `https://ikvs4adub6fg2ipcn7kxxllgsm0thcja.lambda-url.us-west-2.on.aws/api/health`  
> **Live API Call:** `curl -s -X POST https://ikvs4adub6fg2ipcn7kxxllgsm0thcja.lambda-url.us-west-2.on.aws/api/run -H 'Content-Type: application/json' -d '{}'`  
> **Interactive Trace Player:** [https://ritwikareddykancharla.github.io/aegis-ops/](https://ritwikareddykancharla.github.io/aegis-ops/)

**AegisOps** investigates production service alerts by walking CloudWatch logs, Prometheus metrics, recent deployments, and runbooks in an explicit diagnostic sequence—preventing agents from guessing root causes, skipping log checks, or triggering unapproved rollbacks during an outage (`+25.0%` root-cause accuracy across 12 AWS outage scenarios; `95.8%` agreement with human SRE postmortem scores).

---

## What Problem This Solves

- **Unstructured tool-calling loops jump straight to guesswork or unsafe rollbacks:** Free-form agents often propose a service restart before checking recent deployments or error logs, or execute mutating commands without approval. Enforcing an explicit investigation state machine (`TRIAGE_METRICS -> INSPECT_LOGS -> CORRELATE_DEPLOYMENTS -> CONSULT_RUNBOOK -> PROPOSE_REMEDIATION`) with hard step/cost limits improves root-cause accuracy by **+25.0%** ($p < 0.05$) across 12 simulated AWS outages while gating **100%** of write/rollback actions on human approval.
- **Final-answer grading misses broken intermediate steps:** An agent can guess the right root cause while hallucinating tool arguments or skipping log verification. Checking the tool-call sequence against per-incident prerequisite rules catches out-of-order actions, schema errors, and unauthorized mutation attempts automatically.
- **Uncalibrated LLM graders reward verbose prose and prompt order:** Naive rubric prompts prefer longer postmortems and change their winner when candidate A and B are swapped. Normalizing for verbosity and calibrating against 24 human SRE-scored postmortems reaches **95.8%** agreement ($\kappa = 0.917$) and **100%** consistency under `(A, B)` vs. `(B, A)` prompt-order swaps.

---

## System Architecture

> **Excalidraw Source:** [`docs/architecture.excalidraw`](docs/architecture.excalidraw)

![AegisOps Architecture Diagram](docs/architecture.svg)

## How It Works

1. **MCP Tool Servers (`aegis_ops/mcp_servers.py`)**  
   Implements three schema-validated MCP servers with structured error codes and per-call OpenTelemetry latency/token spans (`aegis_ops/otel_tracer.py`):
   - `CloudWatchLogsMCP`: Queries structured error logs by service, severity, and trace window, grouping stack traces into 12 failure signatures (`ConnectionPoolExhausted`, `OOMKilled`, `IAMAccessDenied`, `HotPartitionThrottled`, `TLSHandshakeTimeout`, `NATPortExhausted`, `DeadlockDetected`, `BGPFlapDetected`, `DNSResolutionFailure`, `DiskIOPSThrottled`, `RedisEvictionSpike`, `KMSKeyDisabled`).
   - `PrometheusMetricsMCP`: Reads golden signals (`p99_latency_ms`, `error_rate_pct`, `cpu_saturation_pct`, `memory_saturation_pct`, `db_pool_utilization_pct`) and correlates suspect releases via `get_recent_deployments`.
   - `RunbookRemediationMCP`: Fetches standard operating procedures and blocks `execute_remediation(dry_run=False)` unless a valid human-approval token is supplied (`SAFETY_GATE_VIOLATION`).

2. **Checkpointable State-Machine Agent (`aegis_ops/triage_agent.py`)**  
   Steps deterministically through metrics triage, log inspection, deployment correlation, and runbook lookup, supporting crash-recovery checkpointing (`save_checkpoint` / `resume_from_checkpoint`), step-count and USD spend caps, and an AWS Bedrock Converse `toolConfig` client (`BedrockAgentClient`).

3. **Step-Order Trajectory Checker & Rubric Grader (`aegis_ops/trajectory_eval.py`, `aegis_ops/calibrated_judge.py`)**  
   - Verifies required tool calls and prerequisite ordering (`must_precede`), invalid tool parameters, tool efficiency, and safety-gate violations across 12 AWS outage scenarios (`aegis_ops/golden_dataset.py`).
   - Scores root-cause summaries on factuality, completeness, actionability, and safety with length normalization, paired 1,000-resample bootstrap confidence intervals, and a CI PR check (`PASS` / `BLOCK_PR`).

4. **Local SQLite & Config Fault-Injection Sandbox (`aegis_ops/live_sandbox.py`, `aegis_ops/server.py`)**  
   Runs a local checkout service backed by a 25,000-row SQLite WAL database (`orders.db`) and injects 6 real failure modes (dropped composite SQL index causing full table scans, canary divide-by-zero release, disabled KMS key config drift, zombie table lock, unbounded session cache growth, and a combined missing-index + 12x zero-backoff retry storm) verified by post-fix load probes.

---

## Benchmark Results

Generated via `python3 -m aegis_ops.cli --run-eval-suite --output benchmarks/latest_results.json` across 12 AWS incident scenarios (60 runs, 320 OpenTelemetry spans):

| Evaluation Metric | Candidate Agent (`v2`) | Baseline Agent (`v1`) | Delta / Statistical Check |
| :--- | :---: | :---: | :---: |
| **Root-Cause Diagnosis Accuracy (12 AWS Outages)** | **100.0%** | 75.0% | **+25.0%** (`95% CI [+6.2%, +50.0%]`, $p < 0.05$) |
| **Prerequisite Step-Order Compliance** | **100.0%** | 86.1% | **+13.9%** |
| **Invalid Tool Parameter Rate** | **0.0%** | 6.7% | **-6.7%** |
| **Write/Rollback Human-Approval Gate Enforcement** | **100.0%** (`0%` unapproved writes) | 100.0% | Blocks `UnsafeMutatingPolicy` (`BLOCK_PR`) |
| **Rubric Grader Agreement with Human SRE Scores** | **95.8%** ($\kappa = 0.917$) | — | 24 human-scored postmortems (`MAE = 0.035`) |
| **A/B Prompt-Order Swap Consistency** | **100.0%** (`24/24` pairs) | — | Length-normalized verbosity correlation $r = +0.20$ |

---

## Quickstart

Requires Python 3.11+ with zero external package dependencies:

```bash
# 1. Run all 16 unit and integration tests
python3 -m unittest discover -s tests -v

# 2. Run the 12-incident evaluation suite and CI regression check
python3 -m aegis_ops.cli --run-eval-suite --output benchmarks/latest_results.json
```

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

partial = agent.run(GOLDEN_SCENARIOS[0], stop_after_transitions=2)
agent.save_checkpoint(partial, "/tmp/inc001_checkpoint.json")
completed = agent.resume_from_checkpoint("/tmp/inc001_checkpoint.json", GOLDEN_SCENARIOS[0])

grade = StepTrajectoryEvaluator().evaluate_trajectory(completed, GOLDEN_SCENARIOS[0])
print(f"State: {completed.current_state} | Step-Order Score: {grade.dag_compliance_score:.1%}")
```
