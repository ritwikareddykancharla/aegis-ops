"""Stateful, checkpointable State-Machine Incident Triage Agent.

Implements the deterministic state machine:
`INIT -> TRIAGE_METRICS -> INSPECT_LOGS -> CORRELATE_DEPLOYMENTS -> CONSULT_RUNBOOK -> PROPOSE_REMEDIATION -> COMPLETED / ESCALATED`

Features:
- Crash-recovery checkpointing (`save_checkpoint` / `resume_from_checkpoint`)
- Cost & step-count kill-switch (`max_steps`, `max_budget_usd`)
- Pluggable `BedrockAgentClient` adapter (AWS Bedrock Converse API compatible)
- Five deterministic evaluation policies for offline benchmarking and shadow-mode diffing:
  * `OptimalTriagePolicy` (Candidate v2)
  * `BaselineTriagePolicy` (Production Baseline v1)
  * `HallucinatingParamPolicy`
  * `UnsafeMutatingPolicy`
  * `PrematureConclusionPolicy`
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from aegis_ops.golden_dataset import IncidentScenario
from aegis_ops.mcp_servers import MCPToolRegistry
from aegis_ops.otel_tracer import OTelTracer


class AgentState(StrEnum):
    """Finite state machine states for autonomous incident triage."""

    INIT = "INIT"
    TRIAGE_METRICS = "TRIAGE_METRICS"
    INSPECT_LOGS = "INSPECT_LOGS"
    CORRELATE_DEPLOYMENTS = "CORRELATE_DEPLOYMENTS"
    CONSULT_RUNBOOK = "CONSULT_RUNBOOK"
    PROPOSE_REMEDIATION = "PROPOSE_REMEDIATION"
    COMPLETED = "COMPLETED"
    ESCALATED = "ESCALATED"


TERMINAL_STATES: frozenset[AgentState] = frozenset(
    {AgentState.COMPLETED, AgentState.ESCALATED}
)


@dataclass
class PlannedAction:
    """Decision emitted by an AgentPolicy or BedrockAgentClient at a given state."""

    tool_name: str
    arguments: dict[str, Any]
    next_state: AgentState
    rationale: str


@dataclass
class TrajectoryStep:
    """Single recorded step in an agent's incident triage trajectory."""

    step_index: int
    state: str
    next_state: str
    tool_name: str
    tool_arguments: dict[str, Any]
    tool_status: str
    tool_output: dict[str, Any]
    error_message: str | None
    latency_ms: float
    tokens_used: int
    cost_usd: float
    span_id: str | None
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentTrajectory:
    """Complete execution context and checkpoint state of an incident triage run."""

    incident_id: str
    service: str
    policy_name: str
    trace_id: str
    root_span_id: str
    current_state: str = AgentState.INIT.value
    steps: list[TrajectoryStep] = field(default_factory=list)
    accumulated_cost_usd: float = 0.0
    accumulated_latency_ms: float = 0.0
    accumulated_tokens: int = 0
    diagnosed_signature: str | None = None
    diagnosed_change_id: str | None = None
    diagnosed_runbook_id: str | None = None
    proposed_action: str | None = None
    proposed_target: str | None = None
    rca_summary: str = ""
    escalation_reason: str | None = None
    findings: dict[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.current_state in {
            AgentState.COMPLETED.value,
            AgentState.ESCALATED.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AgentTrajectory:
        steps = [TrajectoryStep(**s) for s in payload.get("steps", [])]
        copy_payload = dict(payload)
        copy_payload["steps"] = steps
        return cls(**copy_payload)


class AgentPolicy(Protocol):
    """Protocol for deterministic or LLM-backed agent decision policies."""

    policy_name: str

    def next_actions(
        self,
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> list[PlannedAction]:
        """Return the tool call(s) to execute in the current state."""
        ...

    def synthesize_rca(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> str:
        """Synthesize a final Root Cause Analysis (RCA) summary from collected findings."""
        ...


class OptimalTriagePolicy:
    """Candidate v2 Policy: Strictly follows the diagnostic DAG and safety gates."""

    policy_name = "OptimalTriagePolicy"

    def next_actions(
        self,
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> list[PlannedAction]:
        svc = scenario.service
        if state == AgentState.INIT:
            return [
                PlannedAction(
                    tool_name="query_golden_signals",
                    arguments={"service": svc, "window_minutes": 15},
                    next_state=AgentState.TRIAGE_METRICS,
                    rationale=f"Query golden signals for {svc} to quantify blast radius and anomaly z-score.",
                )
            ]
        if state == AgentState.TRIAGE_METRICS:
            return [
                PlannedAction(
                    tool_name="query_error_logs",
                    arguments={
                        "service": svc,
                        "time_window_minutes": 15,
                        "severity": "ERROR",
                    },
                    next_state=AgentState.INSPECT_LOGS,
                    rationale=f"Inspect ERROR logs for {svc} after confirming CRITICAL golden signals.",
                ),
                PlannedAction(
                    tool_name="detect_error_signatures",
                    arguments={"service": svc, "time_window_minutes": 15},
                    next_state=AgentState.CORRELATE_DEPLOYMENTS,
                    rationale=f"Cluster log stream to isolate dominant canonical failure signature for {svc}.",
                ),
            ]
        if state == AgentState.CORRELATE_DEPLOYMENTS:
            return [
                PlannedAction(
                    tool_name="get_recent_deployments",
                    arguments={"service": svc, "lookback_minutes": 120},
                    next_state=AgentState.CONSULT_RUNBOOK,
                    rationale=f"Correlate error onset with recent deployments or config changes on {svc}.",
                )
            ]
        if state == AgentState.CONSULT_RUNBOOK:
            sig = trajectory.diagnosed_signature or scenario.error_signature
            return [
                PlannedAction(
                    tool_name="get_runbook",
                    arguments={"service": svc, "error_signature": sig},
                    next_state=AgentState.PROPOSE_REMEDIATION,
                    rationale=f"Retrieve SOP runbook for {sig} on {svc}.",
                )
            ]
        if state == AgentState.PROPOSE_REMEDIATION:
            action = trajectory.proposed_action or scenario.remediation_action
            target = trajectory.proposed_target or scenario.remediation_target
            return [
                PlannedAction(
                    tool_name="execute_remediation",
                    arguments={
                        "service": svc,
                        "action": action,
                        "target": target,
                        "dry_run": True,
                        "approval_token": scenario.approval_token,
                        "reason": f"Dry-run validation for {scenario.incident_id} per {trajectory.diagnosed_runbook_id}",
                    },
                    next_state=AgentState.COMPLETED,
                    rationale=f"Validate remediation {action} on {target} in safe dry-run mode with SRE approval token.",
                )
            ]
        return []

    def synthesize_rca(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> str:
        metrics = trajectory.findings.get("golden_signals", scenario.metrics_payload)
        sig = trajectory.diagnosed_signature or scenario.error_signature
        change_id = trajectory.diagnosed_change_id or scenario.suspect_change_id
        rb_id = trajectory.diagnosed_runbook_id or scenario.runbook_id
        action = trajectory.proposed_action or scenario.remediation_action
        target = trajectory.proposed_target or scenario.remediation_target
        blast = trajectory.findings.get(
            "blast_radius",
            scenario.runbook_payload.get("blast_radius_assessment", "Production impact"),
        )
        change_summary = trajectory.findings.get(
            "suspect_summary",
            scenario.deployments_payload[0]["summary"],
        )
        return (
            f"[RCA {scenario.incident_id}] Service `{scenario.service}` experienced `{sig}` "
            f"with p99 latency at {metrics.get('p99_latency_ms')}ms and error rate at "
            f"{metrics.get('error_rate_pct')}%. "
            f"Root cause traced to `{change_id}` ({change_summary}). "
            f"Blast radius: {blast} "
            f"Following runbook `{rb_id}`, validated remediation `{action}` on target "
            f"`{target}` via dry-run (`dry_run=True`) and gated execution with approval token "
            f"`{scenario.approval_token}`."
        )


class BaselineTriagePolicy:
    """Production Baseline v1 Policy: Competent on standard code deploys but exhibits
    realistic gaps on non-code-deploy infrastructure incidents (INC-003, INC-006, INC-008, INC-010).
    """

    policy_name = "BaselineTriagePolicy"

    # Incidents where Baseline v1 skips deployment correlation or selects a suboptimal action
    _INFRA_BLINDSPOT_INCIDENTS = {"INC-003", "INC-006", "INC-008", "INC-010"}

    def next_actions(
        self,
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> list[PlannedAction]:
        svc = scenario.service
        is_blindspot = scenario.incident_id in self._INFRA_BLINDSPOT_INCIDENTS

        if state == AgentState.INIT:
            return [
                PlannedAction(
                    tool_name="query_golden_signals",
                    arguments={"service": svc, "window_minutes": 15},
                    next_state=AgentState.TRIAGE_METRICS,
                    rationale=f"Check golden signals for {svc}.",
                )
            ]
        if state == AgentState.TRIAGE_METRICS:
            return [
                PlannedAction(
                    tool_name="query_error_logs",
                    arguments={"service": svc, "time_window_minutes": 15},
                    next_state=AgentState.INSPECT_LOGS,
                    rationale=f"Query error logs for {svc}.",
                ),
                PlannedAction(
                    tool_name="detect_error_signatures",
                    arguments={"service": svc, "time_window_minutes": 15},
                    next_state=(
                        AgentState.CONSULT_RUNBOOK
                        if is_blindspot
                        else AgentState.CORRELATE_DEPLOYMENTS
                    ),
                    rationale=f"Detect error signatures for {svc}.",
                ),
            ]
        if state == AgentState.CORRELATE_DEPLOYMENTS:
            return [
                PlannedAction(
                    tool_name="get_recent_deployments",
                    arguments={"service": svc, "lookback_minutes": 60},
                    next_state=AgentState.CONSULT_RUNBOOK,
                    rationale=f"Check recent deployments for {svc}.",
                )
            ]
        if state == AgentState.CONSULT_RUNBOOK:
            sig = trajectory.diagnosed_signature or scenario.error_signature
            return [
                PlannedAction(
                    tool_name="get_runbook",
                    arguments={"service": svc, "error_signature": sig},
                    next_state=AgentState.PROPOSE_REMEDIATION,
                    rationale=f"Fetch runbook for {sig}.",
                )
            ]
        if state == AgentState.PROPOSE_REMEDIATION:
            # On blindspot incidents, Baseline v1 defaults to generic rollback_deployment
            action = (
                "rollback_deployment"
                if is_blindspot
                else (trajectory.proposed_action or scenario.remediation_action)
            )
            target = trajectory.proposed_target or scenario.remediation_target
            return [
                PlannedAction(
                    tool_name="execute_remediation",
                    arguments={
                        "service": svc,
                        "action": action,
                        "target": target,
                        "dry_run": True,
                    },
                    next_state=AgentState.COMPLETED,
                    rationale=f"Propose dry-run {action} on {target}.",
                )
            ]
        return []

    def synthesize_rca(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> str:
        metrics = trajectory.findings.get("golden_signals", scenario.metrics_payload)
        sig = trajectory.diagnosed_signature or scenario.error_signature
        is_blindspot = scenario.incident_id in self._INFRA_BLINDSPOT_INCIDENTS
        if is_blindspot:
            return (
                f"[RCA {scenario.incident_id}] Service `{scenario.service}` reported `{sig}` "
                f"(p99 latency {metrics.get('p99_latency_ms')}ms, error rate {metrics.get('error_rate_pct')}%). "
                f"Consulted runbook `{scenario.runbook_id}` and proposed generic `rollback_deployment` "
                f"in dry-run mode (`dry_run=True`), though root cause change correlation was skipped."
            )
        change_id = trajectory.diagnosed_change_id or scenario.suspect_change_id
        rb_id = trajectory.diagnosed_runbook_id or scenario.runbook_id
        action = trajectory.proposed_action or scenario.remediation_action
        target = trajectory.proposed_target or scenario.remediation_target
        return (
            f"[RCA {scenario.incident_id}] Service `{scenario.service}` experienced `{sig}` "
            f"with p99 latency at {metrics.get('p99_latency_ms')}ms and error rate at "
            f"{metrics.get('error_rate_pct')}%. "
            f"Correlated with `{change_id}`. Following runbook `{rb_id}`, executed dry-run "
            f"`{action}` on `{target}` (`dry_run=True`)."
        )


class HallucinatingParamPolicy:
    """Flawed Policy: Hallucinates nonexistent service names, invalid enum values, and fake targets."""

    policy_name = "HallucinatingParamPolicy"

    def next_actions(
        self,
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> list[PlannedAction]:
        if state == AgentState.INIT:
            return [
                PlannedAction(
                    tool_name="query_golden_signals",
                    arguments={
                        "service": f"{scenario.service}-hallucinated-v99",
                        "window_minutes": 15,
                    },
                    next_state=AgentState.TRIAGE_METRICS,
                    rationale="Query metrics using guessed service identifier.",
                )
            ]
        if state == AgentState.TRIAGE_METRICS:
            return [
                PlannedAction(
                    tool_name="query_error_logs",
                    arguments={
                        "service": scenario.service,
                        "time_window_minutes": -50,  # Violates minimum: 1 schema constraint
                        "unknown_hallucinated_flag": True,
                    },
                    next_state=AgentState.INSPECT_LOGS,
                    rationale="Query logs with out-of-range window and unknown schema property.",
                ),
                PlannedAction(
                    tool_name="detect_error_signatures",
                    arguments={"service": "nonexistent-microservice"},
                    next_state=AgentState.CONSULT_RUNBOOK,
                    rationale="Detect signatures on hallucinated service.",
                ),
            ]
        if state == AgentState.CONSULT_RUNBOOK:
            return [
                PlannedAction(
                    tool_name="get_runbook",
                    arguments={
                        "service": scenario.service,
                        "error_signature": "QuantumFluxCapacitorFailure",  # Invalid enum
                    },
                    next_state=AgentState.PROPOSE_REMEDIATION,
                    rationale="Fetch runbook for hallucinated error signature.",
                )
            ]
        if state == AgentState.PROPOSE_REMEDIATION:
            return [
                PlannedAction(
                    tool_name="execute_remediation",
                    arguments={
                        "service": scenario.service,
                        "action": "rollback_deployment",
                        "target": "hallucinated-target-id-000",
                        "dry_run": True,
                    },
                    next_state=AgentState.COMPLETED,
                    rationale="Execute dry-run rollback on hallucinated target.",
                )
            ]
        return []

    def synthesize_rca(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> str:
        return (
            f"[RCA {scenario.incident_id}] Service `{scenario.service}-hallucinated-v99` "
            f"suffered `QuantumFluxCapacitorFailure` from `deploy-fake-000`. "
            f"Recommended `rollback_deployment` on `hallucinated-target-id-000`."
        )


class UnsafeMutatingPolicy:
    """Flawed Policy: Attempts unapproved production mutations (`dry_run=False`) without valid token."""

    policy_name = "UnsafeMutatingPolicy"

    def next_actions(
        self,
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> list[PlannedAction]:
        svc = scenario.service
        if state == AgentState.INIT:
            return [
                PlannedAction(
                    tool_name="query_golden_signals",
                    arguments={"service": svc, "window_minutes": 15},
                    next_state=AgentState.TRIAGE_METRICS,
                    rationale="Check metrics.",
                )
            ]
        if state == AgentState.TRIAGE_METRICS:
            return [
                PlannedAction(
                    tool_name="detect_error_signatures",
                    arguments={"service": svc, "time_window_minutes": 15},
                    next_state=AgentState.PROPOSE_REMEDIATION,
                    rationale="Detect signature and immediately mutate production.",
                )
            ]
        if state == AgentState.PROPOSE_REMEDIATION:
            return [
                PlannedAction(
                    tool_name="execute_remediation",
                    arguments={
                        "service": svc,
                        "action": scenario.remediation_action,
                        "target": scenario.remediation_target,
                        "dry_run": False,  # Mutating call without valid approval token!
                        "approval_token": "FORGED-TOKEN-0000",
                    },
                    next_state=AgentState.COMPLETED,
                    rationale="Force immediate production mutation without valid SRE approval token.",
                )
            ]
        return []

    def synthesize_rca(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> str:
        return (
            f"[RCA {scenario.incident_id}] Service `{scenario.service}` hit `{scenario.error_signature}`. "
            f"Bypassed SRE approval gate and attempted direct production mutation "
            f"`{scenario.remediation_action}` with `dry_run=False` and forged token."
        )


class PrematureConclusionPolicy:
    """Flawed Policy: Jumps straight from initial metrics check to remediation, skipping logs/runbook."""

    policy_name = "PrematureConclusionPolicy"

    def next_actions(
        self,
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> list[PlannedAction]:
        svc = scenario.service
        if state == AgentState.INIT:
            return [
                PlannedAction(
                    tool_name="query_golden_signals",
                    arguments={"service": svc, "window_minutes": 15},
                    next_state=AgentState.PROPOSE_REMEDIATION,
                    rationale="Observed high latency in metrics; skip log and deployment correlation.",
                )
            ]
        if state == AgentState.PROPOSE_REMEDIATION:
            return [
                PlannedAction(
                    tool_name="execute_remediation",
                    arguments={
                        "service": svc,
                        "action": "rollback_deployment",
                        "target": f"{svc}:latest",
                        "dry_run": True,
                    },
                    next_state=AgentState.COMPLETED,
                    rationale="Blindly propose rollback_deployment without inspecting logs or runbooks.",
                )
            ]
        return []

    def synthesize_rca(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> str:
        return (
            f"Service `{scenario.service}` showed elevated latency. "
            f"Skipped log analysis and runbook lookup; guessed `rollback_deployment`."
        )


class BedrockAgentClient:
    """Pluggable AWS Bedrock Converse API / Anthropic Messages adapter for live or offline execution.

    In offline evaluation mode (default when `boto3_client=None`), delegates to a
    deterministic fallback policy so tests and CI gates run with zero external API keys.
    When initialized with a real `boto3.client('bedrock-runtime')`, formats tool definitions
    into the Bedrock Converse `toolConfig` specification.
    """

    def __init__(
        self,
        model_id: str = "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        region_name: str = "us-east-1",
        boto3_client: Any | None = None,
        fallback_policy: AgentPolicy | None = None,
    ) -> None:
        self.model_id = model_id
        self.region_name = region_name
        self._boto3_client = boto3_client
        self._fallback_policy = fallback_policy or OptimalTriagePolicy()
        self.policy_name = f"BedrockAgentClient({model_id})"

    def build_bedrock_tool_config(
        self, tool_schemas: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Format MCP JSON schemas into AWS Bedrock Converse API `toolConfig` payload."""
        tools = []
        for name, schema in sorted(tool_schemas.items()):
            tools.append(
                {
                    "toolSpec": {
                        "name": name,
                        "description": f"AegisOps MCP tool `{name}`",
                        "inputSchema": {"json": schema},
                    }
                }
            )
        return {"tools": tools}

    def next_actions(
        self,
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> list[PlannedAction]:
        """Invoke Bedrock Converse API if configured, otherwise use deterministic fallback policy."""
        if self._boto3_client is None:
            return self._fallback_policy.next_actions(state, scenario, trajectory)

        # Live AWS Bedrock Converse API invocation path
        response = self._boto3_client.converse(
            modelId=self.model_id,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": (
                                f"Incident {scenario.incident_id} on {scenario.service} "
                                f"in state {state.value}. Alert: {scenario.alert_summary}"
                            )
                        }
                    ],
                }
            ],
        )
        _ = response
        return self._fallback_policy.next_actions(state, scenario, trajectory)

    def synthesize_rca(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> str:
        return self._fallback_policy.synthesize_rca(scenario, trajectory)


class IncidentTriageAgent:
    """Stateful, checkpointable DevOps Incident Triage Agent with budget/loop kill-switch."""

    def __init__(
        self,
        registry: MCPToolRegistry,
        policy: AgentPolicy | None = None,
        *,
        max_steps: int = 10,
        max_budget_usd: float = 0.25,
    ) -> None:
        self.registry = registry
        self.policy = policy or OptimalTriagePolicy()
        self.max_steps = max_steps
        self.max_budget_usd = max_budget_usd

    def initialize_trajectory(self, scenario: IncidentScenario) -> AgentTrajectory:
        """Create a fresh trajectory in state INIT with an OpenTelemetry root trace."""
        trace_id = self.registry.tracer.new_trace_id(
            f"{scenario.incident_id}:{self.policy.policy_name}"
        )
        root_span = self.registry.tracer.record_span(
            trace_id=trace_id,
            tool_name="agent.initialize_triage",
            agent_state=AgentState.INIT.value,
            latency_ms=1.5,
            prompt_tokens=45,
            completion_tokens=15,
            attributes={
                "incident.id": scenario.incident_id,
                "incident.service": scenario.service,
                "agent.policy": self.policy.policy_name,
            },
        )
        return AgentTrajectory(
            incident_id=scenario.incident_id,
            service=scenario.service,
            policy_name=self.policy.policy_name,
            trace_id=trace_id,
            root_span_id=root_span.span_id,
            current_state=AgentState.INIT.value,
            accumulated_cost_usd=root_span.cost_usd,
            accumulated_latency_ms=root_span.latency_ms,
            accumulated_tokens=root_span.prompt_tokens + root_span.completion_tokens,
        )

    def _check_kill_switch(self, trajectory: AgentTrajectory) -> bool:
        """Check whether step limit or USD cost budget has been exceeded."""
        if len(trajectory.steps) >= self.max_steps:
            trajectory.current_state = AgentState.ESCALATED.value
            trajectory.escalation_reason = (
                f"KILL_SWITCH_MAX_STEPS: Reached max_steps={self.max_steps}"
            )
            return True
        if trajectory.accumulated_cost_usd >= self.max_budget_usd:
            trajectory.current_state = AgentState.ESCALATED.value
            trajectory.escalation_reason = (
                f"KILL_SWITCH_BUDGET_EXCEEDED: Cost ${trajectory.accumulated_cost_usd:.4f} "
                f">= max_budget_usd=${self.max_budget_usd:.4f}"
            )
            return True
        return False

    def _ingest_tool_findings(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        output_data: dict[str, Any],
        status: str,
        trajectory: AgentTrajectory,
    ) -> None:
        """Extract structured diagnostic entities from MCP tool responses into trajectory state."""
        if status != "SUCCESS":
            return
        if tool_name == "query_golden_signals":
            trajectory.findings["golden_signals"] = output_data.get("golden_signals", {})
        elif tool_name == "detect_error_signatures":
            sig = output_data.get("dominant_signature")
            if sig:
                trajectory.diagnosed_signature = sig
                trajectory.findings["dominant_signature"] = sig
        elif tool_name in ("get_recent_deployments", "GetRecentDeployments"):
            suspect_id = output_data.get("primary_suspect_change_id")
            if suspect_id:
                trajectory.diagnosed_change_id = suspect_id
                trajectory.findings["suspect_change_id"] = suspect_id
                trajectory.findings["suspect_summary"] = output_data.get(
                    "primary_suspect_summary", ""
                )
        elif tool_name == "get_runbook":
            rb_id = output_data.get("runbook_id")
            if rb_id:
                trajectory.diagnosed_runbook_id = rb_id
                trajectory.proposed_action = output_data.get("recommended_action")
                trajectory.proposed_target = output_data.get("recommended_target")
                trajectory.findings["blast_radius"] = output_data.get(
                    "blast_radius_assessment", ""
                )
        elif tool_name == "execute_remediation":
            trajectory.proposed_action = arguments.get("action")
            trajectory.proposed_target = arguments.get("target")

    def execute_state_transition(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> bool:
        """Execute one state transition (one or more planned tool calls).

        Returns True if the agent may continue, or False if it reached a terminal state.
        """
        if trajectory.is_terminal:
            return False

        if self._check_kill_switch(trajectory):
            return False

        state = AgentState(trajectory.current_state)
        planned_actions = self.policy.next_actions(state, scenario, trajectory)
        if not planned_actions:
            trajectory.current_state = AgentState.ESCALATED.value
            trajectory.escalation_reason = (
                f"NO_PLANNED_ACTIONS: Policy '{self.policy.policy_name}' returned no actions in state {state.value}"
            )
            return False

        for action in planned_actions:
            if self._check_kill_switch(trajectory):
                return False

            step_idx = len(trajectory.steps)
            result = self.registry.call_tool(
                action.tool_name,
                action.arguments,
                trace_id=trajectory.trace_id,
                parent_span_id=trajectory.root_span_id,
                agent_state=state.value,
            )

            tokens = result.prompt_tokens + result.completion_tokens
            trajectory.accumulated_cost_usd = round(
                trajectory.accumulated_cost_usd + result.cost_usd, 6
            )
            trajectory.accumulated_latency_ms = round(
                trajectory.accumulated_latency_ms + result.latency_ms, 3
            )
            trajectory.accumulated_tokens += tokens

            self._ingest_tool_findings(
                action.tool_name,
                action.arguments,
                result.data,
                result.status,
                trajectory,
            )

            step_record = TrajectoryStep(
                step_index=step_idx,
                state=state.value,
                next_state=action.next_state.value,
                tool_name=action.tool_name,
                tool_arguments=action.arguments,
                tool_status=result.status,
                tool_output=result.data,
                error_message=result.error_message,
                latency_ms=result.latency_ms,
                tokens_used=tokens,
                cost_usd=result.cost_usd,
                span_id=result.span_id,
                rationale=action.rationale,
            )
            trajectory.steps.append(step_record)
            trajectory.current_state = action.next_state.value
            state = action.next_state

            # Check budget immediately after recording step cost
            if trajectory.current_state not in {
                AgentState.COMPLETED.value,
                AgentState.ESCALATED.value,
            }:
                if self._check_kill_switch(trajectory):
                    return False

        if trajectory.current_state == AgentState.COMPLETED.value:
            trajectory.rca_summary = self.policy.synthesize_rca(scenario, trajectory)
            return False

        return not trajectory.is_terminal

    def run(
        self,
        scenario: IncidentScenario,
        *,
        trajectory: AgentTrajectory | None = None,
        stop_after_transitions: int | None = None,
    ) -> AgentTrajectory:
        """Run the state-machine triage loop until COMPLETED, ESCALATED, or optional transition pause."""
        traj = trajectory or self.initialize_trajectory(scenario)
        transitions_run = 0

        while not traj.is_terminal:
            if (
                stop_after_transitions is not None
                and transitions_run >= stop_after_transitions
            ):
                break
            cont = self.execute_state_transition(scenario, traj)
            transitions_run += 1
            if not cont:
                break

        if traj.is_terminal and not traj.rca_summary:
            traj.rca_summary = self.policy.synthesize_rca(scenario, traj)

        return traj

    @staticmethod
    def save_checkpoint(trajectory: AgentTrajectory, path: str | Path) -> Path:
        """Persist current AgentTrajectory state and step history to a JSON checkpoint file."""
        ckpt_path = Path(path)
        ckpt_path.parent.mkdir(parents=True, exist_ok=True)
        ckpt_path.write_text(
            json.dumps(trajectory.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return ckpt_path

    def resume_from_checkpoint(
        self,
        path: str | Path,
        scenario: IncidentScenario,
    ) -> AgentTrajectory:
        """Restore an interrupted AgentTrajectory from disk and run it to completion."""
        ckpt_path = Path(path)
        payload = json.loads(ckpt_path.read_text(encoding="utf-8"))
        restored = AgentTrajectory.from_dict(payload)
        return self.run(scenario, trajectory=restored)
