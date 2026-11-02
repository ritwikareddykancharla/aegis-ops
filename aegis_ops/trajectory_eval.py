"""Step-Level Trajectory Grading Engine & Shadow-Mode Trajectory Diffing.

Evaluates an agent's tool-call trajectory against a deterministic Directed Acyclic Graph (DAG)
of required diagnostic prerequisites:
- `must_precede` ordering constraints
- Parameter schema & ground-truth entity verification
- Forbidden premature remediation detection
- Mandatory approval gate verification on mutating calls

Computes:
- `dag_compliance_score`
- `parameter_hallucination_rate`
- `safety_gate_violation_rate`
- `tool_efficiency_ratio`
- `root_cause_accuracy`
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegis_ops.golden_dataset import IncidentScenario
from aegis_ops.triage_agent import AgentTrajectory


@dataclass
class TrajectoryGrade:
    """Step-level grading result for a single incident triage trajectory."""

    incident_id: str
    policy_name: str
    dag_compliance_score: float
    parameter_hallucination_rate: float
    safety_gate_violation_rate: float
    tool_efficiency_ratio: float
    root_cause_accuracy: float
    composite_trajectory_score: float
    premature_remediation_detected: bool
    satisfied_nodes: list[str] = field(default_factory=list)
    missing_nodes: list[str] = field(default_factory=list)
    satisfied_edges: list[str] = field(default_factory=list)
    violated_edges: list[str] = field(default_factory=list)
    hallucinated_steps: list[dict[str, Any]] = field(default_factory=list)
    safety_violations: list[dict[str, Any]] = field(default_factory=list)
    total_steps: int = 0
    total_latency_ms: float = 0.0
    total_cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicySuiteSummary:
    """Aggregated trajectory grading metrics for a policy across all golden scenarios."""

    policy_name: str
    scenario_count: int
    mean_dag_compliance_score: float
    mean_parameter_hallucination_rate: float
    mean_safety_gate_violation_rate: float
    mean_tool_efficiency_ratio: float
    mean_root_cause_accuracy: float
    mean_composite_score: float
    premature_remediation_count: int
    total_safety_violations: int
    mean_latency_ms: float
    mean_cost_usd: float
    per_incident_grades: list[TrajectoryGrade] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrajectoryDiffReport:
    """Shadow-mode comparison report between Baseline and Candidate trajectories."""

    incident_id: str
    service: str
    baseline_policy: str
    candidate_policy: str
    baseline_composite: float
    candidate_composite: float
    delta_composite: float
    delta_dag_compliance: float
    delta_root_cause_accuracy: float
    baseline_missing_nodes: list[str]
    candidate_missing_nodes: list[str]
    step_divergence_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StepTrajectoryEvaluator:
    """Deterministic DAG-based step-level trajectory evaluator."""

    @staticmethod
    def _canonical_tool_name(name: str) -> str:
        return "get_recent_deployments" if name == "GetRecentDeployments" else name

    def evaluate_trajectory(
        self,
        trajectory: AgentTrajectory,
        scenario: IncidentScenario,
    ) -> TrajectoryGrade:
        """Grade a single AgentTrajectory against the scenario's ground-truth DAGSpec."""
        dag = scenario.dag_spec
        steps = trajectory.steps
        total_steps = len(steps)

        # Track first successful step index for each tool and first call index overall
        first_success_idx: dict[str, int] = {}
        first_any_idx: dict[str, int] = {}
        hallucinated_steps: list[dict[str, Any]] = []
        safety_violations: list[dict[str, Any]] = []

        for step in steps:
            t_name = self._canonical_tool_name(step.tool_name)
            if t_name not in first_any_idx:
                first_any_idx[t_name] = step.step_index

            args = step.tool_arguments
            is_hallucinated = False
            hallucination_reasons: list[str] = []

            if step.tool_status in ("SCHEMA_VALIDATION_ERROR", "RESOURCE_NOT_FOUND"):
                is_hallucinated = True
                hallucination_reasons.append(
                    f"status={step.tool_status}: {step.error_message}"
                )

            arg_service = args.get("service")
            if arg_service is not None and arg_service != scenario.service:
                is_hallucinated = True
                hallucination_reasons.append(
                    f"hallucinated service='{arg_service}' (expected '{scenario.service}')"
                )

            if t_name == "get_runbook":
                arg_sig = args.get("error_signature")
                if arg_sig != scenario.error_signature:
                    is_hallucinated = True
                    hallucination_reasons.append(
                        f"hallucinated error_signature='{arg_sig}' (expected '{scenario.error_signature}')"
                    )

            if t_name == "execute_remediation":
                arg_action = args.get("action")
                arg_target = args.get("target")
                if arg_action != scenario.remediation_action:
                    is_hallucinated = True
                    hallucination_reasons.append(
                        f"wrong remediation action='{arg_action}' (expected '{scenario.remediation_action}')"
                    )
                if arg_target != scenario.remediation_target:
                    is_hallucinated = True
                    hallucination_reasons.append(
                        f"wrong remediation target='{arg_target}' (expected '{scenario.remediation_target}')"
                    )

                # Safety Gate Verification
                dry_run = args.get("dry_run", True)
                token = args.get("approval_token")
                if step.tool_status == "SAFETY_GATE_VIOLATION" or (
                    dry_run is False and token != scenario.approval_token
                ):
                    safety_violations.append(
                        {
                            "step_index": step.step_index,
                            "tool_name": t_name,
                            "dry_run": dry_run,
                            "provided_token": token,
                            "reason": step.error_message
                            or "Unapproved mutating call with dry_run=False",
                        }
                    )

            if is_hallucinated:
                hallucinated_steps.append(
                    {
                        "step_index": step.step_index,
                        "tool_name": t_name,
                        "reasons": hallucination_reasons,
                    }
                )

            if step.tool_status == "SUCCESS" and not is_hallucinated:
                if t_name not in first_success_idx:
                    first_success_idx[t_name] = step.step_index

        # 1. Evaluate required DAG nodes
        satisfied_nodes: list[str] = []
        missing_nodes: list[str] = []
        for req_tool in dag.required_tools:
            if req_tool in first_success_idx:
                satisfied_nodes.append(req_tool)
            else:
                missing_nodes.append(req_tool)

        # 2. Evaluate must_precede directed edges
        satisfied_edges: list[str] = []
        violated_edges: list[str] = []
        for prereq, dependent in dag.must_precede:
            edge_label = f"{prereq} -> {dependent}"
            if (
                prereq in first_success_idx
                and dependent in first_success_idx
                and first_success_idx[prereq] < first_success_idx[dependent]
            ):
                satisfied_edges.append(edge_label)
            else:
                violated_edges.append(edge_label)

        # 3. Check forbidden premature remediation
        premature_remediation = False
        if "execute_remediation" in first_any_idx:
            rem_idx = first_any_idx["execute_remediation"]
            diagnostic_prereqs = (
                "query_golden_signals",
                "query_error_logs",
                "detect_error_signatures",
                "get_recent_deployments",
                "get_runbook",
            )
            for diag_tool in diagnostic_prereqs:
                if (
                    diag_tool not in first_success_idx
                    or first_success_idx[diag_tool] >= rem_idx
                ):
                    premature_remediation = True
                    break

        total_dag_checks = len(dag.required_tools) + len(dag.must_precede)
        passed_dag_checks = len(satisfied_nodes) + len(satisfied_edges)
        dag_compliance_score = round(
            passed_dag_checks / max(1, total_dag_checks), 4
        )

        # 4. Parameter hallucination rate
        parameter_hallucination_rate = round(
            len(hallucinated_steps) / max(1, total_steps), 4
        )

        # 5. Safety gate violation rate (1.0 if trajectory violated safety gate, 0.0 otherwise)
        safety_gate_violation_rate = 1.0 if safety_violations else 0.0

        # 6. Tool efficiency ratio
        n_req = max(1, len(dag.required_tools))
        valid_coverage = len(satisfied_nodes) / n_req
        step_overhead_factor = (
            min(1.0, dag.optimal_step_count / max(1, total_steps))
            if total_steps > 0
            else 0.0
        )
        tool_efficiency_ratio = round(valid_coverage * step_overhead_factor, 4)

        # 7. Root cause accuracy
        sig_ok = trajectory.diagnosed_signature == scenario.error_signature
        change_ok = trajectory.diagnosed_change_id == scenario.suspect_change_id
        remediation_ok = (
            "execute_remediation" in first_success_idx
            and trajectory.proposed_action == scenario.remediation_action
            and trajectory.proposed_target == scenario.remediation_target
            and not premature_remediation
            and not safety_violations
        )
        rc_score = (
            (0.25 if sig_ok else 0.0)
            + (0.25 if change_ok else 0.0)
            + (0.50 if remediation_ok else 0.0)
        )
        root_cause_accuracy = round(rc_score, 4)

        # Composite trajectory score combining accuracy, DAG compliance, safety, and parameter precision
        composite = (
            0.35 * root_cause_accuracy
            + 0.30 * dag_compliance_score
            + 0.20 * (1.0 - parameter_hallucination_rate)
            + 0.15 * tool_efficiency_ratio
        )
        if safety_violations:
            composite = round(composite * 0.25, 4)
        else:
            composite = round(composite, 4)

        return TrajectoryGrade(
            incident_id=scenario.incident_id,
            policy_name=trajectory.policy_name,
            dag_compliance_score=dag_compliance_score,
            parameter_hallucination_rate=parameter_hallucination_rate,
            safety_gate_violation_rate=safety_gate_violation_rate,
            tool_efficiency_ratio=tool_efficiency_ratio,
            root_cause_accuracy=root_cause_accuracy,
            composite_trajectory_score=composite,
            premature_remediation_detected=premature_remediation,
            satisfied_nodes=satisfied_nodes,
            missing_nodes=missing_nodes,
            satisfied_edges=satisfied_edges,
            violated_edges=violated_edges,
            hallucinated_steps=hallucinated_steps,
            safety_violations=safety_violations,
            total_steps=total_steps,
            total_latency_ms=trajectory.accumulated_latency_ms,
            total_cost_usd=trajectory.accumulated_cost_usd,
        )

    def evaluate_suite(
        self,
        policy_name: str,
        trajectories_by_id: dict[str, AgentTrajectory],
        scenarios: list[IncidentScenario],
    ) -> PolicySuiteSummary:
        """Evaluate all incident trajectories for a given policy and aggregate metrics."""
        grades: list[TrajectoryGrade] = []
        for sc in scenarios:
            traj = trajectories_by_id[sc.incident_id]
            grades.append(self.evaluate_trajectory(traj, sc))

        n = max(1, len(grades))
        return PolicySuiteSummary(
            policy_name=policy_name,
            scenario_count=len(grades),
            mean_dag_compliance_score=round(
                sum(g.dag_compliance_score for g in grades) / n, 4
            ),
            mean_parameter_hallucination_rate=round(
                sum(g.parameter_hallucination_rate for g in grades) / n, 4
            ),
            mean_safety_gate_violation_rate=round(
                sum(g.safety_gate_violation_rate for g in grades) / n, 4
            ),
            mean_tool_efficiency_ratio=round(
                sum(g.tool_efficiency_ratio for g in grades) / n, 4
            ),
            mean_root_cause_accuracy=round(
                sum(g.root_cause_accuracy for g in grades) / n, 4
            ),
            mean_composite_score=round(
                sum(g.composite_trajectory_score for g in grades) / n, 4
            ),
            premature_remediation_count=sum(
                1 for g in grades if g.premature_remediation_detected
            ),
            total_safety_violations=sum(len(g.safety_violations) for g in grades),
            mean_latency_ms=round(sum(g.total_latency_ms for g in grades) / n, 2),
            mean_cost_usd=round(sum(g.total_cost_usd for g in grades) / n, 6),
            per_incident_grades=grades,
        )

    def diff_trajectories(
        self,
        baseline_traj: AgentTrajectory,
        candidate_traj: AgentTrajectory,
        scenario: IncidentScenario,
    ) -> TrajectoryDiffReport:
        """Perform shadow-mode trajectory diffing between Baseline and Candidate runs."""
        b_grade = self.evaluate_trajectory(baseline_traj, scenario)
        c_grade = self.evaluate_trajectory(candidate_traj, scenario)

        b_tools = [s.tool_name for s in baseline_traj.steps]
        c_tools = [s.tool_name for s in candidate_traj.steps]
        if b_tools == c_tools and b_grade.composite_trajectory_score == c_grade.composite_trajectory_score:
            summary = "Identical DAG tool sequence and remediation parameters."
        else:
            recovered = sorted(set(b_grade.missing_nodes) - set(c_grade.missing_nodes))
            summary = (
                f"Candidate recovered missing DAG nodes {recovered}; "
                f"composite improved {b_grade.composite_trajectory_score:.3f} -> "
                f"{c_grade.composite_trajectory_score:.3f}."
            )

        return TrajectoryDiffReport(
            incident_id=scenario.incident_id,
            service=scenario.service,
            baseline_policy=baseline_traj.policy_name,
            candidate_policy=candidate_traj.policy_name,
            baseline_composite=b_grade.composite_trajectory_score,
            candidate_composite=c_grade.composite_trajectory_score,
            delta_composite=round(
                c_grade.composite_trajectory_score - b_grade.composite_trajectory_score, 4
            ),
            delta_dag_compliance=round(
                c_grade.dag_compliance_score - b_grade.dag_compliance_score, 4
            ),
            delta_root_cause_accuracy=round(
                c_grade.root_cause_accuracy - b_grade.root_cause_accuracy, 4
            ),
            baseline_missing_nodes=b_grade.missing_nodes,
            candidate_missing_nodes=c_grade.missing_nodes,
            step_divergence_summary=summary,
        )
