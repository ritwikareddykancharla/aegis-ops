"""Command-Line Interface for AegisOps Evaluation Suite, Shadow-Mode Trajectory Diffing & CI Regression Gate.

Usage:
    python3 -m aegis_ops.cli --run-eval-suite --output benchmarks/latest_results.json
    python3 -m aegis_ops.cli
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from aegis_ops.calibrated_judge import (
    CalibratedRCAJudge,
    bootstrap_significance_test,
    evaluate_ci_regression_gate,
)
from aegis_ops.golden_dataset import CALIBRATION_ANCHORS, GOLDEN_SCENARIOS
from aegis_ops.mcp_servers import MCPToolRegistry
from aegis_ops.otel_tracer import OTelTracer
from aegis_ops.trajectory_eval import PolicySuiteSummary, StepTrajectoryEvaluator
from aegis_ops.triage_agent import (
    AgentPolicy,
    AgentTrajectory,
    BaselineTriagePolicy,
    HallucinatingParamPolicy,
    IncidentTriageAgent,
    OptimalTriagePolicy,
    PrematureConclusionPolicy,
    UnsafeMutatingPolicy,
)


def run_full_evaluation_suite(
    output_path: str | Path = "benchmarks/latest_results.json",
    traces_path: str | Path | None = "benchmarks/otel_traces.jsonl",
) -> dict[str, Any]:
    """Execute the complete AegisOps evaluation suite across 12 AWS scenarios and 5 policies."""
    tracer = OTelTracer(service_name="aegis-ops-eval-harness")
    registry = MCPToolRegistry(scenarios=GOLDEN_SCENARIOS, tracer=tracer)
    evaluator = StepTrajectoryEvaluator()
    judge = CalibratedRCAJudge()

    policies: list[AgentPolicy] = [
        OptimalTriagePolicy(),
        BaselineTriagePolicy(),
        HallucinatingParamPolicy(),
        UnsafeMutatingPolicy(),
        PrematureConclusionPolicy(),
    ]

    trajectories_by_policy: dict[str, dict[str, AgentTrajectory]] = {}
    suite_summaries: dict[str, PolicySuiteSummary] = {}
    rca_scores_by_policy: dict[str, dict[str, float]] = {}

    for policy in policies:
        agent = IncidentTriageAgent(
            registry=registry,
            policy=policy,
            max_steps=10,
            max_budget_usd=0.25,
        )
        policy_trajs: dict[str, AgentTrajectory] = {}
        policy_rca_scores: dict[str, float] = {}

        for scenario in GOLDEN_SCENARIOS:
            traj = agent.run(scenario)
            policy_trajs[scenario.incident_id] = traj
            rca_eval = judge.score_rca(traj.rca_summary, scenario)
            policy_rca_scores[scenario.incident_id] = rca_eval.overall_score

        trajectories_by_policy[policy.policy_name] = policy_trajs
        rca_scores_by_policy[policy.policy_name] = policy_rca_scores
        suite_summaries[policy.policy_name] = evaluator.evaluate_suite(
            policy.policy_name, policy_trajs, GOLDEN_SCENARIOS
        )

    # 1. Shadow-mode trajectory diffing: Baseline v1 vs Candidate v2 (OptimalTriagePolicy)
    baseline_trajs = trajectories_by_policy["BaselineTriagePolicy"]
    candidate_trajs = trajectories_by_policy["OptimalTriagePolicy"]
    shadow_diffs = [
        evaluator.diff_trajectories(
            baseline_trajs[sc.incident_id],
            candidate_trajs[sc.incident_id],
            sc,
        ).to_dict()
        for sc in GOLDEN_SCENARIOS
    ]

    # 2. Calibrate LLM-as-a-Judge against the 24 human-anchored RCA samples
    calibration_report = judge.calibrate_against_anchors(CALIBRATION_ANCHORS)

    # 3. Bootstrap 95% Confidence Intervals (1,000 resamples)
    base_summary = suite_summaries["BaselineTriagePolicy"]
    cand_summary = suite_summaries["OptimalTriagePolicy"]

    base_composite_list = [
        g.composite_trajectory_score for g in base_summary.per_incident_grades
    ]
    cand_composite_list = [
        g.composite_trajectory_score for g in cand_summary.per_incident_grades
    ]
    base_rc_list = [g.root_cause_accuracy for g in base_summary.per_incident_grades]
    cand_rc_list = [g.root_cause_accuracy for g in cand_summary.per_incident_grades]

    bootstrap_composite = bootstrap_significance_test(
        base_composite_list, cand_composite_list, n_resamples=1000, seed=42
    )
    bootstrap_rc_accuracy = bootstrap_significance_test(
        base_rc_list, cand_rc_list, n_resamples=1000, seed=42
    )

    # 4. CI/CD Regression Gate Evaluations (Candidate v2 PASS + Flawed Policies BLOCK_PR)
    ci_gate_candidate = evaluate_ci_regression_gate(
        baseline_policy="BaselineTriagePolicy",
        candidate_policy="OptimalTriagePolicy",
        baseline_task_scores=base_rc_list,
        candidate_task_scores=cand_rc_list,
        candidate_safety_violation_rate=cand_summary.mean_safety_gate_violation_rate,
        judge_cohens_kappa=calibration_report.cohens_kappa,
    )

    unsafe_summary = suite_summaries["UnsafeMutatingPolicy"]
    unsafe_rc_list = [
        g.root_cause_accuracy for g in unsafe_summary.per_incident_grades
    ]
    ci_gate_unsafe = evaluate_ci_regression_gate(
        baseline_policy="BaselineTriagePolicy",
        candidate_policy="UnsafeMutatingPolicy",
        baseline_task_scores=base_rc_list,
        candidate_task_scores=unsafe_rc_list,
        candidate_safety_violation_rate=unsafe_summary.mean_safety_gate_violation_rate,
        judge_cohens_kappa=calibration_report.cohens_kappa,
    )

    halluc_summary = suite_summaries["HallucinatingParamPolicy"]
    halluc_rc_list = [
        g.root_cause_accuracy for g in halluc_summary.per_incident_grades
    ]
    ci_gate_halluc = evaluate_ci_regression_gate(
        baseline_policy="BaselineTriagePolicy",
        candidate_policy="HallucinatingParamPolicy",
        baseline_task_scores=base_rc_list,
        candidate_task_scores=halluc_rc_list,
        candidate_safety_violation_rate=halluc_summary.mean_safety_gate_violation_rate,
        judge_cohens_kappa=calibration_report.cohens_kappa,
    )

    # Export OpenTelemetry spans if requested
    exported_span_count = 0
    if traces_path is not None:
        exported_span_count = tracer.export_jsonl(traces_path)

    results_payload: dict[str, Any] = {
        "benchmark_suite": "AegisOps Production Incident Triage Benchmark v1.0",
        "golden_scenario_count": len(GOLDEN_SCENARIOS),
        "calibration_anchor_count": len(CALIBRATION_ANCHORS),
        "total_otel_spans_recorded": len(tracer.get_spans()),
        "exported_otel_spans": exported_span_count,
        "policy_leaderboard": {
            name: {
                "dag_compliance_score": s.mean_dag_compliance_score,
                "parameter_hallucination_rate": s.mean_parameter_hallucination_rate,
                "safety_gate_violation_rate": s.mean_safety_gate_violation_rate,
                "tool_efficiency_ratio": s.mean_tool_efficiency_ratio,
                "root_cause_accuracy": s.mean_root_cause_accuracy,
                "composite_trajectory_score": s.mean_composite_score,
                "mean_rca_judge_score": round(
                    sum(rca_scores_by_policy[name].values())
                    / len(rca_scores_by_policy[name]),
                    4,
                ),
                "premature_remediation_count": s.premature_remediation_count,
                "total_safety_violations": s.total_safety_violations,
                "mean_latency_ms": s.mean_latency_ms,
                "mean_cost_usd": s.mean_cost_usd,
            }
            for name, s in suite_summaries.items()
        },
        "judge_calibration": {
            "anchor_count": calibration_report.anchor_count,
            "cohens_kappa": calibration_report.cohens_kappa,
            "observed_agreement_rate": calibration_report.observed_agreement_rate,
            "position_swap_consistency_rate": calibration_report.position_swap_consistency_rate,
            "verbosity_bias_correlation": calibration_report.verbosity_bias_correlation,
            "mean_absolute_rubric_error": calibration_report.mean_absolute_rubric_error,
            "is_well_calibrated": calibration_report.is_well_calibrated,
        },
        "statistical_significance": {
            "root_cause_accuracy_bootstrap": bootstrap_rc_accuracy.to_dict(),
            "composite_trajectory_bootstrap": bootstrap_composite.to_dict(),
        },
        "ci_cd_regression_gates": {
            "OptimalTriagePolicy_vs_Baseline": ci_gate_candidate.to_dict(),
            "UnsafeMutatingPolicy_vs_Baseline": ci_gate_unsafe.to_dict(),
            "HallucinatingParamPolicy_vs_Baseline": ci_gate_halluc.to_dict(),
        },
        "shadow_mode_trajectory_diffs": shadow_diffs,
    }

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(
        json.dumps(results_payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return results_payload


def format_markdown_report(results: dict[str, Any], output_path: str | Path) -> str:
    """Render a clean Markdown report of the evaluation suite results."""
    lines: list[str] = []
    lines.append("# AegisOps — Autonomous Incident Triage & Trajectory Evaluation Report")
    lines.append("")
    lines.append(
        f"- **Golden AWS Production Scenarios Evaluated:** `{results['golden_scenario_count']}`"
    )
    lines.append(
        f"- **Human-Labeled RCA Calibration Anchors:** `{results['calibration_anchor_count']}`"
    )
    lines.append(
        f"- **OpenTelemetry Tool & Agent Spans Recorded:** `{results['total_otel_spans_recorded']}`"
    )
    lines.append(f"- **Artifact Saved To:** `{output_path}`")
    lines.append("")
    lines.append("## 1. Step-Level Trajectory & RCA Policy Leaderboard")
    lines.append("")
    lines.append(
        "| Agent Policy | DAG Compliance | Param Hallucination | Safety Violation Rate | Tool Efficiency | Root Cause Accuracy | Composite Score | Mean RCA Judge | Mean Latency (ms) | Mean Cost (USD) |"
    )
    lines.append(
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    )
    for policy_name, metrics in results["policy_leaderboard"].items():
        lines.append(
            f"| `{policy_name}` "
            f"| {metrics['dag_compliance_score'] * 100:.1f}% "
            f"| {metrics['parameter_hallucination_rate'] * 100:.1f}% "
            f"| {metrics['safety_gate_violation_rate'] * 100:.1f}% "
            f"| {metrics['tool_efficiency_ratio'] * 100:.1f}% "
            f"| {metrics['root_cause_accuracy'] * 100:.1f}% "
            f"| {metrics['composite_trajectory_score'] * 100:.1f}% "
            f"| {metrics['mean_rca_judge_score']:.3f} "
            f"| {metrics['mean_latency_ms']:.1f} "
            f"| ${metrics['mean_cost_usd']:.4f} |"
        )

    lines.append("")
    lines.append("## 2. Calibrated LLM-as-a-Judge Diagnostics (24 Human SRE Anchors)")
    lines.append("")
    cal = results["judge_calibration"]
    lines.append(f"- **Cohen's Kappa ($\\kappa$):** `{cal['cohens_kappa']:.4f}`")
    lines.append(
        f"- **Observed Human-Judge Agreement:** `{cal['observed_agreement_rate'] * 100:.2f}%`"
    )
    lines.append(
        f"- **Position-Bias Swap Consistency (`(A,B)` vs `(B,A)`):** `{cal['position_swap_consistency_rate'] * 100:.1f}%`"
    )
    lines.append(
        f"- **Verbosity Bias Correlation ($r$):** `{cal['verbosity_bias_correlation']:+.4f}`"
    )
    lines.append(
        f"- **Mean Absolute Rubric Error (MAE):** `{cal['mean_absolute_rubric_error']:.4f}`"
    )

    lines.append("")
    lines.append("## 3. Paired Bootstrap Statistical Significance (1,000 Resamples)")
    lines.append("")
    rc_boot = results["statistical_significance"]["root_cause_accuracy_bootstrap"]
    comp_boot = results["statistical_significance"]["composite_trajectory_bootstrap"]
    lines.append(
        f"- **Root Cause Accuracy (`OptimalTriagePolicy` vs `BaselineTriagePolicy`):** "
        f"**{rc_boot['summary_statement']}**"
    )
    lines.append(
        f"- **Composite Trajectory Score (`OptimalTriagePolicy` vs `BaselineTriagePolicy`):** "
        f"**{comp_boot['summary_statement']}**"
    )

    lines.append("")
    lines.append("## 4. Automated CI/CD Regression Gate Decisions")
    lines.append("")
    for gate_name, gate_info in results["ci_cd_regression_gates"].items():
        badge = "PASS" if gate_info["decision"] == "PASS" else "BLOCK_PR"
        reasons = (
            "; ".join(gate_info["blocking_reasons"])
            if gate_info["blocking_reasons"]
            else "All accuracy, safety, and calibration checks passed."
        )
        lines.append(
            f"- **`{gate_name}`**: `{badge}` "
            f"(Task Success $\\Delta = {gate_info['task_success_delta_pct']:+.2f}\\%$, "
            f"Safety Violations = `{gate_info['candidate_safety_violation_rate'] * 100:.1f}%`) — {reasons}"
        )

    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-ops",
        description="AegisOps Autonomous DevOps Incident Triage & Trajectory Evaluation CLI",
    )
    parser.add_argument(
        "--run-eval-suite",
        action="store_true",
        default=True,
        help="Run the full 12-scenario, 5-policy evaluation suite and calibration benchmark (default: True).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="benchmarks/latest_results.json",
        help="Path to write JSON evaluation benchmark output (default: benchmarks/latest_results.json).",
    )
    parser.add_argument(
        "--traces-output",
        type=str,
        default="benchmarks/otel_traces.jsonl",
        help="Path to write OpenTelemetry JSONL spans (default: benchmarks/otel_traces.jsonl).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    results = run_full_evaluation_suite(
        output_path=args.output,
        traces_path=args.traces_output,
    )
    report_md = format_markdown_report(results, args.output)
    print(report_md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
