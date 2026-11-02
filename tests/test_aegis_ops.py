"""Comprehensive unit and integration test suite for AegisOps."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aegis_ops.calibrated_judge import (
    CalibratedRCAJudge,
    bootstrap_significance_test,
    compute_cohens_kappa,
    evaluate_ci_regression_gate,
)
from aegis_ops.cli import run_full_evaluation_suite
from aegis_ops.golden_dataset import (
    CALIBRATION_ANCHORS,
    GOLDEN_SCENARIOS,
    SCENARIO_BY_ID,
)
from aegis_ops.llm_client import DEFAULT_MODELS, LiveLLMClient
from aegis_ops.mcp_servers import (
    MCPToolRegistry,
    MCPValidationError,
    validate_json_schema,
)
from aegis_ops.otel_tracer import OTelTracer, compute_token_cost_usd
from aegis_ops.trajectory_eval import StepTrajectoryEvaluator
from aegis_ops.triage_agent import (
    AgentState,
    BaselineTriagePolicy,
    BedrockAgentClient,
    HallucinatingParamPolicy,
    IncidentTriageAgent,
    OptimalTriagePolicy,
    PrematureConclusionPolicy,
    UnsafeMutatingPolicy,
)


class TestAegisOpsSuite(unittest.TestCase):
    """End-to-end unit and integration tests for AegisOps modules."""

    def setUp(self) -> None:
        self.tracer = OTelTracer(service_name="test-aegis-ops")
        self.registry = MCPToolRegistry(scenarios=GOLDEN_SCENARIOS, tracer=self.tracer)
        self.scenario_1 = SCENARIO_BY_ID["INC-001"]
        self.scenario_3 = SCENARIO_BY_ID["INC-003"]

    def test_01_golden_dataset_integrity(self) -> None:
        """Verify 12 golden AWS incident scenarios and 24 human calibration anchors."""
        self.assertEqual(len(GOLDEN_SCENARIOS), 12)
        self.assertEqual(len(CALIBRATION_ANCHORS), 24)
        incident_ids = [s.incident_id for s in GOLDEN_SCENARIOS]
        self.assertEqual(len(set(incident_ids)), 12)
        for sc in GOLDEN_SCENARIOS:
            self.assertTrue(sc.approval_token.startswith("APPROVAL-SRE-"))
            self.assertGreater(sc.metrics_payload["p99_latency_ms"], 0)
            self.assertGreaterEqual(len(sc.logs_payload), 2)

    def test_02_mcp_json_schema_validation_errors(self) -> None:
        """Verify strict JSON-Schema validation rejects missing, out-of-range, and unknown fields."""
        schema = self.registry.cloudwatch.SCHEMAS["query_error_logs"]
        # Missing required time_window_minutes
        with self.assertRaises(MCPValidationError):
            validate_json_schema({"service": "checkout-service"}, schema)

        # Out-of-range time_window_minutes (< 1)
        with self.assertRaises(MCPValidationError):
            validate_json_schema(
                {"service": "checkout-service", "time_window_minutes": 0}, schema
            )

        # Unknown property when additionalProperties is False
        with self.assertRaises(MCPValidationError):
            validate_json_schema(
                {
                    "service": "checkout-service",
                    "time_window_minutes": 15,
                    "injected_field": "bad",
                },
                schema,
            )

        # Registry captures schema validation error as structured MCPToolResult
        res = self.registry.call_tool(
            "query_error_logs",
            {"service": "checkout-service", "time_window_minutes": -10},
        )
        self.assertEqual(res.status, "SCHEMA_VALIDATION_ERROR")
        self.assertEqual(res.error_code, "JSONSchemaValidationError")

    def test_03_cloudwatch_logs_mcp_queries_and_signatures(self) -> None:
        """Verify CloudWatchLogsMCP queries logs by trace_id and detects canonical signatures."""
        log_res = self.registry.call_tool(
            "query_error_logs",
            {
                "service": "checkout-service",
                "time_window_minutes": 15,
                "severity": "ERROR",
            },
        )
        self.assertTrue(log_res.is_ok)
        self.assertEqual(log_res.data["matched_event_count"], 1)

        sig_res = self.registry.call_tool(
            "detect_error_signatures",
            {"service": "checkout-service", "time_window_minutes": 15},
        )
        self.assertTrue(sig_res.is_ok)
        self.assertEqual(sig_res.data["dominant_signature"], "ConnectionPoolExhausted")
        self.assertTrue(sig_res.data["is_canonical_signature"])

        # Unknown service returns RESOURCE_NOT_FOUND
        not_found = self.registry.call_tool(
            "detect_error_signatures",
            {"service": "unknown-ghost-service"},
        )
        self.assertEqual(not_found.status, "RESOURCE_NOT_FOUND")

    def test_04_prometheus_metrics_and_deployments_mcp(self) -> None:
        """Verify PrometheusMetricsMCP golden signals and GetRecentDeployments alias."""
        metrics_res = self.registry.call_tool(
            "query_golden_signals",
            {"service": "checkout-service", "window_minutes": 15},
        )
        self.assertTrue(metrics_res.is_ok)
        self.assertEqual(
            metrics_res.data["golden_signals"]["status"],
            "CRITICAL",
        )

        deploy_res = self.registry.call_tool(
            "GetRecentDeployments",
            {"service": "checkout-service", "lookback_minutes": 60},
        )
        self.assertTrue(deploy_res.is_ok)
        self.assertEqual(
            deploy_res.data["primary_suspect_change_id"],
            "deploy-v2.14.0-8f92a1",
        )

    def test_05_runbook_remediation_mcp_safety_gate(self) -> None:
        """Verify RunbookRemediationMCP enforces mandatory approval token on mutating actions."""
        # 1. Dry-run succeeds without approval token
        dry_res = self.registry.call_tool(
            "execute_remediation",
            {
                "service": "checkout-service",
                "action": "rollback_deployment",
                "target": "checkout-service:deploy-v2.14.0-8f92a1",
                "dry_run": True,
            },
        )
        self.assertEqual(dry_res.status, "SUCCESS")
        self.assertEqual(dry_res.data["execution_mode"], "DRY_RUN_VALIDATED")

        # 2. Mutating call (dry_run=False) without token is blocked by Safety Gate
        blocked_res = self.registry.call_tool(
            "execute_remediation",
            {
                "service": "checkout-service",
                "action": "rollback_deployment",
                "target": "checkout-service:deploy-v2.14.0-8f92a1",
                "dry_run": False,
            },
        )
        self.assertEqual(blocked_res.status, "SAFETY_GATE_VIOLATION")
        self.assertTrue(blocked_res.data["safety_gate_triggered"])

        # 3. Mutating call (dry_run=False) with valid SRE approval token succeeds
        approved_res = self.registry.call_tool(
            "execute_remediation",
            {
                "service": "checkout-service",
                "action": "rollback_deployment",
                "target": "checkout-service:deploy-v2.14.0-8f92a1",
                "dry_run": False,
                "approval_token": self.scenario_1.approval_token,
            },
        )
        self.assertEqual(approved_res.status, "SUCCESS")
        self.assertEqual(
            approved_res.data["execution_mode"],
            "MUTATION_EXECUTED_WITH_APPROVAL",
        )

    def test_06_state_machine_full_optimal_triage(self) -> None:
        """Verify state machine transitions through all 6 diagnostic stages to COMPLETED."""
        agent = IncidentTriageAgent(self.registry, policy=OptimalTriagePolicy())
        traj = agent.run(self.scenario_1)

        self.assertEqual(traj.current_state, AgentState.COMPLETED.value)
        self.assertEqual(len(traj.steps), 6)
        self.assertEqual(traj.diagnosed_signature, "ConnectionPoolExhausted")
        self.assertEqual(traj.diagnosed_change_id, "deploy-v2.14.0-8f92a1")
        self.assertEqual(traj.diagnosed_runbook_id, "RB-RDS-POOL-01")
        self.assertEqual(traj.proposed_action, "rollback_deployment")
        self.assertIn("deploy-v2.14.0-8f92a1", traj.rca_summary)

    def test_07_checkpoint_save_and_crash_recovery(self) -> None:
        """Verify agent can pause mid-trajectory, save checkpoint to disk, and resume to completion."""
        agent = IncidentTriageAgent(self.registry, policy=OptimalTriagePolicy())
        partial_traj = agent.run(self.scenario_1, stop_after_transitions=2)

        # After 2 state transitions (INIT -> TRIAGE_METRICS -> CORRELATE_DEPLOYMENTS), 3 tools ran
        self.assertEqual(
            partial_traj.current_state,
            AgentState.CORRELATE_DEPLOYMENTS.value,
        )
        self.assertEqual(len(partial_traj.steps), 3)
        self.assertFalse(partial_traj.is_terminal)

        with tempfile.TemporaryDirectory() as tmpdir:
            ckpt_file = Path(tmpdir) / "inc001_ckpt.json"
            agent.save_checkpoint(partial_traj, ckpt_file)
            self.assertTrue(ckpt_file.exists())

            resumed_agent = IncidentTriageAgent(
                self.registry, policy=OptimalTriagePolicy()
            )
            final_traj = resumed_agent.resume_from_checkpoint(ckpt_file, self.scenario_1)

            self.assertEqual(final_traj.current_state, AgentState.COMPLETED.value)
            self.assertEqual(len(final_traj.steps), 6)
            self.assertEqual(
                [s.step_index for s in final_traj.steps],
                [0, 1, 2, 3, 4, 5],
            )

    def test_08_kill_switch_max_steps_and_budget(self) -> None:
        """Verify cost and loop kill-switches halt execution and escalate."""
        # 1. Step count kill-switch
        step_limited_agent = IncidentTriageAgent(
            self.registry,
            policy=OptimalTriagePolicy(),
            max_steps=3,
            max_budget_usd=1.0,
        )
        traj_steps = step_limited_agent.run(self.scenario_1)
        self.assertEqual(traj_steps.current_state, AgentState.ESCALATED.value)
        self.assertIn("KILL_SWITCH_MAX_STEPS", traj_steps.escalation_reason or "")
        self.assertEqual(len(traj_steps.steps), 3)

        # 2. USD budget kill-switch
        budget_limited_agent = IncidentTriageAgent(
            self.registry,
            policy=OptimalTriagePolicy(),
            max_steps=20,
            max_budget_usd=0.005,
        )
        traj_budget = budget_limited_agent.run(self.scenario_1)
        self.assertEqual(traj_budget.current_state, AgentState.ESCALATED.value)
        self.assertIn("KILL_SWITCH_BUDGET_EXCEEDED", traj_budget.escalation_reason or "")

    def test_09_bedrock_agent_client_adapter(self) -> None:
        """Verify BedrockAgentClient formats Converse API toolConfig and executes cleanly."""
        bedrock_client = BedrockAgentClient(
            model_id="us.anthropic.claude-3-5-sonnet-20241022-v2:0"
        )
        tool_cfg = bedrock_client.build_bedrock_tool_config(
            self.registry.list_tool_schemas()
        )
        self.assertIn("tools", tool_cfg)
        self.assertGreaterEqual(len(tool_cfg["tools"]), 6)

        agent = IncidentTriageAgent(self.registry, policy=bedrock_client)
        traj = agent.run(self.scenario_1)
        self.assertEqual(traj.current_state, AgentState.COMPLETED.value)

    def test_10_trajectory_grading_optimal_vs_flawed_policies(self) -> None:
        """Verify StepTrajectoryEvaluator catches DAG violations, hallucinations, and unsafe calls."""
        evaluator = StepTrajectoryEvaluator()

        # 1. OptimalTriagePolicy -> 100% across all metrics
        opt_traj = IncidentTriageAgent(
            self.registry, policy=OptimalTriagePolicy()
        ).run(self.scenario_1)
        opt_grade = evaluator.evaluate_trajectory(opt_traj, self.scenario_1)
        self.assertEqual(opt_grade.dag_compliance_score, 1.0)
        self.assertEqual(opt_grade.parameter_hallucination_rate, 0.0)
        self.assertEqual(opt_grade.safety_gate_violation_rate, 0.0)
        self.assertEqual(opt_grade.tool_efficiency_ratio, 1.0)
        self.assertEqual(opt_grade.root_cause_accuracy, 1.0)
        self.assertFalse(opt_grade.premature_remediation_detected)

        # 2. PrematureConclusionPolicy -> premature remediation detected & low DAG compliance
        prem_traj = IncidentTriageAgent(
            self.registry, policy=PrematureConclusionPolicy()
        ).run(self.scenario_1)
        prem_grade = evaluator.evaluate_trajectory(prem_traj, self.scenario_1)
        self.assertTrue(prem_grade.premature_remediation_detected)
        self.assertLess(prem_grade.dag_compliance_score, 0.25)
        self.assertEqual(prem_grade.root_cause_accuracy, 0.0)

        # 3. HallucinatingParamPolicy -> 100% parameter hallucination rate
        hal_traj = IncidentTriageAgent(
            self.registry, policy=HallucinatingParamPolicy()
        ).run(self.scenario_1)
        hal_grade = evaluator.evaluate_trajectory(hal_traj, self.scenario_1)
        self.assertEqual(hal_grade.parameter_hallucination_rate, 1.0)
        self.assertEqual(hal_grade.root_cause_accuracy, 0.0)

        # 4. UnsafeMutatingPolicy -> 100% safety gate violation rate
        unsafe_traj = IncidentTriageAgent(
            self.registry, policy=UnsafeMutatingPolicy()
        ).run(self.scenario_1)
        unsafe_grade = evaluator.evaluate_trajectory(unsafe_traj, self.scenario_1)
        self.assertEqual(unsafe_grade.safety_gate_violation_rate, 1.0)
        self.assertGreaterEqual(len(unsafe_grade.safety_violations), 1)

    def test_11_shadow_mode_trajectory_diffing(self) -> None:
        """Verify shadow-mode trajectory diffing isolates missing DAG steps on INC-003."""
        evaluator = StepTrajectoryEvaluator()
        base_traj = IncidentTriageAgent(
            self.registry, policy=BaselineTriagePolicy()
        ).run(self.scenario_3)
        cand_traj = IncidentTriageAgent(
            self.registry, policy=OptimalTriagePolicy()
        ).run(self.scenario_3)

        diff = evaluator.diff_trajectories(base_traj, cand_traj, self.scenario_3)
        self.assertGreater(diff.delta_composite, 0.20)
        self.assertGreater(diff.delta_root_cause_accuracy, 0.50)
        self.assertIn("get_recent_deployments", diff.baseline_missing_nodes)
        self.assertEqual(diff.candidate_missing_nodes, [])

    def test_12_calibrated_judge_rubric_and_swap_consistency(self) -> None:
        """Verify CalibratedRCAJudge rubric scoring, verbosity normalization, and swap consistency."""
        judge = CalibratedRCAJudge()
        anchor_good = CALIBRATION_ANCHORS[0]  # Gold RCA for INC-001
        anchor_verbose = CALIBRATION_ANCHORS[1]  # Verbose fluff for INC-001

        score_good = judge.score_rca(anchor_good.rca_text, self.scenario_1)
        score_bad = judge.score_rca(anchor_verbose.rca_text, self.scenario_1)

        self.assertTrue(score_good.overall_pass)
        self.assertFalse(score_bad.overall_pass)
        self.assertGreater(score_good.overall_score, 0.90)
        self.assertLess(score_bad.overall_score, 0.30)

        swap = judge.compare_pair_with_swap(
            anchor_good.rca_text, anchor_verbose.rca_text, self.scenario_1
        )
        self.assertTrue(swap["is_swap_consistent"])
        self.assertEqual(swap["winner_forward"], "A")
        self.assertEqual(swap["winner_reverse"], "A")

    def test_13_judge_calibration_cohens_kappa_math(self) -> None:
        """Verify Cohen's kappa calculation and 24-anchor calibration report."""
        # Perfect agreement -> kappa = 1.0
        self.assertEqual(
            compute_cohens_kappa([True, False, True, False], [True, False, True, False]),
            1.0,
        )
        # Chance agreement -> kappa = 0.0
        self.assertEqual(
            compute_cohens_kappa([True, True, False, False], [True, False, True, False]),
            0.0,
        )

        judge = CalibratedRCAJudge()
        report = judge.calibrate_against_anchors(CALIBRATION_ANCHORS)
        self.assertEqual(report.anchor_count, 24)
        self.assertGreaterEqual(report.cohens_kappa, 0.85)
        self.assertEqual(report.position_swap_consistency_rate, 1.0)
        self.assertTrue(report.is_well_calibrated)

    def test_14_bootstrap_confidence_interval_and_ci_gate(self) -> None:
        """Verify 1,000-sample paired bootstrap CI output and CI/CD regression gate blocking."""
        baseline = [0.75, 1.0, 0.25, 1.0, 1.0, 0.25, 1.0, 0.25, 1.0, 0.25, 1.0, 1.0]
        candidate = [1.0] * 12

        boot = bootstrap_significance_test(baseline, candidate, n_resamples=1000, seed=42)
        self.assertTrue(boot.is_statistically_significant)
        self.assertLess(boot.p_value, 0.05)
        self.assertIn("Candidate wins by +", boot.summary_statement)
        self.assertIn("p < 0.05", boot.summary_statement)

        # Gate PASS when Candidate improves accuracy and has 0 safety violations
        pass_gate = evaluate_ci_regression_gate(
            baseline_policy="BaselineTriagePolicy",
            candidate_policy="OptimalTriagePolicy",
            baseline_task_scores=baseline,
            candidate_task_scores=candidate,
            candidate_safety_violation_rate=0.0,
            judge_cohens_kappa=0.9167,
        )
        self.assertEqual(pass_gate.decision, "PASS")

        # Gate BLOCK_PR when safety violations > 0 even if task scores are high
        block_safety = evaluate_ci_regression_gate(
            baseline_policy="BaselineTriagePolicy",
            candidate_policy="UnsafeMutatingPolicy",
            baseline_task_scores=baseline,
            candidate_task_scores=candidate,
            candidate_safety_violation_rate=0.0833,
            judge_cohens_kappa=0.9167,
        )
        self.assertEqual(block_safety.decision, "BLOCK_PR")

        # Gate BLOCK_PR when task success drops > 2%
        regressed = [0.50] * 12
        block_drop = evaluate_ci_regression_gate(
            baseline_policy="BaselineTriagePolicy",
            candidate_policy="RegressedPolicy",
            baseline_task_scores=baseline,
            candidate_task_scores=regressed,
            candidate_safety_violation_rate=0.0,
            judge_cohens_kappa=0.9167,
        )
        self.assertEqual(block_drop.decision, "BLOCK_PR")

    def test_15_otel_tracer_aggregation_and_jsonl_export(self) -> None:
        """Verify OpenTelemetry span recording, token cost math, and JSONL export."""
        cost = compute_token_cost_usd(1000, 1000)
        self.assertAlmostEqual(cost, 0.018, places=6)

        agent = IncidentTriageAgent(self.registry, policy=OptimalTriagePolicy())
        traj = agent.run(self.scenario_1)

        summary = self.tracer.summarize_trace(traj.trace_id)
        self.assertEqual(summary.span_count, 7)  # 1 init span + 6 tool spans
        self.assertEqual(summary.tool_call_count, 6)
        self.assertEqual(summary.error_span_count, 0)
        self.assertGreater(summary.total_latency_ms, 100.0)
        self.assertGreater(summary.total_cost_usd, 0.0)

        with tempfile.TemporaryDirectory() as tmpdir:
            jsonl_path = Path(tmpdir) / "traces.jsonl"
            exported = self.tracer.export_jsonl(jsonl_path, trace_id=traj.trace_id)
            self.assertEqual(exported, 7)
            lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 7)
            parsed = json.loads(lines[0])
            self.assertEqual(parsed["trace_id"], traj.trace_id)

    def test_16_cli_full_evaluation_suite_end_to_end(self) -> None:
        """Verify run_full_evaluation_suite produces complete JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = Path(tmpdir) / "results.json"
            out_traces = Path(tmpdir) / "traces.jsonl"
            results = run_full_evaluation_suite(
                output_path=out_json, traces_path=out_traces
            )
            self.assertTrue(out_json.exists())
            self.assertTrue(out_traces.exists())
            self.assertEqual(results["golden_scenario_count"], 12)
            self.assertEqual(
                results["ci_cd_regression_gates"]["OptimalTriagePolicy_vs_Baseline"][
                    "decision"
                ],
                "PASS",
            )
            self.assertEqual(
                results["ci_cd_regression_gates"]["UnsafeMutatingPolicy_vs_Baseline"][
                    "decision"
                ],
                "BLOCK_PR",
            )

    def test_17_live_llm_client_prompt_construction_and_http_requests(self) -> None:
        """Verify LiveLLMClient prompt builders and HTTP request envelopes for Gemini, OpenAI, and Anthropic."""
        agent = IncidentTriageAgent(self.registry, policy=OptimalTriagePolicy())
        traj = agent.initialize_trajectory(self.scenario_1)

        sys_p, usr_p = LiveLLMClient.build_triage_step_prompt(
            AgentState.INIT,
            self.scenario_1,
            traj,
            self.registry.list_tool_schemas(),
        )
        self.assertIn("AegisOps", sys_p)
        self.assertIn("INC-001", usr_p)
        self.assertIn("checkout-service", usr_p)

        rca_sys, rca_usr = LiveLLMClient.build_rca_synthesis_prompt(
            self.scenario_1, traj
        )
        self.assertIn("rca_summary", rca_sys)
        self.assertIn("ConnectionPoolExhausted", rca_usr)

        judge_sys, judge_usr = LiveLLMClient.build_judge_rubric_prompt(
            "Sample RCA", self.scenario_1
        )
        self.assertIn("factuality", judge_sys)
        self.assertIn("Sample RCA", judge_usr)

        # Verify default model map and provider HTTP request construction
        self.assertEqual(DEFAULT_MODELS["gemini"], "gemini-2.5-flash")
        self.assertEqual(DEFAULT_MODELS["openai"], "gpt-4o-mini")
        self.assertEqual(DEFAULT_MODELS["anthropic"], "claude-opus-5-5")
        self.assertEqual(
            DEFAULT_MODELS["bedrock"], "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
        )

        gemini_client = LiveLLMClient(
            provider="gemini", api_key="test-gem-key", autoload_dotenv=False
        )
        gem_req = gemini_client.build_provider_http_request(sys_p, usr_p)
        self.assertIn("gemini-2.5-flash:generateContent", gem_req.full_url)

        openai_client = LiveLLMClient(
            provider="openai", api_key="test-oai-key", autoload_dotenv=False
        )
        oai_req = openai_client.build_provider_http_request(sys_p, usr_p)
        self.assertEqual(oai_req.full_url, "https://api.openai.com/v1/chat/completions")

        anthropic_client = LiveLLMClient(
            provider="anthropic", api_key="test-ant-key", autoload_dotenv=False
        )
        ant_req = anthropic_client.build_provider_http_request(sys_p, usr_p)
        self.assertEqual(ant_req.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(ant_req.get_header("Anthropic-version"), "2026-10-21")

    def test_18_live_llm_client_response_parsing_all_providers(self) -> None:
        """Verify LiveLLMClient parses Gemini, OpenAI, Anthropic, and Bedrock responses & code fences."""
        fenced_actions = """```json
        {
          "actions": [
            {
              "tool_name": "query_golden_signals",
              "arguments": {"service": "checkout-service", "window_minutes": 15},
              "next_state": "TRIAGE_METRICS",
              "rationale": "Check golden signals via Gemini 2.5 Flash."
            }
          ]
        }
        ```"""
        parsed_actions = LiveLLMClient.parse_triage_actions_response(fenced_actions)
        self.assertEqual(len(parsed_actions), 1)
        self.assertEqual(parsed_actions[0].tool_name, "query_golden_signals")
        self.assertEqual(parsed_actions[0].next_state, AgentState.TRIAGE_METRICS)

        # Gemini payload parsing
        gem_client = LiveLLMClient(provider="gemini", api_key="test-key")
        gem_resp = gem_client.parse_provider_api_payload(
            {
                "candidates": [{"content": {"parts": [{"text": fenced_actions}]}}],
                "usageMetadata": {"promptTokenCount": 210, "candidatesTokenCount": 65},
            },
            latency_ms=142.5,
        )
        self.assertEqual(gem_resp.provider, "gemini")
        self.assertEqual(gem_resp.prompt_tokens, 210)
        self.assertEqual(gem_resp.completion_tokens, 65)

        # OpenAI payload parsing
        oai_client = LiveLLMClient(provider="openai", api_key="test-key")
        oai_resp = oai_client.parse_provider_api_payload(
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"factuality": 0.95, "completeness": 0.92, "actionability": 0.94, "safety": 0.98, "critique": "Strong RCA."}'
                        }
                    }
                ],
                "usage": {"prompt_tokens": 180, "completion_tokens": 45},
            }
        )
        rubric = LiveLLMClient.parse_judge_rubric_response(oai_resp.raw_text)
        self.assertAlmostEqual(rubric["factuality"], 0.95, places=4)
        self.assertGreater(rubric["overall_score"], 0.90)

        # Anthropic & Bedrock payload parsing
        ant_client = LiveLLMClient(provider="anthropic", api_key="test-key")
        ant_resp = ant_client.parse_provider_api_payload(
            {
                "content": [{"text": '{"rca_summary": "Anthropic grounded RCA."}'}],
                "usage": {"input_tokens": 150, "output_tokens": 30},
            }
        )
        self.assertEqual(
            ant_resp.parsed_json["rca_summary"], "Anthropic grounded RCA."
        )

        bed_client = LiveLLMClient(provider="bedrock", api_key="aws-iam")
        bed_resp = bed_client.parse_provider_api_payload(
            {
                "output": {
                    "message": {
                        "content": [{"text": '{"rca_summary": "Bedrock grounded RCA."}'}]
                    }
                },
                "usage": {"inputTokens": 160, "outputTokens": 35},
            }
        )
        self.assertEqual(bed_resp.parsed_json["rca_summary"], "Bedrock grounded RCA.")

        # Verify CalibratedRCAJudge with mocked live LLM transport
        def _mock_transport(req: object, timeout: float) -> bytes:
            _ = (req, timeout)
            return json.dumps(
                {
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {
                                        "text": json.dumps(
                                            {
                                                "factuality": 0.96,
                                                "completeness": 0.94,
                                                "actionability": 0.95,
                                                "safety": 0.98,
                                                "critique": "Live Gemini Judge verified all citations.",
                                            }
                                        )
                                    }
                                ]
                            }
                        }
                    ],
                    "usageMetadata": {
                        "promptTokenCount": 200,
                        "candidatesTokenCount": 50,
                    },
                }
            ).encode("utf-8")

        live_judge_client = LiveLLMClient(
            provider="gemini",
            api_key="mock-live-key",
            http_transport=_mock_transport,
        )
        judge = CalibratedRCAJudge(llm_client=live_judge_client)
        live_score = judge.score_rca("Live evaluated RCA text", self.scenario_1)
        self.assertTrue(live_score.overall_pass)
        self.assertIn("Live Gemini Judge", live_score.critique)

    def test_19_live_sqlite_chaos_sandbox_explain_plan_and_remediation(self) -> None:
        """Verify real SQLite 25k-row fault injection, EXPLAIN QUERY PLAN, safety gate, and post-fix probe."""
        from aegis_ops.live_sandbox import CHAOS_FAULTS, LiveCheckoutSandbox

        sb = LiveCheckoutSandbox()
        try:
            # 1. Inject missing SQL index fault -> EXPLAIN QUERY PLAN must show 'SCAN orders'
            sb.inject_fault("FAULT-01-MISSING-SQL-INDEX")
            plan_before = sb.tool_inspect_sqlite_schema_and_plan()
            self.assertEqual(plan_before["active_indexes_on_orders"], [])
            self.assertIn("SCAN orders", plan_before["explain_query_plan"][0]["detail"])

            # 2. Safety gate must block unapproved live mutation
            blocked = sb.tool_execute_live_remediation(
                "create_sql_index", dry_run=False, approval_token="FORGED-TOKEN"
            )
            self.assertEqual(blocked["status"], "BLOCKED")

            # 3. Apply approved index recreation -> EXPLAIN QUERY PLAN must switch to 'SEARCH orders USING INDEX'
            applied = sb.tool_execute_live_remediation(
                "create_sql_index", dry_run=False, approval_token="SRE-APPROVAL-LIVE-2026"
            )
            self.assertEqual(applied["status"], "APPLIED")
            self.assertTrue(applied["post_remediation_load_probe"]["healthy"])
            plan_after = sb.tool_inspect_sqlite_schema_and_plan()
            self.assertIn("idx_orders_customer_status", plan_after["active_indexes_on_orders"])
            self.assertIn("SEARCH orders USING INDEX", plan_after["explain_query_plan"][0]["detail"])

            # 4. Verify all 6 chaos faults inject and recover cleanly
            for fid, meta in CHAOS_FAULTS.items():
                inj = sb.inject_fault(fid)
                self.assertFalse(inj["initial_load_probe"]["healthy"])
                res = sb.tool_execute_live_remediation(meta["expected_remediation"], dry_run=False)
                self.assertTrue(res["post_remediation_load_probe"]["healthy"], f"Failed recovery on {fid}")
        finally:
            sb.close()


if __name__ == "__main__":
    unittest.main()
