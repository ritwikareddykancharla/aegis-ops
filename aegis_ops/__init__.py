"""AegisOps: Autonomous DevOps Incident Triage Agent, Step-Level Trajectory Grading Engine & Calibrated LLM-as-a-Judge."""

from aegis_ops.calibrated_judge import (
    BootstrapSignificanceResult,
    CalibratedRCAJudge,
    CIRegressionGateResult,
    JudgeCalibrationReport,
    RCARubricScore,
    bootstrap_significance_test,
    compute_cohens_kappa,
    evaluate_ci_regression_gate,
)
from aegis_ops.golden_dataset import (
    CALIBRATION_ANCHORS,
    GOLDEN_SCENARIOS,
    SCENARIO_BY_ID,
    SCENARIO_BY_SERVICE,
    CalibrationAnchor,
    DAGSpec,
    IncidentScenario,
)
from aegis_ops.llm_client import DEFAULT_MODELS, LLMResponse, LiveLLMClient
from aegis_ops.mcp_servers import (
    CloudWatchLogsMCP,
    MCPToolRegistry,
    MCPToolResult,
    MCPValidationError,
    PrometheusMetricsMCP,
    RunbookRemediationMCP,
    validate_json_schema,
)
from aegis_ops.otel_tracer import OTelSpan, OTelTracer, TraceSummary
from aegis_ops.trajectory_eval import (
    PolicySuiteSummary,
    StepTrajectoryEvaluator,
    TrajectoryDiffReport,
    TrajectoryGrade,
)
from aegis_ops.triage_agent import (
    AgentState,
    AgentTrajectory,
    BaselineTriagePolicy,
    BedrockAgentClient,
    HallucinatingParamPolicy,
    IncidentTriageAgent,
    OptimalTriagePolicy,
    PrematureConclusionPolicy,
    UnsafeMutatingPolicy,
)

__version__ = "0.1.0"

__all__ = [
    "AgentState",
    "AgentTrajectory",
    "BaselineTriagePolicy",
    "BedrockAgentClient",
    "BootstrapSignificanceResult",
    "CALIBRATION_ANCHORS",
    "CIRegressionGateResult",
    "CalibratedRCAJudge",
    "CalibrationAnchor",
    "CloudWatchLogsMCP",
    "DAGSpec",
    "DEFAULT_MODELS",
    "GOLDEN_SCENARIOS",
    "HallucinatingParamPolicy",
    "IncidentScenario",
    "IncidentTriageAgent",
    "JudgeCalibrationReport",
    "LLMResponse",
    "LiveLLMClient",
    "MCPToolRegistry",
    "MCPToolResult",
    "MCPValidationError",
    "OTelSpan",
    "OTelTracer",
    "OptimalTriagePolicy",
    "PolicySuiteSummary",
    "PrematureConclusionPolicy",
    "PrometheusMetricsMCP",
    "RCARubricScore",
    "RunbookRemediationMCP",
    "SCENARIO_BY_ID",
    "SCENARIO_BY_SERVICE",
    "StepTrajectoryEvaluator",
    "TraceSummary",
    "TrajectoryDiffReport",
    "TrajectoryGrade",
    "UnsafeMutatingPolicy",
    "bootstrap_significance_test",
    "compute_cohens_kappa",
    "evaluate_ci_regression_gate",
    "validate_json_schema",
]
