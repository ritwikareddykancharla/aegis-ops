"""Model Context Protocol (MCP) deterministic tool servers for DevOps incident triage.

Implements three production-style MCP servers with strict JSON-Schema input validation,
structured error taxonomy, safety-gate enforcement on mutating actions, and OpenTelemetry
latency/token instrumentation:
1. `CloudWatchLogsMCP`: `query_error_logs`, `detect_error_signatures`
2. `PrometheusMetricsMCP`: `query_golden_signals`, `get_recent_deployments` (`GetRecentDeployments`)
3. `RunbookRemediationMCP`: `get_runbook`, `execute_remediation`
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from aegis_ops.golden_dataset import (
    GOLDEN_SCENARIOS,
    SCENARIO_BY_SERVICE,
    IncidentScenario,
)
from aegis_ops.otel_tracer import OTelTracer, compute_token_cost_usd


CANONICAL_ERROR_SIGNATURES: tuple[str, ...] = (
    "OOMKilled",
    "ConnectionPoolExhausted",
    "DeadlockDetected",
    "TLSHandshakeTimeout",
    "IAMAccessDenied",
    "HotPartitionThrottled",
    "NATPortExhausted",
    "BGPFlapDetected",
    "DNSResolutionFailure",
    "DiskIOPSThrottled",
    "RedisEvictionSpike",
    "KMSKeyDisabled",
)

SUPPORTED_REMEDIATION_ACTIONS: tuple[str, ...] = (
    "rollback_deployment",
    "scale_ASG_capacity",
    "rotate_expired_cert",
    "drain_az_traffic",
    "revert_iam_policy",
    "enable_adaptive_capacity",
    "allocate_secondary_nat_eip",
    "flush_coredns_cache",
    "provision_ebs_io2_iops",
    "scale_elasticache_shards",
)


class MCPValidationError(ValueError):
    """Raised when tool arguments violate the declared MCP JSON-Schema."""

    def __init__(self, message: str, field_path: str = "") -> None:
        super().__init__(message)
        self.field_path = field_path
        self.message = message


class SafetyGateViolationError(PermissionError):
    """Raised when a mutating remediation action is invoked without a valid approval token."""


def validate_json_schema(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Validate a Python object against a subset of JSON Schema Draft-07."""
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(instance, dict):
            raise MCPValidationError(
                f"Expected object at {path}, got {type(instance).__name__}", path
            )
        required = schema.get("required", [])
        for req_key in required:
            if req_key not in instance or instance[req_key] is None:
                raise MCPValidationError(
                    f"Missing required property '{req_key}' at {path}",
                    f"{path}.{req_key}",
                )
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = set(instance.keys()) - set(properties.keys())
            if unknown:
                first_unknown = sorted(unknown)[0]
                raise MCPValidationError(
                    f"Unknown property '{first_unknown}' is not allowed at {path}",
                    f"{path}.{first_unknown}",
                )
        for key, value in instance.items():
            if key in properties and value is not None:
                validate_json_schema(value, properties[key], f"{path}.{key}")

    elif expected_type == "string":
        if not isinstance(instance, str):
            raise MCPValidationError(
                f"Expected string at {path}, got {type(instance).__name__}", path
            )
        min_len = schema.get("minLength")
        if min_len is not None and len(instance.strip()) < min_len:
            raise MCPValidationError(
                f"String at {path} must have minLength >= {min_len}", path
            )
        enum_vals = schema.get("enum")
        if enum_vals is not None and instance not in enum_vals:
            raise MCPValidationError(
                f"Value '{instance}' at {path} not in allowed enum {enum_vals}", path
            )
        pattern = schema.get("pattern")
        if pattern is not None and not re.match(pattern, instance):
            raise MCPValidationError(
                f"Value '{instance}' at {path} does not match pattern '{pattern}'", path
            )

    elif expected_type == "integer":
        if isinstance(instance, bool) or not isinstance(instance, int):
            raise MCPValidationError(
                f"Expected integer at {path}, got {type(instance).__name__}", path
            )
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            raise MCPValidationError(
                f"Integer {instance} at {path} is below minimum {minimum}", path
            )
        maximum = schema.get("maximum")
        if maximum is not None and instance > maximum:
            raise MCPValidationError(
                f"Integer {instance} at {path} exceeds maximum {maximum}", path
            )

    elif expected_type == "number":
        if isinstance(instance, bool) or not isinstance(instance, (int, float)):
            raise MCPValidationError(
                f"Expected number at {path}, got {type(instance).__name__}", path
            )
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            raise MCPValidationError(
                f"Number {instance} at {path} is below minimum {minimum}", path
            )

    elif expected_type == "boolean":
        if not isinstance(instance, bool):
            raise MCPValidationError(
                f"Expected boolean at {path}, got {type(instance).__name__}", path
            )


@dataclass
class MCPToolResult:
    """Standardized response envelope returned by every MCP tool call."""

    server_name: str
    tool_name: str
    arguments: dict[str, Any]
    status: str  # SUCCESS, SCHEMA_VALIDATION_ERROR, RESOURCE_NOT_FOUND, SAFETY_GATE_VIOLATION
    data: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    span_id: str | None = None

    @property
    def is_ok(self) -> bool:
        return self.status == "SUCCESS"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CloudWatchLogsMCP:
    """MCP Server for querying AWS CloudWatch error logs and detecting failure signatures."""

    SERVER_NAME = "cloudwatch-logs-mcp"

    SCHEMAS: dict[str, dict[str, Any]] = {
        "query_error_logs": {
            "type": "object",
            "required": ["service", "time_window_minutes"],
            "additionalProperties": False,
            "properties": {
                "service": {"type": "string", "minLength": 2},
                "time_window_minutes": {"type": "integer", "minimum": 1, "maximum": 1440},
                "trace_id": {"type": "string", "minLength": 3},
                "severity": {"type": "string", "enum": ["WARN", "ERROR", "FATAL"]},
            },
        },
        "detect_error_signatures": {
            "type": "object",
            "required": ["service"],
            "additionalProperties": False,
            "properties": {
                "service": {"type": "string", "minLength": 2},
                "time_window_minutes": {"type": "integer", "minimum": 1, "maximum": 1440},
            },
        },
    }

    def __init__(self, scenarios: list[IncidentScenario] | None = None) -> None:
        self._scenarios = scenarios or GOLDEN_SCENARIOS
        self._by_service = {s.service: s for s in self._scenarios}

    def query_error_logs(self, arguments: dict[str, Any]) -> MCPToolResult:
        """Query structured CloudWatch error log events by service, window, and optional trace_id."""
        validate_json_schema(arguments, self.SCHEMAS["query_error_logs"])
        service = arguments["service"]
        window = arguments["time_window_minutes"]
        trace_filter = arguments.get("trace_id")
        sev_filter = arguments.get("severity")

        scenario = self._by_service.get(service)
        if scenario is None:
            return MCPToolResult(
                server_name=self.SERVER_NAME,
                tool_name="query_error_logs",
                arguments=arguments,
                status="RESOURCE_NOT_FOUND",
                error_code="LogGroupNotFoundException",
                error_message=f"CloudWatch log group '/aws/eks/{service}' does not exist.",
                latency_ms=18.4,
                prompt_tokens=110,
                completion_tokens=45,
                cost_usd=compute_token_cost_usd(110, 45),
            )

        logs = list(scenario.logs_payload)
        if trace_filter:
            logs = [entry for entry in logs if entry.get("trace_id") == trace_filter]
        if sev_filter:
            logs = [entry for entry in logs if entry.get("severity") == sev_filter]

        return MCPToolResult(
            server_name=self.SERVER_NAME,
            tool_name="query_error_logs",
            arguments=arguments,
            status="SUCCESS",
            data={
                "log_group": f"/aws/service/{service}/errors",
                "time_window_minutes": window,
                "matched_event_count": len(logs),
                "events": logs,
            },
            latency_ms=42.8,
            prompt_tokens=185,
            completion_tokens=140,
            cost_usd=compute_token_cost_usd(185, 140),
        )

    def detect_error_signatures(self, arguments: dict[str, Any]) -> MCPToolResult:
        """Cluster CloudWatch error logs against canonical failure signatures."""
        validate_json_schema(arguments, self.SCHEMAS["detect_error_signatures"])
        service = arguments["service"]
        scenario = self._by_service.get(service)
        if scenario is None:
            return MCPToolResult(
                server_name=self.SERVER_NAME,
                tool_name="detect_error_signatures",
                arguments=arguments,
                status="RESOURCE_NOT_FOUND",
                error_code="ServiceTelemetryNotFoundError",
                error_message=f"No log stream found for service '{service}'.",
                latency_ms=16.2,
                prompt_tokens=95,
                completion_tokens=40,
                cost_usd=compute_token_cost_usd(95, 40),
            )

        detected_sig = scenario.error_signature
        sample_msg = scenario.logs_payload[0]["message"]
        return MCPToolResult(
            server_name=self.SERVER_NAME,
            tool_name="detect_error_signatures",
            arguments=arguments,
            status="SUCCESS",
            data={
                "service": service,
                "dominant_signature": detected_sig,
                "is_canonical_signature": detected_sig in CANONICAL_ERROR_SIGNATURES,
                "occurrence_count": 414,
                "confidence": 0.99,
                "sample_log": sample_msg,
                "trace_ids": [entry["trace_id"] for entry in scenario.logs_payload],
            },
            latency_ms=36.5,
            prompt_tokens=190,
            completion_tokens=115,
            cost_usd=compute_token_cost_usd(190, 115),
        )


class PrometheusMetricsMCP:
    """MCP Server for querying golden signals and deployment/configuration change events."""

    SERVER_NAME = "prometheus-metrics-mcp"

    SCHEMAS: dict[str, dict[str, Any]] = {
        "query_golden_signals": {
            "type": "object",
            "required": ["service", "window_minutes"],
            "additionalProperties": False,
            "properties": {
                "service": {"type": "string", "minLength": 2},
                "window_minutes": {"type": "integer", "minimum": 1, "maximum": 1440},
            },
        },
        "get_recent_deployments": {
            "type": "object",
            "required": ["service", "lookback_minutes"],
            "additionalProperties": False,
            "properties": {
                "service": {"type": "string", "minLength": 2},
                "lookback_minutes": {"type": "integer", "minimum": 5, "maximum": 10080},
            },
        },
    }

    def __init__(self, scenarios: list[IncidentScenario] | None = None) -> None:
        self._scenarios = scenarios or GOLDEN_SCENARIOS
        self._by_service = {s.service: s for s in self._scenarios}

    def query_golden_signals(self, arguments: dict[str, Any]) -> MCPToolResult:
        """Query SRE golden signals (latency, errors, saturation, DB pool, throttling)."""
        validate_json_schema(arguments, self.SCHEMAS["query_golden_signals"])
        service = arguments["service"]
        window = arguments["window_minutes"]

        scenario = self._by_service.get(service)
        if scenario is None:
            return MCPToolResult(
                server_name=self.SERVER_NAME,
                tool_name="query_golden_signals",
                arguments=arguments,
                status="RESOURCE_NOT_FOUND",
                error_code="MetricNamespaceNotFoundError",
                error_message=f"No Prometheus scrape target registered for service '{service}'.",
                latency_ms=14.1,
                prompt_tokens=100,
                completion_tokens=38,
                cost_usd=compute_token_cost_usd(100, 38),
            )

        metrics = dict(scenario.metrics_payload)
        return MCPToolResult(
            server_name=self.SERVER_NAME,
            tool_name="query_golden_signals",
            arguments=arguments,
            status="SUCCESS",
            data={
                "service": service,
                "region": scenario.region,
                "window_minutes": window,
                "golden_signals": metrics,
            },
            latency_ms=29.4,
            prompt_tokens=160,
            completion_tokens=120,
            cost_usd=compute_token_cost_usd(160, 120),
        )

    def get_recent_deployments(self, arguments: dict[str, Any]) -> MCPToolResult:
        """Query recent code deployments, IAM policy updates, and infrastructure mutations."""
        validate_json_schema(arguments, self.SCHEMAS["get_recent_deployments"])
        service = arguments["service"]
        lookback = arguments["lookback_minutes"]

        scenario = self._by_service.get(service)
        if scenario is None:
            return MCPToolResult(
                server_name=self.SERVER_NAME,
                tool_name="get_recent_deployments",
                arguments=arguments,
                status="RESOURCE_NOT_FOUND",
                error_code="DeploymentServiceNotFoundError",
                error_message=f"Service '{service}' not found in deployment change registry.",
                latency_ms=15.0,
                prompt_tokens=98,
                completion_tokens=40,
                cost_usd=compute_token_cost_usd(98, 40),
            )

        deployments = list(scenario.deployments_payload)
        suspect = next((d for d in deployments if d.get("is_suspect")), deployments[0])
        return MCPToolResult(
            server_name=self.SERVER_NAME,
            tool_name="get_recent_deployments",
            arguments=arguments,
            status="SUCCESS",
            data={
                "service": service,
                "lookback_minutes": lookback,
                "deployments": deployments,
                "primary_suspect_change_id": suspect["change_id"],
                "primary_suspect_summary": suspect["summary"],
            },
            latency_ms=33.7,
            prompt_tokens=175,
            completion_tokens=135,
            cost_usd=compute_token_cost_usd(175, 135),
        )


class RunbookRemediationMCP:
    """MCP Server for retrieving SOP runbooks and executing safety-gated remediations."""

    SERVER_NAME = "runbook-remediation-mcp"

    SCHEMAS: dict[str, dict[str, Any]] = {
        "get_runbook": {
            "type": "object",
            "required": ["service", "error_signature"],
            "additionalProperties": False,
            "properties": {
                "service": {"type": "string", "minLength": 2},
                "error_signature": {
                    "type": "string",
                    "enum": list(CANONICAL_ERROR_SIGNATURES),
                },
            },
        },
        "execute_remediation": {
            "type": "object",
            "required": ["service", "action", "target", "dry_run"],
            "additionalProperties": False,
            "properties": {
                "service": {"type": "string", "minLength": 2},
                "action": {
                    "type": "string",
                    "enum": list(SUPPORTED_REMEDIATION_ACTIONS),
                },
                "target": {"type": "string", "minLength": 3},
                "dry_run": {"type": "boolean"},
                "approval_token": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
    }

    def __init__(self, scenarios: list[IncidentScenario] | None = None) -> None:
        self._scenarios = scenarios or GOLDEN_SCENARIOS
        self._by_service = {s.service: s for s in self._scenarios}
        self._valid_tokens = {s.approval_token for s in self._scenarios}

    def is_valid_approval_token(self, token: str | None, service: str | None = None) -> bool:
        """Verify whether an approval token is authorized for mutating execution."""
        if not token or not isinstance(token, str):
            return False
        if service and service in self._by_service:
            return token == self._by_service[service].approval_token
        return token in self._valid_tokens or bool(
            re.match(r"^APPROVAL-SRE-INC\d{3}-\d{4}$", token)
        )

    def get_runbook(self, arguments: dict[str, Any]) -> MCPToolResult:
        """Fetch standard operating runbook for a given service and error signature."""
        validate_json_schema(arguments, self.SCHEMAS["get_runbook"])
        service = arguments["service"]
        signature = arguments["error_signature"]

        scenario = self._by_service.get(service)
        if scenario is None or scenario.error_signature != signature:
            return MCPToolResult(
                server_name=self.SERVER_NAME,
                tool_name="get_runbook",
                arguments=arguments,
                status="RESOURCE_NOT_FOUND",
                error_code="RunbookNotFoundError",
                error_message=(
                    f"No matching SOP runbook for service='{service}' "
                    f"and error_signature='{signature}'."
                ),
                latency_ms=19.8,
                prompt_tokens=115,
                completion_tokens=45,
                cost_usd=compute_token_cost_usd(115, 45),
            )

        return MCPToolResult(
            server_name=self.SERVER_NAME,
            tool_name="get_runbook",
            arguments=arguments,
            status="SUCCESS",
            data=dict(scenario.runbook_payload),
            latency_ms=26.1,
            prompt_tokens=170,
            completion_tokens=150,
            cost_usd=compute_token_cost_usd(170, 150),
        )

    def execute_remediation(
        self,
        arguments: dict[str, Any],
        require_approval_token: bool = True,
    ) -> MCPToolResult:
        """Execute a dry-run or approval-gated remediation action."""
        validate_json_schema(arguments, self.SCHEMAS["execute_remediation"])
        service = arguments["service"]
        action = arguments["action"]
        target = arguments["target"]
        dry_run = arguments["dry_run"]
        token = arguments.get("approval_token")

        # Mandatory safety gate check on any non-dry-run mutating call
        if not dry_run and require_approval_token:
            if not self.is_valid_approval_token(token, service=service):
                return MCPToolResult(
                    server_name=self.SERVER_NAME,
                    tool_name="execute_remediation",
                    arguments=arguments,
                    status="SAFETY_GATE_VIOLATION",
                    error_code="SafetyGateApprovalRequiredError",
                    error_message=(
                        f"Blocked unapproved mutating remediation '{action}' on '{target}': "
                        "dry_run=False requires a valid SRE approval_token."
                    ),
                    data={
                        "safety_gate_triggered": True,
                        "action": action,
                        "target": target,
                        "dry_run": dry_run,
                        "provided_token": token,
                    },
                    latency_ms=11.2,
                    prompt_tokens=140,
                    completion_tokens=60,
                    cost_usd=compute_token_cost_usd(140, 60),
                )

        scenario = self._by_service.get(service)
        if scenario is None:
            return MCPToolResult(
                server_name=self.SERVER_NAME,
                tool_name="execute_remediation",
                arguments=arguments,
                status="RESOURCE_NOT_FOUND",
                error_code="TargetServiceNotFoundError",
                error_message=f"Cannot execute '{action}': unknown service '{service}'.",
                latency_ms=14.5,
                prompt_tokens=120,
                completion_tokens=45,
                cost_usd=compute_token_cost_usd(120, 45),
            )

        matches_ground_truth = (
            action == scenario.remediation_action and target == scenario.remediation_target
        )
        execution_mode = "DRY_RUN_VALIDATED" if dry_run else "MUTATION_EXECUTED_WITH_APPROVAL"
        return MCPToolResult(
            server_name=self.SERVER_NAME,
            tool_name="execute_remediation",
            arguments=arguments,
            status="SUCCESS",
            data={
                "service": service,
                "action": action,
                "target": target,
                "dry_run": dry_run,
                "execution_mode": execution_mode,
                "approval_verified": not dry_run,
                "matches_expected_remediation": matches_ground_truth,
                "pre_flight_checks_passed": True,
                "estimated_recovery_seconds": 45,
            },
            latency_ms=54.3,
            prompt_tokens=210,
            completion_tokens=130,
            cost_usd=compute_token_cost_usd(210, 130),
        )


class MCPToolRegistry:
    """Unified dispatcher across CloudWatchLogsMCP, PrometheusMetricsMCP, and RunbookRemediationMCP."""

    def __init__(
        self,
        scenarios: list[IncidentScenario] | None = None,
        tracer: OTelTracer | None = None,
    ) -> None:
        self.scenarios = scenarios or GOLDEN_SCENARIOS
        self.tracer = tracer or OTelTracer()
        self.cloudwatch = CloudWatchLogsMCP(self.scenarios)
        self.prometheus = PrometheusMetricsMCP(self.scenarios)
        self.runbook = RunbookRemediationMCP(self.scenarios)
        self._call_history: list[MCPToolResult] = []

    def list_tool_schemas(self) -> dict[str, dict[str, Any]]:
        """Return JSON schemas for all registered MCP tools."""
        schemas: dict[str, dict[str, Any]] = {}
        schemas.update(self.cloudwatch.SCHEMAS)
        schemas.update(self.prometheus.SCHEMAS)
        schemas["GetRecentDeployments"] = self.prometheus.SCHEMAS["get_recent_deployments"]
        schemas.update(self.runbook.SCHEMAS)
        return schemas

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        trace_id: str = "default-trace",
        parent_span_id: str | None = None,
        agent_state: str = "TRIAGE",
    ) -> MCPToolResult:
        """Validate schema, invoke the matching MCP server tool, and record an OTelSpan."""
        canonical_name = (
            "get_recent_deployments"
            if tool_name == "GetRecentDeployments"
            else tool_name
        )

        try:
            if canonical_name == "query_error_logs":
                result = self.cloudwatch.query_error_logs(arguments)
            elif canonical_name == "detect_error_signatures":
                result = self.cloudwatch.detect_error_signatures(arguments)
            elif canonical_name == "query_golden_signals":
                result = self.prometheus.query_golden_signals(arguments)
            elif canonical_name == "get_recent_deployments":
                result = self.prometheus.get_recent_deployments(arguments)
            elif canonical_name == "get_runbook":
                result = self.runbook.get_runbook(arguments)
            elif canonical_name == "execute_remediation":
                result = self.runbook.execute_remediation(arguments)
            else:
                result = MCPToolResult(
                    server_name="mcp-router",
                    tool_name=tool_name,
                    arguments=arguments,
                    status="SCHEMA_VALIDATION_ERROR",
                    error_code="UnknownToolError",
                    error_message=f"Tool '{tool_name}' is not registered on any MCP server.",
                    latency_ms=4.2,
                    prompt_tokens=60,
                    completion_tokens=20,
                    cost_usd=compute_token_cost_usd(60, 20),
                )
        except MCPValidationError as exc:
            result = MCPToolResult(
                server_name="mcp-schema-validator",
                tool_name=canonical_name,
                arguments=arguments,
                status="SCHEMA_VALIDATION_ERROR",
                error_code="JSONSchemaValidationError",
                error_message=exc.message,
                data={"invalid_field_path": exc.field_path},
                latency_ms=5.5,
                prompt_tokens=85,
                completion_tokens=30,
                cost_usd=compute_token_cost_usd(85, 30),
            )

        span = self.tracer.record_span(
            trace_id=trace_id,
            tool_name=canonical_name,
            parent_span_id=parent_span_id,
            agent_state=agent_state,
            latency_ms=result.latency_ms,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
            cost_usd=result.cost_usd,
            status_code="OK" if result.is_ok else "ERROR",
            error_message=result.error_message,
            attributes={
                "mcp.server": result.server_name,
                "mcp.status": result.status,
                "mcp.arguments": arguments,
            },
        )
        result.span_id = span.span_id
        self._call_history.append(result)
        return result

    @property
    def call_history(self) -> list[MCPToolResult]:
        return list(self._call_history)
