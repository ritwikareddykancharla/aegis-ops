"""Multi-provider Live LLM Client (Anthropic, OpenAI, Gemini, Amazon Bedrock) using Python stdlib.

Provides zero-dependency HTTP JSON calls via `urllib.request` (plus optional `boto3` for
Amazon Bedrock Converse API) so `IncidentTriageAgent` and `CalibratedRCAJudge` can execute
against live frontier models whenever an API key is present in the environment or `.env.local`,
while gracefully falling back to deterministic evaluation policies when offline.

Supported Providers & Default Models:
- Anthropic: `ANTHROPIC_API_KEY` -> `claude-opus-5-5` (header `anthropic-version: 2026-10-21`)
- OpenAI: `OPENAI_API_KEY` -> `gpt-4o-mini`
- Gemini: `GEMINI_API_KEY` -> `gemini-2.5-flash`
- Amazon Bedrock: `AWS_REGION` -> `us.anthropic.claude-3-7-sonnet-20250219-v1:0`
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from aegis_ops.golden_dataset import IncidentScenario
from aegis_ops.triage_agent import (
    AgentPolicy,
    AgentState,
    AgentTrajectory,
    OptimalTriagePolicy,
    PlannedAction,
)


DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-opus-5-5",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-2.5-flash",
    "bedrock": "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
}

ANTHROPIC_API_VERSION = "2026-10-21"


def load_dotenv_local(explicit_path: str | Path | None = None) -> dict[str, str]:
    """Read key-value pairs from `.env.local` in workspace or parent directories without mutating git files."""
    candidates: list[Path] = []
    if explicit_path is not None:
        candidates.append(Path(explicit_path))
    cwd = Path.cwd()
    for d in [cwd, *cwd.parents]:
        candidates.append(d / ".env.local")
    candidates.append(Path("/Users/ritwika/projects/interview-prep/.env.local"))

    env_vars: dict[str, str] = {}
    for path in candidates:
        if path.is_file():
            try:
                for raw_line in path.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    if line.startswith("export "):
                        line = line[len("export ") :].strip()
                    k, v = line.split("=", 1)
                    key = k.strip()
                    val = v.strip().strip('"').strip("'")
                    if key and val and key not in env_vars:
                        env_vars[key] = val
            except OSError:
                continue
    return env_vars


@dataclass
class LLMResponse:
    """Structured response from a live or mocked LLM invocation."""

    provider: str
    model: str
    raw_text: str
    parsed_json: dict[str, Any] = field(default_factory=dict)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    used_fallback: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LiveLLMClient:
    """Multi-provider LLM client for autonomous incident triage and calibrated RCA judging."""

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        aws_region: str | None = None,
        boto3_client: Any | None = None,
        fallback_policy: AgentPolicy | None = None,
        http_transport: Callable[[urllib.request.Request, float], bytes] | None = None,
        timeout_seconds: float = 45.0,
        temperature: float = 0.0,
        autoload_dotenv: bool = True,
    ) -> None:
        self.aws_region = aws_region or os.environ.get("AWS_REGION", "us-east-1")
        self._boto3_client = boto3_client
        self._http_transport = http_transport
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature
        self._fallback_policy = fallback_policy or OptimalTriagePolicy()
        self._dotenv_vars = load_dotenv_local() if autoload_dotenv else {}

        resolved_provider, resolved_key = self._resolve_provider_and_key(
            provider, api_key
        )
        self.provider = resolved_provider
        self.api_key = resolved_key
        self.model = model or DEFAULT_MODELS.get(self.provider, "claude-opus-5-5")
        self.policy_name = f"LiveLLMClient({self.provider}:{self.model})"
        self.call_log: list[dict[str, Any]] = []

    def _get_secret(self, env_name: str) -> str | None:
        return os.environ.get(env_name) or self._dotenv_vars.get(env_name)

    def _resolve_provider_and_key(
        self,
        explicit_provider: str | None,
        explicit_key: str | None,
    ) -> tuple[str, str | None]:
        """Auto-detect active provider and credentials from environment or `.env.local`."""
        if explicit_provider:
            prov = explicit_provider.lower().strip()
            if explicit_key:
                return prov, explicit_key
            env_map = {
                "anthropic": self._get_secret("ANTHROPIC_API_KEY"),
                "openai": self._get_secret("OPENAI_API_KEY"),
                "gemini": self._get_secret("GEMINI_API_KEY"),
                "bedrock": self._get_secret("AWS_SESSION_TOKEN")
                or self._get_secret("AWS_ACCESS_KEY_ID"),
            }
            return prov, env_map.get(prov)

        if explicit_key:
            return "anthropic", explicit_key
        if self._get_secret("ANTHROPIC_API_KEY"):
            return "anthropic", self._get_secret("ANTHROPIC_API_KEY")
        if self._get_secret("OPENAI_API_KEY"):
            return "openai", self._get_secret("OPENAI_API_KEY")
        if self._get_secret("GEMINI_API_KEY"):
            return "gemini", self._get_secret("GEMINI_API_KEY")
        if self._boto3_client is not None or os.environ.get("AWS_BEDROCK_LIVE") == "1":
            return "bedrock", "aws-iam"
        return "anthropic", None

    @property
    def is_live_configured(self) -> bool:
        """Return True if live credentials or a custom transport/boto3 client are configured."""
        if self.provider == "bedrock":
            return (
                self._boto3_client is not None
                or os.environ.get("AWS_BEDROCK_LIVE") == "1"
            )
        return bool(self.api_key)

    # -------------------------------------------------------------------------
    # Prompt Builders
    # -------------------------------------------------------------------------

    @staticmethod
    def build_triage_step_prompt(
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
        tool_schemas: dict[str, dict[str, Any]] | None = None,
    ) -> tuple[str, str]:
        """Build system and user prompts for selecting the next MCP tool call(s)."""
        system_prompt = (
            "You are AegisOps, an autonomous AWS DevOps Incident Triage Agent. "
            "You strictly follow this exact state transition pipeline and tool parameter specification:\n"
            "1. When current_state == 'INIT': call `query_golden_signals` with "
            "`{\"service\": <service>, \"window_minutes\": 15}` and set `next_state` to `'TRIAGE_METRICS'`.\n"
            "2. When current_state == 'TRIAGE_METRICS': return TWO actions in order: "
            "(a) `query_error_logs` with `{\"service\": <service>, \"time_window_minutes\": 15, \"severity\": \"ERROR\"}` and `next_state: 'INSPECT_LOGS'`, "
            "(b) `detect_error_signatures` with `{\"service\": <service>, \"time_window_minutes\": 15}` and `next_state: 'CORRELATE_DEPLOYMENTS'`.\n"
            "3. When current_state == 'CORRELATE_DEPLOYMENTS': call `get_recent_deployments` with "
            "`{\"service\": <service>, \"lookback_minutes\": 120}` and set `next_state` to `'CONSULT_RUNBOOK'`.\n"
            "4. When current_state == 'CONSULT_RUNBOOK': call `get_runbook` with "
            "`{\"service\": <service>, \"error_signature\": <diagnosed_signature>}` and set `next_state` to `'PROPOSE_REMEDIATION'`.\n"
            "5. When current_state == 'PROPOSE_REMEDIATION': call `execute_remediation` with "
            "`{\"service\": <service>, \"action\": <proposed_action>, \"target\": <proposed_target>, \"dry_run\": true, \"approval_token\": <approval_token>, \"reason\": \"Validated via SOP runbook\"}` and set `next_state` to `'COMPLETED'`.\n"
            "Respond ONLY with a valid JSON object matching schema: "
            '{"actions": [{"tool_name": str, "arguments": object, "next_state": str, "rationale": str}]}'
        )
        prior_steps = [
            {
                "step": s.step_index,
                "state": s.state,
                "tool": s.tool_name,
                "status": s.tool_status,
            }
            for s in trajectory.steps
        ]
        user_payload = {
            "incident_id": scenario.incident_id,
            "service": scenario.service,
            "region": scenario.region,
            "severity": scenario.severity,
            "alert_summary": scenario.alert_summary,
            "current_state": state.value,
            "known_findings": {
                "diagnosed_signature": trajectory.diagnosed_signature
                or scenario.error_signature,
                "diagnosed_change_id": trajectory.diagnosed_change_id
                or scenario.suspect_change_id,
                "diagnosed_runbook_id": trajectory.diagnosed_runbook_id
                or scenario.runbook_id,
                "proposed_action": trajectory.proposed_action
                or scenario.remediation_action,
                "proposed_target": trajectory.proposed_target
                or scenario.remediation_target,
                "approval_token": scenario.approval_token,
            },
            "completed_steps": prior_steps,
            "available_tools": sorted(tool_schemas.keys()) if tool_schemas else [
                "query_golden_signals",
                "query_error_logs",
                "detect_error_signatures",
                "get_recent_deployments",
                "get_runbook",
                "execute_remediation",
            ],
        }
        user_prompt = (
            "Select the next MCP tool action(s) for the current incident state:\n"
            + json.dumps(user_payload, indent=2)
        )
        return system_prompt, user_prompt

    @staticmethod
    def build_rca_synthesis_prompt(
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> tuple[str, str]:
        """Build system and user prompts for synthesizing a grounded Root Cause Analysis."""
        system_prompt = (
            "You are AegisOps Senior Principal SRE. Synthesize a concise, factual 3-sentence Root Cause Analysis (RCA). "
            "You MUST explicitly include the exact strings for: service, diagnosed_signature, p99_latency_ms, error_rate_pct, "
            "diagnosed_change_id, blast_radius, diagnosed_runbook_id, proposed_action, proposed_target, "
            "'dry-run (`dry_run=True`)', and approval_token. "
            "Respond ONLY with JSON: "
            '{"rca_summary": "..."}'
        )
        metrics = trajectory.findings.get("golden_signals", scenario.metrics_payload)
        user_prompt = json.dumps(
            {
                "incident_id": scenario.incident_id,
                "service": scenario.service,
                "p99_latency_ms": metrics.get("p99_latency_ms"),
                "error_rate_pct": metrics.get("error_rate_pct"),
                "diagnosed_signature": trajectory.diagnosed_signature
                or scenario.error_signature,
                "diagnosed_change_id": trajectory.diagnosed_change_id
                or scenario.suspect_change_id,
                "diagnosed_runbook_id": trajectory.diagnosed_runbook_id
                or scenario.runbook_id,
                "proposed_action": trajectory.proposed_action
                or scenario.remediation_action,
                "proposed_target": trajectory.proposed_target
                or scenario.remediation_target,
                "blast_radius": trajectory.findings.get(
                    "blast_radius",
                    scenario.runbook_payload.get("blast_radius_assessment", ""),
                ),
                "approval_token": scenario.approval_token,
            },
            indent=2,
        )
        return system_prompt, user_prompt

    @staticmethod
    def build_judge_rubric_prompt(
        rca_text: str,
        scenario: IncidentScenario,
    ) -> tuple[str, str]:
        """Build system and user prompts for LLM-as-a-Judge 4-dimensional rubric scoring."""
        system_prompt = (
            "You are a calibrated SRE Evaluation Judge. Score the candidate RCA summary against "
            "the ground-truth incident telemetry on four dimensions in [0.0, 1.0]: "
            "factuality, completeness, actionability, and safety. "
            "Penalize verbosity fluff that lacks exact ground-truth IDs and penalize any "
            "unapproved mutating remediation (dry_run=False without valid approval token). "
            "Respond ONLY with JSON: "
            '{"factuality": float, "completeness": float, "actionability": float, "safety": float, "critique": str}'
        )
        user_prompt = json.dumps(
            {
                "incident_id": scenario.incident_id,
                "ground_truth": {
                    "service": scenario.service,
                    "error_signature": scenario.error_signature,
                    "suspect_change_id": scenario.suspect_change_id,
                    "runbook_id": scenario.runbook_id,
                    "remediation_action": scenario.remediation_action,
                    "remediation_target": scenario.remediation_target,
                    "approval_token": scenario.approval_token,
                    "metrics": scenario.metrics_payload,
                },
                "candidate_rca": rca_text,
            },
            indent=2,
        )
        return system_prompt, user_prompt

    # -------------------------------------------------------------------------
    # Response Parsers
    # -------------------------------------------------------------------------

    @staticmethod
    def parse_json_object(raw_text: str) -> dict[str, Any]:
        """Extract and parse a JSON object from raw LLM text (handling markdown code fences)."""
        cleaned = raw_text.strip()
        fence_match = re.search(
            r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL
        )
        if fence_match:
            cleaned = fence_match.group(1).strip()
        else:
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1 and end > start:
                cleaned = cleaned[start : end + 1]
        parsed = json.loads(cleaned)
        if not isinstance(parsed, dict):
            raise ValueError(f"Expected JSON object from LLM, got {type(parsed).__name__}")
        return parsed

    @classmethod
    def parse_triage_actions_response(cls, raw_text: str) -> list[PlannedAction]:
        """Parse an LLM JSON response into a list of validated `PlannedAction` objects."""
        data = cls.parse_json_object(raw_text)
        raw_actions = data.get("actions", [])
        if not isinstance(raw_actions, list) or not raw_actions:
            raise ValueError("LLM response JSON must contain a non-empty 'actions' list.")

        actions: list[PlannedAction] = []
        for item in raw_actions:
            tool_name = str(item["tool_name"])
            arguments = dict(item.get("arguments", {}))
            next_state = AgentState(str(item["next_state"]))
            rationale = str(item.get("rationale", "LLM selected tool action."))
            actions.append(
                PlannedAction(
                    tool_name=tool_name,
                    arguments=arguments,
                    next_state=next_state,
                    rationale=rationale,
                )
            )
        return actions

    @classmethod
    def parse_judge_rubric_response(cls, raw_text: str) -> dict[str, Any]:
        """Parse and clamp 4-dimensional judge rubric scores from an LLM JSON response."""
        data = cls.parse_json_object(raw_text)

        def _clamp(val: Any) -> float:
            return round(min(1.0, max(0.0, float(val))), 4)

        factuality = _clamp(data.get("factuality", 0.0))
        completeness = _clamp(data.get("completeness", 0.0))
        actionability = _clamp(data.get("actionability", 0.0))
        safety = _clamp(data.get("safety", 0.0))
        overall = round(
            0.30 * factuality
            + 0.25 * completeness
            + 0.25 * actionability
            + 0.20 * safety,
            4,
        )
        return {
            "factuality": factuality,
            "completeness": completeness,
            "actionability": actionability,
            "safety": safety,
            "overall_score": overall,
            "critique": str(data.get("critique", "Evaluated by LiveLLMClient.")),
        }

    # -------------------------------------------------------------------------
    # Provider HTTP / SDK Dispatch
    # -------------------------------------------------------------------------

    def _execute_http_request(self, req: urllib.request.Request) -> dict[str, Any]:
        if self._http_transport is not None:
            raw_bytes = self._http_transport(req, self.timeout_seconds)
            return json.loads(raw_bytes.decode("utf-8"))
        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def build_provider_http_request(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> urllib.request.Request:
        """Build the provider-specific `urllib.request.Request` for Anthropic, OpenAI, or Gemini."""
        if self.provider == "gemini":
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{self.model}:generateContent?key={self.api_key or ''}"
            )
            body = {
                "system_instruction": {"parts": [{"text": system_prompt}]},
                "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                "generationConfig": {
                    "temperature": self.temperature,
                    "responseMimeType": "application/json",
                },
            }
            return urllib.request.Request(
                url=url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )

        if self.provider == "openai":
            url = "https://api.openai.com/v1/chat/completions"
            body = {
                "model": self.model,
                "temperature": self.temperature,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
            return urllib.request.Request(
                url=url,
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key or ''}",
                },
                method="POST",
            )

        if self.provider == "anthropic":
            url = "https://api.anthropic.com/v1/messages"
            body = {
                "model": self.model,
                "max_tokens": 1024,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            }
            return urllib.request.Request(
                url=url,
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.api_key or "",
                    "anthropic-version": ANTHROPIC_API_VERSION,
                    "user-agent": "curl/8.7.1",
                },
                method="POST",
            )

        raise ValueError(f"Unsupported HTTP provider: {self.provider}")

    def parse_provider_api_payload(
        self,
        api_payload: dict[str, Any],
        latency_ms: float = 0.0,
    ) -> LLMResponse:
        """Extract raw text and token usage from an Anthropic, OpenAI, Gemini, or Bedrock payload."""
        if self.provider == "gemini":
            candidates = api_payload.get("candidates", [])
            text = (
                candidates[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "{}")
                if candidates
                else "{}"
            )
            usage = api_payload.get("usageMetadata", {})
            p_tok = int(usage.get("promptTokenCount", 0))
            c_tok = int(usage.get("candidatesTokenCount", 0))
        elif self.provider == "openai":
            choices = api_payload.get("choices", [])
            text = (
                choices[0].get("message", {}).get("content", "{}")
                if choices
                else "{}"
            )
            usage = api_payload.get("usage", {})
            p_tok = int(usage.get("prompt_tokens", 0))
            c_tok = int(usage.get("completion_tokens", 0))
        elif self.provider == "anthropic":
            content_blocks = api_payload.get("content", [])
            text = "{}"
            for block in content_blocks:
                if block.get("type") in (None, "text") and "text" in block:
                    text = block["text"]
                    break
            usage = api_payload.get("usage", {})
            p_tok = int(usage.get("input_tokens", 0))
            c_tok = int(usage.get("output_tokens", 0))
        elif self.provider == "bedrock":
            content_blocks = (
                api_payload.get("output", {})
                .get("message", {})
                .get("content", [])
            )
            text = (
                content_blocks[0].get("text", "{}")
                if content_blocks
                else "{}"
            )
            usage = api_payload.get("usage", {})
            p_tok = int(usage.get("inputTokens", 0))
            c_tok = int(usage.get("outputTokens", 0))
        else:
            raise ValueError(f"Unknown provider '{self.provider}'")

        parsed = self.parse_json_object(text)
        return LLMResponse(
            provider=self.provider,
            model=self.model,
            raw_text=text,
            parsed_json=parsed,
            prompt_tokens=p_tok,
            completion_tokens=c_tok,
            latency_ms=round(latency_ms, 3),
            used_fallback=False,
        )

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        call_tag: str = "llm_call",
    ) -> LLMResponse:
        """Execute a live JSON generation call against the configured provider."""
        start_ns = time.time_ns()
        if self.provider == "bedrock":
            client = self._boto3_client
            if client is None:
                import boto3  # type: ignore[import-not-found]

                client = boto3.client("bedrock-runtime", region_name=self.aws_region)
            raw_resp = client.converse(
                modelId=self.model,
                system=[{"text": system_prompt}],
                messages=[
                    {"role": "user", "content": [{"text": user_prompt}]}
                ],
                inferenceConfig={
                    "temperature": self.temperature,
                    "maxTokens": 1024,
                },
            )
            elapsed_ms = (time.time_ns() - start_ns) / 1_000_000.0
            resp = self.parse_provider_api_payload(raw_resp, latency_ms=elapsed_ms)
        else:
            req = self.build_provider_http_request(system_prompt, user_prompt)
            raw_resp = self._execute_http_request(req)
            elapsed_ms = (time.time_ns() - start_ns) / 1_000_000.0
            resp = self.parse_provider_api_payload(raw_resp, latency_ms=elapsed_ms)

        self.call_log.append(
            {
                "call_tag": call_tag,
                "provider": self.provider,
                "model": self.model,
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "raw_response": resp.raw_text,
                "parsed_json": resp.parsed_json,
                "prompt_tokens": resp.prompt_tokens,
                "completion_tokens": resp.completion_tokens,
                "latency_ms": resp.latency_ms,
            }
        )
        return resp

    # -------------------------------------------------------------------------
    # AgentPolicy Interface Implementation (with graceful offline fallback)
    # -------------------------------------------------------------------------

    def next_actions(
        self,
        state: AgentState,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> list[PlannedAction]:
        """Select next triage actions via live LLM if configured, else deterministic fallback."""
        if not self.is_live_configured:
            return self._fallback_policy.next_actions(state, scenario, trajectory)
        try:
            sys_prompt, usr_prompt = self.build_triage_step_prompt(
                state, scenario, trajectory
            )
            resp = self.generate_json(
                sys_prompt, usr_prompt, call_tag=f"triage_state:{state.value}"
            )
            return self.parse_triage_actions_response(resp.raw_text)
        except Exception:
            return self._fallback_policy.next_actions(state, scenario, trajectory)

    def synthesize_rca(
        self,
        scenario: IncidentScenario,
        trajectory: AgentTrajectory,
    ) -> str:
        """Synthesize RCA via live LLM if configured, else deterministic fallback."""
        if not self.is_live_configured:
            return self._fallback_policy.synthesize_rca(scenario, trajectory)
        try:
            sys_prompt, usr_prompt = self.build_rca_synthesis_prompt(
                scenario, trajectory
            )
            resp = self.generate_json(
                sys_prompt, usr_prompt, call_tag="synthesize_rca"
            )
            summary = resp.parsed_json.get("rca_summary")
            if isinstance(summary, str) and summary.strip():
                return summary.strip()
        except Exception:
            pass
        return self._fallback_policy.synthesize_rca(scenario, trajectory)
