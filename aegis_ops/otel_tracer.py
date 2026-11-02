"""OpenTelemetry-compatible span tracer for agent step and MCP tool telemetry.

Records trace_id, span_id, parent_span_id, tool_name, latency_ms,
prompt/completion tokens, and USD cost for every agent state transition and
MCP tool invocation. Supports structured JSONL trace export and per-trace
cost/latency aggregation.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator


# Default AWS Bedrock Claude 3.5 Sonnet on-demand token pricing ($3/1M input, $15/1M output)
DEFAULT_PROMPT_COST_PER_1K = 0.003
DEFAULT_COMPLETION_COST_PER_1K = 0.015


def compute_token_cost_usd(
    prompt_tokens: int,
    completion_tokens: int,
    prompt_cost_per_1k: float = DEFAULT_PROMPT_COST_PER_1K,
    completion_cost_per_1k: float = DEFAULT_COMPLETION_COST_PER_1K,
) -> float:
    """Compute USD cost from prompt and completion token counts."""
    cost = (
        (max(0, prompt_tokens) / 1000.0) * prompt_cost_per_1k
        + (max(0, completion_tokens) / 1000.0) * completion_cost_per_1k
    )
    return round(cost, 6)


def _deterministic_hex_id(seed_str: str, length: int) -> str:
    """Generate a deterministic W3C-formatted hex identifier of given character length."""
    digest = hashlib.sha256(seed_str.encode("utf-8")).hexdigest()
    return digest[:length]


@dataclass
class OTelSpan:
    """OpenTelemetry-compatible span representation for an agent step or MCP tool call."""

    trace_id: str
    span_id: str
    parent_span_id: str | None
    tool_name: str
    service_name: str = "aegis-ops-triage-agent"
    agent_state: str = "UNKNOWN"
    start_time_ns: int = 0
    end_time_ns: int = 0
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    status_code: str = "OK"
    error_message: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Append a structured timestamped event to this span."""
        self.events.append(
            {
                "name": name,
                "timestamp_ns": time.time_ns(),
                "attributes": attributes or {},
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize span to an OpenTelemetry-compatible dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize span to a compact single-line JSON string for JSONL export."""
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class TraceSummary:
    """Aggregated telemetry metrics for a single incident triage trace."""

    trace_id: str
    span_count: int
    tool_call_count: int
    error_span_count: int
    total_latency_ms: float
    p95_latency_ms: float
    total_prompt_tokens: int
    total_completion_tokens: int
    total_tokens: int
    total_cost_usd: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OTelTracer:
    """OpenTelemetry-compatible tracer for AegisOps agent workflows and MCP servers."""

    def __init__(
        self,
        service_name: str = "aegis-ops-triage-agent",
        deterministic_seed: str | None = "aegis-ops",
    ) -> None:
        self.service_name = service_name
        self._seed_prefix = deterministic_seed or "aegis-ops"
        self._counter = 0
        self._spans: list[OTelSpan] = []

    def new_trace_id(self, label: str = "") -> str:
        """Create a 32-character hex W3C trace ID."""
        self._counter += 1
        seed = f"{self._seed_prefix}:trace:{self._counter}:{label}"
        return _deterministic_hex_id(seed, 32)

    def new_span_id(self, label: str = "") -> str:
        """Create a 16-character hex W3C span ID."""
        self._counter += 1
        seed = f"{self._seed_prefix}:span:{self._counter}:{label}"
        return _deterministic_hex_id(seed, 16)

    def record_span(
        self,
        *,
        trace_id: str,
        tool_name: str,
        parent_span_id: str | None = None,
        agent_state: str = "TRIAGE",
        latency_ms: float = 12.5,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost_usd: float | None = None,
        status_code: str = "OK",
        error_message: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> OTelSpan:
        """Record a completed span with explicit latency and token telemetry."""
        span_id = self.new_span_id(tool_name)
        now_ns = time.time_ns()
        duration_ns = int(max(0.0, latency_ms) * 1_000_000)
        computed_cost = (
            cost_usd
            if cost_usd is not None
            else compute_token_cost_usd(prompt_tokens, completion_tokens)
        )
        span = OTelSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            tool_name=tool_name,
            service_name=self.service_name,
            agent_state=agent_state,
            start_time_ns=now_ns - duration_ns,
            end_time_ns=now_ns,
            latency_ms=round(latency_ms, 3),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=computed_cost,
            status_code=status_code,
            error_message=error_message,
            attributes=dict(attributes or {}),
        )
        self._spans.append(span)
        return span

    @contextmanager
    def start_span(
        self,
        *,
        trace_id: str,
        tool_name: str,
        parent_span_id: str | None = None,
        agent_state: str = "TRIAGE",
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        simulated_latency_ms: float | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[OTelSpan]:
        """Context manager that times execution and records an OTelSpan."""
        span_id = self.new_span_id(tool_name)
        start_ns = time.time_ns()
        span = OTelSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            tool_name=tool_name,
            service_name=self.service_name,
            agent_state=agent_state,
            start_time_ns=start_ns,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            attributes=dict(attributes or {}),
        )
        try:
            yield span
        except Exception as exc:
            span.status_code = "ERROR"
            span.error_message = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            end_ns = time.time_ns()
            span.end_time_ns = end_ns
            if simulated_latency_ms is not None:
                span.latency_ms = round(simulated_latency_ms, 3)
            else:
                span.latency_ms = round((end_ns - start_ns) / 1_000_000.0, 3)
            if span.cost_usd == 0.0 and (span.prompt_tokens > 0 or span.completion_tokens > 0):
                span.cost_usd = compute_token_cost_usd(
                    span.prompt_tokens, span.completion_tokens
                )
            self._spans.append(span)

    def get_spans(self, trace_id: str | None = None) -> list[OTelSpan]:
        """Return all recorded spans, optionally filtered by trace_id."""
        if trace_id is None:
            return list(self._spans)
        return [s for s in self._spans if s.trace_id == trace_id]

    def summarize_trace(self, trace_id: str) -> TraceSummary:
        """Aggregate latency, token consumption, and USD cost for a trace."""
        spans = self.get_spans(trace_id)
        if not spans:
            return TraceSummary(
                trace_id=trace_id,
                span_count=0,
                tool_call_count=0,
                error_span_count=0,
                total_latency_ms=0.0,
                p95_latency_ms=0.0,
                total_prompt_tokens=0,
                total_completion_tokens=0,
                total_tokens=0,
                total_cost_usd=0.0,
            )

        latencies = sorted(s.latency_ms for s in spans)
        p95_idx = min(len(latencies) - 1, max(0, math.ceil(0.95 * len(latencies)) - 1))
        p95_latency = latencies[p95_idx]

        prompt_tok = sum(s.prompt_tokens for s in spans)
        comp_tok = sum(s.completion_tokens for s in spans)
        total_cost = round(sum(s.cost_usd for s in spans), 6)
        tool_calls = sum(
            1 for s in spans if not s.tool_name.startswith("agent.")
        )
        errors = sum(1 for s in spans if s.status_code != "OK")

        return TraceSummary(
            trace_id=trace_id,
            span_count=len(spans),
            tool_call_count=tool_calls,
            error_span_count=errors,
            total_latency_ms=round(sum(latencies), 3),
            p95_latency_ms=round(p95_latency, 3),
            total_prompt_tokens=prompt_tok,
            total_completion_tokens=comp_tok,
            total_tokens=prompt_tok + comp_tok,
            total_cost_usd=total_cost,
        )

    def to_jsonl_lines(self, trace_id: str | None = None) -> list[str]:
        """Return spans formatted as JSONL strings."""
        return [s.to_json() for s in self.get_spans(trace_id)]

    def export_jsonl(self, path: str | Path, trace_id: str | None = None) -> int:
        """Write recorded spans to a JSONL file and return the number of spans exported."""
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        lines = self.to_jsonl_lines(trace_id)
        out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return len(lines)
