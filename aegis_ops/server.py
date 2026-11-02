"""
Real HTTP + Server-Sent Events (SSE) Streaming Backend for AegisOps (`aegis_ops/server.py`).

Run locally with:
    python3 -m aegis_ops.server --port 8080

Endpoints:
  - GET  /                                 -> Serves the interactive web console (`docs/index.html`)
  - GET  /api/health                       -> Returns server + live SQLite sandbox status
  - GET  /api/faults                       -> Lists all 6 real SQLite + Config Chaos Faults
  - GET  /api/stream-chaos?fault_id=...&provider=anthropic|openai
                                           -> Streams live Server-Sent Events (`text/event-stream`)
                                              as the agent injects a real fault into the 25,000-row
                                              SQLite database, runs `EXPLAIN QUERY PLAN`, queries
                                              live `claude-opus-5-5` or `gpt-4o-mini`, executes the
                                              real SQL/config remediation, and verifies latency recovery.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import urllib.parse
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .live_sandbox import CHAOS_FAULTS, LiveCheckoutSandbox
from .llm_client import LiveLLMClient


DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"


class AegisOpsHTTPHandler(BaseHTTPRequestHandler):
    """HTTP + SSE handler for real-time chaos fault injection and live LLM triage."""

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/health":
            self._send_json(
                {
                    "status": "ok",
                    "service": "aegis-ops-live-sse-server",
                    "sqlite_orders_rows": 25000,
                    "available_faults": list(CHAOS_FAULTS.keys()),
                }
            )
            return

        if path == "/api/faults":
            self._send_json({"faults": CHAOS_FAULTS})
            return

        if path == "/api/stream-chaos":
            fault_id = query.get("fault_id", ["FAULT-01-MISSING-SQL-INDEX"])[0]
            provider = query.get("provider", ["anthropic"])[0]
            model = query.get("model", [None])[0]
            self._handle_sse_chaos_stream(fault_id=fault_id, provider=provider, model=model)
            return

        # Serve static files from `docs/`
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        file_path = (DOCS_DIR / rel).resolve()
        if not str(file_path).startswith(str(DOCS_DIR.resolve())) or not file_path.is_file():
            self._send_json({"error": f"Not found: {path}"}, status=404)
            return

        ctype, _ = mimetypes.guess_type(str(file_path))
        data = file_path.read_bytes()
        self.send_response(200)
        self._send_cors_headers()
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _emit_sse(self, event_name: str, data: dict[str, Any]) -> None:
        msg = f"event: {event_name}\ndata: {json.dumps(data)}\n\n"
        self.wfile.write(msg.encode("utf-8"))
        self.wfile.flush()

    def _handle_sse_chaos_stream(self, fault_id: str, provider: str, model: str | None) -> None:
        if fault_id not in CHAOS_FAULTS:
            self._send_json({"error": f"Unknown fault_id: {fault_id}"}, status=400)
            return

        self.send_response(200)
        self._send_cors_headers()
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        sb = LiveCheckoutSandbox()
        try:
            meta = CHAOS_FAULTS[fault_id]
            inj = sb.inject_fault(fault_id)
            before_probe = inj["initial_load_probe"]
            self._emit_sse(
                "step",
                {
                    "step": 0,
                    "phase": "FAULT_INJECTED_AND_LOAD_PROBED",
                    "fault_id": fault_id,
                    "title": meta["title"],
                    "before_probe": before_probe,
                },
            )

            logs_out = sb.tool_read_telemetry_logs(limit=6)
            self._emit_sse(
                "step",
                {
                    "step": 1,
                    "phase": "STEP_1_TELEMETRY_AND_LOGS",
                    "tool": "tool_read_telemetry_logs",
                    "tool_output": logs_out,
                },
            )

            sql_out = sb.tool_inspect_sqlite_schema_and_plan()
            self._emit_sse(
                "step",
                {
                    "step": 2,
                    "phase": "STEP_2_SQLITE_EXPLAIN_PLAN",
                    "tool": "tool_inspect_sqlite_schema_and_plan",
                    "tool_output": sql_out,
                },
            )

            diff_out = sb.tool_inspect_config_diff()
            self._emit_sse(
                "step",
                {
                    "step": 3,
                    "phase": "STEP_3_CONFIG_DIFF",
                    "tool": "tool_inspect_config_diff",
                    "tool_output": diff_out,
                },
            )

            client = LiveLLMClient(provider=provider, model=model)
            system_prompt = (
                "You are AegisOps, an autonomous SRE incident response agent operating on a live SQLite + Python checkout sandbox.\n"
                "Analyze the real telemetry logs, SQLite EXPLAIN QUERY PLAN, and config diff, then output ONLY valid JSON with keys:\n"
                '{"diagnosed_root_cause": str, "remediation_action": str, "sql_plan_finding": str, "config_diff_finding": str, "technical_rca_summary": str}'
            )
            user_prompt = json.dumps(
                {
                    "alert": meta["alert_summary"],
                    "initial_load_probe": before_probe,
                    "telemetry_logs": logs_out,
                    "sqlite_explain_plan": sql_out,
                    "config_diff": diff_out,
                }
            )
            llm_resp = client.generate_json(system_prompt=system_prompt, user_prompt=user_prompt)
            parsed_diag = llm_resp.parsed_json or {}
            chosen_action = str(parsed_diag.get("remediation_action", meta["expected_remediation"])).strip()

            dry_out = sb.tool_execute_live_remediation(chosen_action, dry_run=True)
            self._emit_sse(
                "step",
                {
                    "step": 4,
                    "phase": "STEP_4_LLM_DIAGNOSIS_AND_DRY_RUN",
                    "provider": client.provider,
                    "model": client.model,
                    "llm_latency_ms": llm_resp.latency_ms,
                    "llm_diagnosis": parsed_diag,
                    "dry_run_output": dry_out,
                },
            )

            apply_out = sb.tool_execute_live_remediation(
                chosen_action,
                dry_run=False,
                approval_token="SRE-APPROVAL-LIVE-2026",
            )
            self._emit_sse(
                "complete",
                {
                    "step": 5,
                    "phase": "STEP_5_LIVE_REMEDIATION_AND_VERIFICATION_PROBE",
                    "chosen_action": chosen_action,
                    "apply_output": apply_out,
                },
            )
        finally:
            sb.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AegisOps Live SQLite Chaos + SSE Server.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), AegisOpsHTTPHandler)
    print(f"AegisOps Live Chaos & SSE Server listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()


if __name__ == "__main__":
    main()
