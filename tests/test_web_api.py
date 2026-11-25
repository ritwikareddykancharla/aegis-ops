"""Unit tests for AegisOps CloudFront `/api/*` Incident Investigation Web API (`aegis_ops/web_api.py`)."""
from __future__ import annotations

import json
import os
import unittest

from aegis_ops.web_api import lambda_handler, route_api_request


class TestAegisOpsWebApi(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["AEGISOPS_OFFLINE_LLM"] = "1"
        route_api_request("POST", "/api/reset", {}, {})

    def test_01_health_and_initial_topology(self) -> None:
        h = lambda_handler({"rawPath": "/api/health", "requestContext": {"http": {"method": "GET"}}})
        self.assertEqual(h["statusCode"], 200)
        body = json.loads(h["body"])
        self.assertEqual(body["human_sre_agreement_pct"], 95.8)

        st = lambda_handler({"rawPath": "/api/state", "requestContext": {"http": {"method": "GET"}}})
        self.assertEqual(st["statusCode"], 200)
        sdata = json.loads(st["body"])
        self.assertEqual(len(sdata["topology"]["nodes"]), 6)
        self.assertEqual(len(sdata["mcp_timeline"]), 4)

    def test_02_investigate_all_three_production_incidents(self) -> None:
        for inc_id in ("inc_checkout_pool", "inc_ddb_hot_partition", "inc_dc_chiller_drift"):
            code, payload = route_api_request("POST", "/api/investigate", {}, {"incident_id": inc_id})
            self.assertEqual(code, 200)
            self.assertEqual(payload["active_incident_id"], inc_id)
            self.assertEqual(payload["rubric_evaluation"]["dag_step_order_compliance_pct"], 100.0)

    def test_03_safety_gate_blocks_unapproved_and_executes_approved(self) -> None:
        code_blk, blk = route_api_request("POST", "/api/remediate", {}, {"approved": False})
        self.assertEqual(code_blk, 200)
        self.assertTrue(blk["blocked"])
        self.assertEqual(blk["status"], "BLOCKED_SAFETY_GATE")
        self.assertFalse(blk["state"]["remediated"])

        code_ok, ok = route_api_request("POST", "/api/remediate", {}, {"approved": True})
        self.assertEqual(code_ok, 200)
        self.assertFalse(ok["blocked"])
        self.assertTrue(ok["state"]["remediated"])
        for n in ok["state"]["topology"]["nodes"]:
            self.assertEqual(n["status"], "HEALTHY")

    def test_04_custom_symptom_injection(self) -> None:
        code, custom = route_api_request(
            "POST",
            "/api/incidents/custom",
            {},
            {
                "service_id": "payment-auth",
                "error_signature": "CertExpiredError",
                "metric_symptom": "p99 2180ms",
            },
        )
        self.assertEqual(code, 200)
        self.assertTrue(custom["active_incident_id"].startswith("inc_custom_"))


if __name__ == "__main__":
    unittest.main()
