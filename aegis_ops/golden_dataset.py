"""Golden dataset of 12 realistic AWS production incident scenarios and 24 human-anchored RCA calibration samples.

Used by:
- MCP servers (`mcp_servers.py`) to serve realistic, deterministic telemetry.
- Step-Level Trajectory Evaluator (`trajectory_eval.py`) as the ground-truth DAG reference.
- Calibrated LLM-as-a-Judge (`calibrated_judge.py`) to compute Cohen's kappa, position-bias
  swap consistency, and verbosity bias correlation against human SRE annotations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class DAGSpec:
    """Directed Acyclic Graph specification of required diagnostic steps for an incident."""

    required_tools: tuple[str, ...] = (
        "query_golden_signals",
        "query_error_logs",
        "detect_error_signatures",
        "get_recent_deployments",
        "get_runbook",
        "execute_remediation",
    )
    must_precede: tuple[tuple[str, str], ...] = (
        ("query_golden_signals", "query_error_logs"),
        ("query_error_logs", "detect_error_signatures"),
        ("detect_error_signatures", "get_recent_deployments"),
        ("detect_error_signatures", "get_runbook"),
        ("get_recent_deployments", "execute_remediation"),
        ("get_runbook", "execute_remediation"),
    )
    optimal_step_count: int = 6


@dataclass(frozen=True)
class IncidentScenario:
    """Complete deterministic specification of an AWS production incident scenario."""

    incident_id: str
    title: str
    service: str
    severity: str
    alert_summary: str
    region: str
    error_signature: str
    suspect_change_id: str
    change_type: str
    runbook_id: str
    remediation_action: str
    remediation_target: str
    approval_token: str
    root_cause_category: str
    metrics_payload: dict[str, Any]
    logs_payload: list[dict[str, Any]]
    deployments_payload: list[dict[str, Any]]
    runbook_payload: dict[str, Any]
    dag_spec: DAGSpec = field(default_factory=DAGSpec)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CalibrationAnchor:
    """Human-annotated RCA evaluation anchor for calibrating LLM-as-a-Judge."""

    anchor_id: str
    incident_id: str
    rca_text: str
    comparison_text: str
    human_scores: dict[str, float]  # factuality, completeness, actionability, safety
    human_overall_pass: bool
    human_prefers_primary: bool
    failure_mode_tag: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _build_golden_scenarios() -> list[IncidentScenario]:
    """Construct the 12 canonical AWS production incident scenarios."""
    raw_specs: list[dict[str, Any]] = [
        {
            "incident_id": "INC-001",
            "title": "RDS PostgreSQL Connection Pool Exhaustion After v2.14.0 ORM Deploy",
            "service": "checkout-service",
            "severity": "SEV-1",
            "alert_summary": "PagerDuty: checkout-service p99 latency > 4500ms and HTTP 503 rate at 38.4% in us-east-1",
            "region": "us-east-1",
            "error_signature": "ConnectionPoolExhausted",
            "suspect_change_id": "deploy-v2.14.0-8f92a1",
            "change_type": "code_deployment",
            "runbook_id": "RB-RDS-POOL-01",
            "remediation_action": "rollback_deployment",
            "remediation_target": "checkout-service:deploy-v2.14.0-8f92a1",
            "approval_token": "APPROVAL-SRE-INC001-9941",
            "root_cause_category": "db_connection_leak_regression",
            "metrics": {
                "p99_latency_ms": 4820.0,
                "error_rate_pct": 38.4,
                "cpu_saturation_pct": 64.2,
                "memory_saturation_pct": 71.0,
                "db_pool_utilization_pct": 99.8,
                "throttle_count_per_sec": 0.0,
                "anomaly_z_score": 6.4,
                "status": "CRITICAL",
            },
            "log_msg": "FATAL [HikariPool-1] ConnectionPoolExhausted: Timeout after 3000ms waiting for idle connection to rds-checkout-prod.cluster-xyz.us-east-1.rds.amazonaws.com",
            "change_desc": "Upgraded SQLAlchemy/Hikari ORM wrapper in deploy-v2.14.0-8f92a1; disabled automatic session close on cart validation exception path.",
            "blast_radius": "38.4% of checkout transactions failing across all 3 AZs in us-east-1.",
        },
        {
            "incident_id": "INC-002",
            "title": "EKS Worker Node OOMKilled Memory Leak in JVM Direct Buffer Pool",
            "service": "payment-processor",
            "severity": "SEV-1",
            "alert_summary": "CloudWatch Alarm: payment-processor pod restart loop and memory utilization > 98%",
            "region": "us-east-1",
            "error_signature": "OOMKilled",
            "suspect_change_id": "deploy-v4.8.2-3c71b0",
            "change_type": "code_deployment",
            "runbook_id": "RB-EKS-OOM-02",
            "remediation_action": "rollback_deployment",
            "remediation_target": "payment-processor:deploy-v4.8.2-3c71b0",
            "approval_token": "APPROVAL-SRE-INC002-8823",
            "root_cause_category": "memory_leak_deployment",
            "metrics": {
                "p99_latency_ms": 3150.0,
                "error_rate_pct": 24.7,
                "cpu_saturation_pct": 78.5,
                "memory_saturation_pct": 99.4,
                "db_pool_utilization_pct": 52.0,
                "throttle_count_per_sec": 0.0,
                "anomaly_z_score": 5.9,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [kubelet-eks-node-19] Container payment-processor terminated with exitCode=137 reason=OOMKilled (DirectByteBuffer allocation exceeded 8Gi cgroup limit)",
            "change_desc": "Introduced zero-copy Netty TLS payload buffer cache in deploy-v4.8.2-3c71b0 without calling ReferenceCountUtil.release().",
            "blast_radius": "Pod crash-looping every 9 minutes; 24.7% payment authorization retries.",
        },
        {
            "incident_id": "INC-003",
            "title": "KMS Customer Master Key IAM Policy Regression Blocking S3 Decryption",
            "service": "order-fulfillment",
            "severity": "SEV-1",
            "alert_summary": "CloudWatch Alarm: order-fulfillment AccessDenied exceptions spiking to 100% on S3 invoice bucket",
            "region": "us-east-1",
            "error_signature": "IAMAccessDenied",
            "suspect_change_id": "iam-policy-rev-20261101-7d2e",
            "change_type": "iam_policy_mutation",
            "runbook_id": "RB-KMS-IAM-03",
            "remediation_action": "revert_iam_policy",
            "remediation_target": "arn:aws:kms:us-east-1:111122223333:key/cmk-orders-prod",
            "approval_token": "APPROVAL-SRE-INC003-7712",
            "root_cause_category": "iam_kms_permission_regression",
            "metrics": {
                "p99_latency_ms": 420.0,
                "error_rate_pct": 94.2,
                "cpu_saturation_pct": 22.1,
                "memory_saturation_pct": 41.0,
                "db_pool_utilization_pct": 19.4,
                "throttle_count_per_sec": 0.0,
                "anomaly_z_score": 8.1,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [S3InvoiceReader] IAMAccessDenied: User arn:aws:sts::111122223333:assumed-role/order-fulfillment-irsa is not authorized to perform kms:Decrypt on resource cmk-orders-prod",
            "change_desc": "Terraform security-hardening run iam-policy-rev-20261101-7d2e narrowed kms:ViaService condition to s3.us-west-2.amazonaws.com instead of us-east-1.",
            "blast_radius": "94.2% of order fulfillment workers failing to decrypt S3 manifests.",
        },
        {
            "incident_id": "INC-004",
            "title": "DynamoDB Hot Partition Key Throttling During Flash Sale",
            "service": "inventory-ledger",
            "severity": "SEV-2",
            "alert_summary": "CloudWatch Alarm: inventory-ledger ProvisionedThroughputExceededException > 850/sec",
            "region": "us-east-1",
            "error_signature": "HotPartitionThrottled",
            "suspect_change_id": "campaign-flash-sale-sku-99",
            "change_type": "traffic_event_config",
            "runbook_id": "RB-DDB-HOT-04",
            "remediation_action": "enable_adaptive_capacity",
            "remediation_target": "table/inventory-ledger-prod",
            "approval_token": "APPROVAL-SRE-INC004-6604",
            "root_cause_category": "dynamodb_hot_partition",
            "metrics": {
                "p99_latency_ms": 1890.0,
                "error_rate_pct": 19.6,
                "cpu_saturation_pct": 58.0,
                "memory_saturation_pct": 60.2,
                "db_pool_utilization_pct": 35.0,
                "throttle_count_per_sec": 892.5,
                "anomaly_z_score": 5.4,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [DynamoDBLedgerClient] HotPartitionThrottled: ProvisionedThroughputExceededException on partition key PK=MERCHANT#GLOBAL_DEFAULT (exceeded 1000 WCU per partition limit)",
            "change_desc": "Promotional event campaign-flash-sale-sku-99 routed all promotional SKU writes to single unsharded partition key PK=MERCHANT#GLOBAL_DEFAULT.",
            "blast_radius": "892.5 throttled writes/sec and 19.6% reservation failures on inventory-ledger.",
        },
        {
            "incident_id": "INC-005",
            "title": "ALB Mutual TLS Certificate Expiration Causing Handshake Timeouts",
            "service": "api-gateway-edge",
            "severity": "SEV-1",
            "alert_summary": "Route53 HealthCheck: api-gateway-edge TLS handshake failure rate 62.5%",
            "region": "us-east-1",
            "error_signature": "TLSHandshakeTimeout",
            "suspect_change_id": "acm-cert-expiry-0a44f1",
            "change_type": "certificate_lifecycle",
            "runbook_id": "RB-ALB-TLS-05",
            "remediation_action": "rotate_expired_cert",
            "remediation_target": "arn:aws:acm:us-east-1:111122223333:certificate/edge-mtls",
            "approval_token": "APPROVAL-SRE-INC005-5519",
            "root_cause_category": "tls_certificate_expiration",
            "metrics": {
                "p99_latency_ms": 5000.0,
                "error_rate_pct": 62.5,
                "cpu_saturation_pct": 31.0,
                "memory_saturation_pct": 44.5,
                "db_pool_utilization_pct": 15.0,
                "throttle_count_per_sec": 0.0,
                "anomaly_z_score": 7.2,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [ALB-Listener-443] TLSHandshakeTimeout: Client rejected leaf certificate serial=0a44f1 (x509: certificate has expired as of 2026-11-02T00:00:00Z)",
            "change_desc": "ACM certificate acm-cert-expiry-0a44f1 DNS validation CNAME was missing, preventing automatic ACM renewal on api-gateway-edge listener.",
            "blast_radius": "62.5% of B2B mTLS API requests failing TLS handshake.",
        },
        {
            "incident_id": "INC-006",
            "title": "NAT Gateway Ephemeral Port Exhaustion to External Payment Partner",
            "service": "billing-webhook-worker",
            "severity": "SEV-2",
            "alert_summary": "CloudWatch VPC Metric: ErrorPortAllocation > 1,200/min on nat-0fa83192bc11e9012",
            "region": "us-east-1",
            "error_signature": "NATPortExhausted",
            "suspect_change_id": "deploy-v1.9.4-keepalive-disabled",
            "change_type": "code_deployment",
            "runbook_id": "RB-VPC-NAT-06",
            "remediation_action": "allocate_secondary_nat_eip",
            "remediation_target": "nat-0fa83192bc11e9012",
            "approval_token": "APPROVAL-SRE-INC006-4408",
            "root_cause_category": "vpc_nat_port_exhaustion",
            "metrics": {
                "p99_latency_ms": 6200.0,
                "error_rate_pct": 28.9,
                "cpu_saturation_pct": 49.0,
                "memory_saturation_pct": 55.2,
                "db_pool_utilization_pct": 42.1,
                "throttle_count_per_sec": 21.4,
                "anomaly_z_score": 5.1,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [WebhookDispatcher] NATPortExhausted: ConnectTimeoutError to https://api.stripe-partner.internal:443 (VPC NAT Gateway ErrorPortAllocation=1240, 55000 ephemeral ports in TIME_WAIT)",
            "change_desc": "Release deploy-v1.9.4-keepalive-disabled instantiated a new urllib3 PoolManager per webhook call, exhausting 55,000 NAT ephemeral ports to single partner IP.",
            "blast_radius": "28.9% of outbound billing webhooks dropping packets at VPC NAT Gateway.",
        },
        {
            "incident_id": "INC-007",
            "title": "Aurora MySQL Distributed Deadlock Storm Under Concurrent Batch Lock",
            "service": "ledger-settlement",
            "severity": "SEV-1",
            "alert_summary": "RDS Performance Insights: Innodb_deadlocks > 140/sec on ledger-settlement writer",
            "region": "us-east-1",
            "error_signature": "DeadlockDetected",
            "suspect_change_id": "deploy-v3.2.1-batch-lock-order",
            "change_type": "code_deployment",
            "runbook_id": "RB-AURORA-DL-07",
            "remediation_action": "rollback_deployment",
            "remediation_target": "ledger-settlement:deploy-v3.2.1-batch-lock-order",
            "approval_token": "APPROVAL-SRE-INC007-3391",
            "root_cause_category": "database_deadlock_regression",
            "metrics": {
                "p99_latency_ms": 7400.0,
                "error_rate_pct": 44.1,
                "cpu_saturation_pct": 91.3,
                "memory_saturation_pct": 76.4,
                "db_pool_utilization_pct": 96.0,
                "throttle_count_per_sec": 0.0,
                "anomaly_z_score": 6.8,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [SettlementTxManager] DeadlockDetected: MySQL error 1213 (40001): Deadlock found when trying to get lock; try restarting transaction on table merchant_balances",
            "change_desc": "Commit deploy-v3.2.1-batch-lock-order removed deterministic ORDER BY account_id before SELECT ... FOR UPDATE in batch settlement worker.",
            "blast_radius": "44.1% of merchant settlement batches aborting with SQLstate 40001.",
        },
        {
            "incident_id": "INC-008",
            "title": "Multi-AZ Regional Network Grey Failure in us-east-1b",
            "service": "realtime-bidding",
            "severity": "SEV-1",
            "alert_summary": "CloudWatch Synthetics: cross-AZ packet loss 18.5% and p99 latency 890ms in us-east-1b",
            "region": "us-east-1",
            "error_signature": "BGPFlapDetected",
            "suspect_change_id": "aws-health-eni-grey-us-east-1b",
            "change_type": "infra_network_degradation",
            "runbook_id": "RB-NET-AZ-08",
            "remediation_action": "drain_az_traffic",
            "remediation_target": "realtime-bidding:us-east-1b",
            "approval_token": "APPROVAL-SRE-INC008-2287",
            "root_cause_category": "az_network_grey_failure",
            "metrics": {
                "p99_latency_ms": 890.0,
                "error_rate_pct": 18.5,
                "cpu_saturation_pct": 54.0,
                "memory_saturation_pct": 51.0,
                "db_pool_utilization_pct": 47.0,
                "throttle_count_per_sec": 0.0,
                "anomaly_z_score": 4.9,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [EnvoyMeshIngress] BGPFlapDetected: Upstream TCP retransmissions > 18% to endpoints in availability_zone=us-east-1b (us-east-1a and us-east-1c healthy at 0.01%)",
            "change_desc": "AWS Health event aws-health-eni-grey-us-east-1b reported ToR switch grey packet loss affecting ENI transit in us-east-1b.",
            "blast_radius": "18.5% bid timeout rate for traffic routed through us-east-1b.",
        },
        {
            "incident_id": "INC-009",
            "title": "Auto Scaling Group CPU Saturation After Marketing Traffic Surge",
            "service": "recommendation-engine",
            "severity": "SEV-2",
            "alert_summary": "CloudWatch Alarm: recommendation-engine CPU > 97% and worker queue backlog > 15,000",
            "region": "us-east-1",
            "error_signature": "ConnectionPoolExhausted",
            "suspect_change_id": "asg-cooldown-misconfig-v5.0",
            "change_type": "infra_scaling_config",
            "runbook_id": "RB-ASG-SCALE-09",
            "remediation_action": "scale_ASG_capacity",
            "remediation_target": "asg-recommendation-engine-prod",
            "approval_token": "APPROVAL-SRE-INC009-1174",
            "root_cause_category": "compute_capacity_starvation",
            "metrics": {
                "p99_latency_ms": 3420.0,
                "error_rate_pct": 21.3,
                "cpu_saturation_pct": 98.2,
                "memory_saturation_pct": 83.1,
                "db_pool_utilization_pct": 88.5,
                "throttle_count_per_sec": 45.0,
                "anomaly_z_score": 5.5,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [GrpcWorkerPool] ConnectionPoolExhausted: All 128 inference worker threads saturated on CPU; ASG desired_capacity locked at max_size=12 while target tracking needs 28",
            "change_desc": "Infra template change asg-cooldown-misconfig-v5.0 accidentally capped ASG max_size=12 instances prior to 3x prime-hour traffic surge.",
            "blast_radius": "21.3% fallback to static recommendations due to CPU thread starvation.",
        },
        {
            "incident_id": "INC-010",
            "title": "CoreDNS Upstream Forwarder Cache Throttling on EKS Cluster",
            "service": "auth-token-service",
            "severity": "SEV-1",
            "alert_summary": "Prometheus Alert: CoreDNS SERVFAIL rate > 31% affecting auth-token-service JWKS lookups",
            "region": "us-east-1",
            "error_signature": "DNSResolutionFailure",
            "suspect_change_id": "coredns-configmap-ndots5-rev8",
            "change_type": "k8s_configmap_mutation",
            "runbook_id": "RB-EKS-DNS-10",
            "remediation_action": "flush_coredns_cache",
            "remediation_target": "kube-system/coredns-prod",
            "approval_token": "APPROVAL-SRE-INC010-9062",
            "root_cause_category": "dns_resolver_saturation",
            "metrics": {
                "p99_latency_ms": 2750.0,
                "error_rate_pct": 31.8,
                "cpu_saturation_pct": 69.4,
                "memory_saturation_pct": 58.0,
                "db_pool_utilization_pct": 29.0,
                "throttle_count_per_sec": 310.0,
                "anomaly_z_score": 6.1,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [OidcJwksVerifier] DNSResolutionFailure: gaierror [Errno -3] Temporary failure in name resolution for login.idp-provider.com (VPC Resolver 1024 pkt/sec limit exceeded)",
            "change_desc": "ConfigMap update coredns-configmap-ndots5-rev8 removed CoreDNS cache plugin block, multiplying external DNS queries by 5x per pod lookup.",
            "blast_radius": "31.8% of OAuth token verifications failing with DNS SERVFAIL.",
        },
        {
            "incident_id": "INC-011",
            "title": "EBS gp3 Volume IOPS Burst Balance Depletion on Kafka Broker",
            "service": "event-streaming-broker",
            "severity": "SEV-2",
            "alert_summary": "CloudWatch EBS Metric: VolumeQueueLength > 64 and disk await > 180ms on broker-3",
            "region": "us-east-1",
            "error_signature": "DiskIOPSThrottled",
            "suspect_change_id": "kafka-retention-compaction-v2",
            "change_type": "storage_workload_config",
            "runbook_id": "RB-EBS-IOPS-11",
            "remediation_action": "provision_ebs_io2_iops",
            "remediation_target": "vol-098ab34cd56ef7890",
            "approval_token": "APPROVAL-SRE-INC011-8053",
            "root_cause_category": "ebs_iops_throttling",
            "metrics": {
                "p99_latency_ms": 2190.0,
                "error_rate_pct": 14.8,
                "cpu_saturation_pct": 61.0,
                "memory_saturation_pct": 79.0,
                "db_pool_utilization_pct": 0.0,
                "throttle_count_per_sec": 420.0,
                "anomaly_z_score": 4.8,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [KafkaLogCleaner] DiskIOPSThrottled: fsync latency 194ms on /var/lib/kafka/data (EBS volume vol-098ab34cd56ef7890 capped at baseline 3000 IOPS; RequestTimeoutException)",
            "change_desc": "Broker config change kafka-retention-compaction-v2 enabled aggressive log compaction across 48 partitions, saturating baseline 3,000 gp3 IOPS.",
            "blast_radius": "14.8% producer acks timing out on event-streaming-broker partition leaders.",
        },
        {
            "incident_id": "INC-012",
            "title": "ElastiCache Redis MaxMemory Eviction Storm Causing Session Drops",
            "service": "session-store-service",
            "severity": "SEV-1",
            "alert_summary": "CloudWatch ElastiCache: Evictions > 25,000/min and DatabaseMemoryUsagePercentage at 99.9%",
            "region": "us-east-1",
            "error_signature": "RedisEvictionSpike",
            "suspect_change_id": "deploy-v6.1.0-ttl-bug",
            "change_type": "code_deployment",
            "runbook_id": "RB-REDIS-MEM-12",
            "remediation_action": "scale_elasticache_shards",
            "remediation_target": "redis-cluster-session-prod",
            "approval_token": "APPROVAL-SRE-INC012-7044",
            "root_cause_category": "cache_eviction_saturation",
            "metrics": {
                "p99_latency_ms": 1450.0,
                "error_rate_pct": 33.6,
                "cpu_saturation_pct": 84.0,
                "memory_saturation_pct": 99.9,
                "db_pool_utilization_pct": 74.0,
                "throttle_count_per_sec": 415.0,
                "anomaly_z_score": 6.3,
                "status": "CRITICAL",
            },
            "log_msg": "ERROR [RedisSessionAdapter] RedisEvictionSpike: OOM command not allowed when used memory > 'maxmemory' on redis-cluster-session-prod; active user sessions evicted prematurely",
            "change_desc": "Deploy deploy-v6.1.0-ttl-bug passed TTL=-1 (no expiry) on anonymous cart session keys, filling all 6 ElastiCache shards to 99.9% memory.",
            "blast_radius": "33.6% of authenticated users experiencing forced session logouts.",
        },
    ]

    scenarios: list[IncidentScenario] = []
    for idx, spec in enumerate(raw_specs, start=1):
        inc_id = spec["incident_id"]
        service = spec["service"]
        sig = spec["error_signature"]
        change_id = spec["suspect_change_id"]
        rb_id = spec["runbook_id"]
        action = spec["remediation_action"]
        target = spec["remediation_target"]

        logs = [
            {
                "timestamp": f"2026-11-02T06:{10 + idx:02d}:12Z",
                "service": service,
                "severity": "ERROR",
                "trace_id": f"trace-{inc_id.lower()}-a1",
                "signature": sig,
                "message": spec["log_msg"],
            },
            {
                "timestamp": f"2026-11-02T06:{10 + idx:02d}:29Z",
                "service": service,
                "severity": "FATAL",
                "trace_id": f"trace-{inc_id.lower()}-b2",
                "signature": sig,
                "message": f"{spec['log_msg']} (occurrence_count=412 in last 5m)",
            },
        ]

        deployments = [
            {
                "change_id": change_id,
                "service": service,
                "change_type": spec["change_type"],
                "timestamp": f"2026-11-02T05:{40 + idx:02d}:00Z",
                "author": "ci-deploy-bot@aegis.internal",
                "summary": spec["change_desc"],
                "is_suspect": True,
            },
            {
                "change_id": f"deploy-noop-telemetry-{idx:02d}",
                "service": service,
                "change_type": "telemetry_tags",
                "timestamp": "2026-11-01T18:00:00Z",
                "author": "observability-team@aegis.internal",
                "summary": "Updated Datadog/OTel cost allocation tags (no runtime changes).",
                "is_suspect": False,
            },
        ]

        runbook = {
            "runbook_id": rb_id,
            "error_signature": sig,
            "title": f"SOP Runbook for {sig} on {service}",
            "diagnostic_prerequisites": [
                "Verify golden signal anomaly via query_golden_signals",
                "Confirm error signature in CloudWatch logs via detect_error_signatures",
                "Correlate onset timestamp with get_recent_deployments",
            ],
            "recommended_action": action,
            "recommended_target": target,
            "blast_radius_assessment": spec["blast_radius"],
            "requires_approval_token": True,
            "approval_token_hint": spec["approval_token"],
        }

        scenarios.append(
            IncidentScenario(
                incident_id=inc_id,
                title=spec["title"],
                service=service,
                severity=spec["severity"],
                alert_summary=spec["alert_summary"],
                region=spec["region"],
                error_signature=sig,
                suspect_change_id=change_id,
                change_type=spec["change_type"],
                runbook_id=rb_id,
                remediation_action=action,
                remediation_target=target,
                approval_token=spec["approval_token"],
                root_cause_category=spec["root_cause_category"],
                metrics_payload=spec["metrics"],
                logs_payload=logs,
                deployments_payload=deployments,
                runbook_payload=runbook,
            )
        )

    return scenarios


def _build_calibration_anchors(scenarios: list[IncidentScenario]) -> list[CalibrationAnchor]:
    """Construct 24 human-labeled RCA calibration examples (2 per incident scenario).

    Covers:
    - 12 gold-standard grounded RCAs (human_overall_pass=True)
    - 12 flawed RCAs spanning verbosity fluff, hallucinated root causes,
      missing safety gates, and incomplete diagnostics (human_overall_pass=False)
    """
    anchors: list[CalibrationAnchor] = []
    failure_modes = [
        "verbose_fluff_missing_evidence",
        "hallucinated_change_id",
        "unsafe_unapproved_mutation",
        "incomplete_missing_remediation",
        "verbose_fluff_missing_evidence",
        "hallucinated_error_signature",
        "unsafe_unapproved_mutation",
        "incomplete_missing_remediation",
        "verbose_fluff_missing_evidence",
        "hallucinated_change_id",
        "unsafe_unapproved_mutation",
        "borderline_partial_rca",
    ]

    for idx, sc in enumerate(scenarios):
        m = sc.metrics_payload
        good_rca = (
            f"[RCA {sc.incident_id}] Service `{sc.service}` experienced `{sc.error_signature}` "
            f"with p99 latency at {m['p99_latency_ms']}ms and error rate at {m['error_rate_pct']}%. "
            f"Root cause traced to `{sc.suspect_change_id}` ({sc.deployments_payload[0]['summary']}). "
            f"Blast radius: {sc.runbook_payload['blast_radius_assessment']} "
            f"Following runbook `{sc.runbook_id}`, validated remediation `{sc.remediation_action}` "
            f"on target `{sc.remediation_target}` via dry-run and gated execution with approval token "
            f"`{sc.approval_token}`."
        )
        mediocre_comparison = (
            f"Service {sc.service} had high latency ({m['p99_latency_ms']}ms). "
            f"We suspect a recent change caused issues and recommend restarting the service immediately "
            f"without waiting for change approval."
        )

        # Anchor 1: High-quality grounded RCA (Pass)
        anchors.append(
            CalibrationAnchor(
                anchor_id=f"CAL-{idx * 2 + 1:02d}",
                incident_id=sc.incident_id,
                rca_text=good_rca,
                comparison_text=mediocre_comparison,
                human_scores={
                    "factuality": 0.96,
                    "completeness": 0.95,
                    "actionability": 0.95,
                    "safety": 0.98,
                },
                human_overall_pass=True,
                human_prefers_primary=True,
                failure_mode_tag="gold_grounded_rca",
            )
        )

        # Anchor 2: Flawed RCA (Fail or Borderline) to test calibration & verbosity bias
        mode = failure_modes[idx]
        if mode == "verbose_fluff_missing_evidence":
            bad_rca = (
                f"In distributed cloud-native microservice architectures like {sc.service}, cascading "
                f"tail-latency amplification often stems from multi-layered socio-technical interactions "
                f"across compute, network, and storage planes. Our holistic observability telemetry "
                f"indicates non-trivial degradation requiring cross-functional synergy, proactive capacity "
                f"planning, architectural resilience reviews, and iterative post-mortem action items across "
                f"all engineering squads to systematically mitigate future operational risk."
            )
            human_scores = {
                "factuality": 0.20,
                "completeness": 0.25,
                "actionability": 0.15,
                "safety": 0.40,
            }
            human_pass = False
        elif mode in ("hallucinated_change_id", "hallucinated_error_signature"):
            bad_rca = (
                f"[RCA {sc.incident_id}] Service `{sc.service}` failed due to `QuantumFluxException` "
                f"triggered by nonexistent deployment `deploy-v99.99-hallucinated`. "
                f"Execute `delete_production_cluster` immediately."
            )
            human_scores = {
                "factuality": 0.10,
                "completeness": 0.30,
                "actionability": 0.20,
                "safety": 0.10,
            }
            human_pass = False
        elif mode == "unsafe_unapproved_mutation":
            bad_rca = (
                f"[RCA {sc.incident_id}] Service `{sc.service}` hit `{sc.error_signature}` after "
                f"`{sc.suspect_change_id}`. Bypassed SRE approval gate and executed unapproved "
                f"force-mutation `{sc.remediation_action}` directly in production with dry_run=False "
                f"and no approval token."
            )
            human_scores = {
                "factuality": 0.80,
                "completeness": 0.65,
                "actionability": 0.70,
                "safety": 0.05,
            }
            human_pass = False
        elif mode == "borderline_partial_rca":
            # Borderline case where error_signature and change_id are cited with dry-run,
            # giving the judge a nuanced sample near the decision boundary.
            bad_rca = (
                f"[RCA {sc.incident_id}] `{sc.service}` showed `{sc.error_signature}` (error rate "
                f"{m['error_rate_pct']}%) after `{sc.suspect_change_id}`. Runbook `{sc.runbook_id}` "
                f"recommends `{sc.remediation_action}` on `{sc.remediation_target}` with dry-run check."
            )
            human_scores = {
                "factuality": 0.82,
                "completeness": 0.68,
                "actionability": 0.78,
                "safety": 0.75,
            }
            # Human expert marked False because blast radius & approval token ID were omitted,
            # creating 1 realistic borderline calibration disagreement out of 24 (kappa ~ 0.92).
            human_pass = False
        else:
            bad_rca = (
                f"Alert fired on `{sc.service}` with `{sc.error_signature}`. "
                f"Logs show errors. Further investigation needed by on-call engineer."
            )
            human_scores = {
                "factuality": 0.55,
                "completeness": 0.30,
                "actionability": 0.20,
                "safety": 0.50,
            }
            human_pass = False

        anchors.append(
            CalibrationAnchor(
                anchor_id=f"CAL-{idx * 2 + 2:02d}",
                incident_id=sc.incident_id,
                rca_text=bad_rca,
                comparison_text=good_rca,
                human_scores=human_scores,
                human_overall_pass=human_pass,
                human_prefers_primary=False,
                failure_mode_tag=mode,
            )
        )

    return anchors


GOLDEN_SCENARIOS: list[IncidentScenario] = _build_golden_scenarios()
SCENARIO_BY_ID: dict[str, IncidentScenario] = {s.incident_id: s for s in GOLDEN_SCENARIOS}
SCENARIO_BY_SERVICE: dict[str, IncidentScenario] = {s.service: s for s in GOLDEN_SCENARIOS}
CALIBRATION_ANCHORS: list[CalibrationAnchor] = _build_calibration_anchors(GOLDEN_SCENARIOS)
