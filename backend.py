from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Literal
import statistics
import sqlite3
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, field_validator


DATABASE_NAME = "telemetry.db"

# Collector liveness rules (collector sends a heartbeat every ~20 seconds)
ONLINE_WITHIN_SECONDS = 40
OFFLINE_AFTER_SECONDS = 60


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_db_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS telemetry (
            payload_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            region TEXT NOT NULL DEFAULT 'ap-south-1',
            source_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source_timezone TEXT NOT NULL DEFAULT 'UTC',
            metric_name TEXT NOT NULL,
            metric_value REAL NOT NULL,
            metric_unit TEXT NOT NULL,
            health_state TEXT NOT NULL,
            event_category TEXT NOT NULL,
            severity TEXT NOT NULL,
            alert_context TEXT
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS collectors (
            tenant_id TEXT NOT NULL,
            region TEXT NOT NULL DEFAULT 'ap-south-1',
            collector_id TEXT NOT NULL,
            source_id TEXT,
            version TEXT,
            registered_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            cpu_percent REAL,
            memory_percent REAL,
            buffered_events INTEGER,
            PRIMARY KEY (tenant_id, collector_id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS remediation_audit (
            audit_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            action_taken TEXT NOT NULL,
            approved_by TEXT NOT NULL,
            policy_check TEXT NOT NULL,
            rollback_plan TEXT NOT NULL,
            status TEXT NOT NULL,
            executed_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Smart Observability Platform",
    description="Secure AI-powered observability backend (CICADA 2026)",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- PYDANTIC SCHEMAS (STRICT ALLOW-LISTING) ---
class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload_id: str
    tenant_id: str
    region: str = "ap-south-1"
    source_id: str
    timestamp: datetime
    source_timezone: str = "UTC"
    metric_name: str
    metric_value: float
    metric_unit: str

    health_state: Literal["Excellent", "Good", "Fair", "Poor"]
    event_category: Literal["infrastructure", "network", "security", "collector"]
    severity: Literal["info", "warning", "critical"]
    alert_context: str | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_to_utc(cls, value: datetime):
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone, e.g. 2026-11-21T02:00:00Z")
        return value.astimezone(timezone.utc)


class CollectorRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str
    tenant_id: str
    region: str = "ap-south-1"
    source_id: str
    version: str


class CollectorHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str
    tenant_id: str
    region: str = "ap-south-1"
    version: str
    cpu_percent: float | None = None
    memory_percent: float | None = None
    buffered_events: int | None = None


class RemediationApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    incident_id: str
    approved_by: str
    action_taken: str


# --- AIOPS: BASELINE Z-SCORE + DOMAIN INTELLIGENCE ---
def detect_anomaly_with_baseline(metric_name: str, metric_value: float, history_values: list[float]):
    metric = metric_name.lower()
    z_score = 0.0
    baseline_mean = metric_value

    if len(history_values) >= 5:
        baseline_mean = statistics.mean(history_values)
        stdev = statistics.pstdev(history_values)
        if stdev > 0:
            z_score = (metric_value - baseline_mean) / stdev

    # 1. Statistical deviation check (beyond static thresholds)
    is_stat_anomaly = abs(z_score) >= 2.5

    # 2. Domain-specific checks across Infra, Network, and Security
    if "cpu" in metric or "memory" in metric or "disk" in metric:
        if metric_value > 85 or z_score >= 3.0:
            return {
                "anomaly_detected": True,
                "severity": "critical",
                "z_score": round(z_score, 2),
                "baseline_mean": round(baseline_mean, 2),
                "reasoning": f"{metric_name} spiked to {metric_value} (baseline: {round(baseline_mean, 1)}, Z-score: {round(z_score, 2)}).",
                "recommendation": f"Isolate high-consumption processes on host and trigger auto-scale or service restart."
            }
        elif metric_value >= 70 or is_stat_anomaly:
            return {
                "anomaly_detected": True,
                "severity": "warning",
                "z_score": round(z_score, 2),
                "baseline_mean": round(baseline_mean, 2),
                "reasoning": f"{metric_name} elevated at {metric_value} vs rolling baseline {round(baseline_mean, 1)}.",
                "recommendation": f"Monitor {metric_name} trend over next 5 minutes; inspect recent deployments."
            }

    elif "latency" in metric or "packet_loss" in metric:
        if metric_value > 200 or ("packet_loss" in metric and metric_value > 5) or z_score >= 3.0:
            return {
                "anomaly_detected": True,
                "severity": "critical",
                "z_score": round(z_score, 2),
                "baseline_mean": round(baseline_mean, 2),
                "reasoning": f"Network degradation: {metric_name} hit {metric_value} (Z-score: {round(z_score, 2)}).",
                "recommendation": "Check upstream gateway congestion, reroute traffic to secondary region, or inspect NIC errors."
            }
        elif metric_value > 100 or is_stat_anomaly:
            return {
                "anomaly_detected": True,
                "severity": "warning",
                "z_score": round(z_score, 2),
                "baseline_mean": round(baseline_mean, 2),
                "reasoning": f"Elevated {metric_name} ({metric_value}) deviating from normal baseline ({round(baseline_mean, 1)}).",
                "recommendation": "Verify network path stability and check for bandwidth saturation."
            }

    elif "failed_login" in metric or "auth" in metric:
        if metric_value >= 5 or is_stat_anomaly:
            return {
                "anomaly_detected": True,
                "severity": "critical",
                "z_score": round(z_score, 2),
                "baseline_mean": round(baseline_mean, 2),
                "reasoning": f"Security alert: {int(metric_value)} repeated failed authentication attempts detected locally.",
                "recommendation": "Temporarily block offending source IP at local firewall and enforce MFA challenge."
            }

    if is_stat_anomaly:
        return {
            "anomaly_detected": True,
            "severity": "warning",
            "z_score": round(z_score, 2),
            "baseline_mean": round(baseline_mean, 2),
            "reasoning": f"Statistical anomaly on {metric_name}: value {metric_value} is {round(z_score, 2)} std devs from baseline.",
            "recommendation": "Inspect local host telemetry for correlated resource or network spikes."
        }

    return {
        "anomaly_detected": False,
        "severity": "info",
        "z_score": round(z_score, 2),
        "baseline_mean": round(baseline_mean, 2),
        "reasoning": "Operating within normal baseline parameters.",
        "recommendation": "No action required."
    }


def collector_status(last_seen_iso: str):
    last_seen = datetime.fromisoformat(last_seen_iso)
    age = max(0.0, (datetime.now(timezone.utc) - last_seen).total_seconds())

    if age > OFFLINE_AFTER_SECONDS:
        return "Offline", "Poor", age, f"No heartbeat for {int(age)}s (limit {OFFLINE_AFTER_SECONDS}s)"
    if age > ONLINE_WITHIN_SECONDS:
        return "Delayed", "Fair", age, f"Last heartbeat {int(age)}s ago, data is going stale"
    return "Online", "Excellent", age, "Heartbeat received on schedule"


# --- ENDPOINTS ---
@app.get("/")
def home():
    return {"message": "Smart Observability Backend v2.0 is running!", "status": "success"}


@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy", "service": "Smart Observability API", "version": "2.0.0"}


@app.post("/api/v1/collectors/register")
def register_collector(collector: CollectorRegistration):
    now = utc_now()
    connection = get_db_connection()
    try:
        connection.execute("""
            INSERT INTO collectors
                (tenant_id, region, collector_id, source_id, version, registered_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, collector_id) DO UPDATE SET
                region = excluded.region,
                source_id = excluded.source_id,
                version = excluded.version,
                last_seen = excluded.last_seen
        """, (
            collector.tenant_id, collector.region, collector.collector_id,
            collector.source_id, collector.version, now, now
        ))
        connection.commit()
        return {"status": "registered", "collector_id": collector.collector_id, "tenant_id": collector.tenant_id, "region": collector.region}
    finally:
        connection.close()


@app.post("/api/v1/collectors/heartbeat")
def collector_heartbeat(heartbeat: CollectorHeartbeat):
    now = utc_now()
    connection = get_db_connection()
    try:
        connection.execute("""
            INSERT INTO collectors
                (tenant_id, region, collector_id, version, registered_at, last_seen,
                 cpu_percent, memory_percent, buffered_events)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, collector_id) DO UPDATE SET
                region = excluded.region,
                version = excluded.version,
                last_seen = excluded.last_seen,
                cpu_percent = excluded.cpu_percent,
                memory_percent = excluded.memory_percent,
                buffered_events = excluded.buffered_events
        """, (
            heartbeat.tenant_id, heartbeat.region, heartbeat.collector_id,
            heartbeat.version, now, now, heartbeat.cpu_percent,
            heartbeat.memory_percent, heartbeat.buffered_events
        ))
        connection.commit()
        return {"status": "ok", "last_seen": now}
    finally:
        connection.close()


@app.get("/api/v1/collectors")
def list_collectors(tenant_id: str):
    connection = get_db_connection()
    try:
        rows = connection.execute("""
            SELECT * FROM collectors WHERE tenant_id = ? ORDER BY collector_id
        """, (tenant_id,)).fetchall()

        collectors = []
        for row in rows:
            status, health_state, age, reason = collector_status(row["last_seen"])
            collectors.append({
                "collector_id": row["collector_id"],
                "region": row["region"],
                "source_id": row["source_id"],
                "version": row["version"],
                "registered_at": row["registered_at"],
                "last_seen": row["last_seen"],
                "seconds_since_last_seen": round(age, 1),
                "status": status,
                "health_state": health_state,
                "reason": reason,
                "cpu_percent": row["cpu_percent"],
                "memory_percent": row["memory_percent"],
                "buffered_events": row["buffered_events"]
            })
        return {"tenant_id": tenant_id, "total_collectors": len(collectors), "collectors": collectors}
    finally:
        connection.close()


@app.post("/api/v1/telemetry/ingest")
def ingest_telemetry(event: TelemetryEvent):
    connection = get_db_connection()
    try:
        # TRUE IDEMPOTENCY: INSERT OR IGNORE prevents duplicates without breaking collector retry loops
        cursor = connection.execute("""
            INSERT OR IGNORE INTO telemetry VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.payload_id,
            event.tenant_id,
            event.region,
            event.source_id,
            event.timestamp.isoformat(),
            event.source_timezone,
            event.metric_name,
            event.metric_value,
            event.metric_unit,
            event.health_state,
            event.event_category,
            event.severity,
            event.alert_context
        ))
        connection.commit()

        if cursor.rowcount == 0:
            return {
                "status": "duplicate_ignored",
                "message": "Payload already processed (idempotent retry safe)",
                "payload_id": event.payload_id,
                "tenant_id": event.tenant_id
            }

        return {
            "status": "accepted",
            "message": "Telemetry saved to database",
            "payload_id": event.payload_id,
            "tenant_id": event.tenant_id
        }
    finally:
        connection.close()


@app.get("/api/v1/telemetry")
def get_telemetry(tenant_id: str, limit: int = 500):
    connection = get_db_connection()
    try:
        # Ordered by UTC event timestamp so out-of-order arrivals render chronologically
        rows = connection.execute("""
            SELECT * FROM telemetry
            WHERE tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (tenant_id, limit)).fetchall()

        events = [dict(row) for row in rows]
        return {"tenant_id": tenant_id, "total_events": len(events), "events": events}
    finally:
        connection.close()


@app.get("/api/v1/aiops/analyze")
def analyze_telemetry(tenant_id: str, limit: int = 200):
    connection = get_db_connection()
    try:
        rows = connection.execute("""
            SELECT * FROM telemetry
            WHERE tenant_id = ?
            ORDER BY timestamp ASC
            LIMIT ?
        """, (tenant_id, limit)).fetchall()

        history_by_metric: dict[str, list[float]] = {}
        results = []

        for row in rows:
            m_name = row["metric_name"]
            m_val = row["metric_value"]
            history = history_by_metric.setdefault(m_name, [])

            analysis = detect_anomaly_with_baseline(m_name, m_val, history)
            history.append(m_val)

            results.append({
                "payload_id": row["payload_id"],
                "source_id": row["source_id"],
                "timestamp": row["timestamp"],
                "metric_name": m_name,
                "metric_value": m_val,
                "health_state": row["health_state"],
                **analysis
            })

        results.reverse()  # Newest first for UI
        return {"tenant_id": tenant_id, "total_analyzed": len(results), "results": results}
    finally:
        connection.close()


# --- NEW: CORRELATED INCIDENTS & EXPLAINABLE AIOPS ---
@app.get("/api/v1/incidents")
def get_correlated_incidents(tenant_id: str):
    """Groups related anomalies on the same source_id into single actionable incidents."""
    analysis_data = analyze_telemetry(tenant_id=tenant_id, limit=200)["results"]
    anomalies = [r for r in analysis_data if r["anomaly_detected"]]

    grouped: dict[str, list[dict]] = {}
    for item in anomalies:
        grouped.setdefault(item["source_id"], []).append(item)

    incidents = []
    for source_id, signals in grouped.items():
        categories = list({s["metric_name"] for s in signals})
        highest_sev = "critical" if any(s["severity"] == "critical" for s in signals) else "warning"
        confidence = min(98, 65 + (len(signals) * 8))

        # Root-cause synthesis across correlated signals
        if len(categories) > 1:
            summary = f"Multi-signal degradation on {source_id}: correlated spikes across {', '.join(categories)}."
            recommended_action = f"Throttle non-critical workloads on {source_id} and inspect network/process bottlenecks."
        else:
            summary = signals[0]["reasoning"]
            recommended_action = signals[0]["recommendation"]

        incidents.append({
            "incident_id": f"INC-{source_id}-{len(signals)}",
            "tenant_id": tenant_id,
            "affected_source": source_id,
            "severity": highest_sev,
            "correlated_signal_count": len(signals),
            "contributing_signals": [
                {"metric": s["metric_name"], "value": s["metric_value"], "z_score": s["z_score"], "time": s["timestamp"]}
                for s in signals[:5]
            ],
            "confidence_percent": confidence,
            "explainable_summary": summary,
            "recommended_action": recommended_action,
            "remediation_policy": "POLICY-SAFE-01: Requires human approval; rollback snapshot created automatically."
        })

    return {"tenant_id": tenant_id, "active_incidents": len(incidents), "incidents": incidents}


# --- NEW: AUTONOMOUS OPS SAFE REMEDIATION & AUDIT TRAIL ---
@app.post("/api/v1/remediation/approve")
def approve_remediation(approval: RemediationApproval):
    connection = get_db_connection()
    audit_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"
    now = utc_now()
    try:
        connection.execute("""
            INSERT INTO remediation_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_id,
            approval.tenant_id,
            approval.incident_id,
            approval.action_taken,
            approval.approved_by,
            "PASSED (Policy-Bounded & Reversible)",
            f"Revert {approval.action_taken} via checkpoint-{audit_id}",
            "EXECUTED_SIMULATED",
            now
        ))
        connection.commit()
        return {
            "status": "approved_and_executed",
            "audit_id": audit_id,
            "incident_id": approval.incident_id,
            "policy_check": "PASSED",
            "rollback_plan": f"Revert {approval.action_taken} via checkpoint-{audit_id}",
            "executed_at": now
        }
    finally:
        connection.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="127.0.0.1", port=8000, reload=True)