from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal
import sqlite3

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, field_validator


DATABASE_NAME = "telemetry.db"

# Collector liveness rules (collector sends a heartbeat every ~20 seconds)
ONLINE_WITHIN_SECONDS = 40
OFFLINE_AFTER_SECONDS = 60


def utc_now():
    return datetime.now(timezone.utc).isoformat()


# DATABASE CONNECTION
def get_db_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


# CREATE DATABASE TABLES
def initialize_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS telemetry (
            payload_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
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

    connection.commit()
    connection.close()


# FASTAPI LIFESPAN
@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


# FASTAPI INITIALIZATION
app = FastAPI(
    title="Smart Observability Platform",
    description="Secure AI-powered observability backend",
    version="1.1.0",
    lifespan=lifespan
)

# Allow the dashboard (Live Server) to call this API from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


# TELEMETRY DATA VALIDATION
class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload_id: str
    tenant_id: str
    source_id: str
    timestamp: datetime
    metric_name: str
    metric_value: float
    metric_unit: str

    health_state: Literal[
        "Excellent", "Good", "Fair", "Poor"
    ]

    event_category: Literal[
        "infrastructure", "network", "security", "collector"
    ]

    severity: Literal[
        "info", "warning", "critical"
    ]

    alert_context: str | None = None

    # Store everything in UTC so ordering is correct across time zones.
    @field_validator("timestamp")
    @classmethod
    def timestamp_to_utc(cls, value: datetime):
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone, e.g. 2026-11-20T10:00:00Z")
        return value.astimezone(timezone.utc)


# COLLECTOR REGISTRATION / HEARTBEAT VALIDATION
class CollectorRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str
    tenant_id: str
    source_id: str
    version: str


class CollectorHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str
    tenant_id: str
    version: str
    cpu_percent: float | None = None
    memory_percent: float | None = None
    buffered_events: int | None = None


def detect_anomaly(metric_name: str, metric_value: float):
    metric = metric_name.lower()

    if metric == "cpu usage":
        if metric_value > 85:
            return {
                "anomaly_detected": True,
                "severity": "critical",
                "recommendation": "CPU usage is critically high. Investigate resource-heavy processes and consider scaling resources."
            }

        elif metric_value >= 70:
            return {
                "anomaly_detected": True,
                "severity": "warning",
                "recommendation": "CPU usage is elevated. Monitor running processes and check for unusual activity."
            }

        else:
            return {
                "anomaly_detected": False,
                "severity": "info",
                "recommendation": "CPU usage is within normal limits."
            }

    return {
        "anomaly_detected": False,
        "severity": "info",
        "recommendation": "No detection rule is configured for this metric yet."
    }


def collector_status(last_seen_iso: str):
    """Stale or missing data downgrades the state instead of showing the last good value."""
    last_seen = datetime.fromisoformat(last_seen_iso)
    age = max(0.0, (datetime.now(timezone.utc) - last_seen).total_seconds())

    if age > OFFLINE_AFTER_SECONDS:
        return "Offline", "Poor", age, (
            f"No heartbeat for {int(age)}s (limit {OFFLINE_AFTER_SECONDS}s)"
        )

    if age > ONLINE_WITHIN_SECONDS:
        return "Delayed", "Fair", age, (
            f"Last heartbeat {int(age)}s ago, data is going stale"
        )

    return "Online", "Excellent", age, "Heartbeat received on schedule"


# HOME ENDPOINT
@app.get("/")
def home():
    return {
        "message": "Smart Observability Backend is running!",
        "status": "success"
    }


# HEALTH ENDPOINT
@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Smart Observability API",
        "version": "1.1.0"
    }


# REGISTER COLLECTOR
@app.post("/api/v1/collectors/register")
def register_collector(collector: CollectorRegistration):

    now = utc_now()
    connection = get_db_connection()

    try:
        connection.execute("""
            INSERT INTO collectors
                (tenant_id, collector_id, source_id, version, registered_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, collector_id) DO UPDATE SET
                source_id = excluded.source_id,
                version = excluded.version,
                last_seen = excluded.last_seen
        """, (
            collector.tenant_id,
            collector.collector_id,
            collector.source_id,
            collector.version,
            now,
            now
        ))

        connection.commit()

        return {
            "status": "registered",
            "collector_id": collector.collector_id,
            "tenant_id": collector.tenant_id
        }

    finally:
        connection.close()


# COLLECTOR HEARTBEAT (also re-registers if the backend database was reset)
@app.post("/api/v1/collectors/heartbeat")
def collector_heartbeat(heartbeat: CollectorHeartbeat):

    now = utc_now()
    connection = get_db_connection()

    try:
        connection.execute("""
            INSERT INTO collectors
                (tenant_id, collector_id, version, registered_at, last_seen,
                 cpu_percent, memory_percent, buffered_events)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, collector_id) DO UPDATE SET
                version = excluded.version,
                last_seen = excluded.last_seen,
                cpu_percent = excluded.cpu_percent,
                memory_percent = excluded.memory_percent,
                buffered_events = excluded.buffered_events
        """, (
            heartbeat.tenant_id,
            heartbeat.collector_id,
            heartbeat.version,
            now,
            now,
            heartbeat.cpu_percent,
            heartbeat.memory_percent,
            heartbeat.buffered_events
        ))

        connection.commit()

        return {"status": "ok", "last_seen": now}

    finally:
        connection.close()


# COLLECTOR FLEET STATUS
@app.get("/api/v1/collectors")
def list_collectors(tenant_id: str):

    connection = get_db_connection()

    try:
        rows = connection.execute("""
            SELECT * FROM collectors
            WHERE tenant_id = ?
            ORDER BY collector_id
        """, (tenant_id,)).fetchall()

        collectors = []

        for row in rows:
            status, health_state, age, reason = collector_status(row["last_seen"])

            collectors.append({
                "collector_id": row["collector_id"],
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

        return {
            "tenant_id": tenant_id,
            "total_collectors": len(collectors),
            "collectors": collectors
        }

    finally:
        connection.close()


# INGEST TELEMETRY
@app.post("/api/v1/telemetry/ingest")
def ingest_telemetry(event: TelemetryEvent):

    connection = get_db_connection()

    try:
        connection.execute("""
            INSERT INTO telemetry VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            event.payload_id,
            event.tenant_id,
            event.source_id,
            event.timestamp.isoformat(),
            event.metric_name,
            event.metric_value,
            event.metric_unit,
            event.health_state,
            event.event_category,
            event.severity,
            event.alert_context
        ))

        connection.commit()

        return {
            "status": "accepted",
            "message": "Telemetry saved to database",
            "payload_id": event.payload_id,
            "tenant_id": event.tenant_id
        }

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Duplicate payload detected"
        )

    finally:
        connection.close()


# RETRIEVE TENANT TELEMETRY
@app.get("/api/v1/telemetry")
def get_telemetry(tenant_id: str, limit: int = 500):

    connection = get_db_connection()

    try:
        rows = connection.execute("""
            SELECT * FROM telemetry
            WHERE tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (tenant_id, limit)).fetchall()

        events = [dict(row) for row in rows]

        return {
            "tenant_id": tenant_id,
            "total_events": len(events),
            "events": events
        }

    finally:
        connection.close()


# AIOPS ANOMALY DETECTION ENDPOINT
@app.get("/api/v1/aiops/analyze")
def analyze_telemetry(tenant_id: str, limit: int = 500):

    connection = get_db_connection()

    try:
        rows = connection.execute("""
            SELECT * FROM telemetry
            WHERE tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (tenant_id, limit)).fetchall()

        results = []

        for row in rows:
            analysis = detect_anomaly(
                row["metric_name"],
                row["metric_value"]
            )

            results.append({
                "payload_id": row["payload_id"],
                "metric_name": row["metric_name"],
                "metric_value": row["metric_value"],
                "health_state": row["health_state"],
                **analysis
            })

        return {
            "tenant_id": tenant_id,
            "total_analyzed": len(results),
            "results": results
        }

    finally:
        connection.close()


# Lets the VS Code run button (or `python backend.py`) start the server.
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="127.0.0.1", port=8000, reload=True)