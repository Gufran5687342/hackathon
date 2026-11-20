
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
from typing import Literal
from datetime import datetime
import sqlite3


DATABASE_NAME = "telemetry.db"


# DATABASE CONNECTION
def get_db_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


# CREATE DATABASE TABLE
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
    version="1.0.0",
    lifespan=lifespan
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
        "version": "1.0.0"
    }


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
def get_telemetry(tenant_id: str):

    connection = get_db_connection()

    try:
        rows = connection.execute("""
            SELECT * FROM telemetry
            WHERE tenant_id = ?
            ORDER BY timestamp DESC
        """, (tenant_id,)).fetchall()

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
def analyze_telemetry(tenant_id: str):

    connection = get_db_connection()

    try:
        rows = connection.execute("""
            SELECT * FROM telemetry
            WHERE tenant_id = ?
            ORDER BY timestamp DESC
        """, (tenant_id,)).fetchall()

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

