
import sqlite3
import json
import uuid
import os
import joblib

from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException, Header, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from sklearn.ensemble import IsolationForest
import numpy as np


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_NAME = BASE_DIR / "telemetry.db"
MODEL_DIR = BASE_DIR / "ml_models"

MODEL_DIR.mkdir(exist_ok=True)

COLLECTOR_API_TOKEN = "cicada-2026-secure-collector-key"

MINIMUM_TRAINING_SAMPLES = 20
DEFAULT_CONTAMINATION = 0.05

app = FastAPI(
    title="CICADA 2026 - Smart Observability Platform",
    description="Secure AI-powered observability backend with ML anomaly detection",
    version="2.0.0"
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database():
    with get_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id TEXT UNIQUE NOT NULL,
                tenant_id TEXT NOT NULL,
                region TEXT NOT NULL,
                source_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_timezone TEXT,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                metric_unit TEXT,
                health_state TEXT,
                event_category TEXT,
                severity TEXT,
                alert_context TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS collectors (
                collector_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                region TEXT NOT NULL,
                source_id TEXT NOT NULL,
                version TEXT,
                status TEXT DEFAULT 'Offline',
                last_heartbeat TEXT,
                cpu_percent REAL,
                memory_percent REAL,
                buffered_events INTEGER DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                status TEXT DEFAULT 'Open',
                metric_name TEXT,
                source_id TEXT,
                occurrence_count INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS remediation_audit (
                audit_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                incident_id TEXT,
                action TEXT NOT NULL,
                approved_by TEXT,
                status TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_telemetry_tenant
            ON telemetry(tenant_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_telemetry_metric
            ON telemetry(tenant_id, metric_name)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_tenant
            ON incidents(tenant_id)
        """)

        conn.commit()

    print("[DATABASE] Database initialized successfully.")


@app.on_event("startup")
def startup_event():
    initialize_database()


# ============================================================
# AUTHENTICATION
# ============================================================

def verify_collector_token(
    x_collector_token: Optional[str] = Header(default=None)
):
    if x_collector_token != COLLECTOR_API_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized collector: invalid or missing X-Collector-Token"
        )

    return True


# ============================================================
# PYDANTIC MODELS
# ============================================================

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

    health_state: Literal[
        "Excellent",
        "Good",
        "Fair",
        "Poor"
    ]

    event_category: Literal[
        "infrastructure",
        "network",
        "security",
        "collector"
    ]

    severity: Literal[
        "info",
        "warning",
        "critical"
    ]

    alert_context: Optional[str] = None


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

    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    buffered_events: Optional[int] = None


class IncidentStatusUpdate(BaseModel):
    status: Literal[
        "Open",
        "Acknowledged",
        "Investigating",
        "Resolved",
        "Closed"
    ]


class RemediationApproval(BaseModel):
    tenant_id: str
    incident_id: str
    action: str
    approved_by: str


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def current_time():
    return datetime.now(timezone.utc).isoformat()


def row_to_dict(row):
    return dict(row) if row else None


# ============================================================
# ROOT AND HEALTH
# ============================================================

@app.get("/")
def root():
    return {
        "platform": "CICADA 2026",
        "name": "Smart Observability Platform",
        "status": "running",
        "version": "2.0.0",
        "features": [
            "Telemetry ingestion",
            "Collector monitoring",
            "Incident management",
            "ML anomaly detection",
            "Remediation audit"
        ]
    }


@app.get("/api/v1/health")
def health_check():
    try:
        with get_db() as conn:
            conn.execute("SELECT 1")

        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": current_time()
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# TELEMETRY INGESTION
# ============================================================

@app.post(
    "/api/v1/telemetry/ingest",
    dependencies=[Depends(verify_collector_token)]
)
def ingest_telemetry(event: TelemetryEvent):

    with get_db() as conn:

        existing = conn.execute(
            "SELECT payload_id FROM telemetry WHERE payload_id = ?",
            (event.payload_id,)
        ).fetchone()

        if existing:
            return {
                "message": "Duplicate telemetry event",
                "payload_id": event.payload_id
            }

        conn.execute("""
            INSERT INTO telemetry (
                payload_id,
                tenant_id,
                region,
                source_id,
                timestamp,
                source_timezone,
                metric_name,
                metric_value,
                metric_unit,
                health_state,
                event_category,
                severity,
                alert_context
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        conn.commit()

    incident_created = None

    if event.severity in ("warning", "critical"):
        incident_created = create_or_update_incident(event)

    return {
        "message": "Telemetry ingested successfully",
        "payload_id": event.payload_id,
        "tenant_id": event.tenant_id,
        "incident": incident_created
    }


# ============================================================
# TELEMETRY RETRIEVAL
# ============================================================

@app.get("/api/v1/telemetry")
def get_telemetry(
    tenant_id: str,
    limit: int = Query(default=100, ge=1, le=10000)
):

    with get_db() as conn:

        rows = conn.execute("""
            SELECT *
            FROM telemetry
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (tenant_id, limit)).fetchall()

    return {
        "tenant_id": tenant_id,
        "total_returned": len(rows),
        "results": [dict(row) for row in rows]
    }


# ============================================================
# COLLECTOR REGISTRATION
# ============================================================

@app.post(
    "/api/v1/collectors/register",
    dependencies=[Depends(verify_collector_token)]
)
def register_collector(collector: CollectorRegistration):

    with get_db() as conn:

        existing = conn.execute("""
            SELECT collector_id
            FROM collectors
            WHERE collector_id = ?
        """, (collector.collector_id,)).fetchone()

        if existing:

            conn.execute("""
                UPDATE collectors
                SET tenant_id = ?,
                    region = ?,
                    source_id = ?,
                    version = ?
                WHERE collector_id = ?
            """, (
                collector.tenant_id,
                collector.region,
                collector.source_id,
                collector.version,
                collector.collector_id
            ))

        else:

            conn.execute("""
                INSERT INTO collectors (
                    collector_id,
                    tenant_id,
                    region,
                    source_id,
                    version,
                    status
                )
                VALUES (?, ?, ?, ?, ?, 'Offline')
            """, (
                collector.collector_id,
                collector.tenant_id,
                collector.region,
                collector.source_id,
                collector.version
            ))

        conn.commit()

    return {
        "message": "Collector registered successfully",
        "collector_id": collector.collector_id,
        "tenant_id": collector.tenant_id
    }


# ============================================================
# COLLECTOR HEARTBEAT
# ============================================================

@app.post(
    "/api/v1/collectors/heartbeat",
    dependencies=[Depends(verify_collector_token)]
)
def collector_heartbeat(heartbeat: CollectorHeartbeat):

    with get_db() as conn:

        collector = conn.execute("""
            SELECT collector_id
            FROM collectors
            WHERE collector_id = ?
            AND tenant_id = ?
        """, (
            heartbeat.collector_id,
            heartbeat.tenant_id
        )).fetchone()

        if not collector:
            raise HTTPException(
                status_code=404,
                detail="Collector not registered"
            )

        conn.execute("""
            UPDATE collectors
            SET region = ?,
                version = ?,
                status = 'Online',
                last_heartbeat = ?,
                cpu_percent = ?,
                memory_percent = ?,
                buffered_events = ?
            WHERE collector_id = ?
            AND tenant_id = ?
        """, (
            heartbeat.region,
            heartbeat.version,
            current_time(),
            heartbeat.cpu_percent,
            heartbeat.memory_percent,
            heartbeat.buffered_events,
            heartbeat.collector_id,
            heartbeat.tenant_id
        ))

        conn.commit()

    return {
        "message": "Heartbeat received successfully",
        "collector_id": heartbeat.collector_id,
        "status": "Online"
    }


# ============================================================
# COLLECTOR MONITORING
# ============================================================

@app.get("/api/v1/collectors")
def list_collectors(
    tenant_id: str,
    offline_threshold_seconds: int = 60
):

    now = datetime.now(timezone.utc)

    with get_db() as conn:

        rows = conn.execute("""
            SELECT *
            FROM collectors
            WHERE tenant_id = ?
        """, (tenant_id,)).fetchall()

        results = []

        for row in rows:

            collector = dict(row)

            last_heartbeat = collector["last_heartbeat"]

            online = False

            if last_heartbeat:
                try:
                    heartbeat_time = datetime.fromisoformat(
                        last_heartbeat
                    )

                    online = (
                        now - heartbeat_time
                    ).total_seconds() <= offline_threshold_seconds

                except ValueError:
                    online = False

            collector["status"] = (
                "Online" if online else "Offline"
            )

            results.append(collector)

    online_count = sum(
        1 for item in results
        if item["status"] == "Online"
    )

    return {
        "tenant_id": tenant_id,
        "total_collectors": len(results),
        "online_collectors": online_count,
        "offline_collectors": len(results) - online_count,
        "offline_threshold_seconds": offline_threshold_seconds,
        "collectors": results
    }


# ============================================================
# INCIDENT CORRELATION
# ============================================================

def create_or_update_incident(event):

    now = current_time()

    window_start = (
        datetime.now(timezone.utc) - timedelta(minutes=5)
    ).isoformat()

    with get_db() as conn:

        existing = conn.execute("""
            SELECT *
            FROM incidents
            WHERE tenant_id = ?
            AND metric_name = ?
            AND source_id = ?
            AND status IN ('Open', 'Acknowledged', 'Investigating')
            AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
        """, (
            event.tenant_id,
            event.metric_name,
            event.source_id,
            window_start
        )).fetchone()

        if existing:

            conn.execute("""
                UPDATE incidents
                SET occurrence_count = occurrence_count + 1,
                    severity = CASE
                        WHEN severity = 'critical'
                        OR ? = 'critical'
                        THEN 'critical'
                        ELSE 'warning'
                    END,
                    updated_at = ?
                WHERE incident_id = ?
            """, (
                event.severity,
                now,
                existing["incident_id"]
            ))

            conn.commit()

            return {
                "incident_id": existing["incident_id"],
                "action": "correlated"
            }

        incident_id = str(uuid.uuid4())

        conn.execute("""
            INSERT INTO incidents (
                incident_id,
                tenant_id,
                title,
                description,
                severity,
                status,
                metric_name,
                source_id,
                occurrence_count,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, 'Open', ?, ?, 1, ?, ?)
        """, (
            incident_id,
            event.tenant_id,
            f"{event.severity.upper()}: {event.metric_name}",
            event.alert_context or "Telemetry threshold exceeded",
            event.severity,
            event.metric_name,
            event.source_id,
            now,
            now
        ))

        conn.commit()

    return {
        "incident_id": incident_id,
        "action": "created"
    }


# ============================================================
# INCIDENT RETRIEVAL
# ============================================================

@app.get("/api/v1/incidents")
def get_incidents(
    tenant_id: str,
    status: Optional[str] = None
):

    with get_db() as conn:

        if status:

            rows = conn.execute("""
                SELECT *
                FROM incidents
                WHERE tenant_id = ?
                AND status = ?
                ORDER BY created_at DESC
            """, (tenant_id, status)).fetchall()

        else:

            rows = conn.execute("""
                SELECT *
                FROM incidents
                WHERE tenant_id = ?
                ORDER BY created_at DESC
            """, (tenant_id,)).fetchall()

    return {
        "tenant_id": tenant_id,
        "total_incidents": len(rows),
        "incidents": [dict(row) for row in rows]
    }


# ============================================================
# INCIDENT STATUS UPDATE
# ============================================================

@app.patch("/api/v1/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: str,
    update: IncidentStatusUpdate,
    tenant_id: str
):

    with get_db() as conn:

        incident = conn.execute("""
            SELECT *
            FROM incidents
            WHERE incident_id = ?
            AND tenant_id = ?
        """, (incident_id, tenant_id)).fetchone()

        if not incident:
            raise HTTPException(
                status_code=404,
                detail="Incident not found"
            )

        previous_status = incident["status"]

        conn.execute("""
            UPDATE incidents
            SET status = ?,
                updated_at = ?
            WHERE incident_id = ?
            AND tenant_id = ?
        """, (
            update.status,
            current_time(),
            incident_id,
            tenant_id
        ))

        conn.commit()

    return {
        "message": "Incident status updated successfully",
        "incident_id": incident_id,
        "previous_status": previous_status,
        "current_status": update.status
    }


# ============================================================
# REMEDIATION APPROVAL
# ============================================================

@app.post("/api/v1/remediation/approve")
def approve_remediation(request: RemediationApproval):

    audit_id = str(uuid.uuid4())

    with get_db() as conn:

        incident = conn.execute("""
            SELECT incident_id
            FROM incidents
            WHERE incident_id = ?
            AND tenant_id = ?
        """, (
            request.incident_id,
            request.tenant_id
        )).fetchone()

        if not incident:
            raise HTTPException(
                status_code=404,
                detail="Incident not found"
            )

        conn.execute("""
            INSERT INTO remediation_audit (
                audit_id,
                tenant_id,
                incident_id,
                action,
                approved_by,
                status,
                details,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_id,
            request.tenant_id,
            request.incident_id,
            request.action,
            request.approved_by,
            "Approved",
            "Approval recorded. No automatic system action executed.",
            current_time()
        ))

        conn.commit()

    return {
        "message": "Remediation approval recorded successfully",
        "audit_id": audit_id,
        "incident_id": request.incident_id,
        "status": "Approved"
    }


@app.get("/api/v1/remediation/audit")
def get_remediation_audit(tenant_id: str):

    with get_db() as conn:

        rows = conn.execute("""
            SELECT *
            FROM remediation_audit
            WHERE tenant_id = ?
            ORDER BY created_at DESC
        """, (tenant_id,)).fetchall()

    return {
        "tenant_id": tenant_id,
        "total_records": len(rows),
        "audit_records": [dict(row) for row in rows]
    }


# ============================================================
# MACHINE LEARNING - MODEL UTILITIES
# ============================================================

def get_model_path(tenant_id, metric_name):

    safe_tenant = "".join(
        c for c in tenant_id if c.isalnum() or c in "-_"
    )

    safe_metric = "".join(
        c for c in metric_name if c.isalnum() or c in "-_"
    )

    return MODEL_DIR / f"{safe_tenant}_{safe_metric}.joblib"


def get_training_records(tenant_id, limit):

    with get_db() as conn:

        rows = conn.execute("""
            SELECT metric_name, metric_value, timestamp
            FROM telemetry
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (
            tenant_id,
            limit
        )).fetchall()

    grouped = {}

    for row in rows:

        metric = row["metric_name"]

        grouped.setdefault(metric, []).append({
            "metric_value": float(row["metric_value"]),
            "timestamp": row["timestamp"]
        })

    return grouped


def load_model(tenant_id, metric_name):

    model_path = get_model_path(
        tenant_id,
        metric_name
    )

    if not model_path.exists():
        return None

    try:
        return joblib.load(model_path)

    except Exception:
        return None


# ============================================================
# ML MODEL TRAINING
# ============================================================

@app.post("/api/v1/aiops/ml/train")
def train_ml_models(
    tenant_id: str,
    limit: int = Query(default=5000, ge=1, le=100000)
):

    grouped_records = get_training_records(
        tenant_id,
        limit
    )

    if not grouped_records:
        raise HTTPException(
            status_code=404,
            detail="No telemetry records found for this tenant."
        )

    training_results = []

    for metric_name, records in grouped_records.items():

        values = np.array([
            record["metric_value"]
            for record in records
        ]).reshape(-1, 1)

        if len(values) < MINIMUM_TRAINING_SAMPLES:

            training_results.append({
                "metric_name": metric_name,
                "status": "Insufficient data",
                "samples": len(values),
                "minimum_required": MINIMUM_TRAINING_SAMPLES
            })

            continue

        model = IsolationForest(
            n_estimators=100,
            contamination=DEFAULT_CONTAMINATION,
            random_state=42
        )

        model.fit(values)

        model_path = get_model_path(
            tenant_id,
            metric_name
        )

        joblib.dump(model, model_path)

        training_results.append({
            "metric_name": metric_name,
            "status": "Trained",
            "samples": len(values),
            "algorithm": "Isolation Forest",
            "model_file": model_path.name
        })

    trained_count = sum(
        1 for item in training_results
        if item["status"] == "Trained"
    )

    return {
        "message": "ML training process completed",
        "tenant_id": tenant_id,
        "total_metrics": len(grouped_records),
        "trained_models": trained_count,
        "results": training_results
    }


# ============================================================
# ML MODEL STATUS
# ============================================================

@app.get("/api/v1/aiops/ml/status")
def ml_model_status(tenant_id: str):

    grouped_records = get_training_records(
        tenant_id,
        100000
    )

    results = []

    for metric_name, records in grouped_records.items():

        model_path = get_model_path(
            tenant_id,
            metric_name
        )

        results.append({
            "metric_name": metric_name,
            "samples_available": len(records),
            "model_trained": model_path.exists(),
            "minimum_required": MINIMUM_TRAINING_SAMPLES
        })

    return {
        "tenant_id": tenant_id,
        "algorithm": "Isolation Forest",
        "total_metrics": len(results),
        "trained_models": sum(
            1 for item in results
            if item["model_trained"]
        ),
        "models": results
    }


# ============================================================
# ML ANOMALY PREDICTION
# ============================================================

@app.get("/api/v1/aiops/ml/predict")
def predict_anomaly(
    tenant_id: str,
    metric_name: str,
    metric_value: float
):

    model = load_model(
        tenant_id,
        metric_name
    )

    if model is None:
        raise HTTPException(
            status_code=404,
            detail="Trained model not found. Train the model first."
        )

    prediction = int(
        model.predict([[metric_value]])[0]
    )

    anomaly_score = float(
        model.decision_function([[metric_value]])[0]
    )

    is_anomaly = prediction == -1

    return {
        "tenant_id": tenant_id,
        "metric_name": metric_name,
        "metric_value": metric_value,
        "prediction": (
            "Anomaly" if is_anomaly else "Normal"
        ),
        "is_anomaly": is_anomaly,
        "anomaly_score": round(anomaly_score, 6),
        "algorithm": "Isolation Forest"
    }


# ============================================================
# ML ANALYSIS OF LATEST TELEMETRY
# ============================================================

@app.get("/api/v1/aiops/analyze")
def analyze_telemetry(tenant_id: str):

    with get_db() as conn:

        rows = conn.execute("""
            SELECT *
            FROM telemetry
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT 100
        """, (tenant_id,)).fetchall()

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="No telemetry available for analysis."
        )

    results = []

    for row in rows:

        metric_name = row["metric_name"]
        metric_value = float(row["metric_value"])

        model = load_model(
            tenant_id,
            metric_name
        )

        if model is None:

            results.append({
                "payload_id": row["payload_id"],
                "metric_name": metric_name,
                "metric_value": metric_value,
                "ml_status": "Model not trained"
            })

            continue

        prediction = int(
            model.predict([[metric_value]])[0]
        )

        score = float(
            model.decision_function([[metric_value]])[0]
        )

        results.append({
            "payload_id": row["payload_id"],
            "metric_name": metric_name,
            "metric_value": metric_value,
            "prediction": (
                "Anomaly" if prediction == -1 else "Normal"
            ),
            "is_anomaly": prediction == -1,
            "anomaly_score": round(score, 6)
        })

    anomaly_count = sum(
        1 for item in results
        if item.get("is_anomaly") is True
    )

    return {
        "tenant_id": tenant_id,
        "total_analyzed": len(results),
        "anomalies_detected": anomaly_count,
        "normal_records": len(results) - anomaly_count,
        "results": results
    }


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
