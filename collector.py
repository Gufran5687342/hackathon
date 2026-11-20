import hashlib
import json
import random
import re
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import requests
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# =====================================================
# CONFIGURATION
# =====================================================

BACKEND_URL = "http://127.0.0.1:8000"

TELEMETRY_URL = f"{BACKEND_URL}/api/v1/telemetry/ingest"
REGISTER_URL = f"{BACKEND_URL}/api/v1/collectors/register"
HEARTBEAT_URL = f"{BACKEND_URL}/api/v1/collectors/heartbeat"

TENANT_ID = "customer-001"
REGION = "ap-south-1"
COLLECTOR_ID = "collector-001"
RAW_HOST_NAME = "prod-db-server-02.internal"
COLLECTOR_VERSION = "2.0.0"

COLLECTION_INTERVAL = 4
HEARTBEAT_INTERVAL = 20

BASE_DIR = Path(__file__).resolve().parent
QUEUE_DB = BASE_DIR / "collector_buffer.db"
AUDIT_FILE = BASE_DIR / "egress_audit.jsonl"

# Strict Allow-List: ONLY these fields can cross the Tier 1 -> Tier 2 trust boundary
APPROVED_FIELDS = [
    "payload_id",
    "tenant_id",
    "region",
    "source_id",
    "timestamp",
    "source_timezone",
    "metric_name",
    "metric_value",
    "metric_unit",
    "health_state",
    "event_category",
    "severity",
    "alert_context"
]

session = requests.Session()
collector_running = True


# =====================================================
# HELPERS: TIME & PSEUDONYMIZATION
# =====================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def pseudonymize_source(raw_hostname: str) -> str:
    """Deterministic pseudonymous ID so internal hostnames never leave Tier 1."""
    digest = hashlib.sha256(f"{TENANT_ID}:{raw_hostname}".encode()).hexdigest()[:8]
    return f"node-{digest}"


SOURCE_ID = pseudonymize_source(RAW_HOST_NAME)


# =====================================================
# LOCAL DATABASE BUFFER (SQLITE)
# =====================================================

def initialize_buffer():
    connection = sqlite3.connect(QUEUE_DB)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT UNIQUE NOT NULL,
            payload_json TEXT NOT NULL,
            raw_log_json TEXT NOT NULL,
            redacted_fields_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            attempts INTEGER DEFAULT 0
        )
    """)
    connection.commit()
    connection.close()


def add_to_buffer(safe_payload: dict, raw_event: dict, redacted_fields: list):
    connection = sqlite3.connect(QUEUE_DB)
    connection.execute("""
        INSERT OR IGNORE INTO telemetry_queue
        (payload_id, payload_json, raw_log_json, redacted_fields_json, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        safe_payload["payload_id"],
        json.dumps(safe_payload),
        json.dumps(raw_event),
        json.dumps(redacted_fields),
        utc_now()
    ))
    connection.commit()
    connection.close()


def get_pending_events(limit=25):
    connection = sqlite3.connect(QUEUE_DB)
    rows = connection.execute("""
        SELECT id, payload_json, raw_log_json, redacted_fields_json, attempts
        FROM telemetry_queue
        ORDER BY id ASC
        LIMIT ?
    """, (limit,)).fetchall()
    connection.close()

    return [
        {
            "id": row[0],
            "payload": json.loads(row[1]),
            "raw_log": json.loads(row[2]),
            "redacted_fields": json.loads(row[3]),
            "attempts": row[4]
        }
        for row in rows
    ]


def remove_from_buffer(row_id: int):
    connection = sqlite3.connect(QUEUE_DB)
    connection.execute("DELETE FROM telemetry_queue WHERE id = ?", (row_id,))
    connection.commit()
    connection.close()


def increment_attempts(row_id: int):
    connection = sqlite3.connect(QUEUE_DB)
    connection.execute("""
        UPDATE telemetry_queue SET attempts = attempts + 1 WHERE id = ?
    """, (row_id,))
    connection.commit()
    connection.close()


def get_buffer_count() -> int:
    connection = sqlite3.connect(QUEUE_DB)
    result = connection.execute("SELECT COUNT(*) FROM telemetry_queue").fetchone()
    connection.close()
    return result[0]


# =====================================================
# LOCAL DATA REDACTION & ALLOW-LIST SANITIZER
# =====================================================

def redact_sensitive_data(text: str):
    if not text:
        return text, []

    redacted_fields = []

    email_pattern = r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b'
    secret_pattern = r'\b(password|passwd|pwd|api_key|apikey|secret|token|bearer)\s*[:=]\s*\S+'
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    if re.search(email_pattern, text):
        redacted_fields.append("alert_context.email")
        text = re.sub(email_pattern, "[REDACTED_EMAIL]", text)

    if re.search(secret_pattern, text, flags=re.IGNORECASE):
        redacted_fields.append("alert_context.secret")
        text = re.sub(secret_pattern, r'\1=[REDACTED_SECRET]', text, flags=re.IGNORECASE)

    if re.search(ipv4_pattern, text):
        redacted_fields.append("alert_context.internal_ip")
        text = re.sub(ipv4_pattern, "[REDACTED_IP]", text)

    return text, redacted_fields


def calculate_health(metric_name: str, value: float) -> str:
    if metric_name in ("CPU Usage", "Memory Usage"):
        if value >= 90:
            return "Poor"
        if value >= 80:
            return "Fair"
        if value >= 60:
            return "Good"
        return "Excellent"

    if metric_name == "Network Latency":
        if value >= 200:
            return "Poor"
        if value >= 100:
            return "Fair"
        if value >= 60:
            return "Good"
        return "Excellent"

    if metric_name == "Failed Logins":
        if value >= 5:
            return "Poor"
        if value >= 3:
            return "Fair"
        if value >= 1:
            return "Good"
        return "Excellent"

    return "Excellent"


def calculate_severity(metric_name: str, value: float) -> str:
    if metric_name in ("CPU Usage", "Memory Usage"):
        if value >= 90:
            return "critical"
        if value >= 80:
            return "warning"
    elif metric_name == "Network Latency":
        if value >= 200:
            return "critical"
        if value >= 100:
            return "warning"
    elif metric_name == "Failed Logins":
        if value >= 5:
            return "critical"
        if value >= 3:
            return "warning"
    return "info"


def sanitize_telemetry(raw_event: dict):
    redacted_fields = []

    if raw_event.get("raw_hostname"):
        redacted_fields.append(f"hostname({raw_event['raw_hostname']}->{SOURCE_ID})")

    # Drop raw_payload / credentials completely (never crosses boundary)
    if "raw_log_line" in raw_event:
        redacted_fields.append("dropped:raw_log_line")

    safe_context, context_redactions = redact_sensitive_data(
        raw_event.get("alert_context", "")
    )
    redacted_fields.extend(context_redactions)

    candidate = {
        "payload_id": raw_event.get("payload_id") or str(uuid.uuid4()),
        "tenant_id": raw_event.get("tenant_id", TENANT_ID),
        "region": raw_event.get("region", REGION),
        "source_id": SOURCE_ID,
        "timestamp": raw_event.get("timestamp", utc_now()),
        "source_timezone": raw_event.get("source_timezone", "Asia/Kolkata"),
        "metric_name": raw_event["metric_name"],
        "metric_value": float(raw_event["metric_value"]),
        "metric_unit": raw_event["metric_unit"],
        "health_state": raw_event.get("health_state") or calculate_health(raw_event["metric_name"], float(raw_event["metric_value"])),
        "event_category": raw_event.get("event_category", "infrastructure"),
        "severity": raw_event.get("severity") or calculate_severity(raw_event["metric_name"], float(raw_event["metric_value"])),
        "alert_context": safe_context
    }

    # Strict allow-list filter: guarantees no unapproved field ever leaves Tier 1
    safe_event = {
        key: value
        for key, value in candidate.items()
        if key in APPROVED_FIELDS
    }

    return safe_event, redacted_fields


# =====================================================
# LOCAL EGRESS PROOF AUDIT LOG
# =====================================================

def write_egress_audit(raw_event: dict, safe_payload: dict, redacted_fields: list, status: str, status_code: int | None):
    audit_record = {
        "audit_timestamp": utc_now(),
        "payload_id": safe_payload["payload_id"],
        "tenant_id": safe_payload["tenant_id"],
        "approved_fields": APPROVED_FIELDS,
        "redacted_fields": redacted_fields,
        "local_raw_event": raw_event,          # Stays strictly on Tier 1
        "transmitted_payload": safe_payload,   # Exact JSON sent to Tier 2 SaaS
        "transmission_status": status,
        "http_status_code": status_code
    }
    with open(AUDIT_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(audit_record) + "\n")


# =====================================================
# SIMULATED TELEMETRY GENERATOR
# =====================================================

def generate_raw_telemetry():
    metric_name = random.choice([
        "CPU Usage",
        "Memory Usage",
        "Network Latency",
        "Failed Logins"
    ])

    if metric_name == "CPU Usage":
        value = round(random.uniform(20, 98), 1)
        unit, category = "percent", "infrastructure"
    elif metric_name == "Memory Usage":
        value = round(random.uniform(30, 96), 1)
        unit, category = "percent", "infrastructure"
    elif metric_name == "Network Latency":
        value = round(random.uniform(15, 250), 1)
        unit, category = "ms", "network"
    else:
        value = float(random.randint(0, 8))
        unit, category = "count", "security"

    health = calculate_health(metric_name, value)
    severity = calculate_severity(metric_name, value)

    alert_context = f"{metric_name} measured at {value} {unit} on 10.24.18.42. Health: {health}."
    raw_log_line = f"SYS_RAW host={RAW_HOST_NAME} ip=10.24.18.42 metric={metric_name} val={value}"

    # Inject sensitive secrets ~25% of the time for live demo proof
    if random.random() < 0.25 or metric_name == "Failed Logins":
        alert_context += " User=admin@example.com Password=SuperSecretPassword123!"
        raw_log_line += " auth_user=admin@example.com api_key=sk-live-987654321"

    return {
        "tenant_id": TENANT_ID,
        "region": REGION,
        "raw_hostname": RAW_HOST_NAME,
        "timestamp": utc_now(),
        "source_timezone": "Asia/Kolkata",
        "metric_name": metric_name,
        "metric_value": value,
        "metric_unit": unit,
        "health_state": health,
        "event_category": category,
        "severity": severity,
        "alert_context": alert_context,
        "raw_log_line": raw_log_line
    }


# =====================================================
# BACKEND COMMUNICATION (REGISTER, HEARTBEAT, FLUSH)
# =====================================================

def register_collector():
    registration_data = {
        "collector_id": COLLECTOR_ID,
        "tenant_id": TENANT_ID,
        "region": REGION,
        "source_id": SOURCE_ID,
        "version": COLLECTOR_VERSION
    }
    try:
        response = session.post(REGISTER_URL, json=registration_data, timeout=5)
        print(f"[REGISTRATION] HTTP {response.status_code} -> {response.text}")
        return response.status_code in (200, 201)
    except requests.exceptions.RequestException as error:
        print(f"[REGISTRATION FAILED] Backend unreachable: {error}")
        return False


def send_heartbeat():
    heartbeat_data = {
        "collector_id": COLLECTOR_ID,
        "tenant_id": TENANT_ID,
        "region": REGION,
        "version": COLLECTOR_VERSION,
        "cpu_percent": round(random.uniform(4.0, 14.0), 1),
        "memory_percent": round(random.uniform(18.0, 32.0), 1),
        "buffered_events": get_buffer_count()
    }
    try:
        response = session.post(HEARTBEAT_URL, json=heartbeat_data, timeout=5)
        if response.status_code == 200:
            print(f"[HEARTBEAT] Online | Buffered events: {heartbeat_data['buffered_events']}")
        else:
            print(f"[HEARTBEAT WARNING] HTTP {response.status_code}: {response.text}")
    except requests.exceptions.RequestException as error:
        print(f"[HEARTBEAT FAILED] SaaS Offline ({error})")


def send_event(payload: dict):
    try:
        response = session.post(TELEMETRY_URL, json=payload, timeout=5)
        if response.status_code in (200, 201):
            body = response.json()
            if body.get("status") == "duplicate_ignored":
                return "duplicate_ignored", response.status_code
            return "accepted", response.status_code
        if response.status_code == 409:
            return "duplicate_ignored", 409
        return "rejected", response.status_code
    except requests.exceptions.RequestException:
        return "failed_offline", None


def flush_buffer():
    pending = get_pending_events(limit=25)
    if not pending:
        return

    for item in pending:
        row_id = item["id"]
        payload = item["payload"]

        status, status_code = send_event(payload)

        if status in ("accepted", "duplicate_ignored"):
            remove_from_buffer(row_id)
            write_egress_audit(
                item["raw_log"],
                payload,
                item["redacted_fields"],
                status,
                status_code
            )
            print(f"[DELIVERED] {payload['metric_name']} | ID: {payload['payload_id'][:8]}... | Status: {status}")
        else:
            increment_attempts(row_id)
            print(f"[BUFFERED - SAAS OFFLINE] Queued ID: {payload['payload_id'][:8]}... | Total buffered: {get_buffer_count()}")
            if status_code is None:
                break


# =====================================================
# BACKGROUND WORKER LOOP
# =====================================================

def collector_loop():
    initialize_buffer()
    register_collector()
    last_heartbeat = 0

    while collector_running:
        current_time = time.time()

        if current_time - last_heartbeat >= HEARTBEAT_INTERVAL:
            send_heartbeat()
            last_heartbeat = current_time

        raw_event = generate_raw_telemetry()
        safe_event, redacted_fields = sanitize_telemetry(raw_event)

        add_to_buffer(safe_event, raw_event, redacted_fields)
        flush_buffer()

        time.sleep(COLLECTION_INTERVAL)


# =====================================================
# TIER 1 LOCAL EGRESS PROOF API (PORT 8001)
# =====================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_buffer()
    thread = threading.Thread(target=collector_loop, daemon=True)
    thread.start()
    yield
    global collector_running
    collector_running = False


local_app = FastAPI(
    title="Tier 1 Local Collector & Egress Proof Node",
    version="2.0.0",
    lifespan=lifespan
)

local_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@local_app.get("/local/status")
def local_status():
    return {
        "collector_id": COLLECTOR_ID,
        "tenant_id": TENANT_ID,
        "region": REGION,
        "raw_hostname_kept_local": RAW_HOST_NAME,
        "pseudonymous_source_id_sent": SOURCE_ID,
        "buffered_events_waiting": get_buffer_count(),
        "approved_allow_list": APPROVED_FIELDS
    }


@local_app.get("/local/egress-proof")
def get_egress_proof(limit: int = 15):
    """Side-by-side proof for judges: what stayed local vs. exact JSON sent to SaaS."""
    if not AUDIT_FILE.exists():
        return {"records": []}

    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]

    records = [json.loads(line) for line in reversed(lines)]
    return {
        "collector_id": COLLECTOR_ID,
        "buffered_events_waiting": get_buffer_count(),
        "records": records
    }


@local_app.post("/local/ingest-raw")
def ingest_organizer_stream(raw_event: dict):
    """Hook to pipe the organizer-provided simulated telemetry stream directly into Tier 1."""
    safe_event, redacted_fields = sanitize_telemetry(raw_event)
    add_to_buffer(safe_event, raw_event, redacted_fields)
    flush_buffer()
    return {
        "status": "processed_locally",
        "payload_id": safe_event["payload_id"],
        "redacted_fields": redacted_fields,
        "egress_payload": safe_event
    }


if __name__ == "__main__":
    print("=" * 60)
    print("TIER 1 LOCAL COLLECTOR + EGRESS PROOF SERVER (PORT 8001)")
    print(f"Raw Hostname (Local Only): {RAW_HOST_NAME}")
    print(f"Pseudonymous ID (Sent):    {SOURCE_ID}")
    print("=" * 60)
    uvicorn.run(local_app, host="127.0.0.1", port=8001)