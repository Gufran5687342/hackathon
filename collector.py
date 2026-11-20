
import json
import re
import uuid
import time
import random
import sqlite3
import requests

from pathlib import Path
from datetime import datetime, timezone


# =====================================================
# CONFIGURATION
# =====================================================

BACKEND_URL = "http://127.0.0.1:8000"

TELEMETRY_URL = f"{BACKEND_URL}/api/v1/telemetry/ingest"
REGISTER_URL = f"{BACKEND_URL}/api/v1/collectors/register"
HEARTBEAT_URL = f"{BACKEND_URL}/api/v1/collectors/heartbeat"

TENANT_ID = "customer-001"
COLLECTOR_ID = "collector-001"
SOURCE_ID = "server-02"
COLLECTOR_VERSION = "1.0.0"

COLLECTION_INTERVAL = 4
HEARTBEAT_INTERVAL = 20
MAX_RETRIES = 5

BASE_DIR = Path(__file__).resolve().parent

QUEUE_DB = BASE_DIR / "collector_buffer.db"
AUDIT_FILE = BASE_DIR / "egress_audit.jsonl"

APPROVED_FIELDS = [
    "payload_id",
    "tenant_id",
    "source_id",
    "timestamp",
    "metric_name",
    "metric_value",
    "metric_unit",
    "health_state",
    "event_category",
    "severity",
    "alert_context"
]

session = requests.Session()


# =====================================================
# TIME
# =====================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


# =====================================================
# LOCAL DATABASE BUFFER
# =====================================================

def initialize_buffer():

    connection = sqlite3.connect(QUEUE_DB)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT UNIQUE NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            attempts INTEGER DEFAULT 0
        )
    """)

    connection.commit()
    connection.close()


def add_to_buffer(payload):

    connection = sqlite3.connect(QUEUE_DB)

    connection.execute("""
        INSERT OR IGNORE INTO telemetry_queue
        (payload_id, payload_json, created_at)
        VALUES (?, ?, ?)
    """, (
        payload["payload_id"],
        json.dumps(payload),
        utc_now()
    ))

    connection.commit()
    connection.close()


def get_pending_events(limit=20):

    connection = sqlite3.connect(QUEUE_DB)

    rows = connection.execute("""
        SELECT id, payload_json, attempts
        FROM telemetry_queue
        ORDER BY id ASC
        LIMIT ?
    """, (limit,)).fetchall()

    connection.close()

    events = []

    for row in rows:

        events.append({
            "id": row[0],
            "payload": json.loads(row[1]),
            "attempts": row[2]
        })

    return events


def remove_from_buffer(row_id):

    connection = sqlite3.connect(QUEUE_DB)

    connection.execute(
        "DELETE FROM telemetry_queue WHERE id = ?",
        (row_id,)
    )

    connection.commit()
    connection.close()


def increment_attempts(row_id):

    connection = sqlite3.connect(QUEUE_DB)

    connection.execute("""
        UPDATE telemetry_queue
        SET attempts = attempts + 1
        WHERE id = ?
    """, (row_id,))

    connection.commit()
    connection.close()


def get_buffer_count():

    connection = sqlite3.connect(QUEUE_DB)

    result = connection.execute(
        "SELECT COUNT(*) FROM telemetry_queue"
    ).fetchone()

    connection.close()

    return result[0]


# =====================================================
# LOCAL DATA REDACTION
# =====================================================

def redact_sensitive_data(text):

    if not text:
        return text, []

    redacted_fields = []

    email_pattern = r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b'

    secret_pattern = (
        r'\b(password|api_key|secret|token)\s*[:=]\s*\S+'
    )

    if re.search(email_pattern, text):

        redacted_fields.append("alert_context.email")

    text = re.sub(
        email_pattern,
        "[REDACTED_EMAIL]",
        text
    )

    if re.search(secret_pattern, text, flags=re.IGNORECASE):

        redacted_fields.append("alert_context.secret")

    text = re.sub(
        secret_pattern,
        r'\1=[REDACTED_SECRET]',
        text,
        flags=re.IGNORECASE
    )

    return text, redacted_fields


# =====================================================
# HEALTH STATE CALCULATION
# =====================================================

def calculate_health(metric_name, value):

    if metric_name == "CPU Usage":

        if value >= 90:
            return "Poor"

        if value >= 80:
            return "Fair"

        if value >= 60:
            return "Good"

        return "Excellent"

    if metric_name == "Memory Usage":

        if value >= 90:
            return "Poor"

        if value >= 80:
            return "Fair"

        if value >= 65:
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


# =====================================================
# SEVERITY CALCULATION
# =====================================================

def calculate_severity(metric_name, value):

    if metric_name == "CPU Usage":

        if value >= 90:
            return "critical"

        if value >= 80:
            return "warning"

    elif metric_name == "Memory Usage":

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


# =====================================================
# TELEMETRY SIMULATION
# =====================================================

def generate_raw_telemetry():

    metric_options = [
        "CPU Usage",
        "Memory Usage",
        "Network Latency",
        "Failed Logins"
    ]

    metric_name = random.choice(metric_options)

    if metric_name == "CPU Usage":

        value = round(random.uniform(20, 98), 1)
        unit = "percent"
        category = "infrastructure"

    elif metric_name == "Memory Usage":

        value = round(random.uniform(30, 96), 1)
        unit = "percent"
        category = "infrastructure"

    elif metric_name == "Network Latency":

        value = round(random.uniform(15, 250), 1)
        unit = "ms"
        category = "network"

    else:

        value = float(random.randint(0, 8))
        unit = "count"
        category = "security"

    health = calculate_health(metric_name, value)

    severity = calculate_severity(metric_name, value)

    alert_context = (
        f"{metric_name} measured at {value} {unit}. "
        f"Current health state: {health}."
    )

    # Simulated sensitive information to demonstrate redaction.
    if random.random() < 0.15:

        alert_context += (
            " Contact admin@example.com. "
            "Password=Secret123"
        )

    return {
        "tenant_id": TENANT_ID,
        "source_id": SOURCE_ID,
        "timestamp": utc_now(),
        "metric_name": metric_name,
        "metric_value": value,
        "metric_unit": unit,
        "health_state": health,
        "event_category": category,
        "severity": severity,
        "alert_context": alert_context
    }


# =====================================================
# SANITIZE TELEMETRY
# =====================================================

def sanitize_telemetry(raw_event):

    safe_context, redacted_fields = redact_sensitive_data(
        raw_event["alert_context"]
    )

    safe_event = {
        "payload_id": str(uuid.uuid4()),
        "tenant_id": raw_event["tenant_id"],
        "source_id": raw_event["source_id"],
        "timestamp": raw_event["timestamp"],
        "metric_name": raw_event["metric_name"],
        "metric_value": raw_event["metric_value"],
        "metric_unit": raw_event["metric_unit"],
        "health_state": raw_event["health_state"],
        "event_category": raw_event["event_category"],
        "severity": raw_event["severity"],
        "alert_context": safe_context
    }

    # Enforce the approved field allow-list.
    safe_event = {
        key: value
        for key, value in safe_event.items()
        if key in APPROVED_FIELDS
    }

    return safe_event, redacted_fields


# =====================================================
# LOCAL EGRESS AUDIT
# =====================================================

def write_audit(payload, redacted_fields, status, status_code):

    audit_record = {

        "audit_timestamp": utc_now(),

        "payload_id": payload["payload_id"],

        "tenant_id": payload["tenant_id"],

        "source_id": payload["source_id"],

        "approved_fields": APPROVED_FIELDS.copy(),

        "redacted_fields": redacted_fields,

        # Exact sanitized payload, not the raw original event.
        "transmitted_payload": payload,

        "transmission_status": status,

        "http_status_code": status_code
    }

    with open(AUDIT_FILE, "a", encoding="utf-8") as file:

        file.write(json.dumps(audit_record) + "\n")


# =====================================================
# COLLECTOR REGISTRATION
# =====================================================

def register_collector():

    registration_data = {

        "collector_id": COLLECTOR_ID,

        "tenant_id": TENANT_ID,

        "source_id": SOURCE_ID,

        "version": COLLECTOR_VERSION
    }

    try:

        response = session.post(
            REGISTER_URL,
            json=registration_data,
            timeout=5
        )

        print(
            "\n[REGISTRATION]",
            response.status_code,
            response.text
        )

        return response.status_code in (200, 201)

    except requests.exceptions.RequestException as error:

        print("\n[REGISTRATION FAILED]", error)

        return False


# =====================================================
# COLLECTOR HEARTBEAT
# =====================================================

def send_heartbeat():

    heartbeat_data = {

        "collector_id": COLLECTOR_ID,

        "tenant_id": TENANT_ID,

        "version": COLLECTOR_VERSION
    }

    try:

        response = session.post(
            HEARTBEAT_URL,
            json=heartbeat_data,
            timeout=5
        )

        if response.status_code == 200:

            print("[HEARTBEAT] Collector is Online")

        else:

            print(
                "[HEARTBEAT WARNING]",
                response.status_code,
                response.text
            )

    except requests.exceptions.RequestException as error:

        print("[HEARTBEAT FAILED]", error)


# =====================================================
# SEND ONE TELEMETRY EVENT
# =====================================================

def send_event(payload):

    try:

        response = session.post(
            TELEMETRY_URL,
            json=payload,
            timeout=5
        )

        # A duplicate payload is already stored by the backend.
        # Treat HTTP 409 as delivered to prevent endless retries.
        if response.status_code == 409:

            return "duplicate", 409

        if 200 <= response.status_code < 300:

            return "accepted", response.status_code

        return "rejected", response.status_code

    except requests.exceptions.RequestException:

        return "failed", None


# =====================================================
# RETRY AND BUFFER DELIVERY
# =====================================================

def flush_buffer():

    pending = get_pending_events(limit=20)

    if not pending:
        return

    print(
        f"\n[BUFFER] Attempting to deliver {len(pending)} queued events..."
    )

    for item in pending:

        row_id = item["id"]
        payload = item["payload"]

        status, status_code = send_event(payload)

        if status in ("accepted", "duplicate"):

            remove_from_buffer(row_id)

            print(
                f"[DELIVERED] {payload['metric_name']} | "
                f"Payload: {payload['payload_id']} | "
                f"HTTP: {status_code}"
            )

        else:

            increment_attempts(row_id)

            print(
                f"[DELIVERY FAILED] Payload: {payload['payload_id']} | "
                f"HTTP: {status_code} | "
                f"Attempts: {item['attempts'] + 1}"
            )

            # Stop this flush if the backend is unavailable.
            if status_code is None:
                break

    print("[BUFFER] Remaining events:", get_buffer_count())


# =====================================================
# MAIN COLLECTOR LOOP
# =====================================================

def main():

    initialize_buffer()

    print("\n" + "=" * 60)
    print("       SMART OBSERVABILITY - LOCAL COLLECTOR")
    print("=" * 60)

    print("Tenant ID:", TENANT_ID)
    print("Collector ID:", COLLECTOR_ID)
    print("Source ID:", SOURCE_ID)
    print("Backend:", BACKEND_URL)
    print("Local queue:", QUEUE_DB)
    print("Local audit:", AUDIT_FILE)

    print("\nInitializing collector...")

    register_collector()

    last_heartbeat = 0

    print("\nCollector is running. Press CTRL+C to stop.")
    print("=" * 60)

    try:

        while True:

            current_time = time.time()

            # Send periodic heartbeat.
            if current_time - last_heartbeat >= HEARTBEAT_INTERVAL:

                send_heartbeat()

                last_heartbeat = current_time

            # Generate telemetry.
            raw_event = generate_raw_telemetry()

            # Sanitize before transmission.
            safe_event, redacted_fields = sanitize_telemetry(
                raw_event
            )

            # Add every event to persistent local queue first.
            add_to_buffer(safe_event)

            print(
                f"\n[{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}] "
                f"{raw_event['metric_name']:<20} "
                f"{raw_event['metric_value']:<8} "
                f"{raw_event['metric_unit']:<10} "
                f"{raw_event['health_state']:<10} "
                f"{raw_event['severity']}"
            )

            print("    Redacted fields:", redacted_fields)

            print(
                "    Buffered locally:",
                get_buffer_count()
            )

            # Record the exact sanitized payload locally.
            write_audit(
                safe_event,
                redacted_fields,
                "queued",
                None
            )

            # Try delivering queued events.
            flush_buffer()

            time.sleep(COLLECTION_INTERVAL)

    except KeyboardInterrupt:

        print("\n\n" + "=" * 60)
        print("COLLECTOR STOPPED")
        print("=" * 60)

        print(
            "Events still buffered locally:",
            get_buffer_count()
        )

        print("Buffer database:", QUEUE_DB)
        print("Audit file:", AUDIT_FILE)

        print("\nYour unsent events are preserved locally.")

    finally:

        session.close()


# =====================================================
# START
# =====================================================

if __name__ == "__main__":

    main()