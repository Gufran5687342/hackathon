
import json
import sqlite3
import time
import uuid
import socket
import platform
import re
from pathlib import Path
from datetime import datetime, timezone

import requests
import psutil


# ============================================================
# CONFIGURATION
# ============================================================

BACKEND_URL = "http://127.0.0.1:8000"
TELEMETRY_URL = f"{BACKEND_URL}/api/v1/telemetry/ingest"

TENANT_ID = "customer-001"
COLLECTOR_ID = "collector-001"
REGION = "ap-south-1"

COLLECTION_INTERVAL = 5
REQUEST_TIMEOUT = 10
MAX_BATCH_SIZE = 50
MAX_RETRY_DELAY = 60

BASE_DIR = Path(__file__).resolve().parent
BUFFER_DB = BASE_DIR / "collector_buffer.db"

HOSTNAME = socket.gethostname()
OS_NAME = platform.system()

COLLECTOR_API_TOKEN = "cicada-2026-secure-collector-key"

session = requests.Session()
session.headers.update({
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Collector-Token": COLLECTOR_API_TOKEN
})


# ============================================================
# DATABASE: PERSISTENT TELEMETRY BUFFER
# ============================================================

def initialize_buffer():
    with sqlite3.connect(BUFFER_DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_buffer (
                payload_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                next_attempt REAL DEFAULT 0,
                last_error TEXT DEFAULT '',
                created_at REAL NOT NULL
            )
        """)
        conn.commit()

    print("[BUFFER] Persistent telemetry buffer initialized.")


def enqueue_event(payload):
    payload_json = json.dumps(payload)

    with sqlite3.connect(BUFFER_DB) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO telemetry_buffer
            (payload_id, payload, attempts, next_attempt, last_error, created_at)
            VALUES (?, ?, 0, 0, '', ?)
        """, (
            payload["payload_id"],
            payload_json,
            time.time()
        ))
        conn.commit()


def get_buffer_count():
    with sqlite3.connect(BUFFER_DB) as conn:
        result = conn.execute(
            "SELECT COUNT(*) FROM telemetry_buffer"
        ).fetchone()

    return result[0]


def remove_event(payload_id):
    with sqlite3.connect(BUFFER_DB) as conn:
        conn.execute(
            "DELETE FROM telemetry_buffer WHERE payload_id = ?",
            (payload_id,)
        )
        conn.commit()


def update_failed_event(payload_id, attempts, error):
    retry_delay = min(
        2 ** min(attempts, 6),
        MAX_RETRY_DELAY
    )

    with sqlite3.connect(BUFFER_DB) as conn:
        conn.execute("""
            UPDATE telemetry_buffer
            SET attempts = ?,
                next_attempt = ?,
                last_error = ?
            WHERE payload_id = ?
        """, (
            attempts,
            time.time() + retry_delay,
            str(error)[:1000],
            payload_id
        ))
        conn.commit()


def get_pending_events():
    with sqlite3.connect(BUFFER_DB) as conn:
        rows = conn.execute("""
            SELECT payload_id, payload, attempts
            FROM telemetry_buffer
            WHERE next_attempt <= ?
            ORDER BY created_at ASC
            LIMIT ?
        """, (
            time.time(),
            MAX_BATCH_SIZE
        )).fetchall()

    return rows


# ============================================================
# PRIVACY PROTECTION
# ============================================================

EMAIL_PATTERN = re.compile(
    r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"
)

SECRET_PATTERN = re.compile(
    r"\b(password|api_key|secret|token)\s*[:=]\s*\S+",
    re.IGNORECASE
)


def redact_sensitive_data(value):

    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            key_lower = str(key).lower()

            if any(word in key_lower for word in [
                "password",
                "secret",
                "api_key",
                "token"
            ]):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = redact_sensitive_data(item)

        return cleaned

    if isinstance(value, list):
        return [
            redact_sensitive_data(item)
            for item in value
        ]

    if isinstance(value, str):
        value = EMAIL_PATTERN.sub(
            "[REDACTED_EMAIL]",
            value
        )

        value = SECRET_PATTERN.sub(
            r"\1=[REDACTED]",
            value
        )

        return value

    return value


# ============================================================
# TELEMETRY HEALTH CLASSIFICATION
# ============================================================

def get_metric_health(value):

    if value >= 90:
        return "Poor", "critical"

    if value >= 75:
        return "Fair", "warning"

    if value >= 50:
        return "Good", "info"

    return "Excellent", "info"


# ============================================================
# TELEMETRY GENERATION
# ============================================================

def create_telemetry(metric_name, metric_value, metric_unit):

    metric_value = round(float(metric_value), 2)

    health_state, severity = get_metric_health(metric_value)

    payload = {
        "payload_id": str(uuid.uuid4()),
        "tenant_id": TENANT_ID,
        "region": REGION,
        "source_id": COLLECTOR_ID,

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds"),

        "source_timezone": "UTC",

        "metric_name": metric_name,
        "metric_value": metric_value,
        "metric_unit": metric_unit,

        "health_state": health_state,
        "event_category": "infrastructure",
        "severity": severity,

        # Backend expects Optional[str], NOT a dictionary.
        "alert_context": (
            f"Collector: {COLLECTOR_ID}; "
            f"Hostname: {HOSTNAME}; "
            f"OS: {OS_NAME}; "
            f"Description: {metric_name} telemetry"
        )
    }

    return redact_sensitive_data(payload)


# ============================================================
# LEGACY BUFFER PAYLOAD COMPATIBILITY
# ============================================================

def normalize_legacy_payload(payload):

    payload.setdefault("tenant_id", TENANT_ID)
    payload.setdefault("region", REGION)
    payload.setdefault("source_id", COLLECTOR_ID)
    payload.setdefault("source_timezone", "UTC")

    if "timestamp" not in payload:
        payload["timestamp"] = datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds")

    if "metric_value" not in payload:
        raise ValueError("Missing metric_value in buffered event")

    value = float(payload["metric_value"])
    payload["metric_value"] = round(value, 2)

    # Normalize health state.
    old_health = str(
        payload.get("health_state", "")
    ).lower()

    health_mapping = {
        "healthy": "Excellent",
        "excellent": "Excellent",
        "good": "Good",
        "warning": "Fair",
        "fair": "Fair",
        "critical": "Poor",
        "poor": "Poor"
    }

    if old_health in health_mapping:
        payload["health_state"] = health_mapping[old_health]
    else:
        payload["health_state"] = get_metric_health(value)[0]

    # Normalize event category.
    old_category = str(
        payload.get("event_category", "")
    ).lower()

    category_mapping = {
        "system_metric": "infrastructure",
        "infrastructure": "infrastructure",
        "network": "network",
        "security": "security",
        "collector": "collector"
    }

    payload["event_category"] = category_mapping.get(
        old_category,
        "infrastructure"
    )

    # Normalize severity.
    if payload.get("severity") not in (
        "info",
        "warning",
        "critical"
    ):
        payload["severity"] = get_metric_health(value)[1]

    payload.setdefault("metric_unit", "percent")
    payload.setdefault("metric_name", "Unknown Metric")

    # CRITICAL FIX:
    # Convert previously buffered dictionaries into strings.
    alert_context = payload.get("alert_context")

    if isinstance(alert_context, (dict, list)):
        payload["alert_context"] = json.dumps(
            alert_context,
            ensure_ascii=False
        )

    elif alert_context is not None and not isinstance(alert_context, str):
        payload["alert_context"] = str(alert_context)

    return redact_sensitive_data(payload)


# ============================================================
# SYSTEM METRIC COLLECTION
# ============================================================

def collect_system_metrics():

    metrics = []

    cpu_usage = psutil.cpu_percent(interval=None)

    metrics.append(
        create_telemetry(
            "CPU Usage",
            cpu_usage,
            "percent"
        )
    )

    memory_usage = psutil.virtual_memory().percent

    metrics.append(
        create_telemetry(
            "Memory Usage",
            memory_usage,
            "percent"
        )
    )

    disk_path = Path.home().anchor or str(Path.cwd())

    disk_usage = psutil.disk_usage(disk_path).percent

    metrics.append(
        create_telemetry(
            "Disk Usage",
            disk_usage,
            "percent"
        )
    )

    return metrics


# ============================================================
# BACKEND CONNECTIVITY
# ============================================================

def check_backend_connection():

    print("\n[CONNECTIVITY] Checking backend...")

    try:
        response = session.get(
            f"{BACKEND_URL}/docs",
            timeout=REQUEST_TIMEOUT
        )

        print(
            f"[CONNECTIVITY] Backend reachable. "
            f"HTTP {response.status_code}"
        )

        return response.ok

    except requests.RequestException as error:
        print(f"[CONNECTIVITY ERROR] {error}")
        return False


# ============================================================
# TELEMETRY DELIVERY
# ============================================================

def send_event(payload):

    try:
        response = session.post(
            TELEMETRY_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        print(
            f"[DELIVERY] Payload {payload['payload_id']} "
            f"| HTTP {response.status_code}"
        )

        if response.status_code in (200, 201, 202):
            try:
                print("[BACKEND RESPONSE]", response.json())
            except ValueError:
                print("[BACKEND RESPONSE]", response.text[:500])

            return "accepted", None

        if response.status_code == 409:
            print("[DUPLICATE] Backend already has this payload.")
            return "duplicate", None

        error = (
            f"HTTP {response.status_code}: "
            f"{response.text[:1000]}"
        )

        print("[DELIVERY ERROR]", error)

        return "failed", error

    except requests.RequestException as error:
        error_message = (
            f"{type(error).__name__}: {error}"
        )

        print("[NETWORK ERROR]", error_message)

        return "failed", error_message


# ============================================================
# BUFFER FLUSH
# ============================================================

def flush_buffer():

    pending = get_pending_events()

    if not pending:
        return

    print(
        f"\n[BUFFER] Attempting to deliver "
        f"{len(pending)} queued events..."
    )

    for payload_id, payload_json, attempts in pending:

        try:
            payload = json.loads(payload_json)

            # Convert older payloads to the current backend schema.
            payload = normalize_legacy_payload(payload)

        except (json.JSONDecodeError, ValueError, TypeError) as error:

            print(
                f"[BUFFER ERROR] Invalid stored payload "
                f"{payload_id}: {error}"
            )

            update_failed_event(
                payload_id,
                attempts + 1,
                error
            )

            continue

        result, error = send_event(payload)

        if result in ("accepted", "duplicate"):

            remove_event(payload_id)

            print(f"[DELIVERED] {payload_id}")

        else:

            update_failed_event(
                payload_id,
                attempts + 1,
                error
            )

            print(
                f"[BUFFERED - DELIVERY FAILED] "
                f"{payload_id} | Attempts: {attempts + 1}"
            )

    print(
        f"[BUFFER] Remaining events: {get_buffer_count()}"
    )


# ============================================================
# MAIN COLLECTOR LOOP
# ============================================================

def main():

    print("=" * 60)
    print("SMART OBSERVABILITY PLATFORM")
    print("TELEMETRY COLLECTOR")
    print("=" * 60)

    print(f"Tenant ID: {TENANT_ID}")
    print(f"Collector ID: {COLLECTOR_ID}")
    print(f"Region: {REGION}")
    print(f"Backend: {BACKEND_URL}")
    print(f"Buffer database: {BUFFER_DB}")

    initialize_buffer()

    # Prime CPU measurement.
    psutil.cpu_percent(interval=1)

    if not check_backend_connection():
        print(
            "[WARNING] Backend is not responding successfully. "
            "Telemetry will remain buffered."
        )

    print("\n[COLLECTOR] Starting telemetry collection...\n")

    try:
        while True:

            try:
                events = collect_system_metrics()

                # Save every event before transmission.
                for event in events:
                    enqueue_event(event)

                    print(
                        f"[COLLECTED] "
                        f"{event['metric_name']}: "
                        f"{event['metric_value']} "
                        f"{event['metric_unit']}"
                    )

                print(
                    f"[BUFFER] Total queued: {get_buffer_count()}"
                )

                flush_buffer()

                print(
                    f"\n[WAITING] Next collection in "
                    f"{COLLECTION_INTERVAL} seconds...\n"
                )

                time.sleep(COLLECTION_INTERVAL)

            except KeyboardInterrupt:
                raise

            except Exception as error:
                print(
                    f"[COLLECTOR ERROR] "
                    f"{type(error).__name__}: {error}"
                )

                print("[COLLECTOR] Retrying after 5 seconds...")
                time.sleep(5)

    except KeyboardInterrupt:
        print("\n[COLLECTOR] Stopped by user.")

        print(
            f"[BUFFER] Undelivered events preserved: "
            f"{get_buffer_count()}"
        )

    finally:
        session.close()


if __name__ == "__main__":
    main()
