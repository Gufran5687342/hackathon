
import json
import sqlite3
import time
import uuid
import socket
import platform
from pathlib import Path
from datetime import datetime, timezone

import requests
import psutil


# ============================================================
# CONFIGURATION — MUST MATCH BACKEND
# ============================================================

BACKEND_URL = "http://127.0.0.1:8000"

TENANT_ID = "customer-001"
COLLECTOR_ID = "collector-001"
SOURCE_ID = socket.gethostname()

REGION = "ap-south-1"
COLLECTOR_VERSION = "1.0.0"

# Exact token from backend.py
COLLECTOR_API_TOKEN = "cicada-2026-secure-collector-key"

TELEMETRY_URL = f"{BACKEND_URL}/api/v1/telemetry/ingest"
REGISTER_URL = f"{BACKEND_URL}/api/v1/collectors/register"
HEARTBEAT_URL = f"{BACKEND_URL}/api/v1/collectors/heartbeat"

COLLECTION_INTERVAL = 5
REQUEST_TIMEOUT = 10
MAX_BATCH_SIZE = 50
HEARTBEAT_INTERVAL = 20

BASE_DIR = Path(__file__).resolve().parent
BUFFER_DB = BASE_DIR / "collector_buffer.db"

session = requests.Session()

session.headers.update({
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Collector-Token": COLLECTOR_API_TOKEN
})


# ============================================================
# DATABASE / BUFFER
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

    print("[BUFFER] Persistent buffer initialized.")


def enqueue_event(payload):

    with sqlite3.connect(BUFFER_DB) as conn:

        conn.execute("""
            INSERT OR IGNORE INTO telemetry_buffer
            (payload_id, payload, attempts, next_attempt,
             last_error, created_at)
            VALUES (?, ?, 0, 0, '', ?)
        """, (
            payload["payload_id"],
            json.dumps(payload),
            time.time()
        ))

        conn.commit()


def get_buffer_count():

    with sqlite3.connect(BUFFER_DB) as conn:

        result = conn.execute(
            "SELECT COUNT(*) FROM telemetry_buffer"
        ).fetchone()

    return result[0]


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


def remove_event(payload_id):

    with sqlite3.connect(BUFFER_DB) as conn:

        conn.execute("""
            DELETE FROM telemetry_buffer
            WHERE payload_id = ?
        """, (payload_id,))

        conn.commit()


def update_failed_event(payload_id, attempts, error):

    delay = min(
        2 ** min(attempts, 6),
        60
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
            time.time() + delay,
            str(error)[:1000],
            payload_id
        ))

        conn.commit()


# ============================================================
# HEALTH AND SEVERITY
# Must match backend Pydantic Literal values.
# ============================================================

def get_health_state(value):

    if value >= 90:
        return "Poor"

    if value >= 75:
        return "Fair"

    if value >= 50:
        return "Good"

    return "Excellent"


def get_severity(value):

    if value >= 90:
        return "critical"

    if value >= 75:
        return "warning"

    return "info"


# ============================================================
# TELEMETRY PAYLOAD
# Must match TelemetryEvent in backend.py.
# ============================================================

def create_telemetry(metric_name, metric_value, metric_unit):

    metric_value = round(float(metric_value), 2)

    return {
        "payload_id": str(uuid.uuid4()),

        "tenant_id": TENANT_ID,

        "region": REGION,

        "source_id": SOURCE_ID,

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "source_timezone": "UTC",

        "metric_name": metric_name,

        "metric_value": metric_value,

        "metric_unit": metric_unit,

        "health_state": get_health_state(metric_value),

        "event_category": "infrastructure",

        "severity": get_severity(metric_value),

        "alert_context": (
            f"Collector: {COLLECTOR_ID}; "
            f"Host: {SOURCE_ID}; "
            f"OS: {platform.system()}; "
            f"Metric: {metric_name}"
        )
    }


# ============================================================
# SYSTEM METRICS
# ============================================================

def collect_system_metrics():

    events = []

    # CPU
    cpu = psutil.cpu_percent(interval=1)

    events.append(
        create_telemetry(
            "CPU Usage",
            cpu,
            "percent"
        )
    )

    # MEMORY
    memory = psutil.virtual_memory().percent

    events.append(
        create_telemetry(
            "Memory Usage",
            memory,
            "percent"
        )
    )

    # DISK
    disk_path = Path.cwd().anchor or str(Path.cwd())

    disk = psutil.disk_usage(disk_path).percent

    events.append(
        create_telemetry(
            "Disk Usage",
            disk,
            "percent"
        )
    )

    return events


# ============================================================
# BACKEND CONNECTIVITY
# ============================================================

def check_backend():

    print("\n[CONNECTIVITY] Checking backend...")

    try:

        response = session.get(
            f"{BACKEND_URL}/",
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:

            print(
                "[CONNECTIVITY] Backend reachable. HTTP 200"
            )

            return True

        print(
            f"[CONNECTIVITY ERROR] HTTP {response.status_code}"
        )

        return False

    except requests.RequestException as error:

        print(
            f"[CONNECTIVITY ERROR] {error}"
        )

        return False


# ============================================================
# COLLECTOR REGISTRATION
# ============================================================

def register_collector():

    payload = {
        "collector_id": COLLECTOR_ID,
        "tenant_id": TENANT_ID,
        "region": REGION,
        "source_id": SOURCE_ID,
        "version": COLLECTOR_VERSION
    }

    try:

        response = session.post(
            REGISTER_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:

            print("[REGISTRATION] Collector registered successfully.")

            return True

        print(
            f"[REGISTRATION ERROR] HTTP {response.status_code}: "
            f"{response.text[:500]}"
        )

        return False

    except requests.RequestException as error:

        print(f"[REGISTRATION ERROR] {error}")

        return False


# ============================================================
# COLLECTOR HEARTBEAT
# ============================================================

def send_heartbeat():

    payload = {
        "collector_id": COLLECTOR_ID,
        "tenant_id": TENANT_ID,
        "region": REGION,
        "version": COLLECTOR_VERSION,
        "cpu_percent": round(
            psutil.cpu_percent(interval=None),
            2
        ),
        "memory_percent": round(
            psutil.virtual_memory().percent,
            2
        ),
        "buffered_events": get_buffer_count()
    }

    try:

        response = session.post(
            HEARTBEAT_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:

            print("[HEARTBEAT] Successfully delivered.")

            return True

        print(
            f"[HEARTBEAT ERROR] HTTP {response.status_code}: "
            f"{response.text[:500]}"
        )

        return False

    except requests.RequestException as error:

        print(f"[HEARTBEAT ERROR] {error}")

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
            f"[DELIVERY] {payload['metric_name']} "
            f"| HTTP {response.status_code}"
        )

        if response.status_code in (200, 201):

            try:
                result = response.json()
            except ValueError:
                result = response.text[:500]

            print("[BACKEND RESPONSE]", result)

            return True, None

        if response.status_code == 409:

            print("[DUPLICATE] Payload already exists.")

            return True, None

        error = (
            f"HTTP {response.status_code}: "
            f"{response.text[:500]}"
        )

        print("[DELIVERY ERROR]", error)

        return False, error

    except requests.RequestException as error:

        print("[NETWORK ERROR]", error)

        return False, str(error)


# ============================================================
# BUFFER DELIVERY
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

        except json.JSONDecodeError as error:

            update_failed_event(
                payload_id,
                attempts + 1,
                error
            )

            print(
                f"[BUFFER ERROR] Invalid payload {payload_id}"
            )

            continue

        success, error = send_event(payload)

        if success:

            remove_event(payload_id)

            print(
                f"[DELIVERED] {payload_id}"
            )

        else:

            update_failed_event(
                payload_id,
                attempts + 1,
                error
            )

            print(
                f"[BUFFERED] {payload_id} "
                f"| Attempts: {attempts + 1}"
            )

    print(
        f"[BUFFER] Remaining events: {get_buffer_count()}"
    )


# ============================================================
# MAIN LOOP
# ============================================================

def main():

    print("=" * 60)
    print("CICADA 2026 - SMART OBSERVABILITY COLLECTOR")
    print("=" * 60)

    print("Tenant:", TENANT_ID)
    print("Collector:", COLLECTOR_ID)
    print("Source:", SOURCE_ID)
    print("Region:", REGION)
    print("Backend:", BACKEND_URL)

    initialize_buffer()

    # Initialize CPU measurement.
    psutil.cpu_percent(interval=None)

    if not check_backend():

        print(
            "[WARNING] Backend is currently unreachable. "
            "Telemetry will be buffered."
        )

    else:

        register_collector()

        send_heartbeat()

    last_heartbeat = time.time()

    print("\n[COLLECTOR] Starting collection...\n")

    while True:

        try:

            # 1. Collect metrics.
            events = collect_system_metrics()

            # 2. Persist every event before attempting delivery.
            for event in events:

                enqueue_event(event)

                print(
                    f"[COLLECTED] {event['metric_name']}: "
                    f"{event['metric_value']} "
                    f"{event['metric_unit']} "
                    f"| Health: {event['health_state']}"
                )

            print(
                f"[BUFFER] Total queued: {get_buffer_count()}"
            )

            # 3. Deliver queued telemetry.
            flush_buffer()

            # 4. Send periodic heartbeat.
            if (
                time.time() - last_heartbeat
                >= HEARTBEAT_INTERVAL
            ):

                send_heartbeat()

                last_heartbeat = time.time()

            print(
                f"\n[WAITING] Next collection in "
                f"{COLLECTION_INTERVAL} seconds...\n"
            )

            time.sleep(COLLECTION_INTERVAL)

        except KeyboardInterrupt:

            print("\n[COLLECTOR] Stopped.")

            print(
                "[BUFFER] Preserved queued events:",
                get_buffer_count()
            )

            break

        except Exception as error:

            print(
                f"[COLLECTOR ERROR] "
                f"{type(error).__name__}: {error}"
            )

            time.sleep(5)

    session.close()


if __name__ == "__main__":
    main()
