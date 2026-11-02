import hashlib
import hmac
import ipaddress
import json
import os
import csv
from pathlib import Path
import socket
import sqlite3
import threading
import time
import uuid
import urllib.error
import urllib.request
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


DB_PATH = os.environ.get("DB_PATH", "/evidence/events.sqlite3")
DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"
ALLOWED_HOSTS = {
    value.strip()
    for value in os.environ.get("ALLOWED_HOSTS", "server-a,server-b").split(",")
    if value.strip()
}
ENABLE_LAB_AUTOREPAIR = os.environ.get(
    "ENABLE_LAB_AUTOREPAIR", os.environ.get("ENABLE_LAB_DRAIN", "false")
).lower() == "true"
DEMO_REPAIR_HOST = os.environ.get("DEMO_REPAIR_HOST", "server-a")
DEMO_REPAIR_DELAY_SECONDS = max(0, int(os.environ.get("DEMO_REPAIR_DELAY_SECONDS", "0")))
TRAFFIC_PROBE_ENABLED = os.environ.get("TRAFFIC_PROBE_ENABLED", "true").lower() == "true"
TRAFFIC_PROBE_URL = os.environ.get("TRAFFIC_PROBE_URL", "http://haproxy:8080/healthz")
TRAFFIC_PROBE_INTERVAL = max(0.2, float(os.environ.get("TRAFFIC_PROBE_INTERVAL", "1")))
HAPROXY_HOST = os.environ.get("HAPROXY_HOST", "haproxy")
HAPROXY_RUNTIME_PORT = int(os.environ.get("HAPROXY_RUNTIME_PORT", "9999"))
REMEDIATOR_URLS = {
    "server-a": os.environ.get(
        "REMEDIATOR_URL_SERVER_A", "http://remediator-a:8091/v1/repair"
    ),
    "server-b": os.environ.get(
        "REMEDIATOR_URL_SERVER_B", "http://remediator-b:8091/v1/repair"
    ),
}
REMEDIATOR_HEALTH_URLS = {
    "server-a": os.environ.get(
        "REMEDIATOR_HEALTH_URL_SERVER_A", "http://remediator-a:8091/healthz"
    ),
    "server-b": os.environ.get(
        "REMEDIATOR_HEALTH_URL_SERVER_B", "http://remediator-b:8091/healthz"
    ),
}
IMPACT_CIA = (1, 3, 2)
IMPACT = sum(IMPACT_CIA) / 3
KEY_PATHS = ("etc/kunci1.dat", "etc/kunci2.dat")
MAX_BODY_BYTES = 64_000_000
MAX_INVENTORY_DIRECTORIES = 200_000
MAX_INVENTORY_ENTRIES = 1_000_000
MAX_LISTING_ENTRIES = 5000
API_TOKEN = os.environ.get("LAB_API_TOKEN", "")
AGENT_PATHS = {"/v1/events", "/v1/patrol/snapshot", "/v1/patrol/inventory", "/api/patrol/events", "/v1/agent/heartbeat"}
ENTRY_WINDOW_SECONDS = 600
CHAIN_LOCK = threading.Lock()
MAX_OPEN_PORTS = 32
OPEN_PORTS = {}
FS_ENTRY_KINDS = {"dir", "file", "link", "other", "virtual"}
FS_KIND_ORDER = {"dir": 0, "virtual": 1, "link": 2, "file": 3, "other": 4}


def connect():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with connect() as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS chain_state (id INTEGER PRIMARY KEY CHECK (id = 1), last_hash TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT OR IGNORE INTO chain_state (id, last_hash) VALUES (1, '')"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_status (
                host_id TEXT PRIMARY KEY,
                last_seen TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS remediation_runs (
                event_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                quarantine_path TEXT,
                step_history TEXT NOT NULL DEFAULT '[]',
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            )"""
        )
        remediation_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(remediation_runs)")
        }
        if "step_history" not in remediation_columns:
            connection.execute(
                "ALTER TABLE remediation_runs ADD COLUMN step_history TEXT NOT NULL DEFAULT '[]'"
            )
        if "detect_seconds" not in remediation_columns:
            connection.execute("ALTER TABLE remediation_runs ADD COLUMN detect_seconds REAL")
        if "entry_json" not in remediation_columns:
            connection.execute("ALTER TABLE remediation_runs ADD COLUMN entry_json TEXT")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                trajectory_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                host_id TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                previous_hash TEXT NOT NULL,
                integrity_hash TEXT NOT NULL,
                p_attack REAL NOT NULL,
                impact REAL NOT NULL,
                risk REAL NOT NULL,
                level INTEGER NOT NULL,
                recommendation TEXT NOT NULL,
                advisor_verdict TEXT NOT NULL,
                mode TEXT NOT NULL
            )"""
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(events)")
        }
        if "content_signal" not in columns:
            connection.execute(
                "ALTER TABLE events ADD COLUMN content_signal INTEGER NOT NULL DEFAULT 0"
            )
        if "response_action" not in columns:
            connection.execute(
                "ALTER TABLE events ADD COLUMN response_action TEXT NOT NULL DEFAULT 'none'"
            )
        if "canonical_json" not in columns:
            connection.execute("ALTER TABLE events ADD COLUMN canonical_json TEXT")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_snapshots (
                host_id TEXT PRIMARY KEY,
                scanned_at TEXT NOT NULL,
                files_json TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_fs_scans (
                host_id TEXT PRIMARY KEY,
                scanned_at TEXT NOT NULL,
                directory_count INTEGER NOT NULL,
                entry_count INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_fs_directories (
                host_id TEXT NOT NULL,
                path TEXT NOT NULL,
                denied INTEGER NOT NULL,
                entries_json TEXT NOT NULL,
                PRIMARY KEY (host_id, path)
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                type TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                host_id TEXT NOT NULL,
                path TEXT NOT NULL,
                severity TEXT NOT NULL,
                hash_old TEXT,
                hash_new TEXT,
                status TEXT NOT NULL
            )"""
        )
        patrol_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(patrol_events)")
        }
        if "port" not in patrol_columns:
            connection.execute("ALTER TABLE patrol_events ADD COLUMN port INTEGER")


def evaluate(event):
    if is_canary_detection(event):
        probability = 0.99
        risk = round(probability * IMPACT, 3)
        return probability, risk, 3, "auto_repair_canary_and_rejoin", "lab_canary_match"
    if is_key_detection(event):
        probability = 0.99
        risk = round(probability * IMPACT, 3)
        return probability, risk, 3, "auto_repair_keys_and_rejoin", "lab_key_match"

    probability = {
        "file_created": 0.20,
        "file_modified": 0.55,
        "file_deleted": 0.72,
    }[event["event_type"]]
    risk = round(probability * IMPACT, 3)
    if risk >= 1.0:
        level, recommendation = 2, "operator_review"
    elif risk >= 0.5:
        level, recommendation = 1, "alert"
    else:
        level, recommendation = 0, "record"
    verdict = "suspicious" if event["event_type"] != "file_created" else "insufficient_evidence"
    return probability, risk, level, recommendation, verdict


def is_canary_detection(event):
    return (
        event.get("content_signal") is True
        and event.get("indicator") == "DEFNETT_LAB_CANARY"
        and Path(event.get("path", "")).name == "DEFNETT-LAB-CANARY.txt"
        and event.get("event_type") in {"file_created", "file_modified"}
        and event.get("new_hash") is not None
    )


def is_key_detection(event):
    """Kunci hanya dipicu oleh perubahan isi (tamper); karantina dan pemulihan
    worker sendiri memicu deleted/created dan sengaja tidak dihitung detection
    agar playbook tidak memanggil dirinya berulang."""
    return (
        event.get("path", "").lstrip("/") in KEY_PATHS
        and event.get("event_type") == "file_modified"
        and event.get("new_hash") is not None
    )


def haproxy_command(command):
    with socket.create_connection((HAPROXY_HOST, HAPROXY_RUNTIME_PORT), timeout=3) as connection:
        connection.settimeout(3)
        connection.sendall((command + "\n").encode("ascii"))
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


def backend_is_up(server_name):
    response = haproxy_command("show stat")
    lines = response.splitlines()
    if not lines:
        return False
    header = lines[0].lstrip("# ").split(",")
    for row in csv.DictReader(lines[1:], fieldnames=header):
        if row.get("pxname") == "defnett_servers" and row.get("svname") == server_name:
            # "UP 1/2" berarti HAProxy masih menunggu hasil pemeriksaan; hanya "UP" yang dianggap sehat.
            return row.get("status", "").strip() == "UP"
    return False


def wait_for_backend(server_name, expected_up, attempts=10):
    for _ in range(attempts):
        if backend_is_up(server_name) is expected_up:
            return True
        time.sleep(0.5)
    return False


TRAFFIC_PHASES = ("before", "during", "after")
TRAFFIC_STAGE_PHASE = {
    "ISOLATED": "during", "REPAIRING": "during", "VERIFYING": "during",
    "REJOINING": "during", "REPAIRED": "after",
}
TRAFFIC_LOCK = threading.Lock()


def _traffic_bucket():
    return {"ok": 0, "fail": 0, "by_host": {host: 0 for host in sorted(ALLOWED_HOSTS)}, "first_at": None, "last_at": None}


TRAFFIC = {"phase": "before", "run_id": None, "buckets": {phase: _traffic_bucket() for phase in TRAFFIC_PHASES}}


def traffic_enter_stage(event_id, stage):
    """Pindahkan fase hitungan trafik mengikuti tahap playbook yang tercatat."""
    with TRAFFIC_LOCK:
        if stage == "DETECTED":
            if TRAFFIC["run_id"] == event_id:
                return
            if TRAFFIC["phase"] == "after":
                # trafik sehat sejak pemulihan sebelumnya menjadi baseline insiden baru
                TRAFFIC["buckets"]["before"] = TRAFFIC["buckets"]["after"]
            TRAFFIC["buckets"]["during"] = _traffic_bucket()
            TRAFFIC["buckets"]["after"] = _traffic_bucket()
            TRAFFIC["phase"] = "before"
            TRAFFIC["run_id"] = event_id
        elif TRAFFIC["run_id"] == event_id and stage in TRAFFIC_STAGE_PHASE:
            TRAFFIC["phase"] = TRAFFIC_STAGE_PHASE[stage]


def traffic_record(ok, host_id=None):
    now = datetime.now(timezone.utc).isoformat()
    with TRAFFIC_LOCK:
        bucket = TRAFFIC["buckets"][TRAFFIC["phase"]]
        bucket["ok" if ok else "fail"] += 1
        if ok and host_id in bucket["by_host"]:
            bucket["by_host"][host_id] += 1
        bucket["first_at"] = bucket["first_at"] or now
        bucket["last_at"] = now


def traffic_probe_once():
    host_id = None
    try:
        with urllib.request.urlopen(TRAFFIC_PROBE_URL, timeout=2) as response:
            ok = response.status == 200
            host_id = response.headers.get("X-DEFNETT-Host")
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        ok = False
    traffic_record(ok, host_id)


def traffic_probe_loop():
    while True:
        started = time.monotonic()
        traffic_probe_once()
        time.sleep(max(0.05, TRAFFIC_PROBE_INTERVAL - (time.monotonic() - started)))


def traffic_state():
    with TRAFFIC_LOCK:
        windows = {}
        for phase in TRAFFIC_PHASES:
            bucket = TRAFFIC["buckets"][phase]
            windows[phase] = {
                "ok": bucket["ok"], "fail": bucket["fail"], "total": bucket["ok"] + bucket["fail"],
                "by_host": dict(bucket["by_host"]),
                "first_at": bucket["first_at"], "last_at": bucket["last_at"],
            }
        return {
            "enabled": TRAFFIC_PROBE_ENABLED,
            "interval_seconds": TRAFFIC_PROBE_INTERVAL,
            "phase": TRAFFIC["phase"],
            "windows": windows,
        }


def format_duration(seconds):
    return f"{seconds // 60} menit" if seconds >= 60 and seconds % 60 == 0 else f"{seconds} detik"


def set_remediation(event_id, status, detail, quarantine_path=None, complete=False):
    now = datetime.now(timezone.utc).isoformat()
    with connect() as connection:
        row = connection.execute(
            "SELECT step_history FROM remediation_runs WHERE event_id = ?", (event_id,)
        ).fetchone()
        history = json.loads(row["step_history"]) if row else []
        history.append({"stage": status, "detail": detail, "timestamp": now})
        connection.execute(
            """UPDATE remediation_runs
               SET status = ?, detail = ?, quarantine_path = COALESCE(?, quarantine_path),
                   step_history = ?, updated_at = ?,
                   completed_at = CASE WHEN ? THEN ? ELSE completed_at END
               WHERE event_id = ?""",
            (status, detail, quarantine_path, json.dumps(history), now, int(complete), now, event_id),
        )
    traffic_enter_stage(event_id, status)


def remediation_rows(limit=20):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM remediation_runs ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
    result = [dict(row) for row in rows]
    for row in result:
        try:
            row["steps"] = json.loads(row.pop("step_history"))
        except (json.JSONDecodeError, TypeError):
            row["steps"] = []
        try:
            row["entry"] = json.loads(row.pop("entry_json") or "null")
        except (json.JSONDecodeError, TypeError):
            row["entry"] = None
        row["metrics"] = run_metrics(row)
    return result


def run_metrics(run):
    """Waktu respons satu insiden, dihitung dari stempel waktu tahap yang tercatat."""
    stamps = {}
    for step in run["steps"]:
        try:
            stamps[step["stage"]] = datetime.fromisoformat(step["timestamp"])
        except (KeyError, TypeError, ValueError):
            continue

    def elapsed(start, end):
        if start not in stamps or end not in stamps:
            return None
        return round((stamps[end] - stamps[start]).total_seconds(), 2)

    recover = elapsed("DETECTED", "REPAIRED")
    hold = DEMO_REPAIR_DELAY_SECONDS if repair_delay_applies(run["host_id"]) else 0
    return {
        "detect": run.get("detect_seconds"),
        "isolate": elapsed("DETECTED", "ISOLATED"),
        "recover": recover,
        "demo_hold": hold,
        "recover_without_hold": None if recover is None else round(max(0.0, recover - hold), 2),
    }


def recent_entry(host_id):
    """Login berhasil terakhir di host ini, dipakai sebagai dugaan jalur masuk insiden."""
    with connect() as connection:
        rows = connection.execute(
            """SELECT ts, actor, port, path FROM patrol_events
               WHERE host_id = ? AND action = 'login' AND status = 'allowed' AND port IS NOT NULL
               ORDER BY id DESC LIMIT 1""",
            (host_id,),
        ).fetchall()
    if not rows:
        return None
    entry = dict(rows[0])
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(entry["ts"])).total_seconds()
    except ValueError:
        return None
    return entry if 0 <= age <= ENTRY_WINDOW_SECONDS else None


def verify_evidence():
    """Periksa rantai hash event: tautan antarbaris, hash isi, dan kecocokan kolom utama."""
    with connect() as connection:
        rows = connection.execute(
            """SELECT id, host_id, path, old_hash, new_hash, previous_hash, integrity_hash, canonical_json
               FROM events ORDER BY rowid"""
        ).fetchall()
        last_hash = connection.execute("SELECT last_hash FROM chain_state WHERE id = 1").fetchone()["last_hash"]

    def broken(row, reason):
        return {"status": "broken", "events": len(rows), "reason": reason, "event_id": row["id"] if row else None}

    previous = ""
    fully_verified = 0
    for row in rows:
        if row["previous_hash"] != previous:
            return broken(row, "chain_link_mismatch")
        canonical = row["canonical_json"]
        if canonical is not None:
            if hashlib.sha256((previous + canonical).encode("utf-8")).hexdigest() != row["integrity_hash"]:
                return broken(row, "content_hash_mismatch")
            recorded = json.loads(canonical)
            if any(recorded.get(key) != row[key] for key in ("host_id", "path", "old_hash", "new_hash")):
                return broken(row, "stored_field_mismatch")
            fully_verified += 1
        previous = row["integrity_hash"]
    if previous != last_hash:
        return broken(rows[-1] if rows else None, "chain_head_mismatch")
    return {"status": "ok", "events": len(rows), "fully_verified": fully_verified,
            "link_only": len(rows) - fully_verified}


def internal_headers():
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return headers


def request_lab_repair(event_id, host_id, kind="canary"):
    payload = json.dumps({"host_id": host_id, "event_id": event_id, "kind": kind}).encode("utf-8")
    request = urllib.request.Request(
        REMEDIATOR_URLS[host_id],
        data=payload,
        headers=internal_headers(),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"remediator returned HTTP {response.status}")
        result = json.loads(response.read())
    expected_status = "RESTORED_KEYS" if kind == "kunci" else "QUARANTINED_CANARY"
    if result.get("status") != expected_status or not result.get("quarantine_path"):
        raise RuntimeError(result.get("detail", "remediation_not_verified"))
    return result


RESTORED_HASHES = {}
ATTACK_LOCK = threading.Lock()
ATTACK_SETTLE_SECONDS = 20
ATTACK_ENTRY_SECONDS = 5
LAB_ATTACK_PORTS = {"ssh": 22, "web": 80}
LAST_ATTACK = {}


def repair_delay_applies(target):
    return DEMO_REPAIR_HOST in ("all", target)


def start_lab_attack(host_id, vector=None, actor=None):
    """Minta worker host target mengubah kunci demo; deteksi dan isolasi berjalan lewat playbook.

    vector hanya menentukan pintu yang dilewati intruder di peta; tidak ada serangan
    nyata ke SSH atau web.
    """
    if not ENABLE_LAB_AUTOREPAIR:
        raise PermissionError("lab_drain_mode_disabled")
    if host_id not in ALLOWED_HOSTS or host_id not in REMEDIATOR_URLS:
        raise LookupError("unknown_host")
    if vector is not None and vector not in LAB_ATTACK_PORTS:
        raise LookupError("unknown_vector")
    survivor = "server-b" if host_id == "server-a" else "server-a"
    with ATTACK_LOCK:
        if any(run["completed_at"] is None for run in remediation_rows(10)) \
                or time.monotonic() - LAST_ATTACK.get(host_id, -ATTACK_SETTLE_SECONDS) < ATTACK_SETTLE_SECONDS:
            raise RuntimeError("attack_in_progress")
        if not backend_is_up(host_id):
            raise RuntimeError("target_not_up")
        if not backend_is_up(survivor):
            raise RuntimeError("survivor_not_healthy")
        if vector is not None:
            LAST_ATTACK[host_id] = time.monotonic()
            store_patrol_event({
                "type": "alert", "actor": actor, "action": "login", "host_id": host_id,
                "path": f"simulasi-{vector}", "severity": "suspicious", "status": "allowed",
                "port": LAB_ATTACK_PORTS[vector],
            })
            time.sleep(ATTACK_ENTRY_SECONDS)
        request = urllib.request.Request(
            REMEDIATOR_URLS[host_id].rsplit("/", 1)[0] + "/lab/attack",
            data=json.dumps({"host_id": host_id}).encode("utf-8"),
            headers=internal_headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                result = json.loads(response.read())
            LAST_ATTACK[host_id] = time.monotonic()
            return result
        except urllib.error.HTTPError as error:
            try:
                body = json.loads(error.read())
                detail = body.get("detail") or body.get("error") or "attack_rejected"
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError, AttributeError):
                detail = "attack_rejected"
            raise RuntimeError(str(detail)) from None


def remediator_health(host_id):
    try:
        with urllib.request.urlopen(REMEDIATOR_HEALTH_URLS[host_id], timeout=1) as response:
            return "ready" if response.status == 200 else "unavailable"
    except (OSError, urllib.error.URLError, TimeoutError):
        return "unavailable"


def run_canary_response(event, event_id):
    is_canary = is_canary_detection(event)
    is_key = is_key_detection(event)
    if not is_canary and not is_key:
        return "DRY_RUN", "none"
    if not ENABLE_LAB_AUTOREPAIR:
        return "DRY_RUN", "would_isolate_repair_and_verify"
    if is_key and RESTORED_HASHES.get((event["host_id"], event["path"].lstrip("/"))) == event.get("new_hash"):
        return "ACTIVE_LAB", "restore_confirmed"
    target = event["host_id"]
    if target not in ALLOWED_HOSTS or target not in REMEDIATOR_URLS:
        return "BLOCKED", "automatic_repair_not_allowed_for_this_host"
    survivor = "server-b" if target == "server-a" else "server-a"
    kind = "kunci" if is_key else "canary"
    artifact = "kunci rahasia" if is_key else "canary"
    detected_detail = "Kunci lab terverifikasi." if is_key else "Canary lab terverifikasi."

    now = datetime.now(timezone.utc).isoformat()
    detect_seconds = event.get("detect_seconds")
    if not isinstance(detect_seconds, (int, float)) or isinstance(detect_seconds, bool) or not 0 <= detect_seconds <= 3600:
        detect_seconds = None
    entry = recent_entry(target)
    with connect() as connection:
        connection.execute(
            """INSERT OR REPLACE INTO remediation_runs
               (event_id, host_id, path, status, detail, quarantine_path,
                step_history, started_at, updated_at, completed_at, detect_seconds, entry_json)
               VALUES (?, ?, ?, 'DETECTED', ?, NULL, ?, ?, ?, NULL, ?, ?)""",
            (
                event_id, event["host_id"], event["path"], detected_detail,
                json.dumps([{
                    "stage": "DETECTED",
                    "detail": detected_detail,
                    "timestamp": now,
                }]), now, now, detect_seconds, entry and json.dumps(entry),
            ),
        )
    traffic_enter_stage(event_id, "DETECTED")

    try:
        if not backend_is_up(survivor):
            set_remediation(
                event_id, "FAILED",
                f"{survivor} tidak sehat; {target} tidak diubah agar layanan tetap tersedia.",
                complete=True,
            )
            return "FAILED", f"survivor_not_healthy:{survivor}"
        set_remediation(event_id, "ISOLATING", f"Mengeluarkan {target} saja dari rotasi HAProxy.")
        haproxy_command(f"disable server defnett_servers/{target}")
        if not wait_for_backend(target, False):
            set_remediation(event_id, "FAILED", f"HAProxy belum mengonfirmasi isolasi {target}.", complete=True)
            return "FAILED", f"target_isolation_not_confirmed:{target}"

        set_remediation(
            event_id, "ISOLATED",
            f"{target} terisolasi; {survivor} tetap aktif dan tidak diubah.",
        )
        if repair_delay_applies(target) and DEMO_REPAIR_DELAY_SECONDS:
            set_remediation(
                event_id,
                "REPAIRING",
                f"Demo: perbaikan {target} berlangsung {format_duration(DEMO_REPAIR_DELAY_SECONDS)}; host tetap terisolasi.",
            )
            time.sleep(DEMO_REPAIR_DELAY_SECONDS)
        else:
            set_remediation(
                event_id, "REPAIRING",
                f"Worker {target} mengarantina artefak {artifact} pada host itu saja.",
            )
        repair = request_lab_repair(event_id, target, kind)
        for restored in repair.get("restored", []):
            RESTORED_HASHES[(target, restored["path"])] = restored["sha256"]
        set_remediation(
            event_id, "VERIFYING",
            f"{('Kunci' if is_key else 'Canary')} {target} dipulihkan; menunggu health check.",
            quarantine_path=repair["quarantine_path"],
        )
        haproxy_command(f"enable server defnett_servers/{target}")
        set_remediation(event_id, "REJOINING", f"HAProxy memeriksa {target} sebelum menerima trafik.")
        if not wait_for_backend(target, True, attempts=20):
            haproxy_command(f"disable server defnett_servers/{target}")
            set_remediation(event_id, "FAILED", f"Health check gagal; {target} tetap terisolasi.", complete=True)
            return "FAILED_ISOLATED", f"health_check_failed:{target}_remains_isolated"

        set_remediation(
            event_id, "REPAIRED", f"Health check {target} lolos; {target} aktif kembali. {survivor} tidak diubah.",
            quarantine_path=repair["quarantine_path"], complete=True,
        )
        return "ACTIVE_LAB", f"AUTO_REPAIRED_AND_REJOINED_{target.upper().replace('-', '_')}"
    except (OSError, socket.timeout, UnicodeError, urllib.error.URLError, ValueError, RuntimeError) as error:
        try:
            haproxy_command(f"disable server defnett_servers/{target}")
        except (OSError, socket.timeout, UnicodeError):
            pass
        set_remediation(
            event_id, "FAILED", f"Pemulihan {target} berhenti dengan aman: {type(error).__name__}; host itu tetap diisolasi, {survivor} tidak diubah.",
            complete=True,
        )
        return "FAILED_ISOLATED", f"repair_failed:{target}:{type(error).__name__}"


def finish_canary_response(event, event_id):
    mode, response_action = run_canary_response(event, event_id)
    with connect() as connection:
        connection.execute(
            "UPDATE events SET mode = ?, response_action = ? WHERE id = ?",
            (mode, response_action, event_id),
        )


def store_event(event):
    event_id = str(uuid.uuid4())
    parsed = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    timestamp = parsed.astimezone(timezone.utc).isoformat()
    trajectory_id = f"{event['host_id']}-{int(parsed.timestamp()) // 300}"
    p_attack, risk, level, recommendation, verdict = evaluate(event)
    canonical = json.dumps(
        {
            "event_id": event_id,
            "trajectory_id": trajectory_id,
            "timestamp": timestamp,
            **event,
            "p_attack": p_attack,
            "risk": risk,
            "recommendation": recommendation,
            "content_signal": bool(event.get("content_signal", False)),
            "indicator": event.get("indicator"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    with CHAIN_LOCK, connect() as connection:
        previous_hash = connection.execute(
            "SELECT last_hash FROM chain_state WHERE id = 1"
        ).fetchone()["last_hash"]
        integrity_hash = hashlib.sha256(
            (previous_hash + canonical).encode("utf-8")
        ).hexdigest()
        connection.execute(
            """INSERT INTO events (
                id, trajectory_id, timestamp, host_id, source, event_type, path,
                old_hash, new_hash, previous_hash, integrity_hash, p_attack,
                impact, risk, level, recommendation, advisor_verdict, mode,
                content_signal, response_action, canonical_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id, trajectory_id, timestamp, event["host_id"], event["source"],
                event["event_type"], event["path"], event.get("old_hash"), event.get("new_hash"),
                previous_hash, integrity_hash, p_attack, IMPACT, risk, level,
                recommendation, verdict, "DRY_RUN", int(bool(event.get("content_signal"))), "none",
                canonical,
            ),
        )
        connection.execute(
            "UPDATE chain_state SET last_hash = ? WHERE id = 1", (integrity_hash,)
        )

    patrol_severity = "compromised" if level >= 3 else "suspicious" if level >= 2 else "safe"
    patrol_type = "patrol_check" if event["event_type"] == "file_created" and patrol_severity == "safe" else "alert"
    patrol_action = "delete" if event["event_type"] == "file_deleted" else "modify" if event["event_type"] == "file_modified" else "read"
    store_patrol_event({
        "type": patrol_type,
        "actor": "police",
        "action": patrol_action,
        "host_id": event["host_id"],
        "path": event["path"],
        "severity": patrol_severity,
        "hash_old": event.get("old_hash"),
        "hash_new": event.get("new_hash"),
        "status": "observed",
    })

    if ENABLE_LAB_AUTOREPAIR and is_canary_detection(event):
        threading.Thread(
            target=finish_canary_response,
            args=(event.copy(), event_id),
            name=f"canary-repair-{event_id[:8]}",
            daemon=True,
        ).start()
        mode, response_action = "ACTIVE_LAB", f"AUTO_REPAIR_QUEUED_{event['host_id'].upper().replace('-', '_')}"
    else:
        mode, response_action = run_canary_response(event, event_id)

    return {
        "event_id": event_id,
        "trajectory_id": trajectory_id,
        "risk": risk,
        "level": level,
        "recommendation": recommendation,
        "advisor_verdict": verdict,
        "mode": mode,
        "response_action": response_action,
        "content_signal": bool(event.get("content_signal", False)),
        "integrity_hash": integrity_hash,
    }


def event_rows(limit=100):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def patrol_events(after_id=0, limit=100):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM patrol_events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (after_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def store_patrol_snapshot(host_id, files, scanned_at=None):
    if not isinstance(host_id, str) or host_id not in ALLOWED_HOSTS:
        raise ValueError("unknown_host")
    cleaned = []
    for item in files[:50000]:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        digest = item.get("sha256")
        if not isinstance(path, str) or not path or len(path) > 2048:
            continue
        parts = Path(path).parts
        if Path(path).is_absolute() or ".." in parts:
            continue
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            continue
        size = item.get("size")
        mtime = item.get("mtime")
        if not isinstance(size, int) or size < 0:
            size = None
        if not isinstance(mtime, str):
            mtime = None
        cleaned.append({"path": path, "sha256": digest, "size": size, "mtime": mtime})
    try:
        timestamp = datetime.fromisoformat(scanned_at.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except (AttributeError, TypeError, ValueError):
        timestamp = datetime.now(timezone.utc).isoformat()
    with connect() as connection:
        connection.execute(
            """INSERT INTO patrol_snapshots (host_id, scanned_at, files_json)
               VALUES (?, ?, ?) ON CONFLICT(host_id) DO UPDATE SET
               scanned_at = excluded.scanned_at, files_json = excluded.files_json""",
            (host_id, timestamp, json.dumps(cleaned, ensure_ascii=False)),
        )


def normalize_fs_path(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        raise ValueError("invalid_fs_path")
    parts = [part for part in value.split("/") if part and part != "."]
    if ".." in parts or "\x00" in value:
        raise ValueError("invalid_fs_path")
    return "/" + "/".join(parts)


def clean_fs_entry(entry):
    if not isinstance(entry, list) or len(entry) != 4:
        return None
    name, kind, size, mtime = entry
    if not isinstance(name, str) or not name or len(name) > 1024 or "/" in name or "\x00" in name:
        return None
    if kind not in FS_ENTRY_KINDS:
        return None
    return [
        name, kind,
        size if isinstance(size, int) and size >= 0 else None,
        mtime if isinstance(mtime, int) else None,
    ]


def store_fs_inventory(host_id, directories, scanned_at=None):
    if not isinstance(host_id, str) or host_id not in ALLOWED_HOSTS:
        raise ValueError("unknown_host")
    if not isinstance(directories, dict) or len(directories) > MAX_INVENTORY_DIRECTORIES:
        raise ValueError("invalid_inventory")
    rows = []
    entry_count = 0
    for raw_path, directory in directories.items():
        if not isinstance(directory, dict) or not isinstance(directory.get("entries"), list):
            raise ValueError("invalid_inventory")
        entries = [
            cleaned for cleaned in map(clean_fs_entry, directory["entries"])
            if cleaned is not None
        ]
        entry_count += len(entries)
        if entry_count > MAX_INVENTORY_ENTRIES:
            raise ValueError("inventory_too_large")
        rows.append((
            host_id, normalize_fs_path(raw_path), int(directory.get("denied") is True),
            json.dumps(entries, separators=(",", ":")),
        ))
    try:
        timestamp = datetime.fromisoformat(scanned_at.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except (AttributeError, TypeError, ValueError):
        timestamp = datetime.now(timezone.utc).isoformat()
    with connect() as connection:
        connection.execute("DELETE FROM patrol_fs_directories WHERE host_id = ?", (host_id,))
        connection.executemany(
            """INSERT OR REPLACE INTO patrol_fs_directories (host_id, path, denied, entries_json)
               VALUES (?, ?, ?, ?)""",
            rows,
        )
        connection.execute(
            """INSERT INTO patrol_fs_scans (host_id, scanned_at, directory_count, entry_count)
               VALUES (?, ?, ?, ?) ON CONFLICT(host_id) DO UPDATE SET
               scanned_at = excluded.scanned_at, directory_count = excluded.directory_count,
               entry_count = excluded.entry_count""",
            (host_id, timestamp, len(rows), entry_count),
        )
    return entry_count


def fs_listing(host_id, raw_path="/"):
    if host_id not in ALLOWED_HOSTS:
        raise ValueError("unknown_host")
    path = normalize_fs_path(raw_path)
    with connect() as connection:
        scan = connection.execute(
            "SELECT scanned_at, directory_count, entry_count FROM patrol_fs_scans WHERE host_id = ?",
            (host_id,),
        ).fetchone()
        row = connection.execute(
            "SELECT denied, entries_json FROM patrol_fs_directories WHERE host_id = ? AND path = ?",
            (host_id, path),
        ).fetchone()
    result = {
        "host_id": host_id, "path": path, "found": row is not None, "denied": False,
        "scanned_at": scan["scanned_at"] if scan else None,
        "directory_count": scan["directory_count"] if scan else 0,
        "entry_count": scan["entry_count"] if scan else 0,
        "total": 0, "entries": [],
    }
    if row is None:
        return result
    entries = sorted(
        json.loads(row["entries_json"]),
        key=lambda entry: (FS_KIND_ORDER[entry[1]], entry[0].casefold()),
    )
    result["denied"] = bool(row["denied"])
    result["total"] = len(entries)
    result["entries"] = [
        {"name": name, "type": kind, "size": size, "mtime": mtime}
        for name, kind, size, mtime in entries[:MAX_LISTING_ENTRIES]
    ]
    return result


def store_patrol_event(event):
    allowed_types = {"patrol_check", "access", "alert"}
    allowed_actions = {"read", "download", "modify", "delete", "denied", "login"}
    allowed_severity = {"safe", "suspicious", "compromised"}
    event_type = event.get("type")
    action = event.get("action")
    severity = event.get("severity")
    host_id = event.get("host_id")
    path = event.get("path")
    actor = event.get("actor")
    if not isinstance(event_type, str) or not isinstance(action, str):
        raise ValueError("invalid_patrol_event")
    if event_type not in allowed_types or action not in allowed_actions:
        raise ValueError("invalid_patrol_event")
    if not isinstance(severity, str) or not isinstance(host_id, str):
        raise ValueError("invalid_patrol_event")
    if severity not in allowed_severity or host_id not in ALLOWED_HOSTS:
        raise ValueError("invalid_patrol_event")
    if not isinstance(path, str) or not path or len(path) > 2048:
        raise ValueError("invalid_patrol_path")
    path = "".join(char if char.isprintable() else "?" for char in path)[:2048]
    actor = str(actor or "unknown")[:96]
    if actor != "police":
        try:
            actor = str(ipaddress.ip_address(actor))
        except ValueError:
            actor = "unknown"
    status = event.get("status", "observed")
    if not isinstance(status, str) or status not in {"observed", "allowed", "blocked", "not_found", "contained", "demo"}:
        status = "observed"
    try:
        timestamp = datetime.fromisoformat(str(event.get("ts") or "").replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        timestamp = datetime.now(timezone.utc).isoformat()
    hashes = []
    for key in ("hash_old", "hash_new"):
        value = event.get(key)
        hashes.append(value if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value) else None)
    port = event.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
        port = None
    with connect() as connection:
        cursor = connection.execute(
            """INSERT INTO patrol_events
               (ts, type, actor, action, host_id, path, severity, hash_old, hash_new, status, port)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, event_type, actor, action, host_id, path, severity, hashes[0], hashes[1], status, port),
        )
        return cursor.lastrowid


def patrol_state():
    with connect() as connection:
        snapshots = connection.execute(
            "SELECT host_id, scanned_at, files_json FROM patrol_snapshots ORDER BY host_id"
        ).fetchall()
    files = []
    scanned = {}
    for snapshot in snapshots:
        scanned[snapshot["host_id"]] = snapshot["scanned_at"]
        for item in json.loads(snapshot["files_json"]):
            files.append({
                "host_id": snapshot["host_id"],
                "path": item["path"],
                "sha256": item["sha256"],
                "size": item.get("size"),
                "mtime": item.get("mtime"),
                "checked_at": snapshot["scanned_at"],
            })
    events = patrol_events(max(0, (latest_patrol_event_id() or 0) - 100), 100)
    recent = list(reversed(events))
    severity_by_file = {}
    for event in recent:
        key = (event["host_id"], event["path"])
        if key not in severity_by_file:
            severity_by_file[key] = event["severity"]
    safe = sum(1 for file in files if severity_by_file.get((file["host_id"], file["path"]), "safe") == "safe")
    suspicious = sum(1 for severity in severity_by_file.values() if severity == "suspicious")
    compromised = sum(1 for severity in severity_by_file.values() if severity == "compromised")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "scanned_at": scanned,
        "events": events[-100:],
        "counters": {"safe": safe, "suspicious": suspicious, "compromised": compromised},
    }


def build_fs_tree(root="/"):
    """Build per-host filesystem trees from the latest agent snapshots."""
    with connect() as connection:
        snapshots = connection.execute(
            "SELECT host_id, scanned_at, files_json FROM patrol_snapshots ORDER BY host_id"
        ).fetchall()

    hosts = []
    for snapshot in snapshots:
        root_node = {"name": "/", "path": "/", "type": "directory", "children": []}
        nodes = {"": root_node}
        for item in json.loads(snapshot["files_json"]):
            relative = item.get("path", "")
            parts = Path(relative).parts
            if not relative or Path(relative).is_absolute() or ".." in parts:
                continue
            parent = ""
            for part in parts[:-1]:
                current = f"{parent}/{part}" if parent else part
                if current not in nodes:
                    node = {
                        "name": part, "path": f"/{current}", "type": "directory",
                        "children": [],
                    }
                    nodes[parent]["children"].append(node)
                    nodes[current] = node
                parent = current
            name = parts[-1]
            path = f"/{relative}"
            node = {
                "name": name, "path": path, "type": "file",
                "size": item.get("size"), "mtime": item.get("mtime"),
                "sha256": item.get("sha256"),
            }
            nodes[parent]["children"].append(node)

        def sort_nodes(node):
            node["children"].sort(key=lambda child: (child["type"] != "directory", child["name"].casefold()))
            for child in node["children"]:
                if child["type"] == "directory":
                    sort_nodes(child)

        sort_nodes(root_node)
        hosts.append({
            "host_id": snapshot["host_id"],
            "scanned_at": snapshot["scanned_at"],
            "tree": root_node,
        })
    return {
        "root": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
    }


def latest_patrol_event_id():
    with connect() as connection:
        row = connection.execute("SELECT MAX(id) FROM patrol_events").fetchone()
    return row[0]


def backend_states():
    result = {"server-a": "UNKNOWN", "server-b": "UNKNOWN"}
    try:
        lines = haproxy_command("show stat").splitlines()
        if not lines:
            return result
        header = lines[0].lstrip("# ").split(",")
        for row in csv.DictReader(lines[1:], fieldnames=header):
            name = row.get("svname")
            if row.get("pxname") == "defnett_servers" and name in result:
                result[name] = row.get("status", "UNKNOWN")
    except (OSError, socket.timeout, UnicodeError):
        pass
    return result


def agent_states():
    with connect() as connection:
        rows = connection.execute("SELECT host_id, last_seen FROM agent_status").fetchall()
    seen = {row["host_id"]: row["last_seen"] for row in rows}
    now = datetime.now(timezone.utc)
    result = {}
    for host_id in sorted(ALLOWED_HOSTS):
        timestamp = seen.get(host_id)
        age = None
        if timestamp:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            age = max(0, int((now - parsed).total_seconds()))
        result[host_id] = {
            "last_seen": timestamp,
            "age_seconds": age,
            "online": age is not None and age <= 25,
        }
    return result


def dashboard_state():
    remediations = remediation_rows(20)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "ACTIVE_LAB" if ENABLE_LAB_AUTOREPAIR else "DRY_RUN",
        "analysis": {
            "engine": "FIM + canary rules",
            "model": "not_connected",
            "canary_response_enabled": ENABLE_LAB_AUTOREPAIR,
            "auto_repair_enabled": ENABLE_LAB_AUTOREPAIR,
            "demo_repair_host": DEMO_REPAIR_HOST,
            "demo_repair_delay_seconds": DEMO_REPAIR_DELAY_SECONDS,
        },
        "remediator": {
            "status": "ready" if all(remediator_health(host) == "ready" for host in ALLOWED_HOSTS) else "unavailable",
            "by_host": {host: {"status": remediator_health(host)} for host in sorted(ALLOWED_HOSTS)},
        },
        "backends": backend_states(),
        "ports": OPEN_PORTS,
        "traffic": traffic_state(),
        "agents": agent_states(),
        "remediation": remediations[0] if remediations else None,
        "remediations": remediations,
        "events": event_rows(40),
    }


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def respond_file(self, filename, content_type):
        try:
            body = (DASHBOARD_DIR / filename).read_bytes()
        except OSError:
            return self.respond(404, {"error": "dashboard_asset_not_found"})
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            return self.respond_file("index.html", "text/html; charset=utf-8")
        if self.path == "/dashboard.css":
            return self.respond_file("dashboard.css", "text/css; charset=utf-8")
        if self.path == "/dashboard.js":
            return self.respond_file("dashboard.js", "text/javascript; charset=utf-8")
        if self.path == "/patrol.css":
            return self.respond_file("patrol.css", "text/css; charset=utf-8")
        if self.path == "/patrol.js":
            return self.respond_file("patrol.js", "text/javascript; charset=utf-8")
        if self.path == "/healthz":
            return self.respond(200, {"status": "ok"})
        if self.path == "/v1/dashboard":
            return self.respond(200, dashboard_state())
        if self.path == "/api/patrol/state":
            return self.respond(200, patrol_state())
        if self.path == "/v1/fsmap":
            return self.respond(200, build_fs_tree("/"))
        if self.path == "/v1/evidence/verify":
            return self.respond(200, verify_evidence())
        if urlsplit(self.path).path == "/api/patrol/fs":
            query = parse_qs(urlsplit(self.path).query)
            try:
                return self.respond(200, fs_listing(
                    query.get("host", [""])[0], query.get("path", ["/"])[0],
                ))
            except ValueError as error:
                return self.respond(400, {"error": str(error)})
        if self.path.startswith("/api/patrol/stream"):
            return self.stream_patrol_events()
        if self.path == "/v1/events":
            return self.respond(200, {"events": event_rows()})
        if self.path == "/v1/summary":
            events = event_rows(1000)
            counts = {}
            for event in events:
                counts[event["host_id"]] = counts.get(event["host_id"], 0) + 1
            return self.respond(200, {"event_count": len(events), "by_host": counts})
        return self.respond(404, {"error": "not_found"})

    def do_POST(self):
        if self.path in AGENT_PATHS and API_TOKEN and not hmac.compare_digest(
            self.headers.get("Authorization", ""), f"Bearer {API_TOKEN}"
        ):
            return self.respond(401, {"error": "unauthorized"})
        if self.path == "/v1/patrol/snapshot":
            return self.receive_patrol_snapshot()
        if self.path == "/v1/patrol/inventory":
            return self.receive_fs_inventory()
        if self.path == "/api/patrol/events":
            return self.receive_patrol_event()
        if self.path == "/v1/agent/heartbeat":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 2048:
                    return self.respond(413, {"error": "invalid_body_size"})
                payload = json.loads(self.rfile.read(length))
                host_id = payload.get("host_id") if isinstance(payload, dict) else None
                if host_id not in ALLOWED_HOSTS:
                    return self.respond(403, {"error": "unknown_host"})
                timestamp = datetime.now(timezone.utc).isoformat()
                ports = payload.get("ports")
                if isinstance(ports, list):
                    OPEN_PORTS[host_id] = sorted({
                        port for port in ports[:MAX_OPEN_PORTS]
                        if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536
                    })
                with connect() as connection:
                    connection.execute(
                        "INSERT INTO agent_status (host_id, last_seen) VALUES (?, ?) "
                        "ON CONFLICT(host_id) DO UPDATE SET last_seen = excluded.last_seen",
                        (host_id, timestamp),
                    )
                return self.respond(202, {"accepted": True, "host_id": host_id})
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                return self.respond(400, {"error": "invalid_heartbeat"})

        if self.path.startswith("/v1/lab/attack/"):
            target = urlsplit(self.path)
            host_id = target.path.rsplit("/", 1)[-1]
            vector = parse_qs(target.query).get("vector", [None])[0]
            try:
                result = start_lab_attack(host_id, vector, self.client_address[0])
            except PermissionError as error:
                return self.respond(403, {"error": str(error)})
            except LookupError as error:
                return self.respond(404, {"error": str(error)})
            except RuntimeError as error:
                return self.respond(409, {"error": str(error)})
            except (OSError, urllib.error.URLError, socket.timeout, UnicodeError, ValueError) as error:
                return self.respond(503, {"error": "attack_unavailable", "detail": type(error).__name__})
            print(f"lab attack simulated on {host_id}", flush=True)
            return self.respond(202, {"accepted": True, "host_id": host_id, "path": result.get("path")})

        if self.path.startswith("/v1/lab/recover/"):
            if not ENABLE_LAB_AUTOREPAIR:
                return self.respond(403, {"error": "lab_drain_mode_disabled"})
            host_id = self.path.rsplit("/", 1)[-1]
            if host_id not in ALLOWED_HOSTS:
                return self.respond(404, {"error": "unknown_host"})
            try:
                haproxy_command(f"enable server defnett_servers/{host_id}")
                if not wait_for_backend(host_id, True):
                    return self.respond(409, {"error": "backend_not_healthy_after_enable", "host_id": host_id})
                print(f"operator action: enable {host_id}", flush=True)
                return self.respond(200, {
                    "mode": "ACTIVE_LAB", "action": f"ENABLE_{host_id.upper().replace('-', '_')}",
                    "host_id": host_id, "result": "backend_up",
                })
            except (OSError, socket.timeout, UnicodeError) as error:
                return self.respond(503, {"error": "haproxy_unavailable", "detail": type(error).__name__})

        if self.path != "/v1/events":
            return self.respond(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 16384:
                return self.respond(413, {"error": "invalid_body_size"})
            event = json.loads(self.rfile.read(length))
            required = {"host_id", "source", "event_type", "path", "timestamp"}
            if not isinstance(event, dict) or not required.issubset(event):
                return self.respond(400, {"error": "missing_fields"})
            if event["host_id"] not in ALLOWED_HOSTS:
                return self.respond(403, {"error": "unknown_host"})
            if event["event_type"] not in {"file_created", "file_modified", "file_deleted"}:
                return self.respond(400, {"error": "unknown_event_type"})
            if "content_signal" in event and not isinstance(event["content_signal"], bool):
                return self.respond(400, {"error": "invalid_content_signal"})
            if not isinstance(event["path"], str) or len(event["path"]) > 2048:
                return self.respond(400, {"error": "invalid_path"})
            result = store_event(event)
            print(json.dumps({"accepted": True, **result}), flush=True)
            return self.respond(201, result)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, KeyError) as error:
            return self.respond(400, {"error": "invalid_event", "detail": str(error)})
        except Exception as error:
            print(f"event storage failed: {error}", flush=True)
            return self.respond(500, {"error": "storage_failure"})

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} {format_string % args}", flush=True)

    def read_json_body(self, maximum=16_000_000):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > maximum:
            raise ValueError("invalid_body_size")
        body = self.rfile.read(length)
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            decoder = zlib.decompressobj(wbits=31)
            try:
                body = decoder.decompress(body, MAX_BODY_BYTES)
            except zlib.error as error:
                raise ValueError("invalid_gzip_body") from error
            if decoder.unconsumed_tail:
                raise ValueError("invalid_body_size")
        return json.loads(body)

    def receive_fs_inventory(self):
        try:
            payload = self.read_json_body()
            if not isinstance(payload, dict):
                return self.respond(400, {"error": "invalid_inventory"})
            host_id = payload.get("host_id")
            entry_count = store_fs_inventory(host_id, payload.get("directories"), payload.get("timestamp"))
            return self.respond(202, {"accepted": True, "host_id": host_id, "entry_count": entry_count})
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(400, {"error": str(error) or "invalid_inventory"})

    def receive_patrol_snapshot(self):
        try:
            payload = self.read_json_body()
            host_id = payload.get("host_id") if isinstance(payload, dict) else None
            files = payload.get("files") if isinstance(payload, dict) else None
            if not isinstance(host_id, str) or host_id not in ALLOWED_HOSTS or not isinstance(files, list):
                return self.respond(400, {"error": "invalid_patrol_snapshot"})
            store_patrol_snapshot(host_id, files, payload.get("timestamp"))
            return self.respond(202, {"accepted": True, "host_id": host_id, "file_count": len(files)})
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(400, {"error": str(error) or "invalid_patrol_snapshot"})

    def receive_patrol_event(self):
        try:
            payload = self.read_json_body(16384)
            if not isinstance(payload, dict):
                return self.respond(400, {"error": "invalid_patrol_event"})
            event_id = store_patrol_event(payload)
            return self.respond(202, {"accepted": True, "id": event_id})
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(400, {"error": str(error) or "invalid_patrol_event"})

    def stream_patrol_events(self):
        query = parse_qs(urlsplit(self.path).query)
        try:
            last_id = max(0, int(self.headers.get("Last-Event-ID", query.get("after", ["0"])[0])))
        except ValueError:
            last_id = 0
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                rows = patrol_events(last_id, 100)
                for event in rows:
                    last_id = event["id"]
                    message = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                    self.wfile.write(f"id: {last_id}\nevent: patrol\ndata: {message}\n\n".encode("utf-8"))
                if not rows:
                    self.wfile.write(b": heartbeat\n\n")
                self.wfile.flush()
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


if __name__ == "__main__":
    initialize()
    if TRAFFIC_PROBE_ENABLED:
        threading.Thread(target=traffic_probe_loop, name="traffic-probe", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
