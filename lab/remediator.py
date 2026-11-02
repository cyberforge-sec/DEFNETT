import hashlib
import hmac
import json
import os
import stat
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


TARGET = Path(os.environ.get("TARGET_ROOT", "/target"))
TARGET_HOST_ID = os.environ.get("TARGET_HOST_ID", "server-a")
QUARANTINE = Path(os.environ.get("QUARANTINE_ROOT", f"/quarantine/{TARGET_HOST_ID}"))
MASTER = Path(os.environ.get("MASTER_ROOT", "/master"))
CANARY_NAME = "DEFNETT-LAB-CANARY.txt"
CANARY = b"DEFNETT-LAB-MALWARE-CANARY"
KEY_NAMES = ("etc/kunci1.dat", "etc/kunci2.dat")
KEY_MARKER = b"SECRET kunci"
MAX_FILE_SIZE = 1024 * 1024
ATTACK_SIMULATION = os.environ.get("LAB_ATTACK_SIMULATION", "false").lower() == "true"
API_TOKEN = os.environ.get("LAB_API_TOKEN", "")


def read_regular_file(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(MAX_FILE_SIZE + 1)
    finally:
        os.close(descriptor)
    if len(content) > MAX_FILE_SIZE:
        raise ValueError("key_file_too_large")
    return content


def atomic_write(path, content, mode):
    temporary = path.parent / f".{path.name}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    if hashlib.sha256(temporary.read_bytes()).hexdigest() != hashlib.sha256(content).hexdigest():
        temporary.unlink(missing_ok=True)
        raise OSError("write_hash_mismatch")
    os.replace(temporary, path)


def ensure_masters():
    """Simpan salinan bersih kunci di /master sekali saat worker hidup; dipakai untuk pemulihan."""
    for name in KEY_NAMES:
        master = MASTER / Path(name).name
        if master.exists():
            continue
        source = TARGET / name
        try:
            metadata = source.lstat()
        except FileNotFoundError:
            print(f"remediator-{TARGET_HOST_ID} master skip {name}: source_missing", flush=True)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_SIZE:
            print(f"remediator-{TARGET_HOST_ID} master skip {name}: source_type_or_size_rejected", flush=True)
            continue
        content = source.read_bytes()
        if KEY_MARKER not in content:
            print(f"remediator-{TARGET_HOST_ID} master skip {name}: key_marker_missing", flush=True)
            continue
        MASTER.mkdir(parents=True, exist_ok=True)
        atomic_write(master, content, 0o600)
        print(f"remediator-{TARGET_HOST_ID} master seeded {name} sha256={hashlib.sha256(content).hexdigest()}", flush=True)


def quarantine_canary():
    source = TARGET / CANARY_NAME
    try:
        metadata = source.lstat()
    except FileNotFoundError:
        raise ValueError("canary_file_missing") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_SIZE:
        raise ValueError("canary_file_type_or_size_rejected")
    content = read_regular_file(source)
    if CANARY not in content:
        raise ValueError("canary_marker_not_verified")
    digest = hashlib.sha256(content).hexdigest()
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    name = f"{TARGET_HOST_ID}-{uuid.uuid4().hex}-{CANARY_NAME}"
    atomic_write(QUARANTINE / name, content, 0o600)
    source.unlink()
    if source.exists():
        raise OSError("source_file_still_present")
    return {
        "status": "QUARANTINED_CANARY",
        "action": "MOVE_VERIFIED_CANARY_TO_QUARANTINE",
        "quarantine_path": str((QUARANTINE / name).relative_to(QUARANTINE.parent)),
        "sha256": digest,
        "bytes": len(content),
    }


def quarantine_keys():
    """Kunci tampered dikarantina sebagai bukti, lalu kedua kunci dipulihkan dari master.

    Kunci yang masih identik dengan master tidak disentuh; jika file hilang,
    langsung dipulihkan dari master. Verifikasi akhir: sha256 di /target
    harus sama dengan sha256 master untuk kedua kunci.
    """
    quarantined = []
    restored = []
    untouched = []
    digests = {}
    for name in KEY_NAMES:
        master = MASTER / Path(name).name
        try:
            master_content = master.read_bytes()
        except FileNotFoundError as error:
            raise ValueError(f"master_missing:{name}") from None
        if KEY_MARKER not in master_content:
            raise ValueError(f"master_not_verified:{name}")
        master_digest = hashlib.sha256(master_content).hexdigest()
        digests[name] = master_digest

        source = TARGET / name
        try:
            metadata = source.lstat()
        except FileNotFoundError:
            metadata = None
        if metadata is not None and (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_SIZE):
            raise ValueError("key_file_type_or_size_rejected")
        current = None if metadata is None else read_regular_file(source)
        current_digest = None if current is None else hashlib.sha256(current).hexdigest()
        if current_digest == master_digest:
            untouched.append(name)
            continue

        if current is not None:
            QUARANTINE.mkdir(parents=True, exist_ok=True)
            evidence_name = f"{TARGET_HOST_ID}-{uuid.uuid4().hex}-{Path(name).name}"
            atomic_write(QUARANTINE / evidence_name, current, 0o600)
            source.unlink()
            if source.exists():
                raise OSError("source_file_still_present")
            quarantined.append({
                "path": name,
                "evidence": evidence_name,
                "tampered_sha256": current_digest,
                "bytes": len(current),
            })

        source.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(source, master_content, 0o644)
        verify_digest = hashlib.sha256(read_regular_file(source)).hexdigest()
        if verify_digest != master_digest:
            raise OSError("restore_hash_mismatch")
        restored.append({"path": name, "sha256": master_digest, "bytes": len(master_content)})

    QUARANTINE.mkdir(parents=True, exist_ok=True)
    manifest_name = f"{TARGET_HOST_ID}-{uuid.uuid4().hex}-KEYS-RESTORE.json"
    manifest = {
        "host": TARGET_HOST_ID,
        "quarantined": quarantined,
        "restored": restored,
        "untouched_pristine": untouched,
        "sha256": {name: digests[name] for name in KEY_NAMES},
    }
    atomic_write(QUARANTINE / manifest_name, json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"), 0o600)
    if not quarantined and not restored:
        raise ValueError("keys_already_pristine")
    return {
        "status": "RESTORED_KEYS",
        "action": "QUARANTINE_AND_RESTORE_KEYS",
        "quarantine_path": str((QUARANTINE / manifest_name).relative_to(QUARANTINE.parent)),
        "quarantined": quarantined,
        "restored": restored,
    }


def simulate_key_tamper():
    """Simulasi pencurian untuk demo lab: menambah satu baris penanda ke kunci demo.

    Hanya menyentuh etc/kunci1.dat milik host ini, dan menolak bila file itu sudah
    berbeda dari salinan master, agar serangan tidak menumpuk. Perubahan ini yang
    nanti dideteksi agent dan memicu playbook isolasi sungguhan.
    """
    name = KEY_NAMES[0]
    source = TARGET / name
    try:
        metadata = source.lstat()
    except FileNotFoundError:
        raise ValueError("key_file_missing") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_SIZE:
        raise ValueError("key_file_type_or_size_rejected")
    content = read_regular_file(source)
    if KEY_MARKER not in content:
        raise ValueError("key_marker_not_verified")
    master = MASTER / Path(name).name
    if not master.exists() or master.read_bytes() != content:
        raise ValueError("key_not_pristine")
    stamp = datetime.now(timezone.utc).isoformat()
    atomic_write(source, content + f"DEFNETT-LAB-ATTACK-SIM {stamp}\n".encode("utf-8"), 0o644)
    return {
        "status": "ATTACK_SIMULATED",
        "action": "APPEND_MARKER_TO_DEMO_KEY",
        "path": name,
        "sha256": hashlib.sha256(read_regular_file(source)).hexdigest(),
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

    def do_GET(self):
        if self.path == "/healthz":
            return self.respond(200, {"status": "ok"})
        return self.respond(404, {"error": "not_found"})

    def do_POST(self):
        if self.path not in ("/v1/repair", "/v1/lab/attack"):
            return self.respond(404, {"error": "not_found"})
        if API_TOKEN and not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {API_TOKEN}"):
            return self.respond(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2048:
                return self.respond(413, {"error": "invalid_body_size"})
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or payload.get("host_id") != TARGET_HOST_ID:
                return self.respond(403, {"error": "host_not_allowed"})
            if self.path == "/v1/lab/attack":
                if not ATTACK_SIMULATION:
                    return self.respond(403, {"error": "attack_simulation_disabled"})
                result = simulate_key_tamper()
                result["host_id"] = TARGET_HOST_ID
                return self.respond(200, result)
            kind = payload.get("kind", "canary")
            if kind == "kunci":
                result = quarantine_keys()
            elif kind == "canary":
                result = quarantine_canary()
            else:
                return self.respond(409, {"error": "unknown_repair_kind", "detail": kind})
            result["event_id"] = str(payload.get("event_id", ""))[:64]
            result["host_id"] = TARGET_HOST_ID
            return self.respond(200, result)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(409, {"error": "repair_rejected", "detail": str(error)})
        except OSError as error:
            return self.respond(500, {"error": "quarantine_failed", "detail": type(error).__name__})

    def log_message(self, format_string, *args):
        print(f"remediator-{TARGET_HOST_ID} {self.address_string()} {format_string % args}", flush=True)


if __name__ == "__main__":
    ensure_masters()
    ThreadingHTTPServer(("0.0.0.0", 8091), Handler).serve_forever()
