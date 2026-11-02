import gzip
import hashlib
import ipaddress
import json
import os
import re
import stat
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


HOST_ID = os.environ["HOST_ID"]
WATCH_ROOT = Path(os.environ.get("WATCH_ROOT", "/watched"))
STATE_PATH = Path(os.environ.get("STATE_PATH", "/state/baseline.json"))
COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://collector:8090/v1/events")
HEARTBEAT_URL = os.environ.get(
    "HEARTBEAT_URL", COLLECTOR_URL.rsplit("/", 1)[0] + "/agent/heartbeat"
)
POLL_SECONDS = max(1, float(os.environ.get("POLL_SECONDS", "3")))
HEARTBEAT_SECONDS = max(3, float(os.environ.get("HEARTBEAT_SECONDS", "10")))
SNAPSHOT_SECONDS = max(10, float(os.environ.get("SNAPSHOT_SECONDS", "30")))
MAX_SNAPSHOT_FILES = 50000
COLLECTOR_TIMEOUT = max(5, float(os.environ.get("COLLECTOR_TIMEOUT", "45")))
PATROL_SNAPSHOT_URL = os.environ.get(
    "PATROL_SNAPSHOT_URL", COLLECTOR_URL.rsplit("/", 1)[0] + "/patrol/snapshot"
)
INVENTORY_ROOT = Path(os.environ.get("INVENTORY_ROOT", str(WATCH_ROOT)))
INVENTORY_SECONDS = max(30, float(os.environ.get("INVENTORY_SECONDS", "300")))
INVENTORY_RETRY_SECONDS = 30
INVENTORY_URL = os.environ.get(
    "INVENTORY_URL", COLLECTOR_URL.rsplit("/", 1)[0] + "/patrol/inventory"
)
API_TOKEN = os.environ.get("LAB_API_TOKEN", "")
PATROL_EVENT_URL = os.environ.get(
    "PATROL_EVENT_URL", COLLECTOR_URL.rsplit("/", 2)[0] + "/api/patrol/events"
)
AUTH_LOG = os.environ.get("AUTH_LOG", "")
WEB_LOG = os.environ.get("WEB_LOG", "")
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
WEB_PORT = int(os.environ.get("WEB_PORT", "80"))
LOGIN_POLL_SECONDS = 2
FAILED_LOGIN_INTERVAL = 5
TRUSTED_SSH_METHODS = {
    item.strip() for item in os.environ.get("TRUSTED_SSH_METHODS", "publickey").split(",") if item.strip()
}
SSH_ACCEPTED = re.compile(r"sshd(?:-session)?\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port \d+")
SSH_FAILED = re.compile(r"sshd(?:-session)?\[\d+\]: Failed \S+ for (?:invalid user )?(\S+) from (\S+) port \d+")
WEB_REQUEST = re.compile(
    r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "[^"]*"(?: "([^"]*)")?'
)
MAX_REPORTED_PORTS = 32
CANARY = b"DEFNETT-LAB-MALWARE-CANARY"
VIRTUAL_ROOTS = {"proc", "sys", "dev", "run"}


def api_headers(extra=None):
    headers = {"Content-Type": "application/json", **(extra or {})}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return headers


def snapshot():
    result = {}
    root = WATCH_ROOT.resolve()
    previous = load_state() or {}
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if current_path == root == Path("/"):
            directories[:] = [name for name in directories if name not in VIRTUAL_ROOTS]
        directories[:] = sorted(
            name for name in directories
            if not (current_path / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = current_path / filename
            try:
                stat_result = path.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(stat_result.st_mode):
                continue
            relative_path = path.relative_to(root).as_posix()
            prior = previous.get(relative_path, {})
            if isinstance(prior, str):
                prior = {"sha256": prior}
            signature = (
                stat_result.st_dev, stat_result.st_ino, stat_result.st_size,
                stat_result.st_mtime_ns, stat_result.st_ctime_ns,
            )
            prior_signature = (
                prior.get("device"), prior.get("inode"), prior.get("size"),
                prior.get("mtime_ns"), prior.get("ctime_ns"),
            )
            canary_match = prior.get("canary_match", False)
            if prior.get("sha256") and signature == prior_signature:
                digest_value = prior["sha256"]
            else:
                digest = hashlib.sha256()
                canary_match = False
                overlap = b""
                try:
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                            if not canary_match and CANARY in overlap + chunk:
                                canary_match = True
                            overlap = (overlap + chunk)[-(len(CANARY) - 1):]
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                digest_value = digest.hexdigest()
            result[relative_path] = {
                "sha256": digest_value,
                "size": stat_result.st_size,
                "mtime": datetime.fromtimestamp(stat_result.st_mtime, timezone.utc).isoformat(),
                "mtime_ns": stat_result.st_mtime_ns,
                "ctime_ns": stat_result.st_ctime_ns,
                "device": stat_result.st_dev,
                "inode": stat_result.st_ino,
                "canary_match": canary_match,
            }
    return result


def display_name(value):
    return os.fsencode(value).decode("utf-8", "replace")


def entry_kind(stat_result):
    if stat.S_ISLNK(stat_result.st_mode):
        return "link"
    if stat.S_ISDIR(stat_result.st_mode):
        return "dir"
    if stat.S_ISREG(stat_result.st_mode):
        return "file"
    return "other"


def inventory():
    """Daftar seluruh file system per direktori: metadata saja, tanpa hash atau isi file."""
    root = INVENTORY_ROOT.resolve()
    directories = {}
    pending = [(str(root), "/")]
    while pending:
        current, shown = pending.pop()
        entries = []
        denied = False
        try:
            with os.scandir(current) as iterator:
                items = list(iterator)
        except OSError:
            items = []
            denied = True
        for item in items:
            name = display_name(item.name)
            if current == "/" and item.name in VIRTUAL_ROOTS:
                entries.append([name, "virtual", None, None])
                continue
            try:
                stat_result = item.stat(follow_symlinks=False)
            except OSError:
                entries.append([name, "other", None, None])
                continue
            kind = entry_kind(stat_result)
            size = stat_result.st_size if kind == "file" else None
            entries.append([name, kind, size, int(stat_result.st_mtime)])
            if kind == "dir":
                pending.append((item.path, f"{shown.rstrip('/')}/{name}"))
        directories[shown] = {"denied": denied, "entries": entries}
    return directories


def send_inventory(directories):
    payload = {
        "host_id": HOST_ID,
        "directories": directories,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    request = urllib.request.Request(
        INVENTORY_URL,
        data=gzip.compress(json.dumps(payload).encode("utf-8"), compresslevel=5),
        headers=api_headers({"Content-Encoding": "gzip"}),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=COLLECTOR_TIMEOUT) as response:
        if response.status != 202:
            raise RuntimeError(f"inventory returned HTTP {response.status}")


def inventory_loop():
    while True:
        delay = INVENTORY_SECONDS
        try:
            send_inventory(inventory())
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
            print(f"{HOST_ID}: inventory failed: {error}", flush=True)
            delay = INVENTORY_RETRY_SECONDS
        time.sleep(delay)


def send_event(event_type, path, old_hash, new_hash, event_signal, detect_seconds=None):
    event_path = f"/{path}" if WATCH_ROOT.resolve() == Path("/") else path
    event = {
        "detect_seconds": detect_seconds,
        "host_id": HOST_ID,
        "source": "lab-fim-agent",
        "event_type": event_type,
        "path": event_path,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "content_signal": bool(event_signal),
        "indicator": "DEFNETT_LAB_CANARY" if event_signal else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    request = urllib.request.Request(
        COLLECTOR_URL,
        data=json.dumps(event).encode("utf-8"),
        headers=api_headers(),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=COLLECTOR_TIMEOUT) as response:
        if response.status != 201:
            raise RuntimeError(f"collector returned HTTP {response.status}")


def listening_ports():
    """Port TCP yang menerima koneksi dari luar host; yang hanya di loopback tidak dihitung."""
    ports = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, encoding="ascii") as stream:
                rows = stream.readlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            address, port = fields[1].rsplit(":", 1)
            # Alamat IPv4 tersimpan terbalik per byte, jadi 127.x.x.x berakhir dengan 7F.
            if address.endswith("7F") or address == "00000000000000000000000001000000":
                continue
            ports.add(int(port, 16))
    return sorted(ports)[:MAX_REPORTED_PORTS]


class LogFollower:
    """Membaca baris baru sebuah log, dimulai dari akhir file, dan tahan terhadap rotasi."""

    def __init__(self, path):
        self.path = path
        self.inode = None
        self.offset = 0
        self.partial = b""
        try:
            metadata = os.stat(path)
            self.inode, self.offset = metadata.st_ino, metadata.st_size
        except OSError:
            pass

    def read_lines(self):
        try:
            metadata = os.stat(self.path)
        except OSError:
            return []
        if metadata.st_ino != self.inode or metadata.st_size < self.offset:
            self.inode, self.offset, self.partial = metadata.st_ino, 0, b""
        if metadata.st_size == self.offset:
            return []
        with open(self.path, "rb") as stream:
            stream.seek(self.offset)
            data = stream.read()
        self.offset += len(data)
        lines = (self.partial + data).split(b"\n")
        self.partial = lines.pop()
        return [line.decode("utf-8", "replace") for line in lines]


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def parse_auth_line(line):
    accepted = SSH_ACCEPTED.search(line)
    if accepted:
        method, user, address = accepted.groups()
        if method in TRUSTED_SSH_METHODS or not valid_ip(address):
            return None
        return {"port": SSH_PORT, "actor": valid_ip(address), "user": user, "success": True}
    failed = SSH_FAILED.search(line)
    if failed and valid_ip(failed.group(2)):
        return {"port": SSH_PORT, "actor": valid_ip(failed.group(2)), "user": failed.group(1), "success": False}
    return None


def parse_web_line(line):
    match = WEB_REQUEST.match(line)
    if not match:
        return None
    remote, method, target, status, forwarded = match.groups()
    actor = valid_ip((forwarded or "").split(",", 1)[0]) or valid_ip(remote)
    path = target.split("?", 1)[0]
    if not actor:
        return None
    if method == "POST" and path == "/wp-login.php" and status in ("200", "302"):
        return {"port": WEB_PORT, "actor": actor, "user": "wp-login", "success": status == "302"}
    if path.startswith("/wp-content/uploads/") and path.endswith(".php") and status == "200":
        return {"port": WEB_PORT, "actor": actor, "user": "upload-php", "success": True}
    return None


def send_login_event(login):
    payload = {
        "host_id": HOST_ID,
        "type": "alert",
        "actor": login["actor"],
        "action": "login",
        "path": f"port-{login['port']}/{login['user']}"[:256],
        "severity": "suspicious",
        "status": "allowed" if login["success"] else "blocked",
        "port": login["port"],
    }
    request = urllib.request.Request(
        PATROL_EVENT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers=api_headers(),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status != 202:
            raise RuntimeError(f"patrol event returned HTTP {response.status}")


def login_watch_loop():
    followers = [
        (LogFollower(path), parser)
        for path, parser in ((AUTH_LOG, parse_auth_line), (WEB_LOG, parse_web_line))
        if path
    ]
    last_failed = {}
    while True:
        time.sleep(LOGIN_POLL_SECONDS)
        for follower, parser in followers:
            for line in follower.read_lines():
                login = parser(line)
                if login is None:
                    continue
                key = (login["actor"], login["port"])
                now = time.monotonic()
                if not login["success"]:
                    if now - last_failed.get(key, -FAILED_LOGIN_INTERVAL) < FAILED_LOGIN_INTERVAL:
                        continue
                    last_failed[key] = now
                try:
                    send_login_event(login)
                except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
                    print(f"{HOST_ID}: login event failed: {error}", flush=True)


def send_heartbeat():
    payload = {
        "host_id": HOST_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ports": listening_ports(),
    }
    request = urllib.request.Request(
        HEARTBEAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers=api_headers(),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status != 202:
            raise RuntimeError(f"collector returned HTTP {response.status}")


def send_patrol_snapshot(current):
    payload = {
        "host_id": HOST_ID,
        "files": [
            {
                "path": path,
                "sha256": state["sha256"],
                "size": state.get("size"),
                "mtime": state.get("mtime"),
            }
            for path, state in sorted(current.items())[:MAX_SNAPSHOT_FILES]
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    request = urllib.request.Request(
        PATROL_SNAPSHOT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers=api_headers(),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=COLLECTOR_TIMEOUT) as response:
        if response.status != 202:
            raise RuntimeError(f"patrol snapshot returned HTTP {response.status}")


def load_state():
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.pop("__watch_root__", None) != str(WATCH_ROOT.resolve()):
            return None
        return state
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def save_state(current):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    state = {**current, "__watch_root__": str(WATCH_ROOT.resolve())}
    temporary.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    temporary.replace(STATE_PATH)


def main():
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    threading.Thread(target=inventory_loop, daemon=True).start()
    threading.Thread(target=login_watch_loop, daemon=True).start()
    previous = load_state()
    last_snapshot_attempt = 0.0
    if previous is None:
        previous = snapshot()
        save_state(previous)
        try:
            send_patrol_snapshot(previous)
            last_snapshot_attempt = time.monotonic()
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
            last_snapshot_attempt = time.monotonic()
            print(f"{HOST_ID}: patrol snapshot failed: {error}", flush=True)
        print(f"{HOST_ID}: initial baseline recorded", flush=True)

    while True:
        time.sleep(POLL_SECONDS)
        current = snapshot()
        now = time.monotonic()
        if now - last_snapshot_attempt >= SNAPSHOT_SECONDS:
            try:
                send_patrol_snapshot(current)
            except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
                print(f"{HOST_ID}: patrol snapshot failed: {error}", flush=True)
            finally:
                last_snapshot_attempt = now
        failed = False
        for path in sorted(previous.keys() | current.keys()):
            old_state = previous.get(path)
            new_state = current.get(path)
            if isinstance(old_state, str):
                old_state = {"sha256": old_state, "canary_match": False}
            old_hash = old_state.get("sha256") if old_state else None
            new_hash = new_state.get("sha256") if new_state else None
            if old_hash == new_hash:
                continue
            event_type = (
                "file_created" if old_hash is None else
                "file_deleted" if new_hash is None else
                "file_modified"
            )
            try:
                signal = (
                    new_state.get("canary_match", False) if new_state
                    else old_state.get("canary_match", False)
                )
                detect_seconds = (
                    round(max(0.0, time.time() - new_state["mtime_ns"] / 1e9), 2)
                    if new_state and new_state.get("mtime_ns") else None
                )
                send_event(event_type, path, old_hash, new_hash, signal, detect_seconds)
                print(f"{HOST_ID}: {event_type} {path}", flush=True)
            except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
                print(f"{HOST_ID}: send failed: {error}", flush=True)
                failed = True
                break
        if not failed:
            previous = current
            save_state(previous)


def heartbeat_loop():
    while True:
        try:
            send_heartbeat()
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
            print(f"{HOST_ID}: heartbeat failed: {error}", flush=True)
        time.sleep(HEARTBEAT_SECONDS)


if __name__ == "__main__":
    main()
