import hashlib
import html
import ipaddress
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
import urllib.error
import urllib.request


HOST_ID = os.environ.get("HOST_ID", "server")
DATA_ROOT = Path("/data").resolve()
DATA_FILE = DATA_ROOT / "index.txt"
COLLECTOR_URL = os.environ.get(
    "PATROL_EVENT_URL", "http://collector:8090/api/patrol/events"
)
PUBLIC_FILES = {
    item.strip().replace("\\", "/")
    for item in os.environ.get("PATROL_PUBLIC_FILES", "index.txt").split(",")
    if item.strip() and not Path(item.strip()).is_absolute() and ".." not in Path(item.strip()).parts
}
SENSITIVE_NAMES = {".env", ".git", ".ssh", "id_rsa", "credentials", "secrets"}
SENSITIVE_SUFFIXES = {".key", ".pem", ".p12", ".pfx"}
SPINNER_NAMES = (
    "Alya Putri", "Bima Arta", "Citra Naya", "Dimas Raka",
    "Farah Nuri", "Galang Pratama", "Hana Kirana", "Jati Mahesa",
)


def landing_page():
    """Halaman demo node; pemilihan nama hanya berjalan di browser."""
    host = html.escape(HOST_ID)
    names = json.dumps(SPINNER_NAMES, ensure_ascii=False).replace("<", "\\u003c")
    return f"""<!doctype html>
<html lang=\"id\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>DEFNETT · {host}</title>
  <style>
    :root {{
      color-scheme: dark; --night: #0c1720; --panel: #132731; --line: #29434d;
      --ink: #eef5f1; --muted: #a3b8b8; --mint: #65d5af; --mint-dim: #1e785f;
      --signal: #e8b650; --display: ui-rounded, "Avenir Next", "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{ min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 24px; color: var(--ink); background: radial-gradient(circle at 85% 10%, #173b42 0, transparent 34rem), var(--night); font-family: var(--display); }}
    main {{ width: min(100%, 680px); }}
    header {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 24px; color: var(--muted); font-size: 13px; }}
    .brand {{ display: flex; align-items: center; gap: 10px; color: var(--ink); font-weight: 800; letter-spacing: .02em; }}
    .brand-mark {{ width: 28px; height: 28px; display: grid; place-items: center; border: 1px solid #40706c; border-radius: 8px; color: var(--mint); }}
    .host {{ display: inline-flex; align-items: center; gap: 7px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }}
    .dot {{ width: 8px; height: 8px; border-radius: 50%; background: var(--mint); box-shadow: 0 0 0 4px rgba(101, 213, 175, .13); }}
    .spinner {{ overflow: hidden; border: 1px solid var(--line); border-radius: 18px; background: linear-gradient(145deg, rgba(30, 120, 95, .18), transparent 55%), var(--panel); box-shadow: 0 24px 70px rgba(0, 0, 0, .26); }}
    .spinner-head {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 20px 22px; border-bottom: 1px solid var(--line); }}
    h1 {{ margin: 0; font-size: clamp(22px, 5vw, 32px); letter-spacing: -.035em; }}
    .spinner-head p {{ max-width: 32ch; margin: 5px 0 0; color: var(--muted); font-size: 13px; line-height: 1.5; }}
    .local {{ flex: none; padding: 6px 8px; border: 1px solid #3b6f61; border-radius: 999px; color: var(--mint); font: 700 10px ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .wheel-wrap {{ position: relative; display: grid; place-items: center; min-height: 240px; padding: 32px 22px; }}
    .wheel-wrap::before, .wheel-wrap::after {{ content: ""; position: absolute; z-index: 1; left: 14%; right: 14%; height: 1px; background: linear-gradient(90deg, transparent, var(--signal), transparent); }}
    .wheel-wrap::before {{ top: 50%; transform: translateY(-27px); }} .wheel-wrap::after {{ top: 50%; transform: translateY(27px); }}
    .wheel {{ height: 164px; overflow: hidden; width: min(100%, 440px); mask-image: linear-gradient(transparent, #000 29%, #000 71%, transparent); }}
    .name-list {{ margin: 0; padding: 54px 0; list-style: none; text-align: center; transform: translateY(0); }}
    .name-list li {{ height: 54px; color: #6d898a; font-size: 19px; font-weight: 700; line-height: 54px; transition: color 180ms ease, transform 180ms ease; }}
    .name-list li.selected {{ color: var(--ink); font-size: 24px; transform: scale(1.03); }}
    .controls {{ display: flex; justify-content: center; padding: 0 22px 24px; }}
    button {{ min-height: 48px; min-width: min(100%, 236px); border: 1px solid #78e4bd; border-radius: 10px; background: var(--mint); color: #092019; font: 800 14px var(--display); cursor: pointer; transition: transform 150ms ease, background 150ms ease, box-shadow 150ms ease; }}
    button:hover {{ background: #8be8c6; box-shadow: 0 8px 22px rgba(101, 213, 175, .2); }} button:active {{ transform: scale(.97); }} button:disabled {{ cursor: wait; opacity: .7; }} button:focus-visible {{ outline: 3px solid var(--signal); outline-offset: 4px; }}
    .result {{ min-height: 22px; margin: 0; color: var(--muted); text-align: center; font-size: 13px; }} .result strong {{ color: var(--mint); }}
    footer {{ margin-top: 18px; color: #789091; text-align: center; font-size: 11px; line-height: 1.5; }}
    @media (prefers-reduced-motion: reduce) {{ *, *::before, *::after {{ scroll-behavior: auto !important; transition-duration: .01ms !important; animation-duration: .01ms !important; }} }}
  </style>
</head>
<body>
  <main>
    <header><div class=\"brand\"><span class=\"brand-mark\" aria-hidden=\"true\">◈</span>DEFNETT node</div><span class=\"host\"><i class=\"dot\"></i>{host} online</span></header>
    <section class=\"spinner\" aria-labelledby=\"title\">
      <div class=\"spinner-head\"><div><h1 id=\"title\">Pilih operator demo</h1><p>Putar daftar untuk memilih nama acak. Interaksi ini hanya ada di browser.</p></div><span class=\"local\">LOCAL</span></div>
      <div class=\"wheel-wrap\"><div class=\"wheel\" aria-live=\"polite\" aria-label=\"Nama operator terpilih\"><ul id=\"names\" class=\"name-list\"></ul></div></div>
      <p id=\"result\" class=\"result\">Tekan tombol untuk mulai.</p>
      <div class=\"controls\"><button id=\"spin\" type=\"button\">Pilih nama acak</button></div>
    </section>
    <footer>Node ini menerima trafik lewat HAProxy. Pemilihan nama tidak mengubah file, database, atau telemetry.</footer>
  </main>
  <script>
    (() => {{
      const names = {names};
      const list = document.querySelector('#names');
      const button = document.querySelector('#spin');
      const result = document.querySelector('#result');
      const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
      const rowHeight = 54;
      let selected = 0;
      const entries = [...names, ...names, ...names];
      entries.forEach((name, index) => {{
        const item = document.createElement('li');
        item.textContent = name;
        item.dataset.index = String(index);
        list.append(item);
      }});
      function paint(index) {{
        list.querySelectorAll('li').forEach((item) => item.classList.toggle('selected', Number(item.dataset.index) === index));
      }}
      paint(selected);
      button.addEventListener('click', () => {{
        if (button.disabled) return;
        button.disabled = true;
        result.textContent = 'Memilih operator…';
        const picked = Math.floor(Math.random() * names.length);
        const target = names.length * 2 + picked;
        const distance = (target - selected) * rowHeight;
        list.style.transition = reduceMotion ? 'none' : 'transform 1450ms cubic-bezier(.15,.85,.25,1)';
        requestAnimationFrame(() => {{ list.style.transform = `translateY(-${{distance}}px)`; }});
        window.setTimeout(() => {{
          selected = picked;
          list.style.transition = 'none';
          list.style.transform = 'translateY(0)';
          paint(selected);
          result.innerHTML = `Operator demo: <strong>${{names[selected]}}</strong>`;
          button.disabled = false;
        }}, reduceMotion ? 20 : 1500);
      }});
    }})();
  </script>
</body>
</html>"""


def normalized_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return "unknown"


def is_sensitive(path):
    parts = [part.lower() for part in Path(path).parts]
    return any(
        part in SENSITIVE_NAMES or part.startswith(".env.") or part.endswith(tuple(SENSITIVE_SUFFIXES))
        for part in parts
    )


class Handler(BaseHTTPRequestHandler):
    def client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        return normalized_ip(forwarded or self.client_address[0])

    def record_access(self, path, action, severity, status, old_hash=None, new_hash=None):
        payload = {
            "host_id": HOST_ID,
            "type": "alert" if severity != "safe" or action == "denied" else "access",
            "actor": self.client_ip(),
            "action": action,
            "path": path[:2048],
            "severity": severity,
            "hash_old": old_hash,
            "hash_new": new_hash,
            "status": status,
        }
        request = urllib.request.Request(
            COLLECTOR_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=0.5):
                pass
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

    def do_GET(self):
        request_path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        if request_path == "/healthz":
            return self.respond(200, b"ok\n", "text/plain; charset=utf-8")

        if request_path == "/":
            body = landing_page().encode("utf-8")
            self.record_access("index.html", "read", "safe", "allowed", None, None)
            return self.respond(200, body, "text/html; charset=utf-8")
        elif request_path.startswith("/files/"):
            relative_path = unquote(request_path[len("/files/"):])
            target = (DATA_ROOT / relative_path).resolve()
        else:
            relative_path = request_path.lstrip("/") or "index.txt"
            target = None

        severity = "safe"
        if target is not None:
            try:
                target.relative_to(DATA_ROOT)
            except ValueError:
                severity = "suspicious"
                self.record_access(relative_path, "denied", severity, "blocked")
                return self.respond(403, b"forbidden\n", "text/plain; charset=utf-8")

        if target is not None and relative_path not in PUBLIC_FILES:
            self.record_access(relative_path, "denied", "suspicious", "blocked")
            return self.respond(403, b"forbidden\n", "text/plain; charset=utf-8")

        if is_sensitive(relative_path):
            self.record_access(relative_path, "denied", "suspicious", "blocked")
            return self.respond(403, b"forbidden\n", "text/plain; charset=utf-8")

        if target is None or not target.is_file():
            self.record_access(relative_path, "read", severity, "not_found")
            return self.respond(404, b"not found\n", "text/plain; charset=utf-8")

        try:
            digest = hashlib.sha256()
            content = bytearray()
            with target.open("rb") as stream:
                for chunk in iter(lambda: stream.read(64 * 1024), b""):
                    digest.update(chunk)
                    if len(content) < 1024 * 1024:
                        content.extend(chunk[:1024 * 1024 - len(content)])
        except (PermissionError, OSError):
            self.record_access(relative_path, "denied", "suspicious", "blocked")
            return self.respond(403, b"forbidden\n", "text/plain; charset=utf-8")

        digest = digest.hexdigest()
        action = "download" if query.get("download") == ["1"] else "read"
        body = f"DEFNETT lab response from {HOST_ID}\n".encode() + bytes(content) if relative_path == "index.txt" else bytes(content)
        self.record_access(relative_path, action, severity, "allowed", digest, digest)
        self.respond(
            200,
            body,
            "text/plain; charset=utf-8",
            Path(relative_path).name if action == "download" else None,
        )

    def do_POST(self):
        self.record_access(urlsplit(self.path).path, "modify", "suspicious", "blocked")
        self.respond(405, b"method not allowed\n", "text/plain; charset=utf-8")

    def do_PUT(self):
        self.record_access(urlsplit(self.path).path, "modify", "suspicious", "blocked")
        self.respond(405, b"method not allowed\n", "text/plain; charset=utf-8")

    def do_DELETE(self):
        self.record_access(urlsplit(self.path).path, "delete", "suspicious", "blocked")
        self.respond(405, b"method not allowed\n", "text/plain; charset=utf-8")

    def respond(self, status, body, content_type, download_name=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-DEFNETT-Host", HOST_ID)
        if download_name:
            safe_name = "".join(char for char in download_name if char.isalnum() or char in "._-")[:128] or "file"
            self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        print(f"{HOST_ID} {self.address_string()} {format_string % args}", flush=True)


if __name__ == "__main__":
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text(f"Sample content on {HOST_ID}\n", encoding="utf-8")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
