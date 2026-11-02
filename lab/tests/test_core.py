"""Pengujian inti DEFNETT. Jalankan dari root repo: python3 -m unittest discover -s lab/tests"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

WORK = tempfile.mkdtemp()
os.environ.update(
    DB_PATH=f"{WORK}/evidence/events.sqlite3",
    LAB_API_TOKEN="uji-token",
    ENABLE_LAB_AUTOREPAIR="false",
    TRAFFIC_PROBE_ENABLED="false",
    HOST_ID="server-a",
    WATCH_ROOT=WORK,
    STATE_PATH=f"{WORK}/baseline.json",
    COLLECTOR_URL="http://127.0.0.1:1/v1/events",
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agent  # noqa: E402
import collector  # noqa: E402


def key_event(new_hash="b" * 64):
    return {
        "host_id": "server-a", "source": "lab-fim-agent", "event_type": "file_modified",
        "path": "etc/kunci1.dat", "old_hash": "a" * 64, "new_hash": new_hash,
        "timestamp": "2026-11-02T00:00:00+00:00", "detect_seconds": 1.5,
    }


class LoginParsing(unittest.TestCase):
    prefix = "2026-11-02T06:58:39+00:00 server-a sshd-session[37473]: "

    def test_key_login_is_trusted(self):
        line = self.prefix + "Accepted publickey for malas from 192.168.56.1 port 63247 ssh2"
        self.assertIsNone(agent.parse_auth_line(line))

    def test_password_login_reports_port_22(self):
        line = self.prefix + "Accepted password for malas from 192.168.56.7 port 5000 ssh2"
        self.assertEqual(agent.parse_auth_line(line),
                         {"port": 22, "actor": "192.168.56.7", "user": "malas", "success": True})

    def test_failed_login(self):
        line = self.prefix + "Failed password for invalid user admin from 10.0.0.9 port 1 ssh2"
        self.assertFalse(agent.parse_auth_line(line)["success"])

    def web(self, request, status):
        return f'192.168.56.10 - - [02/Nov/2026:07:07:36 +0000] "{request} HTTP/1.1" {status} 202 "-" "x" "192.168.56.1"'

    def test_page_views_are_ignored(self):
        self.assertIsNone(agent.parse_web_line(self.web("GET /?p=1", 200)))

    def test_web_login(self):
        result = agent.parse_web_line(self.web("POST /wp-login.php", 302))
        self.assertEqual((result["port"], result["actor"], result["success"]), (80, "192.168.56.1", True))


class LogFollowing(unittest.TestCase):
    def test_partial_lines_and_rotation(self):
        path = f"{WORK}/ikut.log"
        Path(path).write_text("lama\n")
        follower = agent.LogFollower(path)
        self.assertEqual(follower.read_lines(), [])
        with open(path, "a") as stream:
            stream.write("satu\ndu")
        self.assertEqual(follower.read_lines(), ["satu"])
        with open(path, "a") as stream:
            stream.write("a\n")
        self.assertEqual(follower.read_lines(), ["dua"])
        os.rename(path, path + ".1")
        Path(path).write_text("baru\n")
        self.assertEqual(follower.read_lines(), ["baru"])


class Evidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        collector.initialize()

    def corrupt(self, statement, *values):
        with sqlite3.connect(os.environ["DB_PATH"]) as connection:
            connection.execute(statement, values)

    def test_chain_detects_tampering(self):
        collector.store_event(key_event("c" * 64))
        collector.store_event(key_event("d" * 64))
        self.assertEqual(collector.verify_evidence()["status"], "ok")
        original = "etc/kunci1.dat"
        self.corrupt("UPDATE events SET path = 'dipalsukan' WHERE rowid = 1")
        result = collector.verify_evidence()
        self.assertEqual((result["status"], result["reason"]), ("broken", "stored_field_mismatch"))
        self.corrupt("UPDATE events SET path = ? WHERE rowid = 1", original)
        self.assertEqual(collector.verify_evidence()["status"], "ok")

    def test_concurrent_events_keep_one_chain(self):
        threads = [threading.Thread(target=collector.store_event, args=(key_event(f"{i:064d}"),)) for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(collector.verify_evidence()["status"], "ok")


class Metrics(unittest.TestCase):
    def test_times_come_from_recorded_stages(self):
        run = {"host_id": "server-a", "detect_seconds": 2.0, "steps": [
            {"stage": "DETECTED", "timestamp": "2026-11-02T00:00:00+00:00"},
            {"stage": "ISOLATED", "timestamp": "2026-11-02T00:00:01+00:00"},
            {"stage": "REPAIRED", "timestamp": "2026-11-02T00:00:19+00:00"},
        ]}
        metrics = collector.run_metrics(run)
        self.assertEqual((metrics["detect"], metrics["isolate"], metrics["recover"]), (2.0, 1.0, 19.0))


class ApiAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        collector.initialize()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), collector.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def post(self, path, headers):
        request = urllib.request.Request(self.base + path, data=json.dumps({"host_id": "server-a"}).encode(),
                                         headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    def test_agent_endpoints_require_token(self):
        self.assertEqual(self.post("/v1/agent/heartbeat", {}), 401)
        self.assertEqual(self.post("/v1/agent/heartbeat", {"Authorization": "Bearer salah"}), 401)
        self.assertEqual(self.post("/v1/agent/heartbeat", {"Authorization": "Bearer uji-token"}), 202)


if __name__ == "__main__":
    unittest.main()
