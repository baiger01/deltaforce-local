"""Exercise the built local provider against bounded identity transport faults."""
import ctypes
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import struct
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent


class IdentityRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stage = ROOT / "work/sdk-local-provider-stage"
        record = json.loads((stage / "build-record.json").read_text(encoding="utf-8"))
        dll = stage / "rail_api64.dll"
        assert hashlib.sha256(dll.read_bytes()).hexdigest() == record["provider_sha256"]
        cls.logs = tempfile.TemporaryDirectory(prefix="df-identity-retry-")
        os.environ["DF_SDK_OBSERVER_LOG"] = str(Path(cls.logs.name) / "events.jsonl")
        cls.provider = ctypes.CDLL(str(dll))
        cls.provider.DFLocalAuthorize.argtypes = [ctypes.c_uint16, ctypes.c_char_p]
        cls.provider.DFLocalAuthorize.restype = ctypes.c_bool
        cls.provider.DFLocalRefresh.argtypes = []
        cls.provider.DFLocalRefresh.restype = ctypes.c_bool

    @classmethod
    def tearDownClass(cls):
        cls.logs.cleanup()

    def setUp(self):
        fixture = self
        self.token = secrets.token_urlsafe(32)
        self.mode = "ok"
        self.requests = 0
        self.native_id = 1234567
        self.expires = int(time.time()) + 600

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path != "/api/local/native-identity" or self.headers.get("Authorization") != "Bearer " + fixture.token:
                    status, payload = 401, b""
                else:
                    fixture.requests += 1
                    mode, count = fixture.mode, fixture.requests
                    if mode == "timeout_then_ok" and count == 1:
                        time.sleep(7)
                    if mode == "drop_then_ok" and count == 1:
                        self.connection.close()
                        return
                    status = 503 if mode == "unavailable" or (mode == "busy_then_ok" and count == 1) else 401 if mode == "revoked" else 200
                    name = b"local-retry-test"
                    identity = fixture.native_id + (mode == "different_identity")
                    expiry = int(time.time()) - 1 if mode == "expired" else fixture.expires
                    payload = struct.pack("<4sHHQII", b"DFID", 1, 24, identity, expiry, len(name)) + name
                    if mode == "malformed":
                        payload = b"DFID"
                    if status != 200:
                        payload = b""
                self.send_response(status)
                self.send_header("Content-Type", "application/vnd.df-local.identity")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except (ConnectionResetError, BrokenPipeError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.assertTrue(self.provider.DFLocalAuthorize(self.server.server_port, self.token.encode("ascii")))
        self.requests = 0

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def test_temporary_server_failure_recovers(self):
        self.mode = "busy_then_ok"
        self.assertTrue(self.provider.DFLocalRefresh())
        self.assertGreaterEqual(self.requests, 2)
        self.assertLessEqual(self.requests, 3)

    def test_receive_timeout_recovers(self):
        self.mode = "timeout_then_ok"
        self.assertTrue(self.provider.DFLocalRefresh())
        self.assertGreaterEqual(self.requests, 2)

    def test_closed_connection_recovers(self):
        self.mode = "drop_then_ok"
        self.assertTrue(self.provider.DFLocalRefresh())

    def test_unavailability_is_bounded(self):
        self.mode = "unavailable"
        self.assertFalse(self.provider.DFLocalRefresh())
        self.assertEqual(self.requests, 3)

    def test_revocation_is_not_retried(self):
        self.mode = "revoked"
        self.assertFalse(self.provider.DFLocalRefresh())
        self.assertEqual(self.requests, 1)

    def test_invalid_identity_is_not_retried(self):
        for mode in ("malformed", "expired", "different_identity"):
            with self.subTest(mode=mode):
                self.mode, self.requests = "ok", 0
                self.assertTrue(self.provider.DFLocalAuthorize(self.server.server_port, self.token.encode("ascii")))
                self.mode, self.requests = mode, 0
                self.assertFalse(self.provider.DFLocalRefresh())
                self.assertEqual(self.requests, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
