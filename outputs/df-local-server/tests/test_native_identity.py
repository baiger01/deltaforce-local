from pathlib import Path
import struct
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dfserver.core import Backend, DomainError
from dfserver.http_api import create_server
from dfserver.native_identity import HEADER, CONTENT_TYPE
from dfserver.protobuf_codec import ProtobufCodec

ROOT = Path(__file__).resolve().parent.parent


class NativeIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "save.sqlite3"
        self.backend = Backend(self.database, ROOT / "definitions.json")

    def test_identity_is_stable_across_sessions_and_backend_restart(self):
        one = self.backend.register("本地玩家", "native-local-password")
        before = self.backend.dispatch(one["session"], "hall.get")
        identity = self.backend.native_identity(one["session"])
        self.assertGreater(identity["native_id"], 0)
        self.backend.logout(one["session"])
        self.backend = Backend(self.database, ROOT / "definitions.json")
        two = self.backend.login("本地玩家", "native-local-password")
        self.assertEqual(self.backend.native_identity(two["session"])["native_id"], identity["native_id"])
        self.assertEqual(self.backend.dispatch(two["session"], "hall.get"), before)
        other = self.backend.register("other", "native-other-password")
        self.assertNotEqual(self.backend.native_identity(other["session"])["native_id"], identity["native_id"])

    def test_invalid_expired_and_revoked_sessions_cannot_resolve_identity(self):
        one = self.backend.register("native", "native-local-password")
        for token in ("bad-session",):
            with self.assertRaises(DomainError) as caught:
                self.backend.native_identity(token)
            self.assertEqual(caught.exception.code, "UNAUTHORIZED")
        self.backend.logout(one["session"])
        with self.assertRaises(DomainError):
            self.backend.native_identity(one["session"])
        two = self.backend.login("native", "native-local-password")
        with self.backend.connection() as connection:
            connection.execute("UPDATE sessions SET expires=0")
            connection.commit()
        with self.assertRaises(DomainError):
            self.backend.native_identity(two["session"])
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM native_identities").fetchone()[0], 0)

    def test_http_binary_contract_is_authenticated_and_utf8_length_is_exact(self):
        registered = self.backend.register("独立玩家", "native-local-password")
        server = create_server(self.backend, ProtobufCodec(ROOT / "protocol/recovered_telemetry.pb"), port=0)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval":.01}, daemon=True)
        worker.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/api/local/native-identity"
            for token in (None, "wrong-session"):
                headers = {"Content-Type":"application/json"}
                if token: headers["Authorization"] = "Bearer " + token
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(url, data=b"{}", headers=headers), timeout=3)
                self.assertEqual(caught.exception.code, 401)
                caught.exception.close()
            headers = {"Content-Type":"application/json", "Authorization":"Bearer " + registered["session"]}
            with urlopen(Request(url, data=b"{}", headers=headers), timeout=3) as response:
                self.assertEqual(response.headers["Content-Type"], CONTENT_TYPE)
                payload = response.read()
            magic, version, size, native_id, expires, count = HEADER.unpack_from(payload)
            self.assertEqual((magic, version, size), (b"DFID", 1, 24))
            self.assertEqual(len(payload), size + count)
            self.assertEqual(payload[size:].decode("utf-8"), "独立玩家")
            self.assertEqual(native_id, self.backend.native_identity(registered["session"])["native_id"])
            self.assertEqual(expires, registered["expires"])
            self.assertNotIn(registered["session"].encode(), payload)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
