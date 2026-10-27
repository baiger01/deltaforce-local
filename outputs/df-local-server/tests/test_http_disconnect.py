import io
import json
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from dfserver.core import Backend
from dfserver.http_api import handler_factory


ROOT = Path(__file__).resolve().parent.parent
DISCONNECTS = (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)


class FailingWriter:
    def __init__(self, fail_at, error):
        self.fail_at = fail_at
        self.error = error
        self.attempts = []

    def write(self, data):
        self.attempts.append(data)
        if len(self.attempts) == self.fail_at:
            raise self.error
        return len(data)


class HttpDisconnectTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.backend = Backend(Path(temporary.name) / "save.sqlite3", ROOT / "definitions.json")

    def handler(self, path, body, writer, token=None):
        handler_type = handler_factory(self.backend, None, None)
        handler = handler_type.__new__(handler_type)
        raw = json.dumps(body).encode()
        handler.path = path
        handler.command = "POST"
        handler.request_version = "HTTP/1.1"
        handler.requestline = "POST " + path + " HTTP/1.1"
        handler.server = SimpleNamespace(server_port=8877)
        handler.connection = SimpleNamespace(settimeout=lambda timeout: None)
        handler.headers = Message()
        handler.headers["Host"] = "127.0.0.1:8877"
        handler.headers["Content-Length"] = str(len(raw))
        if token is not None:
            handler.headers["Authorization"] = "Bearer " + token
        handler.rfile = io.BytesIO(raw)
        handler.wfile = writer
        handler.close_connection = False
        handler.log_message = Mock()
        handler.log_error = Mock()
        return handler

    def assert_single_response(self, handler, writer, fail_at, status, response):
        self.assertEqual([call.args[0] for call in response.call_args_list], [status])
        self.assertEqual(len(writer.attempts), fail_at)
        self.assertTrue(handler.close_connection)
        handler.log_error.assert_not_called()
        self.assertNotIn(b"rolled back", b"".join(writer.attempts))

    def test_disconnected_headers_or_body_do_not_replay_committed_mutation(self):
        for error_type in DISCONNECTS:
            for fail_at in (1, 2):
                with self.subTest(error=error_type.__name__, fail_at=fail_at):
                    registered = self.backend.register(
                        error_type.__name__ + str(fail_at), "disconnect-test-password")
                    token = registered["session"]
                    request_id = "disconnect-" + error_type.__name__ + str(fail_at)
                    writer = FailingWriter(fail_at, error_type("client disconnected"))
                    handler = self.handler("/api/local/dispatch", {
                        "operation": "quests.accept", "payload": {"quest_id": "local_supply"},
                        "request_id": request_id, "expected_revision": 0}, writer, token)
                    with patch.object(self.backend, "dispatch", wraps=self.backend.dispatch) as dispatch:
                        with patch.object(handler, "send_response", wraps=handler.send_response) as response:
                            handler.do_POST()
                        dispatch.assert_called_once()
                    self.assertEqual(self.backend.dispatch(token, "hall.get")["revision"], 1)
                    with self.backend.connection() as connection:
                        self.assertEqual(connection.execute(
                            "SELECT COUNT(*) FROM requests WHERE request_id=?",
                            (request_id,)).fetchone()[0], 1)
                    self.assert_single_response(handler, writer, fail_at, 200, response)

    def test_native_identity_disconnect_does_not_send_internal_error(self):
        registered = self.backend.register("native-disconnect", "disconnect-test-password")
        for error_type in DISCONNECTS:
            for fail_at in (1, 2):
                with self.subTest(error=error_type.__name__, fail_at=fail_at):
                    writer = FailingWriter(fail_at, error_type("client disconnected"))
                    handler = self.handler("/api/local/native-identity", {}, writer, registered["session"])
                    with patch.object(self.backend, "native_identity", wraps=self.backend.native_identity) as identity:
                        with patch.object(handler, "send_response", wraps=handler.send_response) as response:
                            handler.do_POST()
                        identity.assert_called_once()
                    self.assert_single_response(handler, writer, fail_at, 200, response)

    def test_disconnect_during_domain_error_response_is_quiet(self):
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                writer = FailingWriter(fail_at, BrokenPipeError("client disconnected"))
                handler = self.handler("/api/local/dispatch", {"operation": "hall.get"}, writer)
                with patch.object(handler, "send_response", wraps=handler.send_response) as response:
                    handler.do_POST()
                self.assertEqual([call.args[0] for call in response.call_args_list], [401])
                self.assertEqual(len(writer.attempts), fail_at)
                self.assertTrue(handler.close_connection)
                handler.log_error.assert_not_called()

    def test_ordinary_send_oserror_is_not_suppressed(self):
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                error = OSError("unrelated output failure")
                writer = FailingWriter(fail_at, error)
                handler = self.handler("/unused", {}, writer)
                with self.assertRaises(OSError) as caught:
                    handler._bytes(200, b"body", "application/octet-stream")
                self.assertIs(caught.exception, error)
                self.assertEqual(len(writer.attempts), fail_at)
                self.assertTrue(handler.close_connection)

    def test_backend_oserrors_still_report_internal_error(self):
        registered = self.backend.register("business-failure", "disconnect-test-password")
        for error_type in (OSError,) + DISCONNECTS:
            with self.subTest(error=error_type.__name__):
                writer = FailingWriter(0, None)
                handler = self.handler("/api/local/dispatch", {"operation": "hall.get"},
                                       writer, registered["session"])
                with patch.object(self.backend, "dispatch", side_effect=error_type("business failure")) as dispatch:
                    with patch.object(handler, "send_response", wraps=handler.send_response) as response:
                        handler.do_POST()
                    dispatch.assert_called_once()
                self.assertEqual([call.args[0] for call in response.call_args_list], [500])
                self.assertEqual(json.loads(writer.attempts[-1])["error"]["code"], "INTERNAL_ERROR")
                handler.log_error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
