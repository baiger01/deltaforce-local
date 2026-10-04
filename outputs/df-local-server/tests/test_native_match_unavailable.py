"""Unavailable local matching must reply without creating matching state."""

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from dfserver.core import Backend
from dfserver.gcp_control import AuthRequest
from dfserver.gcp_crypto import encrypt_body
from dfserver.gcp_data import decode_data_frame, encode_data_frame
from dfserver.gcp_framing import Frame, StreamDecoder
from dfserver.handshake_diagnostic import _candidate_codec, inspect_exchange


ROOT = Path(__file__).resolve().parent.parent


def database_dump(backend):
    with backend.connection() as connection:
        return tuple(connection.iterdump())


class NativeMatchUnavailableWireTests(unittest.TestCase):
    def exercise_route(self, *, registered):
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', ROOT / 'definitions.json')
            token = backend.register('unavailable-match-wire', 'separate-test-password')['session']
            if registered:
                backend.register_game_nick(token, 'MatchWire')
            identity = backend.native_identity(token)
            expected = {'token': token, 'native_id': identity['native_id'],
                        'username': identity['username'], 'game_nick': identity['game_nick'],
                        'game_registered': registered}
            codec, decoder, pending = _candidate_codec(), StreamDecoder(), []
            client, server = socket.socketpair()
            key = hashlib.md5(b'\x12').digest()
            results, failures, progress_output = [], [], io.StringIO()

            def serve():
                try:
                    with redirect_stdout(progress_output):
                        results.append(inspect_exchange(
                            server, timeout=2, diagnostic_exponent_one=True,
                            expected_identity=expected, response_probe=True, ready_probe=True,
                            auth_identity_probe=True, business_login_probe=True,
                            business_bootstrap_probe=True, continuation_seconds=30,
                            backend=backend, local_session=token))
                except Exception as error:
                    failures.append(error)
                finally:
                    server.close()

            def receive():
                while not pending:
                    try:
                        data = client.recv(4096)
                    except socket.timeout:
                        self.fail('Authenticated matching request received no response')
                    except OSError:
                        if failures:
                            raise failures[0]
                        raise
                    self.assertTrue(data, 'Server closed before the expected response')
                    pending.extend(decoder.feed(data))
                return pending.pop(0)

            def send(name, fields, sequence):
                body = sequence.to_bytes(4, 'big') + codec.encode(name, fields, sequence=sequence)
                client.sendall(encode_data_frame(
                    (body,), key, direction='client_to_server',
                    header_word4=12, header_word9=sequence + 2).encode())

            def reply(name, sequence, fields=None):
                frame = receive()
                self.assertEqual(frame.command, 0x4013)
                messages = decode_data_frame(frame, key, direction='server_to_client',
                                             compression_method=1).messages
                self.assertEqual(len(messages), 1)
                response = codec.decode(messages[0])
                self.assertEqual((response.name, response.sequence), (name, sequence))
                if name == 'CSRoomMatchStartAllocRes':
                    self.assertEqual(response.service, 'matchgate')
                if fields is None:
                    self.assertEqual(response.fields['result'], 0)
                else:
                    self.assertEqual(response.fields, fields)

            worker = threading.Thread(target=serve)
            try:
                client.settimeout(2)
                worker.start()
                client.sendall(Frame(11, 12, 0x1001, 0, 1,
                    b'\x03\x00\x01\x12' + bytes(64) + b'\x03', b'').encode())
                self.assertEqual(receive().command, 0x1002)
                auth = AuthRequest(0x1000, b'QQ', token.encode(), b'')
                client.sendall(Frame(11, 12, 0x2001, 0, 2, b'',
                                     encrypt_body(auth.encode(), key)).encode())
                self.assertEqual(receive().command, 0x2002)
                self.assertEqual(receive().command, 0x6002)
                if registered:
                    send('CSAccountLoginReq', {}, 1)
                    reply('CSAccountLoginRes', 1)
                    send('CSStateGetInfoReq', {}, 2)
                    reply('CSStateGetInfoRes', 2)
                send('CSFriendRecommendReq', {}, 30)
                reply('CSFriendRecommendRes', 30, {'result': 0})
                before = database_dump(backend)
                for sequence in (41, 42, 42, 99):
                    send('CSRoomMatchStartAllocReq', {
                        'mode_infos': [], 'is_add_member': False, 'is_ranked_match': False}, sequence)
                    reply('CSRoomMatchStartAllocRes', sequence, {'result': 139005})
                client.shutdown(socket.SHUT_WR)
                worker.join(3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(failures, [])
                self.assertEqual(database_dump(backend), before)
                backend = Backend(backend.database, ROOT / 'definitions.json')
                self.assertEqual(database_dump(backend), before)
                route = 'bounded_business_continuation' if registered else 'registration_continuation'
                entries = results[0][route]
                match_entries = [entry for entry in entries
                                 if entry.get('request_name') == 'CSRoomMatchStartAllocReq']
                self.assertEqual(len(match_entries), 4)
                for entry in match_entries:
                    self.assertTrue(entry['response_sent'])
                    self.assertNotIn('request_not_answered', entry)
                self.assertNotIn(token, str(results))
                self.assertNotIn(token, progress_output.getvalue())
                self.assertEqual(pending, [])
                self.assertEqual(client.recv(4096), b'')
                decoder.finish()
            finally:
                client.close()
                server.close()
                worker.join(3)

    def test_normal_login_repeated_matching_requests_reply_without_state_changes(self):
        self.exercise_route(registered=True)

    def test_registration_continuation_repeated_matching_requests_reply_without_state_changes(self):
        self.exercise_route(registered=False)


class NativeMatchUnavailableFieldsTests(unittest.TestCase):
    def test_unavailable_reply_requires_session_and_preserves_every_table(self):
        from dfserver import native_match_unavailable
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', ROOT / 'definitions.json')
            token = backend.register('unavailable-match-fields', 'separate-test-password')['session']
            codec = _candidate_codec()
            request = codec.decode(codec.encode('CSRoomMatchStartAllocReq', {}, sequence=17))
            before = database_dump(backend)
            for _ in range(3):
                self.assertEqual(native_match_unavailable.response_fields(request, backend, token),
                                 {'result': 139005})
            self.assertEqual(native_match_unavailable.response_fields(request, backend, 'missing-session'),
                             {'result': 10010})
            self.assertEqual(database_dump(backend), before)
            unrelated = codec.decode(codec.encode('CSMatchGateIsRankEnableReq', {}, sequence=18))
            self.assertIsNone(native_match_unavailable.response_fields(unrelated, backend, token))
            self.assertEqual(database_dump(backend), before)

    def test_metadata_matches_original_error_and_response_codec(self):
        evidence = json.loads((ROOT / 'protocol/match_unavailable_consumer_evidence.json').read_text(
            encoding='utf-8'))
        errors = json.loads((ROOT / 'protocol/client_error_catalog.json').read_text(encoding='utf-8'))
        self.assertEqual(errors['source_sha256'], evidence['error_source']['sha256'])
        self.assertEqual(errors['source_entry'], evidence['error_source']['entry'])
        self.assertEqual(errors['rows'][evidence['error_name']]['code'], 139005)
        self.assertEqual(errors['rows'][evidence['error_name']]['instruction'],
                         evidence['error_source']['instruction'])
        codecs = json.loads((ROOT / 'protocol/generated_codec_fields.json').read_text(encoding='utf-8'))
        response = next(row for row in codecs['messages'] if row['name'] == evidence['response'])
        self.assertEqual(response['source_sha256'], evidence['codec_source']['sha256'])
        self.assertEqual(response['encode_function_id'], evidence['codec_source']['encode_function'])
        self.assertEqual(response['decode_function_id'], evidence['codec_source']['decode_function'])
        self.assertEqual(evidence['supported_local_response'], {'result': 139005})


if __name__ == '__main__':
    unittest.main()
