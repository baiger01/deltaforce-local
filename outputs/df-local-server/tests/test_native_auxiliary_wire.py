"""Run authenticated one-way/query continuations over actual local sockets."""

import base64
import hashlib
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
TELEMETRY = b'wire-test-event'


class NativeAuxiliaryWireTests(unittest.TestCase):
    def exercise_route(self, *, registered):
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', ROOT / 'definitions.json')
            token = backend.register('auxiliary-wire', 'separate-test-password')['session']
            if registered:
                backend.register_game_nick(token, 'AuxWire')
            identity = backend.native_identity(token)
            expected = {'token': token, 'native_id': identity['native_id'],
                        'username': identity['username'],
                        'game_nick': identity['game_nick'], 'game_registered': registered}
            codec = _candidate_codec()
            client, server = socket.socketpair()
            results, failures = [], []

            def serve():
                try:
                    results.append(inspect_exchange(
                        server, timeout=3, diagnostic_exponent_one=True,
                        expected_identity=expected, response_probe=True, ready_probe=True,
                        auth_identity_probe=True, business_login_probe=True,
                        business_bootstrap_probe=True, continuation_seconds=30,
                        backend=backend, local_session=token))
                except Exception as error:
                    failures.append(error)
                finally:
                    server.close()

            worker = threading.Thread(target=serve)
            decoder, pending = StreamDecoder(), []
            key = hashlib.md5(b'\x12').digest()

            def receive():
                while not pending:
                    try:
                        data = client.recv(4096)
                    except OSError:
                        if failures:
                            raise failures[0]
                        raise
                    if not data and failures:
                        raise failures[0]
                    self.assertTrue(data, 'Server closed before the expected reply')
                    pending.extend(decoder.feed(data))
                return pending.pop(0)

            def send(name, fields, sequence):
                message = sequence.to_bytes(4, 'big') + codec.encode(name, fields, sequence=sequence)
                client.sendall(encode_data_frame(
                    (message,), key, direction='client_to_server',
                    header_word4=12, header_word9=sequence + 2).encode())

            def reply(name, sequence):
                frame = receive()
                self.assertEqual(frame.command, 0x4013)
                messages = decode_data_frame(frame, key, direction='server_to_client',
                                             compression_method=1).messages
                self.assertEqual(len(messages), 1)
                response = codec.decode(messages[0])
                self.assertEqual((response.name, response.sequence), (name, sequence))
                self.assertEqual(response.fields['result'], 0)
                return response.fields

            try:
                client.settimeout(3)
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

                # The first one-way also starts the authenticated followup route.
                send('CSShopAutoRetroRewardReq', {}, 31)
                send('CSTlogAgentTglogReq', {'entry_array': [{
                    'name': 'NativeWireEvent',
                    'pbtlog': base64.b64encode(TELEMETRY).decode('ascii'),
                    'no_autofill': True}]}, 32)
                send('CSFriendRecommendReq', {}, 33)
                self.assertEqual(reply('CSFriendRecommendRes', 33), {'result': 0})
                send('CSPlayerInfoAddButtonHasBeenClickedReq',
                     {'situation_id_list': ['176_42']}, 34)
                self.assertEqual(reply('CSPlayerInfoAddButtonHasBeenClickedRes', 34), {
                    'result': 0, 'button_status_list': [
                        {'situation_id': '176_42', 'has_been_clicked': False}]})
                client.shutdown(socket.SHUT_WR)
                worker.join(4)
                self.assertFalse(worker.is_alive())
                self.assertEqual(failures, [])
                self.assertEqual(len(results), 1)
                # Inspect every remaining frame, so an invented/delayed Res fails.
                trailing = list(pending)
                while True:
                    data = client.recv(4096)
                    if not data:
                        break
                    trailing.extend(decoder.feed(data))
                self.assertEqual(trailing, [])
                decoder.finish()
                result = results[0]
                route_key = ('bounded_business_continuation' if registered
                             else 'registration_continuation')
                entries = result[route_key]
                self.assertEqual([entry['request_name'] for entry in entries], [
                    'CSShopAutoRetroRewardReq', 'CSTlogAgentTglogReq',
                    'CSFriendRecommendReq', 'CSPlayerInfoAddButtonHasBeenClickedReq'])
                for entry in entries:
                    self.assertNotIn('request_not_answered', entry)
                for entry in entries[:2]:
                    self.assertTrue(entry['local_auxiliary_one_way'])
                    self.assertFalse(entry['local_auxiliary_response_expected'])
                    self.assertNotIn('response_sent', entry)
                for entry in entries[2:]:
                    self.assertTrue(entry['response_sent'])
                if not registered:
                    self.assertEqual(result['business_login_probe_result'],
                                     'authenticated_followup_without_login')
                self.assertNotIn(token, str(result))
                with backend.connection() as connection:
                    receipts = list(connection.execute(
                        'SELECT entry_count,payload_bytes,occurrences FROM native_session_telemetry_receipts'))
                    self.assertEqual([tuple(row) for row in receipts], [(1, len(TELEMETRY), 1)])
                    self.assertEqual(connection.execute(
                        'SELECT COUNT(*) FROM native_lobby_shop_records').fetchone()[0], 0)
            finally:
                client.close()
                server.close()
                worker.join(4)

    def test_registration_authenticated_followup_consumes_one_way_and_answers_next_queries(self):
        self.exercise_route(registered=False)

    def test_normal_login_bounded_continuation_consumes_one_way_and_answers_next_queries(self):
        self.exercise_route(registered=True)


if __name__ == '__main__':
    unittest.main()
