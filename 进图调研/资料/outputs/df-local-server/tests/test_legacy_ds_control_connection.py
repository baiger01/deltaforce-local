from dataclasses import replace
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from dfserver.business_envelope import parse_business_envelope
from dfserver.core import Backend
from dfserver.game_server_probe import GameServerProbe
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import _candidate_local_match_join_probe
from dfserver.legacy_ds_control_connection import LegacyDSControlConnection, RELIABLE_RETRY_WINDOW
from dfserver.legacy_ds_control_fields import ControlMessage, decode_messages, encode_message, encode_string
from dfserver.legacy_ds_match_admission import LocalMatchAdmissions
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from dfserver.unreal_handshake_payload import decode_payload
from tests.test_legacy_ds_control_probe import COOKIE, PEER
from tests.test_legacy_ds_wire_codec import HELLO_BODIES

MAPS = {2201: {'level': 'Iris_Entry', 'game': '', 'redirect': ''}}


def decode_lobby_handoff(frame, key):
    # Source-confirmed fields only; unknown nested settlement fields are
    # deliberately skipped rather than filling an invented full descriptor.
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    definition = descriptor_pb2.FileDescriptorProto(name='local_ds_admission_test.proto')
    player = definition.message_type.add(name='MatchPlayer')
    for name, number, kind in (('player_id', 1, 4), ('team_id', 13, 4), ('ds_token', 24, 9)):
        player.field.add(name=name, number=number, type=kind, label=1)
    notice = definition.message_type.add(name='MatchJoin')
    for name, number, kind in (('room_id', 1, 4), ('map_id', 5, 13),
                               ('match_mode_id', 11, 13), ('secret_key', 19, 9)):
        notice.field.add(name=name, number=number, type=kind, label=1)
    notice.field.add(name='player', number=8, type=11, label=1, type_name='.MatchPlayer')
    pool = descriptor_pool.DescriptorPool()
    pool.Add(definition)
    message = message_factory.GetMessageClass(pool.FindMessageTypeByName('MatchJoin'))()
    envelope = parse_business_envelope(decode_data_frame(frame, key,
        direction='server_to_client', compression_method=1).messages[0])
    if envelope.header['name'] != 'CSPlayerJoinMatchNtf':
        raise AssertionError('Unexpected lobby handoff')
    message.ParseFromString(envelope.body)
    return message


def login_payload(ticket, **overrides):
    values = {'PlayerId': ticket.player_id, 'DSRoomId': ticket.room_id,
              'MapId': ticket.map_id, 'Cookie': ticket.cookie}
    values.update(overrides)
    url = '/Game/Maps/Login/Login' + ''.join('?' + k + '=' + str(v) for k, v in values.items())
    return b'\x05' + encode_string('0') + encode_string(url) + b'\x03' + encode_string('Local')


class NativeControlConnectionTests(unittest.TestCase):
    def setUp(self):
        self.clock = [0.0]
        self.admissions = LocalMatchAdmissions(clock=lambda: self.clock[0])
        self.ticket = self.admissions.issue(101, 201, 2201, 142201103, 88000000025)
        self.probe = LegacyDSControlConnection(admissions=self.admissions,
            welcome_maps=MAPS, expected_net_version=1077088301)
        self.probe.register_verified_echo(PEER, COOKIE)
        self.template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)

    def send(self, sequence, ack, channel_sequence=None, payload=b'', *, history=(1,), now=0.1):
        bunches = (() if channel_sequence is None else (
            replace(self.template.bunches[0], open=False, channel_sequence=channel_sequence,
                    payload=payload, payload_bits=len(payload)*8),))
        packet = replace(self.template, sequence=sequence, acknowledged_sequence=ack,
                         history=history, bunches=bunches)
        return self.raw(packet, now)

    def raw(self, packet, now=0.1):
        return self.probe.handle(b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), PEER, now)

    def decode(self, response):
        return decode_observed_application(response, max_packet_bytes=1024, received_by_server=False)

    def hello(self):
        return self.probe.handle(b'opaque!!' + HELLO_BODIES[0], PEER, 0.0)

    def login(self):
        self.hello()
        return self.send(1257, 216, 234, login_payload(self.ticket))

    def test_lobby_ticket_login_emits_evidenced_welcome_and_not_a_fake_spawn(self):
        event, response = self.login()
        packet = self.decode(response)
        self.assertEqual(event, 'control_login_welcome_prepared')
        self.assertEqual(packet.history, (3,))
        self.assertEqual(packet.bunches[0].channel_sequence, 218)
        self.assertEqual(decode_messages(packet.bunches[0].payload),
                         (ControlMessage(1, ('Iris_Entry', '', '')),))
        state = self.probe.control_peers[PEER]
        self.assertEqual(state.ticket.selected_hero_id, 88000000025)
        self.assertEqual(self.probe.summary()['login_authorized_peers'], 1)
        self.assertFalse(self.probe.summary()['player_spawn_implemented'])
        self.assertFalse(self.probe.summary()['native_connection_completed'])

    def test_literal_zero_and_empty_uid_cannot_replace_a_local_cookie(self):
        self.hello()
        payload = login_payload(self.ticket, Cookie='0'*32)
        event, response = self.send(1257, 216, 234, payload)
        self.assertEqual((event, response), ('control_login_or_order_rejected', None))
        self.assertIsNone(self.probe.control_peers[PEER].ticket)
        self.assertEqual(self.probe.peers[PEER].history, 2)
        self.assertEqual(self.probe.ticket_peers, {})

    def test_wrong_room_player_or_map_is_not_delivered(self):
        for fields in ({'DSRoomId': 202}, {'PlayerId': 102}, {'MapId': 2202}):
            with self.subTest(fields=fields):
                self.setUp()
                self.hello()
                _, response = self.send(1257, 216, 234, login_payload(self.ticket, **fields))
                self.assertIsNone(response)
                self.assertIsNone(self.probe.control_peers[PEER].ticket)
                self.assertEqual(self.probe.peers[PEER].history, 2)

    def test_expired_ticket_and_unmapped_map_have_no_welcome(self):
        self.hello()
        self.clock[0] = 121
        _, response = self.send(1257, 216, 234, login_payload(self.ticket))
        self.assertIsNone(response)
        self.setUp()
        self.hello()
        ticket = self.admissions.issue(101, 201, 2202, 142201103)
        _, response = self.send(1257, 216, 234, login_payload(ticket))
        self.assertIsNone(response)
        self.assertEqual(self.probe.ticket_peers, {})

    def test_login_retry_reuses_welcome_without_reauthorizing_or_advancing_channel(self):
        _, first = self.login()
        event, second = self.send(1258, 216, 234, login_payload(self.ticket))
        self.assertEqual(event, 'control_reliable_retry_consumed')
        first, second = self.decode(first), self.decode(second)
        self.assertEqual(first.bunches[0].payload, second.bunches[0].payload)
        self.assertEqual(first.bunches[0].channel_sequence, second.bunches[0].channel_sequence)
        self.assertEqual(second.sequence, first.sequence + 1)
        self.assertEqual(self.admissions.summary()['authorized_login_count'], 1)

    def test_ack_history_zero_retains_welcome_and_timer_keeps_stable_bunch(self):
        _, welcome = self.login()
        _, response = self.send(1258, 217, history=(0,), now=0.2)
        self.assertIsNone(response)  # No ACK-only ping-pong.
        retry = self.probe.poll(0.7)[0][2]
        welcome, retry = self.decode(welcome), self.decode(retry)
        self.assertEqual(retry.sequence, 218)
        self.assertEqual(retry.bunches[0].payload, welcome.bunches[0].payload)
        self.assertEqual(retry.bunches[0].channel_sequence, welcome.bunches[0].channel_sequence)
        # An unrelated nonzero history bit is not this Welcome's delivery ACK.
        self.send(1259, 218, history=(1 << 10,), now=0.8)
        self.assertIsNotNone(self.probe.control_peers[PEER].pending)
        retry2 = self.probe.poll(1.3)[0][2]
        self.assertEqual(self.decode(retry2).sequence, 219)
        # bit1 acknowledges the recorded retransmission in packet218.
        self.send(1260, 219, history=(2,), now=1.4)
        self.assertIsNone(self.probe.control_peers[PEER].pending)
        self.assertEqual(self.probe.poll(2), [])

    def test_netspeed_then_join_in_one_bunch_consumes_one_channel_sequence(self):
        self.login()
        event, response = self.send(1258, 217, 235, encode_message(4, 25000) + encode_message(9))
        self.assertEqual(event, 'control_join_ack_prepared')
        self.assertEqual(self.decode(response).bunches, ())
        self.assertEqual(self.probe.control_peers[PEER].expected_client_sequence, 236)
        self.assertEqual(self.probe.summary()['client_load_map_join_observed_count'], 1)

    def test_multiple_bunches_are_committed_atomically(self):
        self.login()
        first = replace(self.template.bunches[0], open=False, channel_sequence=235,
                        payload=encode_message(4, 25000), payload_bits=40)
        second = replace(first, channel_sequence=236, payload=encode_message(9), payload_bits=8)
        packet = replace(self.template, sequence=1258, acknowledged_sequence=217,
                         history=(1,), bunches=(first, second))
        event, response = self.raw(packet)
        self.assertEqual(event, 'control_join_ack_prepared')
        self.assertEqual(self.decode(response).history, (7,))
        self.setUp()
        self.login()
        second = replace(second, payload=b'\xfa', payload_bits=8)
        event, response = self.raw(replace(packet, bunches=(first, second)))
        self.assertEqual((event, response), ('control_login_or_order_rejected', None))
        state = self.probe.control_peers[PEER]
        self.assertIsNone(state.netspeed)
        self.assertEqual(state.expected_client_sequence, 235)
        self.assertEqual(self.probe.peers[PEER].history, 6)

    def test_login_and_join_cannot_precede_the_sent_welcome(self):
        self.hello()
        payload = login_payload(self.ticket)
        login = replace(self.template.bunches[0], open=False, channel_sequence=234,
                        payload=payload, payload_bits=len(payload)*8)
        premature_join = replace(login, channel_sequence=235,
            payload=encode_message(4, 25000)+encode_message(9), payload_bits=48)
        packet = replace(self.template, sequence=1257, acknowledged_sequence=216,
                         history=(1,), bunches=(login, premature_join))
        event, response = self.raw(packet)
        self.assertEqual((event, response), ('control_login_or_order_rejected', None))
        state = self.probe.control_peers[PEER]
        self.assertIsNone(state.ticket)
        self.assertIsNone(state.netspeed)
        self.assertFalse(state.client_join_observed)
        self.assertEqual(state.expected_client_sequence, 234)
        self.assertEqual(self.probe.ticket_peers, {})
        self.assertEqual(self.probe.peers[PEER].history, 2)
        # Rejected packet sequence advances; the reliable Login must retry in
        # a new packet. Welcome is then sent before the client's later Join.
        event, response = self.send(1258, 216, 234, payload)
        self.assertEqual(event, 'control_login_welcome_prepared')
        self.assertEqual(decode_messages(self.decode(response).bunches[0].payload),
                         (ControlMessage(1, ('Iris_Entry', '', '')),))

    def test_welcome_must_fit_the_explicit_native_packet_size(self):
        for spec in ({'level': 'Iris_Entry', 'game': None},
                     {'level': 'Iris_Entry', 'redirect': 'a'*257},
                     {'level': 'Iris_Entry', 'redirect': '\n'}):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                LegacyDSControlConnection(admissions=self.admissions,
                    welcome_maps={2201: spec}, expected_net_version=1077088301)
        with self.assertRaises(ValueError):
            LegacyDSControlConnection(admissions=self.admissions,
                welcome_maps={2201: {'level': 'Iris_Entry', 'game': 'a'*256,
                                    'redirect': 'b'*256}},
                expected_net_version=1077088301, max_packet_bytes=64)

    def test_join_before_netspeed_partial_and_conflicting_retry_are_rejected(self):
        for kind in ('join', 'partial', 'conflict'):
            with self.subTest(kind=kind):
                self.setUp()
                self.login()
                payload = encode_message(9) if kind == 'join' else encode_message(4, 25000)
                sequence = 234 if kind == 'conflict' else 235
                bunch = replace(self.template.bunches[0], open=False, channel_sequence=sequence,
                    partial=kind == 'partial', partial_initial=kind == 'partial',
                    partial_final=kind == 'partial', payload=payload, payload_bits=len(payload)*8)
                event, response = self.raw(replace(self.template, sequence=1258,
                    acknowledged_sequence=217, history=(1,), bunches=(bunch,)))
                self.assertIsNone(response)
                self.assertEqual(self.probe.summary()['client_load_map_join_observed_count'], 0)

    def test_ticket_binding_is_released_with_peer_cleanup(self):
        self.login()
        self.assertEqual(self.probe.ticket_peers[self.ticket.cookie], PEER)
        self.probe.forget_peer(PEER)
        self.assertEqual(self.probe.ticket_peers, {})
        self.assertEqual(self.probe.poll(10), [])

    def test_challenge_must_fit_even_when_a_short_welcome_would_fit(self):
        with self.assertRaises(ValueError):
            LegacyDSControlConnection(admissions=self.admissions,
                welcome_maps=MAPS, expected_net_version=1077088301, max_packet_bytes=42)

    def _send_netspeed_batches(self, count):
        payload = encode_message(4, 25000)
        for batch in range(count):
            bunches = tuple(replace(self.template.bunches[0], open=False,
                channel_sequence=(235 + batch*32 + i) & 1023,
                payload=payload, payload_bits=40) for i in range(32))
            packet = replace(self.template, sequence=1258 + batch,
                acknowledged_sequence=(self.probe.peers[PEER].out_sequence-1) & 16383,
                history=(1,), bunches=bunches)
            event, response = self.raw(packet)
            self.assertEqual(event, 'control_netspeed_ack_prepared')
            self.assertIsNotNone(response)
            self.assertEqual(self.probe.control_peers[PEER].expected_client_sequence,
                             (235 + (batch+1)*32) & 1023)

    def test_full_channel_sequence_wrap_is_new_even_with_identical_payloads(self):
        self.login()
        self._send_netspeed_batches(33)  # More than a full 1024-value circle.
        self.assertEqual(self.probe.control_peers[PEER].expected_client_sequence, 267)
        self.assertEqual(len(self.probe.control_peers[PEER].consumed), RELIABLE_RETRY_WINDOW)

    def test_retry_older_than_the_local_window_is_rejected(self):
        self.login()
        self._send_netspeed_batches(5)
        transport = self.probe.peers[PEER]
        event, response = self.send(1263, (transport.out_sequence-1) & 16383,
                                    235, encode_message(4, 25000))
        self.assertEqual((event, response), ('control_login_or_order_rejected', None))
        self.assertEqual(self.probe.control_peers[PEER].expected_client_sequence, 395)


class NativeControlUdpTests(unittest.TestCase):
    def test_socket_timeout_retransmits_challenge_without_client_activity(self):
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        with tempfile.TemporaryDirectory() as folder:
            with GameServerProbe(folder, handshake_probe=True, packet_ack_probe=True,
                    control_probe=True, expected_net_version=1077088301,
                    control_welcome_maps=MAPS, max_packets=16) as server:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    address = ('127.0.0.1', server.port)
                    client.sendto(b'opaque!!'+b'\x01'+bytes(23)+b'\x08', address)
                    challenge, _ = client.recvfrom(1500)
                    client.sendto(b'opaque!!'+challenge, address)
                    acknowledged, _ = client.recvfrom(1500)
                    cookie = decode_payload(acknowledged).cookie
                    server_seed = int.from_bytes(cookie[:2], 'little') & 16383
                    client_seed = int.from_bytes(cookie[2:4], 'little') & 16383
                    hello = replace(template, sequence=client_seed,
                        acknowledged_sequence=(server_seed-1)&16383, bunches=(
                            replace(template.bunches[0], channel_sequence=(client_seed+1)&1023),))
                    client.sendto(b'opaque!!'+encode_observed_application(hello,
                        max_packet_bytes=1024, received_by_server=True), address)
                    first, _ = client.recvfrom(1500)
                    retry, _ = client.recvfrom(1500)  # No client ACK or packet triggers this.
                    first = decode_observed_application(first, max_packet_bytes=1024,
                                                        received_by_server=False)
                    retry = decode_observed_application(retry, max_packet_bytes=1024,
                                                        received_by_server=False)
                    self.assertEqual(retry.sequence, (first.sequence+1)&16383)
                    self.assertEqual(retry.bunches[0].channel_sequence,
                                     first.bunches[0].channel_sequence)
                    self.assertEqual(retry.bunches[0].payload, first.bunches[0].payload)
            report = json.loads((Path(folder)/'report.json').read_text(encoding='utf-8'))
            self.assertGreaterEqual(report['native_control_datagrams_sent'], 2)
            self.assertGreaterEqual(report['handshake_probe']['events'][
                'control_timer_retransmit_prepared'], 1)

    def test_real_loopback_udp_hello_login_welcome_netspeed_join(self):
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        def encode(packet):
            return b'opaque!!' + encode_observed_application(packet,
                max_packet_bytes=1024, received_by_server=True)
        def decode(body):
            return decode_observed_application(body, max_packet_bytes=1024, received_by_server=False)
        with tempfile.TemporaryDirectory() as folder:
            with GameServerProbe(folder, handshake_probe=True, packet_ack_probe=True,
                    control_probe=True, expected_net_version=1077088301,
                    control_welcome_maps=MAPS, max_packets=32) as server:
                backend = Backend(Path(folder)/'save.sqlite3',
                    Path(__file__).resolve().parent.parent/'definitions.json')
                session = backend.register('local_ds_udp_test', 'test-only-password')['session']
                backend.set_native_selected_hero(session, 88000000025)
                backend.set_native_selected_hero_for_mode(session, 88000000047, 2)
                player_id = int(backend.native_identity(session)['native_id'])
                key = b'0123456789abcdef'
                mode = {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 142201103}
                with patch.dict('os.environ', {'DF_LOCAL_DS_MAP_ID': '2201'}):
                    frame = _candidate_local_match_join_probe(backend, session, mode,
                        server, key, header_word4=12, header_word9=18)
                handoff = decode_lobby_handoff(frame, key)
                self.assertEqual(handoff.player.player_id, player_id)
                self.assertEqual(handoff.player.team_id, 1)  # Field13 is not the operator.
                self.assertFalse(handoff.HasField('secret_key'))
                url = ('/Game/Maps/Login/Login?PlayerId=' + str(player_id) +
                       '?DSRoomId=' + str(handoff.room_id) + '?MapId=' + str(handoff.map_id) +
                       '?Cookie=' + handoff.player.ds_token)
                ticket = server._admissions.authorize_login_url(url)
                self.assertEqual(ticket.match_mode_id, 142201103)
                self.assertEqual(ticket.selected_hero_id, 88000000025)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    address = ('127.0.0.1', server.port)
                    client.sendto(b'opaque!!' + b'\x01' + bytes(23) + b'\x08', address)
                    challenge, _ = client.recvfrom(1500)
                    client.sendto(b'opaque!!' + challenge, address)
                    acknowledged, _ = client.recvfrom(1500)
                    cookie = decode_payload(acknowledged).cookie
                    server_seed = int.from_bytes(cookie[:2], 'little') & 16383
                    client_seed = int.from_bytes(cookie[2:4], 'little') & 16383
                    packet = replace(template, sequence=client_seed,
                        acknowledged_sequence=(server_seed-1)&16383, bunches=(
                            replace(template.bunches[0], channel_sequence=(client_seed+1)&1023),))
                    client.sendto(encode(packet), address)
                    challenge, _ = client.recvfrom(1500)
                    self.assertEqual(decode_messages(decode(challenge).bunches[0].payload)[0].message_id, 3)
                    payload = login_payload(ticket)
                    packet = replace(packet, sequence=(client_seed+1)&16383,
                        acknowledged_sequence=server_seed, history=(1,), bunches=(
                            replace(packet.bunches[0], open=False,
                                channel_sequence=(client_seed+2)&1023, payload=payload,
                                payload_bits=len(payload)*8),))
                    client.sendto(encode(packet), address)
                    welcome, _ = client.recvfrom(1500)
                    self.assertEqual(decode_messages(decode(welcome).bunches[0].payload),
                                     (ControlMessage(1, ('Iris_Entry', '', '')),))
                    payload = encode_message(4, 25000) + encode_message(9)
                    packet = replace(packet, sequence=(client_seed+2)&16383,
                        acknowledged_sequence=(server_seed+1)&16383, history=(1,), bunches=(
                            replace(packet.bunches[0], channel_sequence=(client_seed+3)&1023,
                                payload=payload, payload_bits=len(payload)*8),))
                    client.sendto(encode(packet), address)
                    joined, _ = client.recvfrom(1500)
                    self.assertEqual(decode(joined).bunches, ())
                    client.settimeout(0.3)
                    packet = replace(packet, sequence=(client_seed+3)&16383,
                        acknowledged_sequence=(server_seed+2)&16383, history=(1,), bunches=())
                    client.sendto(encode(packet), address)
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(1500)
            report = json.loads((Path(folder)/'report.json').read_text(encoding='utf-8'))
            control = report['handshake_probe']['native_control_probe']
            self.assertEqual(control['client_load_map_join_observed_count'], 1)
            self.assertFalse(report['gameplay_server_implemented'])
            self.assertFalse(control['native_connection_completed'])

    def test_handoff_requires_persisted_sol_operator_and_mapped_active_server(self):
        with tempfile.TemporaryDirectory() as folder:
            backend = Backend(Path(folder)/'save.sqlite3',
                Path(__file__).resolve().parent.parent/'definitions.json')
            session = backend.register('local_ds_unselected', 'test-only-password')['session']
            key = b'0123456789abcdef'
            mode = {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 142201103}
            with GameServerProbe(Path(folder)/'packets', handshake_probe=True,
                    packet_ack_probe=True, control_probe=True,
                    expected_net_version=1077088301, control_welcome_maps=MAPS) as server:
                with patch.dict('os.environ', {'DF_LOCAL_DS_MAP_ID': ''}):
                    with self.assertRaisesRegex(ValueError, 'persisted SOL operator'):
                        _candidate_local_match_join_probe(backend, session, mode,
                            server, key, header_word4=12, header_word9=18)
                    self.assertEqual(server._admissions.summary()['issued_ticket_count'], 0)
                    backend.set_native_selected_hero(session, 88000000025)
                    with self.assertRaisesRegex(ValueError, 'evidenced map admission'):
                        _candidate_local_match_join_probe(backend, session, dict(mode, map_id=2202),
                            server, key, header_word4=12, header_word9=18)
            with self.assertRaisesRegex(ValueError, 'active local game-server'):
                _candidate_local_match_join_probe(backend, session, mode,
                    server, key, header_word4=12, header_word9=18)


if __name__ == '__main__':
    unittest.main()

