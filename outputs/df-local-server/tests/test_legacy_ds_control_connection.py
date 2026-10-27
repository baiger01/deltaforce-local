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
from dfserver.legacy_ds_wire_codec import ChannelName, decode_observed_application, encode_observed_application
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

    def test_dam_profile_subworld_is_in_welcome_only_after_local_login(self):
        profile = json.loads((Path(__file__).resolve().parents[1] /
            'protocol/native_ds_wire_profile.json').read_text(encoding='utf-8'))
        maps = {int(key): spec for key, spec in profile['control_welcome_maps'].items()}
        self.probe = LegacyDSControlConnection(admissions=self.admissions,
            welcome_maps=maps, expected_net_version=profile['hello_net_version'])
        self.probe.register_verified_echo(PEER, COOKIE)
        event, reply = self.hello()
        messages = decode_messages(self.decode(reply).bunches[0].payload)
        self.assertEqual([message.message_id for message in messages], [3])
        self.assertIsNone(self.probe.control_peers[PEER].welcome_payload)
        event, reply = self.send(1257, 216, 234, login_payload(self.ticket))
        self.assertEqual(event, 'control_login_welcome_prepared')
        self.assertEqual(decode_messages(self.decode(reply).bunches[0].payload),
            (ControlMessage(1, ('Iris_Entry', '', 'SubWorld=Dam_Iris_Level1')),))
        self.assertEqual(self.probe.summary()['login_authorized_peers'], 1)

    def test_unsupported_actor_is_not_reported_as_bad_login_or_acknowledged(self):
        self.login()
        original = self.probe.control_peers[PEER]
        actor = replace(self.template.bunches[0], channel_index=2,
            channel_name=ChannelName(hardcoded_index=102), open=False,
            channel_sequence=234, payload=b'\x00', payload_bits=8)
        event, response = self.raw(replace(self.template, sequence=1258,
            acknowledged_sequence=217, history=(1,), bunches=(actor,)))
        self.assertEqual((event, response), ('application_channel_payload_unsupported', None))
        state = self.probe.control_peers[PEER]
        self.assertIs(state, original)
        self.assertEqual(state.expected_client_sequence, 235)
        self.assertIsNotNone(state.pending)
        self.assertEqual(self.admissions.summary()['authorized_login_count'], 1)
        self.assertEqual(self.probe.peers[PEER].history & 1, 0)

    def test_mixed_control_and_unknown_actor_rolls_back_whole_packet(self):
        self.login()
        control = replace(self.template.bunches[0], open=False, channel_sequence=235,
            payload=encode_message(4, 25000), payload_bits=40)
        actor = replace(control, channel_index=2,
            channel_name=ChannelName(hardcoded_index=102),
            payload=b'\x00', payload_bits=8)
        event, response = self.raw(replace(self.template, sequence=1258,
            acknowledged_sequence=217, history=(1,), bunches=(control, actor)))
        self.assertEqual((event, response), ('application_channel_payload_unsupported', None))
        state = self.probe.control_peers[PEER]
        self.assertIsNone(state.netspeed)
        self.assertEqual(state.expected_client_sequence, 235)
        self.assertNotIn(235, state.consumed)
        self.assertEqual(self.probe.peers[PEER].history & 1, 0)

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


class PCRestartLifecycleTests(unittest.TestCase):
    """Actual packet-history gates; synthetic actors do not prove native possession."""

    def setUp(self):
        from tests.test_legacy_ds_actor_delivery import ActorDeliveryTests, actor_fields
        from tests.test_legacy_ds_pc_startup_rpc import PROFILE as startup_profile
        from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content
        from dfserver.legacy_ds_game_state_start import GameStateStartProfile
        from tests.test_legacy_ds_pc_restart_rpc import PROFILE as restart_profile
        from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256
        self.fixture = ActorDeliveryTests()
        self.fixture.setUp()
        self.connection = self.fixture.connection
        self.ticket = self.fixture.ticket
        self.profile = restart_profile
        self.fields = tuple(actor_fields(channel_index=channel, actor_guid=guid)
                            for channel, guid in ((2, 4), (3, 6), (4, 2)))
        self.plans = tuple(dict(channel_index=f['channel_index'], actor_guid=f['actor_guid'],
                               content_blocks=(build_empty_rep_layout_content(),)) for f in self.fields)
        self.connection.queue_actor_opens(PEER, self.fields, post_open_actor_contents=self.plans)
        self.connection.set_pc_startup_profile(PEER, 2, 4, startup_profile)
        self.start_profile = GameStateStartProfile('/Game/Fixture.GameState_C', 19,
            SHIPPING_SHA256, 'c' * 64, all_ready_handle=24, abseil_handle=107,
            map_id_handle=52, room_id_handle=53)
        self.connection.set_game_state_start_profile(PEER, 3, 6, self.start_profile)
        self.connection.set_pc_restart_profile(PEER, 2, 4, 2, self.profile)

    def state(self):
        return self.connection.control_peers[PEER]

    def send_packet(self, bunches=(), *, now=0.5, history=(0xffffffff,)):
        transport = self.connection.peers[PEER]
        return self.fixture.send((transport.in_sequence + 1) & 16383,
            (transport.out_sequence - 1) & 16383, bunches=bunches, history=history, now=now)

    def phase(self, now, expected):
        replies = self.connection.poll(now)
        self.assertEqual([row[1] for row in replies], expected)
        if replies:
            self.assertEqual(self.send_packet(now=now + .05), ('control_ack_only_consumed', None))
        return replies

    def ready(self):
        from tests.test_legacy_ds_pc_startup_rpc import rpc
        self.phase(.1, ['actor_open_send_prepared'] * 3)
        self.phase(.3, ['actor_content_send_prepared'] * 3)
        self.assertEqual(self.send_packet((rpc(200, 79), rpc(201, 141, True)), now=.5)[0],
                         'pc_startup_packet_consumed')
        self.phase(.6, ['pc_ready_ack_send_prepared'])
        self.phase(.8, ['game_state_match_info_send_prepared'])
        self.phase(1.0, ['game_state_start_send_prepared'])
        self.phase(1.2, ['game_state_all_ready_send_prepared'])
        self.phase(1.4, ['game_state_abseil_send_prepared'])

    def acknowledgement(self, *, guid=2, sequence=202, index=67, extra=False):
        from dfserver.legacy_ds_pc_restart_rpc import encode_pawn_parameter
        from dfserver.legacy_ds_actor_fields import (
            ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content)
        from dfserver.legacy_ds_actor_content import write_actor_content_blocks
        from dfserver.legacy_ds_bit_archive import BitWriter
        from dfserver.legacy_ds_wire_codec import WireBunch
        payload, bits = encode_pawn_parameter(pawn_guid=guid, profile=self.profile,
            reference_resolved=True, exports_acknowledged=True)
        fields = (ClassFieldEnvelope(index, payload, bits),)
        if extra:
            fields += (ClassFieldEnvelope(79, b'', 0),)
        block = build_class_field_content(fields, profile=NormalClassFieldProfile(245, False))
        writer = BitWriter(maximum_bits=512)
        write_actor_content_blocks(writer, (block,))
        return WireBunch(2, writer.to_bytes(), writer.bit_count, reliable=True,
                         channel_sequence=sequence, channel_name=ChannelName(hardcoded_index=102))

    def test_post_travel_request_is_separate_from_every_actual_delivery_gate(self):
        self.ready()
        self.assertFalse(any(r[1].startswith('pc_restart_') for r in self.connection.poll(1.6)))
        self.assertFalse(self.state().pc_restart_requested)
        self.assertEqual(self.connection.request_pc_restart(PEER)['status'], 'pending')
        deliveries = [*self.state().actor_opens.values(), *self.state().actor_contents.values(),
            self.state().pc_ready_ack, self.state().game_state_match_info, self.state().game_state_start,
            self.state().game_state_all_ready, self.state().game_state_abseil]
        for item in deliveries:
            with self.subTest(channel=item.bunch.channel_index, seq=item.bunch.channel_sequence):
                item.delivered = False
                self.assertFalse(any(r[1].startswith('pc_restart_') for r in self.connection.poll(1.7)))
                item.delivered = True
        first = next(r for r in self.connection.poll(1.8) if r[1] == 'pc_restart_send_prepared')
        from tests.test_legacy_ds_actor_delivery import decode
        bunch, = decode(first[2]).bunches
        self.assertEqual((bunch.channel_index, bunch.channel_sequence),
                         (2, (self.state().pc_ready_ack.bunch.channel_sequence + 1) & 1023))
        self.assertFalse(self.connection.summary()['native_possession_verified'])

    def test_zero_history_and_duplicate_request_do_not_change_the_outbox(self):
        self.ready()
        self.connection.request_pc_restart(PEER)
        first = next(r for r in self.connection.poll(1.6) if r[1] == 'pc_restart_send_prepared')
        before = self.state().pc_restart.bunch
        self.assertEqual(self.connection.request_pc_restart(PEER)['status'], 'queued')
        self.send_packet(now=1.7, history=(0,))
        self.assertFalse(self.state().pc_restart.delivered)
        self.assertFalse(any(r[1].startswith('pc_restart_') for r in self.connection.poll(1.9)))
        retry = next(r for r in self.connection.poll(2.2) if r[1] == 'pc_restart_timer_retransmit_prepared')
        from tests.test_legacy_ds_actor_delivery import decode
        self.assertEqual(decode(first[2]).bunches, decode(retry[2]).bunches)
        self.assertNotEqual(decode(first[2]).sequence, decode(retry[2]).sequence)
        self.assertEqual(self.state().pc_restart.bunch, before)
        self.send_packet(now=2.3)
        self.assertTrue(self.state().pc_restart.delivered)
        self.assertFalse(any(r[1].startswith('pc_restart_') for r in self.connection.poll(3.0)))

    def test_ack_requires_transmission_exact_pawn_and_existing_reliable_ledger(self):
        self.ready()
        ack = self.acknowledgement()
        self.assertIsNone(self.send_packet((ack,), now=1.55)[1])
        self.assertFalse(self.state().pc_possession_ack_received)
        self.connection.request_pc_restart(PEER)
        self.connection.poll(1.6)
        for invalid in (self.acknowledgement(guid=8), self.acknowledgement(extra=True),
                        replace(ack, channel_index=4)):
            self.assertIsNone(self.send_packet((invalid,), now=1.7, history=(0,))[1])
            self.assertFalse(self.state().pc_possession_ack_received)
        event, response = self.send_packet((ack,), now=1.8, history=(0,))
        self.assertEqual(event, 'pc_possession_ack_packet_consumed')
        self.assertIsNotNone(response)
        self.assertFalse(self.state().pc_restart.delivered)  # RPC receipt is not a transport ACK.
        self.assertEqual(self.state().pc_possession_ack_count, 1)
        self.assertEqual(self.state().pc_startup_expected_sequence, 203)
        self.send_packet((ack,), now=1.9)
        self.assertEqual(self.state().pc_possession_ack_count, 1)
        self.assertIsNone(self.send_packet((self.acknowledgement(guid=8),), now=2.0)[1])
        self.assertEqual(self.state().pc_possession_ack_count, 1)
        self.assertFalse(self.connection.summary()['playable_map_verified'])

    def test_request_and_retries_cannot_cross_ticket_peer_actor_or_close_boundaries(self):
        self.ready()
        self.connection.request_pc_restart(PEER)
        state = self.state()
        cases = (('ticket', replace(state.ticket)), ('pc_restart_actor_guid', 8),
                 ('pc_restart_pawn_guid', 10), ('client_closed', True))
        for attr, wrong in cases:
            old = getattr(state, attr)
            setattr(state, attr, wrong)
            with self.subTest(attr=attr), self.assertRaises(ValueError):
                self.connection.request_pc_restart(PEER)
            self.assertFalse(any(r[1].startswith('pc_restart_') for r in self.connection.poll(1.6)))
            setattr(state, attr, old)
        self.connection.ticket_peers[state.ticket.cookie] = ('127.0.0.1', 9999)
        self.assertFalse(any(r[1].startswith('pc_restart_') for r in self.connection.poll(1.7)))
        self.connection.ticket_peers[state.ticket.cookie] = PEER
        with patch.object(self.connection.admissions, 'is_active', return_value=False):
            self.assertFalse(any(r[1].startswith('pc_restart_') for r in self.connection.poll(1.8)))

    def opaque_partial_group(self, *, start=202, parameter_bits=114750):
        """Observed-size framing, with opaque synthetic bytes and no game schema."""
        from dfserver.legacy_ds_bit_archive import BitWriter
        from dfserver.legacy_ds_wire_codec import WireBunch
        field = BitWriter(maximum_bits=512)
        field.write_bounded_int(84, 245)
        field.write_packed_int(parameter_bits)
        block_bits = field.bit_count + parameter_bits
        outer = BitWriter(maximum_bits=512)
        outer.write_bool(False)
        outer.write_bool(True)
        outer.write_packed_int(block_bits)
        bits = outer.bit_count + block_bits
        value = int.from_bytes(outer.to_bytes(), 'little') | (
            int.from_bytes(field.to_bytes(), 'little') << outer.bit_count)
        parts = []
        position = 0
        while position < bits:
            count = min(7624, bits - position)
            payload = ((value >> position) & ((1 << count) - 1)).to_bytes((count + 7) // 8, 'little')
            parts.append(WireBunch(2, payload, count, reliable=True,
                channel_sequence=(start + len(parts)) & 1023,
                channel_name=ChannelName(hardcoded_index=102), partial=True,
                partial_initial=position == 0, partial_final=position + count == bits))
            position += count
        return tuple(parts)

    def test_true_continuous_large_partial_receipt_unblocks_mixed_ack_without_acknowledging_opaque(self):
        self.ready()
        parts = self.opaque_partial_group()
        self.assertEqual(sum(b.payload_bits for b in parts), 114808)
        for offset, part in enumerate(parts):
            event, response = self.send_packet((part,), now=1.5 + offset / 100, history=(0,))
            self.assertEqual(event, 'pc_reliable_receipt_only_consumed')
            self.assertIsNone(response)
            self.assertEqual(self.connection.peers[PEER].history & 1, 0)
        self.assertEqual(self.state().pc_startup_request_count, 2)
        self.assertEqual(self.state().pc_opaque_receipt_count, 1)
        self.assertEqual(self.state().pc_startup_expected_sequence, 218)
        self.connection.request_pc_restart(PEER)
        self.connection.poll(1.8)
        # The qualified acknowledgement may share one envelope with another
        # supported RPC; the isolated public codec remains intentionally strict.
        mixed = self.acknowledgement(sequence=218, extra=True)
        event, response = self.send_packet((mixed,), now=1.9, history=(0,))
        self.assertEqual(event, 'pc_possession_ack_packet_consumed')
        self.assertIsNotNone(response)
        self.assertEqual(self.state().pc_possession_ack_count, 1)
        self.assertFalse(self.state().pc_restart.delivered)
        self.send_packet((mixed,), now=2.0, history=(0,))
        self.assertEqual(self.state().pc_possession_ack_count, 1)
        self.assertEqual(self.state().pc_startup_request_count, 3)
        self.assertEqual(self.state().pc_startup_expected_sequence, 219)

    def test_missing_fragment_cannot_jump_to_later_ack_and_conflicting_fragment_cannot_replace_receipt(self):
        self.ready()
        self.connection.request_pc_restart(PEER)
        self.connection.poll(1.6)
        first, *rest = self.opaque_partial_group()
        self.send_packet((first,), now=1.7, history=(0,))
        expected = self.state().pc_startup_expected_sequence
        self.assertIsNone(self.send_packet((self.acknowledgement(sequence=218),), now=1.8)[1])
        self.assertFalse(self.state().pc_possession_ack_received)
        self.assertEqual(self.state().pc_startup_expected_sequence, expected)
        wrong = replace(first, payload=bytes([first.payload[0] ^ 1]) + first.payload[1:])
        self.assertIsNone(self.send_packet((wrong,), now=1.9)[1])
        self.assertEqual(self.state().pc_startup_expected_sequence, expected)
        for offset, part in enumerate(rest):
            self.send_packet((part,), now=2.0 + offset / 100, history=(0,))
        event, _ = self.send_packet((self.acknowledgement(sequence=218),), now=2.3, history=(0,))
        self.assertEqual(event, 'pc_possession_ack_packet_consumed')
        self.assertEqual(self.state().pc_possession_ack_count, 1)

    def test_qualified_ack_in_same_whole_body_as_unknown_rpc_keeps_packet_skip_ack(self):
        from dfserver.legacy_ds_actor_content import write_actor_content_blocks
        from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content
        from dfserver.legacy_ds_bit_archive import BitWriter
        from dfserver.legacy_ds_pc_restart_rpc import encode_pawn_parameter
        self.ready()
        self.connection.request_pc_restart(PEER)
        self.connection.poll(1.6)
        payload, bits = encode_pawn_parameter(pawn_guid=2, profile=self.profile,
            reference_resolved=True, exports_acknowledged=True)
        block = build_class_field_content((ClassFieldEnvelope(85, b'', 0),
            ClassFieldEnvelope(67, payload, bits)), profile=NormalClassFieldProfile(245, False))
        writer = BitWriter(maximum_bits=512)
        write_actor_content_blocks(writer, (block,))
        mixed = replace(self.acknowledgement(), payload=writer.to_bytes(), payload_bits=writer.bit_count)
        event, response = self.send_packet((mixed,), now=1.7, history=(0,))
        self.assertEqual(event, 'pc_possession_ack_mixed_packet_consumed')
        self.assertIsNone(response)
        self.assertEqual(self.connection.peers[PEER].history & 1, 0)
        self.assertEqual(self.state().pc_possession_ack_count, 1)
        self.assertEqual(self.state().pc_opaque_receipt_count, 1)
        self.send_packet((mixed,), now=1.8, history=(0,))
        self.assertEqual(self.state().pc_possession_ack_count, 1)
        self.assertEqual(self.state().pc_opaque_receipt_count, 1)

    def test_declared_phase_delivery_without_a_recorded_transmission_is_not_enough(self):
        self.ready()
        self.connection.request_pc_restart(PEER)
        for item in (self.state().actor_contents[2], self.state().pc_ready_ack,
                     self.state().game_state_all_ready, self.state().game_state_abseil):
            old = item.sent_packets
            item.sent_packets = ()
            self.assertFalse(any(r[1].startswith('pc_restart_') for r in self.connection.poll(1.6)))
            item.sent_packets = old

    def install_view_target(self):
        from dfserver.legacy_ds_pc_view_target_rpc import PCViewTargetProfile
        self.view_profile = PCViewTargetProfile(self.profile.class_path, 245, 53, 85,
            0x01020CC0, 0x80220CC0, 'd' * 64, self.profile.object_binding)
        self.connection.set_pc_view_target_profile(PEER, self.view_profile)

    def verify_view_target(self, *, sequence=202, parameter_bits=0, unknown=False):
        from dfserver.legacy_ds_actor_content import write_actor_content_blocks
        from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content
        from dfserver.legacy_ds_bit_archive import BitWriter
        from dfserver.legacy_ds_wire_codec import WireBunch
        fields = (ClassFieldEnvelope(85, bytes((parameter_bits + 7) // 8), parameter_bits),)
        if unknown:
            fields += (ClassFieldEnvelope(154, b'', 0),)
        block = build_class_field_content(fields, profile=NormalClassFieldProfile(245, False))
        writer = BitWriter(maximum_bits=1024)
        write_actor_content_blocks(writer, (block,))
        return WireBunch(2, writer.to_bytes(), writer.bit_count, reliable=True,
            channel_sequence=sequence, channel_name=ChannelName(hardcoded_index=102))

    def test_view_target_request_waits_for_explicit_post_travel_restart_actual_delivery(self):
        self.install_view_target()
        self.ready()
        verify = self.verify_view_target()
        event, response = self.send_packet((verify,), now=1.5)
        self.assertEqual(event, 'pc_verify_view_target_packet_consumed')
        self.assertIsNotNone(response)
        self.assertEqual(self.state().pc_verify_view_target_count, 1)
        self.assertTrue(self.state().pc_view_target_requested)
        self.assertEqual(self.connection.poll(1.6), [])
        self.connection.request_pc_restart(PEER)
        replies = self.connection.poll(1.7)
        self.assertEqual([r[1] for r in replies], ['pc_restart_send_prepared'])
        self.assertIsNone(self.state().pc_view_target)
        self.send_packet(now=1.8, history=(0,))
        self.assertFalse(self.state().pc_restart.delivered)
        self.assertFalse(any(r[1].startswith('pc_view_target_') for r in self.connection.poll(1.9)))
        self.send_packet(now=2.0)
        restart = self.state().pc_restart
        sent = restart.sent_packets
        restart.sent_packets = ()
        self.assertFalse(any(r[1].startswith('pc_view_target_') for r in self.connection.poll(2.1)))
        restart.sent_packets = sent
        camera = next(r for r in self.connection.poll(2.2) if r[1] == 'pc_view_target_send_prepared')
        from tests.test_legacy_ds_actor_delivery import decode
        from dfserver.legacy_ds_pc_receipt import bounded_actor_fields
        from dfserver.legacy_ds_pc_view_target_rpc import decode_default_view_target_parameters
        bunch, = decode(camera[2]).bunches
        self.assertEqual((bunch.channel_index, bunch.channel_sequence),
            (2, (restart.bunch.channel_sequence + 1) & 1023))
        field, = bounded_actor_fields(bunch)
        self.assertEqual((field.rep_index, field.payload_bit_count, field.payload), (53, 10, b'\x09\x00'))
        self.assertEqual(decode_default_view_target_parameters(field.payload, field.payload_bit_count,
            expected_actor_guid=2), 2)
        self.assertFalse(self.connection.summary()['native_camera_verified'])

    def test_view_target_retry_keeps_bunch_and_requires_own_transport_history_ack(self):
        self.install_view_target()
        self.ready()
        self.send_packet((self.verify_view_target(),), now=1.5)
        self.connection.request_pc_restart(PEER)
        self.phase(1.6, ['pc_restart_send_prepared'])
        first = next(r for r in self.connection.poll(1.8) if r[1] == 'pc_view_target_send_prepared')
        self.send_packet((self.acknowledgement(sequence=203),), now=1.9, history=(0,))
        self.assertEqual(self.state().pc_possession_ack_count, 1)
        self.assertFalse(self.state().pc_view_target.delivered)
        self.assertFalse(any(r[1].startswith('pc_view_target_') for r in self.connection.poll(2.0)))
        retry = next(r for r in self.connection.poll(2.4) if r[1] == 'pc_view_target_timer_retransmit_prepared')
        from tests.test_legacy_ds_actor_delivery import decode
        self.assertEqual(decode(first[2]).bunches, decode(retry[2]).bunches)
        self.assertNotEqual(decode(first[2]).sequence, decode(retry[2]).sequence)
        self.send_packet(now=2.5)
        self.assertTrue(self.state().pc_view_target.delivered)
        self.assertFalse(any(r[1].startswith('pc_view_target_') for r in self.connection.poll(3.1)))
        self.assertFalse(self.connection.summary()['playable_map_verified'])

    def test_view_target_mixed_request_is_once_only_and_unknown_sibling_keeps_skip_ack(self):
        self.install_view_target()
        self.ready()
        mixed = self.verify_view_target(unknown=True)
        event, response = self.send_packet((mixed,), now=1.5)
        self.assertEqual(event, 'pc_verify_view_target_mixed_packet_consumed')
        self.assertIsNone(response)
        self.assertEqual(self.connection.peers[PEER].history & 1, 0)
        self.assertEqual(self.state().pc_verify_view_target_count, 1)
        self.send_packet((mixed,), now=1.6)
        self.assertEqual(self.state().pc_verify_view_target_count, 1)
        self.assertIsNone(self.state().pc_view_target)
        self.connection.request_pc_restart(PEER)
        self.phase(1.7, ['pc_restart_send_prepared'])
        self.assertEqual([r[1] for r in self.connection.poll(1.9)], ['pc_view_target_send_prepared'])

    def test_view_target_invalid_parameter_or_changed_ticket_namespace_cannot_request_or_send(self):
        self.install_view_target()
        self.ready()
        invalid = self.verify_view_target(parameter_bits=1)
        self.assertIsNone(self.send_packet((invalid,), now=1.5)[1])
        self.assertFalse(self.state().pc_view_target_requested)
        self.send_packet((self.verify_view_target(sequence=203),), now=1.6)
        self.connection.request_pc_restart(PEER)
        self.phase(1.7, ['pc_restart_send_prepared'])
        state = self.state()
        for attr, wrong in (('ticket', replace(state.ticket)), ('pc_restart_pawn_guid', 8),
                            ('pc_restart_actor_guid', 10), ('client_closed', True)):
            old = getattr(state, attr)
            setattr(state, attr, wrong)
            self.assertFalse(any(r[1].startswith('pc_view_target_') for r in self.connection.poll(1.9)))
            setattr(state, attr, old)
        self.assertEqual([r[1] for r in self.connection.poll(2.0)], ['pc_view_target_send_prepared'])


if __name__ == '__main__':
    unittest.main()
