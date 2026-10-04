"""Initial Actor transport tests; synthetic paths are not native spawn evidence."""
from dataclasses import replace
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_actor_content import read_actor_content_blocks
from dfserver.legacy_ds_actor_fields import (
    ClassFieldEnvelope, NormalClassFieldProfile,
    build_class_field_content, read_class_field_content,
)
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_control_connection import LegacyDSControlConnection, MAX_INITIAL_ACTOR_CHANNELS
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_guid_exports import GuidExportNode, read_guid_exports
from dfserver.legacy_ds_match_admission import LocalMatchAdmissions
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from dfserver.unreal_handshake_payload import decode_payload
from tests.test_legacy_ds_control_connection import MAPS, login_payload
from tests.test_legacy_ds_control_probe import COOKIE, PEER
from tests.test_legacy_ds_wire_codec import HELLO_BODIES


def actor_fields(**changes):
    fields = dict(exports=(GuidExportNode(3, 'FixtureClass'), GuidExportNode(5, 'FixtureLevel')),
                  actor_guid=2, archetype_guid=3, level_guid=5,
                  connection_network_version=13, archive_network_version=13,
                  references_resolvable=True, channel_index=1,
                  location=None, scale=None, velocity=None)
    fields.update(changes)
    return fields


def decode(body):
    return decode_observed_application(body, max_packet_bytes=1024, received_by_server=False)


class ActorDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.admissions = LocalMatchAdmissions(clock=lambda: 0.0)
        self.ticket = self.admissions.issue(101, 201, 2201, 142201103, 88000000025)
        self.connection = LegacyDSControlConnection(admissions=self.admissions,
            welcome_maps=MAPS, expected_net_version=1077088301)
        self.connection.register_verified_echo(PEER, COOKIE)
        self.template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        self.connection.handle(b'opaque!!' + HELLO_BODIES[0], PEER, 0.0)
        self.send(1257, 216, 234, login_payload(self.ticket))
        self.send(1258, 217, 235, encode_message(4, 25000) + encode_message(9))

    def send(self, sequence, ack, channel_sequence=None, payload=b'', *, history=(1,),
             bunches=None, now=0.05):
        if bunches is None:
            bunches = () if channel_sequence is None else (replace(self.template.bunches[0],
                open=False, channel_sequence=channel_sequence, payload=payload,
                payload_bits=len(payload) * 8),)
        packet = replace(self.template, sequence=sequence, acknowledged_sequence=ack,
                         history=history, bunches=bunches)
        return self.connection.handle(b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), PEER, now)

    def test_join_does_not_automatically_manufacture_an_actor(self):
        self.assertEqual(self.connection.poll(1.0), [])
        summary = self.connection.summary()
        self.assertEqual(summary['initial_actor_channels_queued'], 0)
        self.assertFalse(summary['native_actor_spawn_verified'])
        self.assertFalse(summary['player_spawn_implemented'])

    def test_queue_requires_local_admission_and_join(self):
        other = ('127.0.0.1', 40001)
        self.connection.register_verified_echo(other, COOKIE)
        with self.assertRaisesRegex(ValueError, 'admitted joined'):
            self.connection.queue_actor_open(other, **actor_fields())
        self.assertEqual(self.connection.control_peers[other].actor_opens, {})
        with self.assertRaises(ValueError):
            self.connection.queue_actor_open(('127.0.0.1', 40002), **actor_fields())

    def test_new_channels_keep_initial_seed_and_share_packet_sequence(self):
        self.connection.queue_actor_open(PEER, **actor_fields())
        self.connection.queue_actor_open(PEER, **actor_fields(channel_index=2, actor_guid=4))
        packets = [decode(body) for _, _, body in self.connection.poll(0.1)]
        self.assertEqual([packet.sequence for packet in packets], [219, 220])
        self.assertEqual([packet.bunches[0].channel_sequence for packet in packets], [217, 217])
        self.assertEqual([packet.bunches[0].channel_index for packet in packets], [1, 2])
        self.assertTrue(all(packet.bunches[0].channel_name.hardcoded_index == 102 for packet in packets))

    def test_sparse_history_acks_only_the_actor_packet_it_names(self):
        self.connection.queue_actor_open(PEER, **actor_fields())
        self.connection.queue_actor_open(PEER, **actor_fields(channel_index=2, actor_guid=4))
        first = [decode(body) for _, _, body in self.connection.poll(0.1)]
        self.send(1259, 220, history=(2,), now=0.2)  # ACK219; packet220 remains missing.
        summary = self.connection.summary()
        self.assertEqual(summary['initial_actor_delivery_acks'], 1)
        retry = self.connection.poll(0.7)
        self.assertEqual(len(retry), 1)
        packet = decode(retry[0][2])
        self.assertEqual(packet.sequence, 221)
        self.assertEqual(packet.bunches[0], replace(first[1].bunches[0],
            header_start_bit=packet.bunches[0].header_start_bit,
            payload_start_bit=packet.bunches[0].payload_start_bit))
        self.send(1260, 221, history=(1,), now=0.8)
        self.assertEqual(self.connection.poll(2.0), [])
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 2)
        self.assertFalse(self.connection.summary()['native_actor_resolution_verified'])

    def test_unrelated_ack_bits_and_ack_only_packets_do_not_send_or_deliver(self):
        self.connection.queue_actor_open(PEER, **actor_fields())
        self.connection.poll(0.1)
        event, response = self.send(1259, 219, history=(1 << 10,), now=0.2)
        self.assertEqual((event, response), ('control_ack_only_consumed', None))
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)
        self.assertEqual(self.connection.poll(0.3), [])
        self.assertEqual(self.connection.poll(0.7)[0][1], 'actor_open_timer_retransmit_prepared')

    def test_unknown_inbound_actor_cannot_commit_ack_or_extend_protocol_acceptance(self):
        self.connection.queue_actor_open(PEER, **actor_fields())
        outgoing = decode(self.connection.poll(0.1)[0][2])
        event, response = self.send(1259, 219, bunches=outgoing.bunches, now=0.2)
        self.assertEqual((event, response), ('control_login_or_order_rejected', None))
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)
        self.assertEqual(self.connection.peers[PEER].history & 1, 0)
        self.connection.poll(0.8)
        self.send(1260, 220, now=0.9)
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 1)

    def test_retries_stop_at_transmission_budget_and_use_new_packet_ids(self):
        self.connection.max_transmissions = 2
        self.connection.queue_actor_open(PEER, **actor_fields())
        first = decode(self.connection.poll(0.1)[0][2])
        retry = decode(self.connection.poll(0.7)[0][2])
        self.assertEqual(retry.sequence, first.sequence + 1)
        self.assertEqual(retry.bunches[0], first.bunches[0])
        self.assertEqual(self.connection.poll(2.0), [])
        self.assertEqual(self.connection.summary()['initial_actor_retries_exhausted'], 1)

    def test_control_and_actors_share_the_total_reply_budget(self):
        self.assertEqual(self.connection.peers[PEER].replies, 3)
        self.connection.max_replies = 4
        self.connection.queue_actor_open(PEER, **actor_fields())
        self.connection.queue_actor_open(PEER, **actor_fields(channel_index=2, actor_guid=4))
        self.assertEqual(len(self.connection.poll(0.1)), 1)
        self.assertEqual(self.connection.poll(1.0), [])
        self.assertEqual(self.connection.peers[PEER].replies, 4)

    def test_packet_sequence_wrap_does_not_change_reliable_actor_sequence(self):
        transport = self.connection.peers[PEER]
        transport.out_sequence, transport.acknowledged_out_sequence = 16383, 16382
        self.connection.queue_actor_open(PEER, **actor_fields())
        first = decode(self.connection.poll(0.1)[0][2])
        retry = decode(self.connection.poll(0.7)[0][2])
        self.assertEqual((first.sequence, retry.sequence), (16383, 0))
        self.assertEqual(retry.bunches[0].channel_sequence, 217)
        self.send(1259, 0, now=0.8)
        self.assertEqual(self.connection.poll(2.0), [])

    def test_reopening_channels_or_actor_guids_is_rejected_even_after_ack(self):
        self.connection.queue_actor_open(PEER, **actor_fields())
        self.connection.poll(0.1)
        self.send(1259, 219, now=0.2)
        for fields in (actor_fields(actor_guid=4), actor_fields(channel_index=2)):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.connection.queue_actor_open(PEER, **fields)
        self.assertEqual(len(self.connection.control_peers[PEER].actor_opens), 1)

    def test_conflicting_export_across_actors_leaves_queue_and_graph_unchanged(self):
        self.connection.queue_actor_open(PEER, **actor_fields())
        state = self.connection.control_peers[PEER]
        previous = dict(state.actor_exports)
        changed = (GuidExportNode(3, 'DifferentClass'), GuidExportNode(5, 'FixtureLevel'))
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            self.connection.queue_actor_open(PEER, **actor_fields(channel_index=2, actor_guid=4, exports=changed))
        self.assertEqual(state.actor_exports, previous)
        self.assertEqual(len(state.actor_opens), 1)

    def test_invalid_or_oversized_actor_is_not_queued_or_counted_as_sent(self):
        self.connection.max_packet_bytes = 64
        before = self.connection.peers[PEER].out_sequence
        with self.assertRaises(ValueError):
            self.connection.queue_actor_open(PEER, **actor_fields(exports=(
                GuidExportNode(3, 'C' * 50), GuidExportNode(5, 'FixtureLevel'))))
        for changes in ({'channel_sequence': 0}, {'max_packet_bytes': 1024}, {'references_resolvable': False}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.connection.queue_actor_open(PEER, **actor_fields(**changes))
        state = self.connection.control_peers[PEER]
        self.assertEqual((state.actor_opens, state.actor_exports), ({}, {}))
        self.assertEqual(self.connection.peers[PEER].out_sequence, before)

    def test_channel_bound_and_peer_cleanup(self):
        for index in range(1, MAX_INITIAL_ACTOR_CHANNELS + 1):
            self.connection.queue_actor_open(PEER, **actor_fields(channel_index=index, actor_guid=index * 2))
        with self.assertRaisesRegex(ValueError, 'limit'):
            self.connection.queue_actor_open(PEER, **actor_fields(channel_index=17, actor_guid=34))
        self.connection.forget_peer(PEER)
        self.assertEqual(self.connection.poll(10), [])
        self.assertEqual(self.connection.summary()['initial_actor_channels_queued'], 0)


class ActorDeliveryUdpTests(unittest.TestCase):
    def test_real_udp_join_bound_actor_send_ack_and_expiry(self):
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        def send(client, address, packet):
            client.sendto(b'opaque!!' + encode_observed_application(packet,
                max_packet_bytes=1024, received_by_server=True), address)
        with tempfile.TemporaryDirectory() as folder:
            with GameServerProbe(folder, handshake_probe=True, packet_ack_probe=True,
                    control_probe=True, expected_net_version=1077088301,
                    control_welcome_maps=MAPS, max_packets=32) as server:
                ticket = server.issue_match_admission(player_id=101, room_id=201, map_id=2201,
                    match_mode_id=142201103, selected_hero_id=88000000025)
                # Synthetic index/profile/body validate composition and UDP only;
                # these are not real game-class fields or a possession RPC.
                field_profile = NormalClassFieldProfile(6, False)
                fields = (ClassFieldEnvelope(3, b'\x05', 3),)
                content = (build_class_field_content(fields, profile=field_profile),)
                with self.assertRaises(ValueError):
                    server.queue_actor_open(player_id=101, room_id=201,
                                            **actor_fields(content_blocks=content))
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
                        acknowledged_sequence=(server_seed - 1) & 16383, bunches=(
                            replace(template.bunches[0], channel_sequence=(client_seed + 1) & 1023),))
                    send(client, address, packet)
                    client.recvfrom(1500)
                    payload = login_payload(ticket)
                    packet = replace(packet, sequence=(client_seed + 1) & 16383,
                        acknowledged_sequence=server_seed, history=(1,), bunches=(
                            replace(packet.bunches[0], open=False, channel_sequence=(client_seed + 2) & 1023,
                                    payload=payload, payload_bits=len(payload) * 8),))
                    send(client, address, packet)
                    client.recvfrom(1500)
                    payload = encode_message(4, 25000) + encode_message(9)
                    packet = replace(packet, sequence=(client_seed + 2) & 16383,
                        acknowledged_sequence=(server_seed + 1) & 16383, bunches=(
                            replace(packet.bunches[0], channel_sequence=(client_seed + 3) & 1023,
                                    payload=payload, payload_bits=len(payload) * 8),))
                    send(client, address, packet)
                    client.recvfrom(1500)
                    for player, room in ((102, 201), (101, 202), (True, 201)):
                        with self.assertRaises(ValueError):
                            server.queue_actor_open(player_id=player, room_id=room, **actor_fields())
                    server.queue_actor_open(player_id=101, room_id=201,
                                            **actor_fields(content_blocks=content))
                    native, _ = client.recvfrom(1500)
                    actor = decode(native)
                    self.assertEqual(actor.bunches[0].channel_sequence, (server_seed + 1) & 1023)
                    self.assertEqual(actor.bunches[0].channel_name.hardcoded_index, 102)
                    reader = BitReader(actor.bunches[0].payload, bit_count=actor.bunches[0].payload_bits)
                    read_guid_exports(reader)
                    reader.read_payload(28)  # Three one-byte GUIDs plus four absent transform flags.
                    received_content = read_actor_content_blocks(reader)
                    self.assertEqual(received_content, content)
                    self.assertEqual(read_class_field_content(received_content[0],
                        profile=field_profile), fields)
                    packet = replace(packet, sequence=(client_seed + 3) & 16383,
                                     acknowledged_sequence=actor.sequence, history=(1,), bunches=())
                    send(client, address, packet)
                    client.settimeout(0.7)
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(1500)
                    server._started_at = time.monotonic() - 700
                    with self.assertRaisesRegex(ValueError, 'unique joined'):
                        server.queue_actor_open(player_id=101, room_id=201, **actor_fields(channel_index=2, actor_guid=4))
                    with server._lock:
                        self.assertEqual(server._handshake.summary()['active_peer_count'], 0)
            report = json.loads((Path(folder) / 'report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['initial_actor_open_datagrams_sent'], 1)
            self.assertFalse(report['gameplay_server_implemented'])


if __name__ == '__main__':
    unittest.main()
