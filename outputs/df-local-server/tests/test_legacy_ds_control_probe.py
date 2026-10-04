from dataclasses import replace
import json
from pathlib import Path
import socket
import tempfile
import unittest

from dfserver.legacy_ds_control_fields import ControlMessage, decode_messages, encode_message
from dfserver.legacy_ds_control_probe import LegacyDSControlProbe
from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_handshake_probe import LegacyDSHandshakeProbe
from dfserver.unreal_handshake_payload import decode_payload
from dfserver.legacy_ds_wire_codec import (decode_observed_application, encode_observed_application)
from tests.test_legacy_ds_wire_codec import HELLO_BODIES

PEER = ('127.0.0.1', 54321)
COOKIE = (216).to_bytes(2, 'little') + (1256).to_bytes(2, 'little') + bytes(16)


class LocalControlProbeTests(unittest.TestCase):
    def probe(self, **kwargs):
        result = LegacyDSControlProbe(expected_net_version=1077088301, **kwargs)
        result.register_verified_echo(PEER, COOKIE)
        return result

    def incoming(self, packet):
        return b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True)

    def packet(self):
        return decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)

    def response(self, body):
        return decode_observed_application(body,
            max_packet_bytes=1024, received_by_server=False)

    def test_exact_real_hello_is_consumed_before_preparing_real_challenge(self):
        probe = self.probe()
        event, response = probe.handle(b'opaque!!' + HELLO_BODIES[0], PEER)
        self.assertEqual(event, 'control_hello_challenge_prepared')
        packet = self.response(response)
        self.assertEqual((packet.sequence, packet.acknowledged_sequence, packet.history),
                         (216, 1256, (1,)))
        bunch = packet.bunches[0]
        self.assertEqual((bunch.channel_index, bunch.reliable, bunch.open,
                          bunch.channel_sequence, bunch.payload_bits), (0, True, False, 217, 304))
        self.assertEqual(decode_messages(bunch.payload),
                         (ControlMessage(3, (probe.control_peers[PEER].challenge_payload[5:-1].decode('ascii'),)),))
        self.assertEqual(probe.summary()['hello_consumed_peers'], 1)
        self.assertFalse(probe.summary()['login_implemented'])

    def test_reliable_hello_retry_preserves_challenge_and_channel_sequence(self):
        probe = self.probe()
        _, first = probe.handle(b'opaque!!' + HELLO_BODIES[0], PEER)
        event, second = probe.handle(b'opaque!!' + HELLO_BODIES[1], PEER)
        self.assertEqual(event, 'control_hello_retry_challenge_prepared')
        first, second = self.response(first), self.response(second)
        self.assertEqual((second.sequence, second.history), (217, (33,)))
        self.assertEqual(first.bunches[0].payload, second.bunches[0].payload)
        self.assertEqual(first.bunches[0].channel_sequence, second.bunches[0].channel_sequence)

    def test_wrong_version_or_encryption_token_never_delivered(self):
        for fields in ((1, 1, ''), (1, 1077088301, 'unsupported-encryption-token')):
            probe = self.probe()
            packet = self.packet()
            payload = encode_message(0, *fields)
            incoming = replace(packet, bunches=(replace(packet.bunches[0],
                payload=payload, payload_bits=len(payload)*8),))
            self.assertEqual(probe.handle(self.incoming(incoming), PEER),
                             ('control_payload_unimplemented', None))
            self.assertFalse(probe.control_peers[PEER].hello_received)
            self.assertEqual(probe.peers[PEER].history, 0)

    def test_unknown_login_is_observed_without_ack_or_accepting_its_fields(self):
        probe = self.probe()
        probe.handle(b'opaque!!' + HELLO_BODIES[0], PEER)
        packet = self.packet()
        incoming = replace(packet, sequence=1257, acknowledged_sequence=216,
            history=(1,), bunches=(replace(packet.bunches[0], open=False,
                channel_sequence=234, payload=b'\x05opaque-local-fields', payload_bits=20*8),))
        self.assertEqual(probe.handle(self.incoming(incoming), PEER),
                         ('control_next_message_unimplemented', None))
        self.assertEqual(probe.peers[PEER].history, 2)
        self.assertEqual(probe.summary()['next_unimplemented_control_message_ids'], {5: 1})
        # A later consumed empty packet has history100b (the unknown packet
        # at bit1 remains explicitly undelivered).
        incoming = replace(incoming, sequence=1258, bunches=())
        _, response = probe.handle(self.incoming(incoming), PEER)
        self.assertEqual(self.response(response).history, (5,))
        self.assertFalse(probe.summary()['native_connection_completed'])

    def test_replay_reply_limit_and_explicit_peer_cleanup(self):
        probe = self.probe(max_replies=1)
        raw = b'opaque!!' + HELLO_BODIES[0]
        probe.handle(raw, PEER)
        self.assertEqual(probe.handle(raw, PEER), ('application_sequence_rejected', None))
        self.assertEqual(probe.handle(b'opaque!!' + HELLO_BODIES[1], PEER),
                         ('application_reply_limit_reached', None))
        probe.forget_peer(PEER)
        self.assertEqual(probe.handle(raw, PEER), ('application_without_verified_echo', None))
        self.assertNotIn(PEER, probe.control_peers)

    def test_real_udp_transport_uses_its_cookie_then_records_control_separately(self):
        with tempfile.TemporaryDirectory() as folder:
            with GameServerProbe(folder, handshake_probe=True, packet_ack_probe=True,
                                 control_probe=True, expected_net_version=1077088301) as server:
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
                    packet = self.packet()
                    packet = replace(packet, sequence=client_seed,
                        acknowledged_sequence=(server_seed-1)&16383,
                        bunches=(replace(packet.bunches[0],
                            channel_sequence=(client_seed+1)&1023),))
                    client.sendto(self.incoming(packet), address)
                    response, _ = client.recvfrom(1500)
                    response = self.response(response)
                    self.assertEqual(response.sequence, server_seed)
                    self.assertEqual(response.bunches[0].channel_sequence, (server_seed+1)&1023)
                    self.assertEqual(decode_messages(response.bunches[0].payload)[0].message_id, 3)
            report = json.loads((Path(folder)/'report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['handshake_datagrams_sent'], 2)
            self.assertEqual(report['native_control_datagrams_sent'], 1)
            self.assertEqual(report['empty_packet_ack_datagrams_sent'], 0)
            self.assertEqual(report['handshake_probe']['native_control_probe']['hello_consumed_peers'], 1)
            self.assertFalse(report['gameplay_server_implemented'])

    def test_expired_session_removes_reliable_channel_state(self):
        handshake = LegacyDSHandshakeProbe(packet_ack_probe=True, control_probe=True,
            expected_net_version=1077088301, verified_session_ttl=2, verified_idle_ttl=1)
        hello = b'opaque!!' + b'\x01' + bytes(23) + b'\x08'
        challenge = handshake.handle(hello, PEER, 0).response
        handshake.handle(b'opaque!!' + challenge, PEER, 0.1)
        self.assertIn(PEER, handshake.packet_ack_probe.control_peers)
        handshake.handle(b'opaque!!' + HELLO_BODIES[0], ('127.0.0.1', 54322), 2)
        self.assertNotIn(PEER, handshake.packet_ack_probe.peers)
        self.assertNotIn(PEER, handshake.packet_ack_probe.control_peers)


if __name__ == '__main__':
    unittest.main()
