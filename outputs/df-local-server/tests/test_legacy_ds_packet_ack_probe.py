import json
from pathlib import Path
import socket
import tempfile
import unittest

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_packet_ack_probe import LegacyDSPacketAckProbe, decode_packet, encode_empty_packet
from dfserver.unreal_handshake_payload import decode_payload

PEER = ('127.0.0.1', 54321)
COOKIE = b'\x34\x12\x78\x16' + bytes(16)
SERVER, CLIENT = 0x1234, 0x1678


def incoming(sequence, ack=SERVER-1, history=0):
    return b'opaque!!' + encode_empty_packet(sequence & 0x3fff, ack & 0x3fff, history)


def control_payload(sequence):
    # Native 35-byte shape: 8 routing bytes, one handler bit, header/history,
    # 146 payload bits before the adjacent terminators. No credentials.
    packed = ((sequence & 0x3fff) << 18) | ((SERVER-1) << 4)
    return b'opaque!!' + ((packed << 1) | (1 << 65) | (1 << 211) | (1 << 212)).to_bytes(27, 'little')


class PacketAckProbeTests(unittest.TestCase):
    def probe(self, **kwargs):
        probe = LegacyDSPacketAckProbe(**kwargs)
        probe.register_verified_echo(PEER, COOKIE)
        return probe

    def test_empty_ack_binds_to_own_cookie_sequences_and_peer_reports_delivery(self):
        probe = self.probe()
        event, reply = probe.handle(incoming(CLIENT), PEER)
        self.assertEqual(event, 'empty_packet_ack_prepared')
        first = decode_packet(reply)
        self.assertEqual((first.sequence, first.acknowledged_sequence, first.history), (SERVER, CLIENT, (1,)))
        event, reply = probe.handle(incoming(CLIENT+1, SERVER, 1), PEER)
        self.assertEqual(event, 'empty_packet_ack_and_peer_delivery_observed')
        second = decode_packet(reply)
        self.assertEqual((second.sequence, second.acknowledged_sequence, second.history), (SERVER+1, CLIENT+1, (3,)))

    def test_control_payload_is_never_marked_delivered(self):
        probe = self.probe()
        event, reply = probe.handle(control_payload(CLIENT), PEER)
        self.assertEqual(event, 'control_payload_unimplemented')
        self.assertIsNone(reply)
        _, reply = probe.handle(incoming(CLIENT+1), PEER)
        self.assertEqual(decode_packet(reply).history, (1,))

    def test_missing_packets_are_naked_and_replays_future_acks_are_rejected(self):
        probe = self.probe()
        _, reply = probe.handle(incoming(CLIENT+2), PEER)
        self.assertEqual(decode_packet(reply).history, (1,))
        for raw in (incoming(CLIENT+2), incoming(CLIENT+1), incoming(CLIENT+3, SERVER+1)):
            self.assertEqual(probe.handle(raw, PEER), ('application_sequence_rejected', None))
        _, reply = probe.handle(incoming(CLIENT+3, SERVER, 1), PEER)
        self.assertEqual(decode_packet(reply).history, (3,))

    def test_sequence_wraparound_and_reply_bound(self):
        probe = self.probe(max_replies=2)
        probe.peers[PEER].in_sequence = 0x3ffe
        _, reply = probe.handle(incoming(0x3fff), PEER)
        self.assertEqual(decode_packet(reply).acknowledged_sequence, 0x3fff)
        _, reply = probe.handle(incoming(0), PEER)
        self.assertEqual(decode_packet(reply).acknowledged_sequence, 0)
        self.assertEqual(probe.handle(incoming(1), PEER), ('application_reply_limit_reached', None))

    def test_unverified_peer_and_malformed_packets_have_no_reply(self):
        probe = self.probe()
        self.assertIsNone(probe.handle(incoming(CLIENT), ('127.0.0.1', 54322))[1])
        bad = incoming(CLIENT)
        variants = (b'', bad[:-1], bad+b'\0', bad[:8]+bytes(10), bad[:8]+b'\xff'+bad[9:])
        for raw in variants:
            self.assertIsNone(probe.handle(raw, PEER)[1])
        self.assertEqual(probe.peers[PEER].replies, 0)
        _, good = probe.handle(bad, PEER)
        self.assertIsNotNone(good)

    def test_real_udp_probe_requires_cookie_echo_and_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            with GameServerProbe(Path(directory), handshake_probe=True, packet_ack_probe=True) as server:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    address = ('127.0.0.1', server.port)
                    client.sendto(b'opaque!!'+b'\x01'+bytes(23)+b'\x08', address)
                    challenge, _ = client.recvfrom(1024)
                    client.sendto(b'opaque!!'+challenge, address)
                    ack, _ = client.recvfrom(1024)
                    cookie = decode_payload(ack).cookie
                    cseq = int.from_bytes(cookie[2:4], 'little') & 0x3fff
                    sseq = int.from_bytes(cookie[0:2], 'little') & 0x3fff
                    client.sendto(incoming(cseq, sseq-1), address)
                    packet_ack, _ = client.recvfrom(1024)
                    self.assertEqual(decode_packet(packet_ack).sequence, sseq)
            report = json.loads((Path(directory)/'report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['empty_packet_ack_datagrams_sent'], 1)
            self.assertEqual(report['handshake_datagrams_sent'], 2)
            self.assertFalse(report['handshake_probe']['control_channel_implemented'])
        with self.assertRaises(ValueError):
            GameServerProbe('unused', packet_ack_probe=True)


if __name__ == '__main__':
    unittest.main()
