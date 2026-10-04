import json
from pathlib import Path
import socket
import tempfile
import unittest

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_handshake_probe import LegacyDSHandshakeProbe
from dfserver.legacy_ds_packet_ack_probe import encode_empty_packet
from dfserver.unreal_handshake_payload import LegacyHandshakePayload, encode_payload, decode_payload


PEER = ('127.0.0.1', 54321)
INITIAL = b'opaque!!' + b'\x01' + bytes(23) + b'\x08'


def echo(response):
    return b'opaque!!' + response


def application(cookie, sequence_offset=0, ack_offset=-1):
    client = (int.from_bytes(cookie[2:4], 'little') + sequence_offset) & 0x3fff
    server = (int.from_bytes(cookie[:2], 'little') + ack_offset) & 0x3fff
    return b'opaque!!' + encode_empty_packet(client, server, 0)


def unknown_control(cookie):
    client = (int.from_bytes(cookie[2:4], 'little') + 1) & 0x3fff
    server = (int.from_bytes(cookie[:2], 'little') - 1) & 0x3fff
    packed = (client << 18) | (server << 4)
    return b'opaque!!' + ((packed << 1) | (1 << 65) | (1 << 211) | (1 << 212)).to_bytes(27, 'little')


class LegacyDSHandshakeProbeTests(unittest.TestCase):
    def verified_probe(self, **kwargs):
        probe = LegacyDSHandshakeProbe(packet_ack_probe=True, **kwargs)
        challenge = probe.handle(INITIAL, PEER, 0).response
        probe.handle(echo(challenge), PEER, 0.1)
        return probe, decode_payload(challenge).cookie, challenge

    def test_challenge_echo_and_ack_without_claiming_a_native_connection(self):
        probe = LegacyDSHandshakeProbe()
        first = probe.handle(INITIAL, PEER, 0)
        challenge = decode_payload(first.response)
        self.assertGreater(challenge.timestamp, 0)
        self.assertTrue(any(challenge.cookie))
        final = probe.handle(echo(first.response), PEER, 0.1)
        ack = decode_payload(final.response)
        self.assertEqual(ack.timestamp, -1)
        self.assertEqual(ack.cookie, challenge.cookie)
        self.assertTrue(ack.third_flag)
        self.assertFalse(ack.restart)
        self.assertEqual(probe.summary()['peers_with_verified_challenge_echo'], 1)
        self.assertFalse(probe.summary()['native_connection_completed'])
        self.assertNotIn(challenge.cookie.hex(), json.dumps(probe.summary()))

    def test_loss_retries_keep_the_same_challenge_and_repeat_ack(self):
        probe = LegacyDSHandshakeProbe()
        first = probe.handle(INITIAL, PEER, 1)
        repeat = probe.handle(INITIAL, PEER, 1.1)
        self.assertEqual(first.response, repeat.response)
        ack = probe.handle(echo(first.response), PEER, 1.2)
        repeat_ack = probe.handle(echo(first.response), PEER, 1.3)
        self.assertEqual(ack.response, repeat_ack.response)

    def test_echo_is_bound_to_peer_cookie_and_timestamp(self):
        probe = LegacyDSHandshakeProbe()
        challenge = decode_payload(probe.handle(INITIAL, PEER, 1).response)
        variants = [
            LegacyHandshakePayload(False, False, challenge.timestamp, bytes(20)),
            LegacyHandshakePayload(False, False, challenge.timestamp + 1, challenge.cookie),
            LegacyHandshakePayload(True, False, challenge.timestamp, challenge.cookie),
        ]
        for value in variants:
            self.assertIsNone(probe.handle(echo(encode_payload(value)), PEER, 1.1).response)
        good = echo(encode_payload(challenge))
        self.assertIsNone(probe.handle(good, ('127.0.0.1', PEER[1] + 1), 1.2).response)
        self.assertIsNotNone(probe.handle(good, PEER, 1.3).response)

    def test_expired_challenge_and_limits_cannot_authorize_an_echo(self):
        probe = LegacyDSHandshakeProbe(ttl=1, max_peers=1, max_replies=2)
        challenge = probe.handle(INITIAL, PEER, 1).response
        self.assertEqual(probe.handle(INITIAL, ('127.0.0.1', 54322), 1.1).event, 'peer_limit_reached')
        self.assertIsNone(probe.handle(echo(challenge), PEER, 2.1).response)
        fresh = probe.handle(INITIAL, PEER, 2.2).response
        self.assertNotEqual(challenge, fresh)
        self.assertIsNotNone(probe.handle(echo(fresh), PEER, 2.3).response)
        self.assertEqual(probe.handle(echo(fresh), PEER, 2.4).event, 'reply_limit_reached')

    def test_verified_peer_survives_original_challenge_expiry(self):
        probe, cookie, _ = self.verified_probe(ttl=1)
        decision = probe.handle(application(cookie), PEER, 31)
        self.assertEqual(decision.event, 'empty_packet_ack_prepared')
        self.assertIsNotNone(decision.response)
        self.assertEqual(probe.summary()['peers_with_verified_challenge_echo'], 1)
        self.assertFalse(probe.summary()['native_connection_completed'])

    def test_unique_accepted_activity_extends_idle_but_not_absolute_lifetime(self):
        probe, cookie, _ = self.verified_probe(ttl=1, verified_session_ttl=10, verified_idle_ttl=5)
        for offset, now in enumerate((4, 7, 10.05)):
            self.assertIsNotNone(probe.handle(application(cookie, offset), PEER, now).response)
        expired = probe.handle(application(cookie, 3), PEER, 10.2)
        self.assertEqual(expired.event, 'application_without_verified_echo')
        self.assertIsNone(expired.response)
        self.assertNotIn(PEER, probe.pending)
        self.assertNotIn(PEER, probe.packet_ack_probe.peers)

    def test_invalid_packets_and_handshake_retries_do_not_refresh_idle_lifetime(self):
        for kind in ('replay', 'malformed', 'future_ack', 'unknown_control', 'initial_retry', 'echo_retry'):
            with self.subTest(kind=kind):
                probe, cookie, challenge = self.verified_probe(
                    ttl=1, verified_session_ttl=30, verified_idle_ttl=5)
                self.assertIsNotNone(probe.handle(application(cookie), PEER, 1).response)
                retry = {
                    'replay': application(cookie),
                    'malformed': b'opaque!!' + bytes(10),
                    'future_ack': application(cookie, 1, 100),
                    'unknown_control': unknown_control(cookie),
                    'initial_retry': INITIAL,
                    'echo_retry': echo(challenge),
                }[kind]
                result = probe.handle(retry, PEER, 5)
                if kind not in ('initial_retry', 'echo_retry'):
                    self.assertIsNone(result.response)
                self.assertEqual(probe.pending[PEER].last_valid_activity_at, 1)
                self.assertEqual(probe.handle(application(cookie, 2), PEER, 6.01).event,
                                 'application_without_verified_echo')

    def test_verified_peers_keep_peer_and_handshake_response_limits(self):
        probe, _, challenge = self.verified_probe(ttl=1, max_peers=1, max_replies=2)
        self.assertEqual(probe.handle(INITIAL, ('127.0.0.1', 54322), 2).event, 'peer_limit_reached')
        self.assertEqual(probe.handle(echo(challenge), PEER, 2.1).event, 'reply_limit_reached')

    def test_reply_limit_does_not_keep_an_authenticated_peer_alive(self):
        probe, cookie, _ = self.verified_probe(ttl=1, verified_session_ttl=30, verified_idle_ttl=5)
        for offset in range(128):
            self.assertIsNotNone(probe.handle(application(cookie, offset), PEER, 1 + offset / 1000).response)
        self.assertEqual(probe.handle(application(cookie, 128), PEER, 2).event,
                         'application_reply_limit_reached')
        self.assertEqual(probe.pending[PEER].last_valid_activity_at, 1.127)
        self.assertEqual(probe.handle(application(cookie, 129), PEER, 6.2).event,
                         'application_without_verified_echo')

    def test_verified_lifetimes_are_finite_and_bounded(self):
        for value in (True, float('nan'), float('inf'), 0, 601):
            for name in ('verified_session_ttl', 'verified_idle_ttl'):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    LegacyDSHandshakeProbe(**{name: value})
        with self.assertRaises(ValueError):
            LegacyDSHandshakeProbe(verified_session_ttl=10, verified_idle_ttl=11)

    def test_no_reply_to_unsupported_or_non_loopback_inputs(self):
        probe = LegacyDSHandshakeProbe()
        for value in (b'', bytes(33), INITIAL[:-1], INITIAL + b'\0', INITIAL[8:]):
            self.assertIsNone(probe.handle(value, PEER, 1).response)
        self.assertIsNone(probe.handle(INITIAL, ('8.8.8.8', 54321), 1).response)
        self.assertEqual(probe.summary()['active_peer_count'], 0)

    def test_real_loopback_exchange_and_opt_in_default(self):
        with tempfile.TemporaryDirectory() as directory:
            with GameServerProbe(Path(directory), handshake_probe=True) as server:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(INITIAL, ('127.0.0.1', server.port))
                    challenge, _ = client.recvfrom(1024)
                    client.sendto(echo(challenge), ('127.0.0.1', server.port))
                    ack, _ = client.recvfrom(1024)
                    self.assertEqual(decode_payload(ack).timestamp, -1)
            report = json.loads((Path(directory)/'report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['handshake_datagrams_sent'], 2)
            self.assertEqual(report['handshake_probe']['peers_with_verified_challenge_echo'], 1)
            self.assertFalse(report['gameplay_server_implemented'])
        with tempfile.TemporaryDirectory() as directory:
            with GameServerProbe(Path(directory)) as server:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(0.25)
                    client.sendto(INITIAL, ('127.0.0.1', server.port))
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(1024)
