"""Source-qualified restart recovery; no client launch or privileged I/O."""
from dataclasses import asdict, replace
import json
import struct
import unittest
from unittest.mock import patch

from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_handshake_probe import LegacyDSHandshakeProbe
from dfserver.legacy_ds_match_admission import LocalMatchAdmissions
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from dfserver.unreal_handshake_payload import LegacyHandshakePayload, decode_payload, encode_payload
from tests.test_legacy_ds_actor_delivery import actor_fields
from tests.test_legacy_ds_control_connection import MAPS, login_payload
from tests.test_legacy_ds_control_probe import COOKIE, PEER
from tests.test_legacy_ds_wire_codec import HELLO_BODIES


PREFIX = b'opaque!!'
INITIAL = PREFIX + b'\x01' + bytes(23) + b'\x08'
RESTART_INITIAL = PREFIX + b'\x03' + bytes(23) + b'\x08'
FRESH_COOKIE = bytes(range(64, 84))
OTHER_PEER = ('127.0.0.1', PEER[1] + 1)
NET_VERSION = 1077088301


def independent_extended(*, timestamp=1.0, cookie=FRESH_COOKIE, old_cookie=COOKIE,
                         restart=True, third=False):
    # Literal field order, independent from codec arithmetic/cursor logic.
    fields = [(1, 1), (int(restart), 1), (int(third), 1)]
    fields += [(byte, 8) for byte in struct.pack('<f', timestamp) + cookie + old_cookie]
    fields.append((1, 1))
    bits = [bool(value & (1 << bit)) for value, width in fields for bit in range(width)]
    raw = bytearray(45)
    for offset, value in enumerate(bits):
        raw[offset // 8] |= int(value) << (offset % 8)
    return bytes(raw)


class RestartCodecTests(unittest.TestCase):
    def test_extended_echo_matches_independent_cross_byte_field_fixture(self):
        cookie, old = bytes(range(20)), bytes(range(20, 40))
        raw = independent_extended(timestamp=2.5, cookie=cookie, old_cookie=old)
        value = LegacyHandshakePayload(True, False, 2.5, cookie, old)
        self.assertEqual(len(raw), 45)
        self.assertEqual(decode_payload(raw), value)
        self.assertEqual(encode_payload(value), raw)
        # The oldcookie starts at195, not at a byte boundary or after padding.
        self.assertEqual((int.from_bytes(raw, 'little') >> 195) & ((1 << 160) - 1),
                         int.from_bytes(old, 'little'))
        self.assertEqual(raw[-1] & 0xf8, 0x08)

    def test_ordinary_fixture_and_dataclass_default_remain_byte_exact(self):
        value = LegacyHandshakePayload(False, False, 0, bytes(20))
        self.assertIsNone(value.old_cookie)
        self.assertEqual(encode_payload(value), INITIAL[8:])
        self.assertEqual(decode_payload(INITIAL[8:]), value)

    def test_extended_flags_sizes_termination_and_nonfinite_are_refused(self):
        raw = independent_extended()
        bad = (raw[:-1], raw + b'\0', raw[:-1] + bytes([raw[-1] ^ 8]),
               raw[:-1] + bytes([raw[-1] | 0x10]), independent_extended(restart=False),
               independent_extended(timestamp=float('nan')), bytearray(raw))
        for value in bad:
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                decode_payload(value)
        for old in (b'', bytes(19), bytes(21), bytearray(20)):
            with self.subTest(old_type=type(old).__name__), self.assertRaises(ValueError):
                encode_payload(LegacyHandshakePayload(True, False, 1, COOKIE, old))
        with self.assertRaises(ValueError):
            encode_payload(LegacyHandshakePayload(False, False, 1, COOKIE, COOKIE))


class RestartFlowFixture:
    def verified(self, **kwargs):
        probe = LegacyDSHandshakeProbe(packet_ack_probe=True, **kwargs)
        with patch('dfserver.legacy_ds_handshake_probe.secrets.token_bytes', return_value=COOKIE):
            challenge = probe.handle(INITIAL, PEER, 0).response
        self.assertEqual(probe.handle(PREFIX + challenge, PEER, 0.01).event,
                         'valid_challenge_echo_ack_prepared')
        return probe, challenge

    def start_restart(self, probe, now=1.0):
        with patch('dfserver.legacy_ds_handshake_probe.secrets.token_bytes', return_value=FRESH_COOKIE):
            result = probe.handle(RESTART_INITIAL, PEER, now)
        self.assertEqual(result.event, 'restart_challenge_reply_prepared')
        challenge = decode_payload(result.response)
        self.assertFalse(challenge.restart or challenge.third_flag)
        return challenge, PREFIX + encode_payload(replace(challenge, restart=True, old_cookie=COOKIE))


class SamePeerRestartTests(RestartFlowFixture, unittest.TestCase):
    def test_zero_cookie_initial_changes_no_generation_activity_or_transport(self):
        probe, _ = self.verified()
        generation, transport = probe.pending[PEER], probe.packet_ack_probe.peers[PEER]
        before = asdict(generation), asdict(transport)
        challenge, _ = self.start_restart(probe)
        self.assertEqual(challenge.cookie, FRESH_COOKIE)
        self.assertIs(probe.pending[PEER], generation)
        self.assertIs(probe.packet_ack_probe.peers[PEER], transport)
        self.assertEqual((asdict(generation), asdict(transport)), before)
        self.assertFalse(probe.restart_pending[PEER].completed)

    def test_verified_extended_echo_ack_keeps_seed_cookie_generation_and_state(self):
        probe, _ = self.verified()
        generation, transport = probe.pending[PEER], probe.packet_ack_probe.peers[PEER]
        before_generation, before_transport = asdict(generation), asdict(transport)
        _, echo = self.start_restart(probe)
        with patch.object(probe.packet_ack_probe, 'register_verified_echo') as register, \
                patch.object(probe.packet_ack_probe, 'forget_peer') as forget:
            result = probe.handle(echo, PEER, 1.1)
        self.assertEqual(result.event, 'valid_restart_echo_ack_prepared')
        self.assertEqual(decode_payload(result.response), LegacyHandshakePayload(False, True, -1, COOKIE))
        self.assertEqual(len(result.response), 25)
        register.assert_not_called()
        forget.assert_not_called()
        self.assertIs(probe.pending[PEER], generation)
        self.assertIs(probe.packet_ack_probe.peers[PEER], transport)
        self.assertEqual(asdict(transport), before_transport)
        self.assertEqual(asdict(generation), {**before_generation, 'last_valid_activity_at': 1.1})
        self.assertTrue(probe.restart_pending[PEER].completed)

    def test_wrong_old_fresh_cookie_time_flags_and_other_peer_do_not_commit(self):
        probe, _ = self.verified()
        challenge, good = self.start_restart(probe)
        generation = probe.pending[PEER]
        before = asdict(generation), asdict(probe.restart_pending[PEER])
        value = decode_payload(good[8:])
        bad = [replace(value, cookie=bytes(20)), replace(value, old_cookie=bytes(20)),
               replace(value, timestamp=challenge.timestamp + 1), replace(value, third_flag=True)]
        for candidate in bad:
            self.assertIsNone(probe.handle(PREFIX + encode_payload(candidate), PEER, 1.1).response)
        self.assertIsNone(probe.handle(good, OTHER_PEER, 1.1).response)
        self.assertIsNone(probe.handle(RESTART_INITIAL, OTHER_PEER, 1.1).response)
        self.assertEqual((asdict(generation), asdict(probe.restart_pending[PEER])), before)
        self.assertNotIn(OTHER_PEER, probe.pending)
        self.assertFalse(probe.summary()['cross_peer_restart_supported'])

    def test_rejects_unverified_zero_old_cookie_and_missing_transport(self):
        probe = LegacyDSHandshakeProbe(packet_ack_probe=True)
        probe.handle(INITIAL, PEER, 0)
        self.assertIsNone(probe.handle(RESTART_INITIAL, PEER, 0.1).response)
        probe, _ = self.verified()
        probe.pending[PEER].cookie = bytes(20)
        self.assertIsNone(probe.handle(RESTART_INITIAL, PEER, 0.1).response)
        probe, _ = self.verified()
        probe.packet_ack_probe.forget_peer(PEER)
        self.assertEqual(probe.handle(RESTART_INITIAL, PEER, 0.1).event, 'restart_transport_missing')
        handshake_only = LegacyDSHandshakeProbe()
        challenge = handshake_only.handle(INITIAL, PEER, 0).response
        handshake_only.handle(PREFIX + challenge, PEER, 0.01)
        self.assertEqual(handshake_only.handle(RESTART_INITIAL, PEER, 0.1).event,
                         'restart_transport_missing')
        self.assertEqual(handshake_only.restart_pending, {})

    def test_initial_and_completed_replays_keep_nonce_deadline_and_activity(self):
        probe, _ = self.verified()
        challenge, echo = self.start_restart(probe)
        repeat = probe.handle(RESTART_INITIAL, PEER, 1.01)
        self.assertEqual(decode_payload(repeat.response), challenge)
        self.assertEqual(probe.restart_pending[PEER].issued_at, 1)
        first_ack = probe.handle(echo, PEER, 1.1)
        self.assertEqual(probe.handle(echo, PEER, 1.2).response, first_ack.response)
        self.assertEqual(probe.pending[PEER].last_valid_activity_at, 1.1)
        # No request-id distinguishes a fresh zero-cookie initial from a replay.
        completed_initial = probe.handle(RESTART_INITIAL, PEER, 1.3)
        self.assertEqual(decode_payload(completed_initial.response), challenge)
        duplicate = probe.handle(echo, PEER, 1.4)
        self.assertEqual(duplicate.event, 'restart_echo_retry_ack_prepared')
        self.assertEqual(probe.restart_pending[PEER].issued_at, 1)
        self.assertEqual(probe.pending[PEER].last_valid_activity_at, 1.1)

    def test_delayed_ordinary_echo_cannot_skip_restart_verification(self):
        probe, original_challenge = self.verified()
        self.start_restart(probe)
        before = asdict(probe.pending[PEER])
        with patch.object(probe.packet_ack_probe, 'register_verified_echo') as register:
            result = probe.handle(PREFIX + original_challenge, PEER, 1.1)
        self.assertEqual((result.event, result.response), ('restart_requires_extended_echo', None))
        self.assertEqual(asdict(probe.pending[PEER]), before)
        register.assert_not_called()

    def test_fresh_challenge_expiry_does_not_replace_or_revoke_old_session(self):
        probe, _ = self.verified(ttl=1)
        generation = probe.pending[PEER]
        _, echo = self.start_restart(probe, now=1)
        self.assertIsNone(probe.handle(echo, PEER, 2).response)
        self.assertNotIn(PEER, probe.restart_pending)
        self.assertIs(probe.pending[PEER], generation)
        self.assertEqual(generation.last_valid_activity_at, 0.01)
        self.assertIn(PEER, probe.packet_ack_probe.peers)

    def test_session_expiry_clears_restart_and_cannot_revive_peer(self):
        probe, _ = self.verified(verified_session_ttl=2, verified_idle_ttl=2)
        _, echo = self.start_restart(probe)
        self.assertIsNone(probe.handle(echo, PEER, 2.011).response)
        self.assertNotIn(PEER, probe.pending)
        self.assertNotIn(PEER, probe.restart_pending)
        self.assertNotIn(PEER, probe.packet_ack_probe.peers)
        self.assertIsNone(probe.handle(RESTART_INITIAL, PEER, 2.1).response)

    def test_duplicate_echo_cannot_extend_idle_or_absolute_lifetime(self):
        probe, _ = self.verified(verified_session_ttl=4, verified_idle_ttl=2)
        _, echo = self.start_restart(probe)
        probe.handle(echo, PEER, 1.1)
        probe.handle(echo, PEER, 2.9)
        self.assertEqual(probe.pending[PEER].last_valid_activity_at, 1.1)
        self.assertIsNone(probe.handle(echo, PEER, 3.1).response)
        self.assertNotIn(PEER, probe.pending)

    def test_restart_reply_budget_bounds_completed_echo_replay(self):
        probe, _ = self.verified(max_replies=2)
        _, echo = self.start_restart(probe)
        self.assertIsNotNone(probe.handle(echo, PEER, 1.1).response)
        self.assertEqual(probe.handle(echo, PEER, 1.2).event, 'restart_reply_limit_reached')
        self.assertEqual(probe.handle(RESTART_INITIAL, PEER, 1.3).event, 'restart_reply_limit_reached')
        self.assertEqual(probe.pending[PEER].last_valid_activity_at, 1.1)


class RestartControlActorIntegrationTests(RestartFlowFixture, unittest.TestCase):
    def setup_joined(self):
        self.clock = [0.0]
        admissions = LocalMatchAdmissions(clock=lambda: self.clock[0])
        ticket = admissions.issue(101, 201, 2201, 142201103, 88000000025)
        probe, _ = self.verified(control_probe=True, control_admissions=admissions,
            control_welcome_maps=MAPS, expected_net_version=NET_VERSION)
        self.probe, self.ticket = probe, ticket
        self.connection = probe.packet_ack_probe
        self.template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        self.send(encode_message(0, 1, NET_VERSION, ''), now=0.02)
        self.send(login_payload(ticket), now=0.03)
        self.send(encode_message(4, 25000) + encode_message(9), now=0.04)
        self.assertTrue(self.connection.control_peers[PEER].client_join_observed)
        self.connection.queue_actor_open(PEER, **actor_fields(channel_index=4))
        first = self.probe.poll(0.1)
        self.assertEqual(len(first), 1)
        self.first_actor = decode_observed_application(first[0][2],
            max_packet_bytes=1024, received_by_server=False)

    def send(self, payload=None, *, now, history=(1,), close=False):
        transport, state = self.connection.peers[PEER], self.connection.control_peers[PEER]
        bunches = ()
        if payload is not None or close:
            bunches = (replace(self.template.bunches[0], open=not state.hello_received,
                close=close, channel_sequence=state.expected_client_sequence,
                payload=payload or b'', payload_bits=len(payload or b'') * 8),)
        packet = replace(self.template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383,
            history=history, bunches=bunches)
        return self.probe.handle(PREFIX + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), PEER, now)

    def test_join_queued_pawn_generation_ticket_exact_ack_and_retry_survive_restart(self):
        self.setup_joined()
        generation = self.probe.pending[PEER]
        registration = {'generation': generation}  # GameServerProbe stores this exact identity.
        transport, control = self.connection.peers[PEER], self.connection.control_peers[PEER]
        actor = control.actor_opens[4]
        before = asdict(transport), asdict(control), dict(self.connection.ticket_peers)
        authorized = self.connection.admissions.summary()['authorized_login_count']
        _, echo = self.start_restart(self.probe)
        self.assertIsNotNone(self.probe.handle(echo, PEER, 1.1).response)
        self.assertIs(registration['generation'], self.probe.pending[PEER])
        self.assertIs(self.connection.peers[PEER], transport)
        self.assertIs(self.connection.control_peers[PEER], control)
        self.assertIs(control.actor_opens[4], actor)
        self.assertIs(control.ticket, self.ticket)
        self.assertEqual((asdict(transport), asdict(control), dict(self.connection.ticket_peers)), before)
        self.assertEqual(self.connection.admissions.summary()['authorized_login_count'], authorized)
        retry = self.probe.poll(1.2)
        self.assertEqual(len(retry), 1)
        retry_packet = decode_observed_application(retry[0][2],
            max_packet_bytes=1024, received_by_server=False)
        self.assertEqual(retry_packet.sequence, (self.first_actor.sequence + 1) & 16383)
        self.assertEqual(retry_packet.bunches[0], self.first_actor.bunches[0])
        self.assertEqual(actor.transmissions, 2)
        self.assertFalse(actor.delivered)
        # A nonmatching ACK history bit cannot deliver the Pawn.
        self.assertIsNone(self.send(now=1.3, history=(1 << 10,)).response)
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)
        self.assertIsNone(self.send(now=1.4, history=(1,)).response)
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 1)
        self.assertEqual(self.probe.poll(2.0), [])

    def test_ticket_expiry_or_changed_owner_rejects_initial_and_echo(self):
        for restriction in ('inactive', 'other_owner'):
            with self.subTest(restriction=restriction):
                self.setup_joined()
                generation = self.probe.pending[PEER]
                _, echo = self.start_restart(self.probe)
                if restriction == 'inactive':
                    self.clock[0] = 120.0
                else:
                    self.connection.ticket_peers[self.ticket.cookie] = OTHER_PEER
                activity = generation.last_valid_activity_at
                self.assertIsNone(self.probe.handle(echo, PEER, 1.1).response)
                self.assertIsNone(self.probe.handle(RESTART_INITIAL, PEER, 1.2).response)
                self.assertIs(self.probe.pending[PEER], generation)
                self.assertEqual(generation.last_valid_activity_at, activity)
                self.assertFalse(self.probe.restart_pending[PEER].completed)

    def test_closed_connection_rejects_both_restart_forms_without_resurrection(self):
        self.setup_joined()
        generation = self.probe.pending[PEER]
        _, echo = self.start_restart(self.probe)
        self.assertEqual(self.send(close=True, now=1.05, history=(0,)).event,
                         'control_client_close_consumed')
        state = self.connection.control_peers[PEER]
        activity = generation.last_valid_activity_at
        self.assertTrue(state.client_closed)
        self.assertEqual(self.probe.handle(echo, PEER, 1.1).event, 'restart_client_closed')
        self.assertEqual(self.probe.handle(RESTART_INITIAL, PEER, 1.2).event, 'restart_client_closed')
        self.assertIs(self.probe.pending[PEER], generation)
        self.assertEqual(generation.last_valid_activity_at, activity)
        self.assertEqual(self.probe.poll(2.0), [])
        self.assertNotIn(self.ticket.cookie, self.connection.ticket_peers)
        self.assertFalse(self.probe.restart_pending[PEER].completed)
        summary = json.dumps(self.probe.summary())
        self.assertNotIn(COOKIE.hex(), summary)
        self.assertNotIn(FRESH_COOKIE.hex(), summary)
