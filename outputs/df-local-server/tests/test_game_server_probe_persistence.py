"""Bounded disk persistence must not hold up the shared UDP receiver.

All clients below are independent synthetic loopback sockets, not the game.
Event gates make disk stalls deterministic; no fixed sleeps or live DS port.
"""
import hashlib
from dataclasses import replace
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from dfserver.game_server_probe import GameServerProbe
from dfserver.unreal_handshake_payload import LegacyHandshakePayload, encode_payload, decode_payload
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from tests.test_legacy_ds_actor_bootstrap import manifest
from tests.test_legacy_ds_control_connection import MAPS, login_payload
from tests.test_legacy_ds_control_probe import COOKIE
from tests.test_legacy_ds_wire_codec import HELLO_BODIES


INITIAL = b'opaque!!' + encode_payload(
    LegacyHandshakePayload(False, False, 0.0, bytes(20)))


class DiskGate:
    def __init__(self, original, *, report=False):
        self.original = original
        self.report = report
        self.entered = threading.Event()
        self.released = threading.Event()
        self.once = False

    def write(self, path, *args, **kwargs):
        target = path.name == 'report.json.tmp' if self.report else path.name == '01-udp.bin'
        if target and not self.once:
            self.once = True
            self.entered.set()
            if not self.released.wait(3):
                raise AssertionError('Disk test gate was not released')
        return self.original(path, *args, **kwargs)


class ProbePersistenceTests(unittest.TestCase):
    def make_probe(self, *, max_packets=8, **kwargs):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        probe = GameServerProbe(folder.name, handshake_probe=True, max_packets=max_packets, **kwargs)
        self.addCleanup(probe.close)
        probe.start()
        return probe

    def two_clients(self):
        clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        for client in clients:
            client.bind(('127.0.0.1', 0))
            client.settimeout(.7)
            self.addCleanup(client.close)
        return clients

    def exercise_gate(self, *, report):
        probe = self.make_probe()
        clients = self.two_clients()
        original = Path.write_text if report else Path.write_bytes
        gate = DiskGate(original, report=report)
        self.addCleanup(gate.released.set)
        method = 'write_text' if report else 'write_bytes'
        with patch.object(Path, method, autospec=True, side_effect=gate.write):
            try:
                clients[0].sendto(INITIAL, ('127.0.0.1', probe.port))
                self.assertTrue(gate.entered.wait(3), 'Synthetic disk stall did not start')
                first = clients[0].recvfrom(2048)[0]
                # A second peer must still get a challenge before disk is released.
                clients[1].sendto(INITIAL, ('127.0.0.1', probe.port))
                second = clients[1].recvfrom(2048)[0]
                self.assertEqual((len(first), len(second)), (25, 25))
                self.assertFalse(gate.released.is_set())
                self.assertTrue(probe.listening)
                self.assertEqual(len(probe._handshake.pending), 2)
                # An old on-disk snapshot must never advertise a missing raw file.
                snapshot = json.loads((probe.capture_dir / 'report.json').read_text(encoding='utf-8'))
                for record in snapshot['records']:
                    self.assertTrue((probe.capture_dir / record['private_packet_file']).is_file())
            finally:
                gate.released.set()
        self.assertTrue(probe.flush(timeout=3))
        probe.close()
        report_data = json.loads((probe.capture_dir / 'report.json').read_text(encoding='utf-8'))
        self.assertFalse(report_data['listening'])
        self.assertEqual(report_data['udp_receive_state'], 'stopped')
        self.assertFalse(report_data['udp_receive_thread_alive'])
        self.assertEqual(len(report_data['records']), 4)
        for record in report_data['records']:
            payload = (probe.capture_dir / record['private_packet_file']).read_bytes()
            self.assertEqual(record['bytes'], len(payload))
            self.assertEqual(record['sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(report_data['packet_persistence']['pending_records'], 0)
        self.assertEqual(report_data['packet_persistence']['state'], 'stopped')

    def test_blocked_raw_capture_keeps_both_peer_challenges_responsive(self):
        self.exercise_gate(report=False)

    def test_blocked_report_publish_keeps_both_peer_challenges_responsive(self):
        self.exercise_gate(report=True)

    def test_capture_queue_remains_bounded_and_zero_timeout_flush_is_honest(self):
        probe = self.make_probe()
        client = self.two_clients()[0]
        gate = DiskGate(Path.write_bytes)
        self.addCleanup(gate.released.set)
        with patch.object(Path, 'write_bytes', autospec=True, side_effect=gate.write):
            try:
                for _ in range(6):
                    client.sendto(INITIAL, ('127.0.0.1', probe.port))
                    self.assertEqual(len(client.recvfrom(2048)[0]), 25)
                self.assertTrue(gate.entered.wait(3))
                self.assertEqual(len(probe.records), 8)
                with probe._persistence_condition:
                    self.assertLessEqual(len(probe._persistence_queue), probe.max_packets)
                self.assertFalse(probe.flush(timeout=0))
                self.assertEqual(probe.persistence_status['pending_records'], 8)
            finally:
                gate.released.set()
        self.assertTrue(probe.flush(timeout=3))
        self.assertEqual(probe.persistence_status['pending_records'], 0)

    def test_failed_raw_write_is_visible_without_stopping_shared_udp(self):
        probe = self.make_probe()
        clients = self.two_clients()
        original = Path.write_bytes

        def fail_first(path, payload):
            if path.name == '01-udp.bin':
                raise OSError(5, 'private-disk-error-do-not-publish')
            return original(path, payload)

        with patch.object(Path, 'write_bytes', autospec=True, side_effect=fail_first):
            for client in clients:
                client.sendto(INITIAL, ('127.0.0.1', probe.port))
                self.assertEqual(len(client.recvfrom(2048)[0]), 25)
            self.assertFalse(probe.flush(timeout=3))
            self.assertTrue(probe.listening)
        probe.close()
        raw = (probe.capture_dir / 'report.json').read_text(encoding='utf-8')
        self.assertNotIn('private-disk-error', raw)
        saved = json.loads(raw)
        self.assertEqual(saved['packet_persistence']['failed_records'], 1)
        self.assertEqual(saved['packet_persistence']['pending_records'], 0)
        self.assertEqual(saved['packet_persistence']['failure'],
                         {'phase': 'packet', 'error_type': 'OSError', 'error_code': 5})
        self.assertFalse(saved['listening'])
        self.assertIsNone(saved['udp_receive_failure'])
        self.assertEqual(len(saved['records']), 3)
        self.assertNotIn('01-udp.bin', [r['private_packet_file'] for r in saved['records']])

    def test_failed_report_write_is_retried_on_next_request_and_failure_is_visible(self):
        probe = self.make_probe()
        client = self.two_clients()[0]
        original = Path.write_text
        failed = threading.Event()

        def fail_once(path, text, *args, **kwargs):
            if path.name == 'report.json.tmp' and not failed.is_set():
                failed.set()
                raise OSError(5, 'private-publish-error')
            return original(path, text, *args, **kwargs)

        with patch.object(Path, 'write_text', autospec=True, side_effect=fail_once):
            client.sendto(INITIAL, ('127.0.0.1', probe.port))
            self.assertEqual(len(client.recvfrom(2048)[0]), 25)
            self.assertTrue(failed.wait(3))
            self.assertFalse(probe.flush(timeout=3))  # Failure is not silently forgotten.
            self.assertTrue(probe.listening)
        probe.close()
        raw = (probe.capture_dir / 'report.json').read_text(encoding='utf-8')
        self.assertNotIn('private-publish-error', raw)
        report = json.loads(raw)
        self.assertEqual(report['packet_persistence']['failure']['phase'], 'report')
        self.assertEqual(report['packet_persistence']['pending_records'], 0)
        self.assertEqual(len(report['records']), 2)

    def test_close_is_idempotent_and_rejects_late_records(self):
        probe = self.make_probe()
        client = self.two_clients()[0]
        client.sendto(INITIAL, ('127.0.0.1', probe.port))
        self.assertEqual(len(client.recvfrom(2048)[0]), 25)
        probe.close()
        requested = probe._report_requested
        records = probe.records
        self.assertTrue(probe.flush(timeout=0))
        probe.close()
        self.assertEqual(probe._report_requested, requested)
        self.assertIsNone(probe._record('udp', b'late-after-close'))
        self.assertEqual(probe.records, records)
        self.assertEqual(len(probe._persistence_queue), 0)
        self.assertEqual(probe.persistence_status['pending_records'], 0)
        self.assertFalse(probe._persistence_thread.is_alive())

    def test_invalid_flush_timeouts_are_rejected(self):
        probe = self.make_probe()
        for value in (True, -1, 31, float('nan'), float('inf'), '3'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                probe.flush(timeout=value)

    def test_noninteger_or_nonfinite_capture_limits_cannot_remove_the_queue_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            for value in (True, 1.5, float('nan'), float('inf')):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    GameServerProbe(folder, max_packets=value)

    def test_record_racing_close_cannot_leave_pending_work_for_a_stopped_writer(self):
        probe = self.make_probe()
        hashing = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        original = hashlib.sha256
        result = []

        def hash_gate(payload):
            if payload == b'late-racing-close':
                hashing.set()
                if not release.wait(3):
                    raise AssertionError('Hash test gate was not released')
            return original(payload)

        with patch('dfserver.game_server_probe.hashlib.sha256', side_effect=hash_gate):
            recorder = threading.Thread(target=lambda: result.append(
                probe._record('udp', b'late-racing-close')))
            recorder.start()
            self.assertTrue(hashing.wait(3))
            closer = threading.Thread(target=probe.close)
            closer.start()
            try:
                self.assertTrue(probe._stop.wait(3))
            finally:
                release.set()
            recorder.join(3)
            closer.join(3)
        self.assertFalse(recorder.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertEqual(result, [None])
        self.assertEqual(probe.records, [])
        self.assertEqual(probe.persistence_status['pending_records'], 0)
        self.assertEqual(len(probe._persistence_queue), 0)
        self.assertTrue(probe.flush(timeout=0))

    def test_integrated_control_actor_queue_timer_summary_and_io_use_one_peer_clock(self):
        probe = self.make_probe(max_packets=32, packet_ack_probe=True, control_probe=True,
                                expected_net_version=1077088301, control_welcome_maps=MAPS)
        # A delayed lobby startup is not the absolute monotonic clock used by admissions.
        probe._started_at = time.monotonic() - 250
        probe.set_initial_actor_manifests(2201, (replace(manifest(), channel_index=4),))
        ticket = probe.issue_match_admission(player_id=101, room_id=201,
            map_id=2201, match_mode_id=142201103, selected_hero_id=88000000025)
        connection = probe._handshake.packet_ack_probe
        ack_consumed = threading.Event()
        original_handle = connection.handle

        def observed_handle(*args, **kwargs):
            result = original_handle(*args, **kwargs)
            if result[0] == 'control_ack_only_consumed':
                ack_consumed.set()
            return result

        connection.handle = observed_handle
        client = self.two_clients()[0]
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)

        def send(sequence, ack, channel_sequence=None, payload=b'', history=(1,)):
            bunches = () if channel_sequence is None else (replace(template.bunches[0],
                open=False, channel_sequence=channel_sequence, payload=payload,
                payload_bits=len(payload) * 8),)
            body = encode_observed_application(replace(template, sequence=sequence,
                acknowledged_sequence=ack, history=history, bunches=bunches),
                max_packet_bytes=1024, received_by_server=True)
            client.sendto(b'opaque!!' + body, ('127.0.0.1', probe.port))

        with patch('dfserver.legacy_ds_handshake_probe.secrets.token_bytes',
                   side_effect=lambda size: COOKIE if size == 20 else bytes(size)):
            client.sendto(INITIAL, ('127.0.0.1', probe.port))
            challenge = decode_payload(client.recvfrom(2048)[0])
            client.sendto(b'opaque!!' + encode_payload(challenge), ('127.0.0.1', probe.port))
            self.assertEqual(decode_payload(client.recvfrom(2048)[0]).timestamp, -1.0)
            client.sendto(b'opaque!!' + HELLO_BODIES[0], ('127.0.0.1', probe.port))
            hello_reply = decode_observed_application(client.recvfrom(2048)[0],
                max_packet_bytes=1024, received_by_server=False)
            self.assertEqual(hello_reply.sequence, 216)
            send(1257, 216, 234, login_payload(ticket))
            self.assertEqual(decode_observed_application(client.recvfrom(2048)[0],
                max_packet_bytes=1024, received_by_server=False).sequence, 217)
            send(1258, 217, 235, encode_message(4, 25000) + encode_message(9))
            replies = [decode_observed_application(client.recvfrom(2048)[0],
                max_packet_bytes=1024, received_by_server=False) for _ in range(2)]
            actor_packet = next(packet for packet in replies if packet.bunches)
            self.assertEqual(actor_packet.bunches[0].channel_index, 4)
            peer = client.getsockname()
            last_activity = probe._handshake.pending[peer].last_valid_activity_at
            # Advance the shared relative time enough for a lost Actor retry;
            # absolute admission time deliberately remains in its own domain.
            probe._started_at -= 1
            probe._send_control_retries()
            retry = decode_observed_application(client.recvfrom(2048)[0],
                max_packet_bytes=1024, received_by_server=False)
            self.assertEqual(retry.bunches, actor_packet.bunches)
            self.assertEqual(probe._handshake.pending[peer].last_valid_activity_at, last_activity)
            actor_packet = retry
            send(1259, actor_packet.sequence, history=(7,))
            self.assertTrue(ack_consumed.wait(3))
        self.assertTrue(probe.flush(timeout=3))
        progress = probe.actor_transport_progress
        self.assertEqual(progress['fully_delivered_sets'], 1)
        self.assertEqual(progress['delivery_acks'], 1)
        self.assertEqual(connection.control_events['actor_open_timer_retransmit_prepared'], 1)
        self.assertFalse(progress['native_spawn_verified'])
        peer = client.getsockname()
        self.assertIn(peer, probe._handshake.pending)
        self.assertIn(peer, connection.peers)
        self.assertIn(peer, connection.control_peers)
        probe._send_control_retries()
        probe._write_report()
        self.assertIn(peer, probe._handshake.pending)
        self.assertEqual(connection.control_events['application_without_verified_echo'], 0)
        saved = json.loads((probe.capture_dir / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual(saved['handshake_probe']['native_control_probe']['login_authorized_peers'], 1)
        self.assertTrue(any(r.get('decision') == 'control_join_ack_prepared'
                            for r in saved['records']))


if __name__ == '__main__':
    unittest.main()
