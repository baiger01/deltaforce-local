"""Private rolling diagnostics retain late admitted traffic without changing ACKs."""
import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_wire_codec import encode_observed_application
from tests import test_admitted_actor_reliable_receipts as receipts
from tests.test_legacy_ds_control_connection import MAPS
from tests.test_legacy_ds_control_probe import PEER


class AdmittedCaptureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = receipts.AdmittedActorReceiptTests()
        self.fixture.setUp()
        self.fixture.deliver()
        self.fixture.enable()
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.probe = GameServerProbe(self.folder.name, max_packets=1, handshake_probe=True,
            packet_ack_probe=True, control_probe=True, expected_net_version=1077088301,
            control_welcome_maps=MAPS, require_initial_actor_profile=True)
        self.addCleanup(self.probe.close)
        self.probe._admissions = self.fixture.connection.admissions
        self.probe._handshake.packet_ack_probe = self.fixture.connection
        self.probe._handshake.pending[PEER] = self.fixture.generation

    def record(self, ordinal, *, reject=False, now=None):
        state = self.fixture.state()
        transport = self.fixture.connection.peers[PEER]
        packet = replace(self.fixture.fixture.template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383, history=(0,),
            bunches=(self.fixture.bunch(14 if reject else 4,
                (self.fixture.seed + ordinal) % 1024),))
        payload = b'opaque!!' + encode_observed_application(packet, max_packet_bytes=1024,
            received_by_server=True)
        owner = self.probe._actual_application_send_owner_locked(PEER)
        event, _ = self.fixture.connection.handle(payload, PEER, .5 + ordinal * .01,
            verified_generation=self.fixture.generation)
        with self.probe._lock:
            self.probe._record_admitted_receipt_locked(payload, PEER, event, owner,
                now=ordinal * 5. if now is None else now)
        return payload

    def test_late_recent_rejected_and_phase_samples_are_bounded_and_private(self):
        self.probe._record('udp', b'first')
        for ordinal in range(900):
            last = self.record(ordinal, reject=True)
        self.assertTrue(self.probe.flush(timeout=5))
        data = json.loads((Path(self.folder.name) / 'admitted-receipt-private.json').read_text())
        rows = data['records']
        self.assertLessEqual(len(rows), 384)
        self.assertLessEqual(sum(r['bytes'] for r in rows), 384 * 1032)
        self.assertEqual(data['observed_packets'], 900)
        self.assertEqual(data['rejection_reasons'], {'actor_channel_outside_owned_namespace': 900})
        self.assertTrue(any(r['elapsed_seconds'] > 4400 for r in rows))
        self.assertTrue(any(r['sample'] == 'phase' and r['elapsed_seconds'] < 3000 for r in rows))
        newest = max(rows, key=lambda r: r['number'])
        self.assertEqual(base64.b64decode(newest['payload_base64']), last)
        self.assertEqual(newest['sha256'], hashlib.sha256(last).hexdigest())
        public = json.loads((Path(self.folder.name) / 'report.json').read_text())
        self.assertEqual(len(public['records']), 1)
        self.assertEqual(public['admitted_receipt_capture']['observed_packets'], 900)
        self.assertNotIn('payload_base64', json.dumps(public))
        self.assertNotIn('opaque!!', json.dumps(public))

    def test_disabled_mode_and_foreign_owner_cannot_record_and_new_epoch_resets(self):
        self.record(0, reject=True)
        with self.probe._lock:
            self.probe._record_admitted_receipt_locked(b'private-token', PEER, 'unsafe-secret',
                (replace(self.fixture.generation), self.fixture.ticket,
                    self.fixture.connection.peers[PEER]), now=1.)
        self.assertEqual(self.probe._admitted_receipt_capture['observed_packets'], 1)
        self.probe._require_initial_actor_profile = False
        self.record(1, reject=True)
        self.assertEqual(self.probe._admitted_receipt_capture['observed_packets'], 1)
        self.probe._require_initial_actor_profile = True
        # A different exact ticket object belongs to another epoch, even if its
        # values compare equal. No old raw bodies or counters enter the new one.
        other = receipts.AdmittedActorReceiptTests()
        other.setUp()
        other.deliver()
        other.enable()
        self.fixture = other
        self.probe._admissions = other.connection.admissions
        self.probe._handshake.packet_ack_probe = other.connection
        self.probe._handshake.pending[PEER] = other.generation
        self.record(2, reject=True)
        capture = self.probe._admitted_receipt_capture
        self.assertEqual(capture['epoch'], 2)
        self.assertEqual(capture['observed_packets'], 1)
        self.assertEqual(len(capture['recent']), 1)
        self.assertEqual(capture['rejection_reasons'], {'actor_channel_outside_owned_namespace': 1})

    def test_stalled_private_snapshot_keeps_newest_packet_without_growing_queue(self):
        self.record(0, reject=True)
        entered, released = threading.Event(), threading.Event()
        self.addCleanup(released.set)
        original = Path.write_text

        def gated_write(path, *args, **kwargs):
            if path.name == 'admitted-receipt-private.json.tmp' and not entered.is_set():
                entered.set()
                if not released.wait(5):
                    raise AssertionError('Private journal disk gate was not released')
            return original(path, *args, **kwargs)

        with patch.object(Path, 'write_text', autospec=True, side_effect=gated_write):
            self.assertFalse(self.probe.flush(timeout=0))
            self.assertTrue(entered.wait(3))
            for ordinal in range(1, 500):
                self.record(ordinal, reject=True)
            with self.probe._persistence_condition:
                self.assertEqual(len(self.probe._persistence_queue), 0)
            capture = self.probe._admitted_receipt_capture
            self.assertEqual(capture['observed_packets'], 500)
            self.assertLessEqual(sum(len(capture[key]) for key in ('recent', 'rejected', 'phase')), 384)
            released.set()
            self.assertTrue(self.probe.flush(timeout=5))
        saved = json.loads((Path(self.folder.name) / 'admitted-receipt-private.json').read_text())
        self.assertEqual(saved['observed_packets'], 500)

    def test_private_disk_failure_reports_only_type_and_code_and_retries_snapshot(self):
        self.record(0, reject=True)
        original = Path.write_text
        failed = threading.Event()

        def fail_once(path, *args, **kwargs):
            if path.name == 'admitted-receipt-private.json.tmp' and not failed.is_set():
                failed.set()
                raise OSError(5, 'private-token-must-not-be-published')
            return original(path, *args, **kwargs)

        with patch.object(Path, 'write_text', autospec=True, side_effect=fail_once):
            self.assertFalse(self.probe.flush(timeout=3))
            self.assertTrue(failed.is_set())
            self.assertFalse(self.probe.flush(timeout=3))
        public_text = (Path(self.folder.name) / 'report.json').read_text()
        self.assertNotIn('private-token', public_text)
        public = json.loads(public_text)
        self.assertEqual(public['packet_persistence']['failure'],
            {'phase': 'report', 'error_type': 'OSError', 'error_code': 5})
        self.assertTrue((Path(self.folder.name) / 'admitted-receipt-private.json').is_file())

    def test_receive_integration_records_accepted_and_rejected_after_base_cap(self):
        from types import SimpleNamespace
        self.probe._udp.close()
        self.probe._udp = SimpleNamespace(sendto=lambda data, peer: len(data), close=lambda: None)
        self.probe._send_control_retries = lambda: None
        for ordinal, channel in enumerate((4, 14)):
            transport = self.fixture.connection.peers[PEER]
            packet = replace(self.fixture.fixture.template,
                sequence=(transport.in_sequence + 1) & 16383,
                acknowledged_sequence=(transport.out_sequence - 1) & 16383,
                history=(0,), bunches=(self.fixture.bunch(channel),))
            raw = b'opaque!!' + encode_observed_application(packet, max_packet_bytes=1024,
                received_by_server=True)
            self.probe._handle_udp_datagram(raw, PEER)
        self.assertTrue(self.probe.flush(timeout=3))
        capture = self.probe._admitted_receipt_capture
        self.assertEqual(capture['observed_packets'], 2)
        self.assertEqual(capture['events'], {'admitted_actor_reliable_packet_received': 1,
            'admitted_actor_reliable_packet_rejected': 1})
        self.assertEqual(capture['rejection_reasons'], {'actor_channel_outside_owned_namespace': 1})
        self.assertEqual(len(self.probe.records), 1)

    def test_sequence_rejection_keeps_exact_private_gate_cursors(self):
        transport = self.fixture.connection.peers[PEER]
        for ordinal, future_ack in enumerate((False, True)):
            packet = replace(self.fixture.fixture.template,
                sequence=(transport.in_sequence + (1 if future_ack else 100)) & 16383,
                acknowledged_sequence=(transport.out_sequence if future_ack else
                    transport.out_sequence - 1) & 16383,
                history=(1,), bunches=())
            raw = b'opaque!!' + encode_observed_application(packet, max_packet_bytes=1024,
                received_by_server=True)
            owner = self.probe._actual_application_send_owner_locked(PEER)
            before = (transport.in_sequence, transport.out_sequence, transport.acknowledged_out_sequence)
            event, response = self.fixture.connection.handle(raw, PEER, .5 + ordinal * .01,
                verified_generation=self.fixture.generation)
            self.assertEqual((event, response), ('application_sequence_rejected', None))
            with self.probe._lock:
                self.probe._record_admitted_receipt_locked(raw, PEER, event, owner, now=.5)
            retained = self.probe._admitted_receipt_capture['recent'][-1]
            self.assertIn('sequence_state', retained)
            row = retained['sequence_state']
            self.assertEqual((row['in_sequence'], row['next_out_sequence'],
                row['acknowledged_out_sequence']), before)
            self.assertEqual(row['receive_delta'], 1 if future_ack else 100)
            self.assertEqual(row['ack_outside_prepared_window'], future_ack)
            self.assertEqual(row['outside_normal_receive_window'], not future_ack)
            self.assertEqual(row['actual_send_count'], len(self.fixture.state().actual_application_sends))
            self.assertEqual(row['positive_actual_send_receipt'], not future_ack)
            self.assertEqual((transport.in_sequence, transport.out_sequence,
                transport.acknowledged_out_sequence), before)
        self.assertTrue(self.probe.flush(timeout=3))
        public = json.loads((Path(self.folder.name) / 'report.json').read_text())
        self.assertNotIn('sequence_state', json.dumps(public))

    def test_terminal_close_is_retained_for_the_same_pre_receive_owner(self):
        transport = self.fixture.connection.peers[PEER]
        closed = replace(self.fixture.control(9), close=True, payload=b'', payload_bits=0)
        packet = replace(self.fixture.fixture.template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383, history=(0,), bunches=(closed,))
        raw = b'opaque!!' + encode_observed_application(packet, max_packet_bytes=1024,
            received_by_server=True)
        owner = self.probe._actual_application_send_owner_locked(PEER)
        event, response = self.fixture.connection.handle(raw, PEER, .5,
            verified_generation=self.fixture.generation)
        self.assertEqual(event, 'control_client_close_consumed')
        self.assertIsNotNone(response)
        with self.probe._lock:
            self.probe._record_admitted_receipt_locked(raw, PEER, event, owner, now=1800.)
        self.assertEqual(self.probe._admitted_receipt_capture['observed_packets'], 1)
        self.assertEqual(self.probe._admitted_receipt_capture['recent'][-1]['event'], event)

    def test_snapshot_is_synced_before_each_atomic_publish(self):
        self.record(0, reject=True)
        actions = []
        original_sync, original_replace = __import__('os').fsync, Path.replace

        def synced(fd):
            actions.append('sync')
            return original_sync(fd)

        def replaced(path, target):
            actions.append(path.name)
            return original_replace(path, target)

        with patch('dfserver.game_server_probe.os.fsync', side_effect=synced), \
                patch.object(Path, 'replace', autospec=True, side_effect=replaced):
            self.assertTrue(self.probe.flush(timeout=3))
        self.assertEqual(actions, ['sync', 'admitted-receipt-private.json.tmp', 'sync', 'report.json.tmp'])
