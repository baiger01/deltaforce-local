"""Whole-packet liveness regressions from the 2026-10-19 native disconnect."""
from dataclasses import replace
import unittest
from unittest.mock import patch

from tests import test_admitted_actor_reliable_receipts as fixtures
from tests.test_legacy_ds_actor_delivery import decode


class AdmittedTransportContinuityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AdmittedActorReceiptTests()
        self.fixture.setUp()
        self.fixture.deliver()
        self.fixture.enable()

    def unreliable(self, channel):
        return replace(self.fixture.bunch(channel), reliable=False,
            channel_sequence=None, channel_name=None)

    def test_unreliable_pawn_pc_and_owned_weapon_do_not_block_mixed_reliable_receipt(self):
        f = self.fixture
        event, response = f.send((self.unreliable(4), self.unreliable(2),
            self.unreliable(12), f.bunch(), f.bunch(5), f.bunch(13)))
        self.assertEqual(event, 'admitted_actor_reliable_packet_received')
        self.assertEqual(decode(response).history[0] & 1, 1)
        self.assertEqual(f.state().admitted_pawn_receipt.expected_sequence, (f.seed + 1) & 1023)
        self.assertFalse(f.connection.summary()['admitted_actor_rpc_gameplay_handled'])

    def test_cross_channel_retries_do_not_deadlock_on_each_others_future_sequence(self):
        f = self.fixture
        event, response = f.send((f.bunch(sequence=(f.seed + 1) & 1023), f.bunch(12)))
        self.assertEqual(event, 'admitted_actor_reliable_packet_received')
        self.assertIsNotNone(response)
        self.assertEqual(f.state().admitted_pawn_receipt.expected_sequence, f.seed)
        event, response = f.send((f.bunch(), f.bunch(12, (f.seed + 1) & 1023)), now=.6)
        self.assertEqual(event, 'admitted_actor_reliable_packet_received')
        self.assertEqual(f.state().admitted_pawn_receipt.expected_sequence, (f.seed + 2) & 1023)
        self.assertEqual(f.state().admitted_actor_receipt_ledgers[12].expected_sequence,
            (f.seed + 2) & 1023)

    def test_unreliable_malformed_or_foreign_body_still_rolls_back_whole_packet(self):
        f = self.fixture
        for bad in (self.unreliable(14), replace(self.unreliable(4), package_exports=True),
                replace(self.unreliable(2), partial=True),
                replace(self.unreliable(12), must_be_mapped=True)):
            with self.subTest(bad=bad):
                _, response = f.send((f.bunch(), bad))
                self.assertIsNone(response)
                self.assertIsNone(f.state().admitted_pawn_receipt)

    def test_idle_poll_does_not_rewalk_delivered_content_prerequisites(self):
        f = self.fixture
        self.assertTrue(all(item.delivered for item in f.state().actor_contents.values()))
        before = tuple(f.state().actual_actor_receipts)
        with patch.object(f.connection, '_content_stage_waiting',
                wraps=f.connection._content_stage_waiting) as waiting:
            for ordinal in range(20):
                self.assertEqual(f.connection.poll(1.0 + ordinal * .01), [])
        self.assertEqual(waiting.call_count, 0)
        self.assertEqual(f.state().actual_actor_receipts, before)

    def test_reordered_pc_startup_only_dispatches_when_gap_is_filled(self):
        from tests.test_legacy_ds_pc_startup_rpc import rpc
        f = self.fixture
        _, response = f.send((rpc((f.seed + 1) & 1023, 79),))
        self.assertIsNotNone(response)
        self.assertFalse(f.state().pc_short_timeout_observed)
        _, response = f.send((rpc(f.seed, 200),), now=.6)
        self.assertIsNotNone(response)
        self.assertTrue(f.state().pc_short_timeout_observed)
        self.assertEqual(f.state().pc_reliable_receipt.expected_sequence, (f.seed + 2) & 1023)

    def test_current_private_prefix_and_late_unreliable_bodies_are_received(self):
        from pathlib import Path
        import runpy
        root = Path(__file__).resolve().parents[3]
        source = root / 'work/audit_late_receipts_1792390754215070100.py'
        if not (root / 'work/native-client-tests/1792390754215070100/game-server-packets/report.json').exists():
            self.skipTest('The exact private native trial is not present')
        result = runpy.run_path(str(source))['replay']()
        self.assertEqual(result['report_sha256'],
            '4055e135de32964b744f1412bdfa81e22b415508fa38b67602200eec696b9c10')
        replay = result['prefix_full_packet_replay']
        self.assertEqual(replay['rejected_packets'], [])
        self.assertEqual(replay['events']['admitted_actor_reliable_packet_received'], 45)
        late = result['isolated_late_unreliable_replay']
        self.assertGreaterEqual(late['bunches'], 68)
        self.assertEqual(set(late['events']), {'admitted_actor_reliable_packet_received'})

    def test_thirty_minute_synthetic_traffic_crosses_reply_limit_and_sequence_wraps(self):
        f = self.fixture
        for ordinal in range(4200):
            seq = (f.seed + ordinal) & 1023
            event, response = f.send((self.unreliable(4), self.unreliable(2),
                f.bunch(sequence=seq)), now=.5 + ordinal * 1800 / 4200, history=(0,))
            self.assertIsNotNone(response, (ordinal, event))
        self.assertEqual(f.state().admitted_pawn_receipt.expected_sequence,
            (f.seed + 4200) & 1023)
        self.assertEqual(f.state().admitted_actor_rejection_counts, {})
        self.assertLessEqual(len(f.state().admitted_actor_opaque_journal), 256)
        self.assertLessEqual(f.state().admitted_actor_opaque_journal_bytes, 262144)


if __name__ == '__main__':
    unittest.main()
