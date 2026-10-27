"""Admitted Actor receipt must tolerate ordinary unreliable and reordered data."""
from dataclasses import replace
import unittest

from dfserver.legacy_ds_pc_receipt import PCReceiptLedger
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch


def bunch(sequence=463, payload=b'x', **flags):
    return WireBunch(4, payload, len(payload) * 8, reliable=True,
        channel_sequence=sequence, channel_name=ChannelName(hardcoded_index=102), **flags)


class OwnedActorTransportTests(unittest.TestCase):
    def ledger(self, **kwargs):
        from dfserver.legacy_ds_owned_actor_transport import OwnedActorReceiptLedger
        return OwnedActorReceiptLedger(4, 463, **kwargs)

    def test_unreliable_complete_body_does_not_consume_reliable_sequence_or_partial(self):
        ledger = self.ledger()
        first = bunch(partial=True, partial_initial=True)
        self.assertTrue(ledger.receive(first).received)
        ordinary = replace(bunch(), reliable=False, channel_sequence=None, channel_name=None)
        result = ledger.receive(ordinary)
        self.assertTrue(result.received)
        self.assertEqual(result.ready, (ordinary,))
        self.assertEqual(ledger.expected_sequence, 464)
        self.assertEqual(ledger.receive(bunch(464, b'y', partial=True,
            partial_final=True)).ready[0].payload, b'xy')

    def test_future_bunches_are_retained_and_drained_in_order_without_skipping_gap(self):
        ledger = self.ledger()
        result = ledger.receive(bunch(465, b'c'))
        self.assertTrue(result.received)
        self.assertEqual(result.reason, 'reliable_queued')
        self.assertEqual(result.ready, ())
        self.assertEqual(ledger.expected_sequence, 463)
        self.assertTrue(ledger.receive(bunch(465, b'c')).duplicate)
        self.assertFalse(ledger.receive(bunch(465, b'd')).received)
        self.assertEqual(ledger.receive(bunch(463, b'a')).ready, (bunch(463, b'a'),))
        self.assertEqual(ledger.receive(bunch(464, b'b')).ready,
            (bunch(464, b'b'), bunch(465, b'c')))
        self.assertEqual(ledger.expected_sequence, 466)

    def test_queue_wrap_partial_reassembly_and_clone_are_isolated(self):
        from dfserver.legacy_ds_owned_actor_transport import OwnedActorReceiptLedger
        ledger = OwnedActorReceiptLedger(4, 1023)
        final = bunch(0, b'b', partial=True, partial_final=True)
        self.assertTrue(ledger.receive(final).received)
        candidate = ledger.clone()
        result = candidate.receive(bunch(1023, b'a', partial=True, partial_initial=True))
        self.assertEqual(result.ready[0].payload, b'ab')
        self.assertEqual(candidate.expected_sequence, 1)
        self.assertEqual(ledger.expected_sequence, 1023)
        self.assertEqual(ledger.queued_count, 1)

    def test_queue_byte_distance_and_count_limits_are_atomic(self):
        ledger = self.ledger(max_queued_bytes=2, max_queued_reliable=1)
        self.assertFalse(ledger.receive(bunch(464, b'xxx')).received)
        self.assertEqual(ledger.queued_count, 0)
        self.assertTrue(ledger.receive(bunch(464, b'x')).received)
        self.assertFalse(ledger.receive(bunch(465, b'y')).received)
        self.assertEqual(ledger.queued_count, 1)
        self.assertFalse(ledger.receive(bunch((463 + 256) & 1023)).received)
        self.assertFalse(ledger.receive(bunch(462)).received)

    def test_unreliable_flags_foreign_channel_and_noncanonical_payload_stay_rejected(self):
        ledger = self.ledger()
        ordinary = replace(bunch(), reliable=False, channel_sequence=None, channel_name=None)
        invalid = [replace(ordinary, channel_index=5), replace(ordinary, payload_bits=1),
            replace(ordinary, channel_name=ChannelName(hardcoded_index=102)),
            replace(ordinary, channel_sequence=463)]
        invalid += [replace(ordinary, **{name:True}) for name in ('open', 'close',
            'flag4', 'connection_flag', 'package_exports', 'must_be_mapped', 'partial',
            'partial_initial', 'partial_final')]
        for value in invalid:
            with self.subTest(value=value):
                self.assertFalse(ledger.receive(value).received)
        self.assertEqual(ledger.expected_sequence, 463)
        self.assertEqual(ledger.queued_count, 0)

    def test_upgrade_preserves_startup_history_and_keeps_default_policy_strict(self):
        from dfserver.legacy_ds_owned_actor_transport import OwnedActorReceiptLedger
        original = PCReceiptLedger(4, 463)
        self.assertTrue(original.receive(bunch()).received)
        self.assertFalse(original.receive(bunch(465)).received)
        upgraded = OwnedActorReceiptLedger.from_ledger(original)
        self.assertTrue(upgraded.receive(bunch()).duplicate)
        self.assertTrue(upgraded.receive(bunch(465)).received)
        self.assertEqual(original.expected_sequence, 464)


if __name__ == '__main__':
    unittest.main()
