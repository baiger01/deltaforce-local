import unittest

from dfserver.legacy_ds_decoded_bunch import (
    CLOSE, FINAL, INITIAL, OPEN, PARTIAL, RELIABLE,
    DecodedBunch, DecodedBunchReceiver,
)


def bunch(sequence, payload=b'x', flags=RELIABLE, *, packet_id=None, bits=None, **kwargs):
    return DecodedBunch(sequence, sequence if packet_id is None else packet_id,
                        flags, payload, len(payload) * 8 if bits is None else bits, **kwargs)


class DecodedBunchTests(unittest.TestCase):
    def test_open_then_out_of_order_delivery_deduplicates_and_drains(self):
        receiver = DecodedBunchReceiver()
        self.assertFalse(receiver.receive(bunch(1, b'hello', RELIABLE | OPEN)).error)
        self.assertFalse(receiver.receive(bunch(3, b'three')).ready)
        self.assertEqual(receiver.receive(bunch(3, b'three')).event, 'queued_sequence_duplicate')
        result = receiver.receive(bunch(2, b'two'))
        self.assertEqual([item.payload for item in result.ready], [b'two', b'three'])
        self.assertEqual(receiver.in_reliable, 3)
        self.assertFalse(receiver.queued_reliable)

    def test_reliable_without_open_never_dispatches(self):
        receiver = DecodedBunchReceiver()
        result = receiver.receive(bunch(1))
        self.assertEqual(result.event, 'reliable_bunch_before_channel_open')
        self.assertTrue(result.error)
        self.assertFalse(result.ready)
        self.assertEqual(receiver.in_reliable, 1)

    def test_fragments_open_once_and_keep_non_byte_aligned_final_bit_count(self):
        receiver = DecodedBunchReceiver()
        self.assertFalse(receiver.receive(bunch(1, b'ab', RELIABLE | OPEN | PARTIAL | INITIAL)).ready)
        result = receiver.receive(bunch(3, b'\x05', RELIABLE | PARTIAL | FINAL, bits=3))
        self.assertFalse(result.ready)
        result = receiver.receive(bunch(2, b'cd', RELIABLE | PARTIAL))
        self.assertEqual(len(result.ready), 1)
        self.assertEqual((result.ready[0].payload, result.ready[0].payload_bits), (b'abcd\x05', 35))
        self.assertEqual(receiver.open_packet_range, (1, 3))
        self.assertTrue(receiver.opened)

    def test_unreliable_initial_cannot_replace_pending_reliable_message(self):
        receiver = DecodedBunchReceiver(opened=True)
        receiver.receive(bunch(1, b'abc', RELIABLE | PARTIAL | INITIAL))
        result = receiver.receive(bunch(5, b'def', PARTIAL | INITIAL))
        self.assertTrue(result.skip_ack)
        self.assertFalse(result.error)
        self.assertEqual(receiver.pending_partial.payload, b'abc')
        result = receiver.receive(bunch(2, b'def', RELIABLE | PARTIAL | FINAL))
        self.assertEqual(result.ready[0].payload, b'abcdef')

    def test_reliable_partial_conflict_fails_without_dispatch(self):
        receiver = DecodedBunchReceiver(opened=True)
        receiver.receive(bunch(1, b'a', RELIABLE | PARTIAL | INITIAL))
        result = receiver.receive(bunch(2, b'b', RELIABLE | PARTIAL | INITIAL))
        self.assertTrue(result.error)
        self.assertFalse(result.ready)

    def test_nonfinal_alignment_exports_and_assembly_limit_are_enforced(self):
        receiver = DecodedBunchReceiver(opened=True)
        result = receiver.receive(bunch(1, b'\x01', RELIABLE | PARTIAL | INITIAL, bits=1))
        self.assertEqual(result.event, 'partial_initial_not_byte_aligned')
        receiver = DecodedBunchReceiver(opened=True)
        self.assertTrue(receiver.receive(bunch(1, has_exports=True)).skip_ack)
        self.assertEqual(receiver.in_reliable, 0)
        receiver = DecodedBunchReceiver(opened=True, max_assembly_bytes=2)
        receiver.receive(bunch(1, b'ab', RELIABLE | PARTIAL | INITIAL))
        result = receiver.receive(bunch(2, b'c', RELIABLE | PARTIAL | FINAL))
        self.assertEqual(result.event, 'local_assembly_limit')
        self.assertFalse(result.ready)

    def test_close_delivers_once_and_does_not_drain_after_close(self):
        receiver = DecodedBunchReceiver(opened=True)
        receiver.receive(bunch(3, b'three'))
        receiver.receive(bunch(2, b'close', RELIABLE | CLOSE))
        result = receiver.receive(bunch(1, b'one'))
        self.assertEqual([item.payload for item in result.ready], [b'one', b'close'])
        self.assertTrue(result.closed)
        self.assertIn(3, receiver.queued_reliable)
        self.assertFalse(receiver.receive(bunch(4)).ready)

    def test_signed_channel_sequence_wrap_is_independent_of_packet_sequence(self):
        receiver = DecodedBunchReceiver(in_reliable=0x7fffffff, opened=True)
        result = receiver.receive(bunch(-0x80000000, packet_id=7))
        self.assertFalse(result.error)
        self.assertEqual(result.ready[0].packet_id, 7)

    def test_native_queue_threshold_bounds_memory(self):
        receiver = DecodedBunchReceiver(opened=True, max_queued_reliable=3)
        receiver.receive(bunch(4))
        receiver.receive(bunch(3))
        result = receiver.receive(bunch(2))
        self.assertEqual(result.event, 'reliable_queue_limit')
        self.assertTrue(result.error)
        self.assertFalse(receiver.receive(bunch(5)).ready)
        self.assertEqual(len(receiver.queued_reliable), 3)

    def test_old_unfiltered_sequence_blocks_queue_head_until_upstream_resolves_it(self):
        receiver = DecodedBunchReceiver(opened=True)
        receiver.receive(bunch(0, b'old'))
        receiver.receive(bunch(2, b'two'))
        result = receiver.receive(bunch(1, b'one'))
        self.assertEqual([item.payload for item in result.ready], [b'one'])
        self.assertEqual(receiver.in_reliable, 1)
        self.assertEqual(sorted(receiver.queued_reliable), [0, 2])

    def test_queued_partial_skip_ack_warns_but_keeps_draining(self):
        receiver = DecodedBunchReceiver(opened=True)
        receiver.receive(bunch(2, b'b', RELIABLE | PARTIAL))
        receiver.receive(bunch(3, b'c'))
        result = receiver.receive(bunch(1, b'a'))
        self.assertEqual([item.payload for item in result.ready], [b'a', b'c'])
        self.assertFalse(result.error)
        self.assertFalse(result.skip_ack)
        self.assertEqual(result.notices, ('queued_bunch_requested_skip_ack',))

    def test_invalid_reliable_continuation_sets_error_and_skip_ack(self):
        receiver = DecodedBunchReceiver(opened=True)
        receiver.receive(bunch(1, b'a', RELIABLE | PARTIAL | INITIAL))
        receiver.receive(bunch(2, b'unrelated'))
        result = receiver.receive(bunch(3, b'c', RELIABLE | PARTIAL | FINAL))
        self.assertTrue(result.error)
        self.assertTrue(result.skip_ack)
        self.assertFalse(result.ready)

    def test_current_skip_ack_still_drains_without_copying_queued_local_flag(self):
        receiver = DecodedBunchReceiver(opened=True)
        receiver.receive(bunch(5, b'old', PARTIAL | INITIAL))
        receiver.receive(bunch(2, b'next'))
        result = receiver.receive(bunch(1, b'conflict', RELIABLE | PARTIAL))
        self.assertTrue(result.skip_ack)
        self.assertFalse(result.error)
        self.assertEqual([item.payload for item in result.ready], [b'next'])
        self.assertEqual(receiver.in_reliable, 2)

    def test_queued_error_is_not_propagated_to_current_packet(self):
        receiver = DecodedBunchReceiver(opened=True)
        receiver.receive(bunch(1, b'initial', RELIABLE | PARTIAL | INITIAL))
        receiver.receive(bunch(4, b'last'))
        receiver.receive(bunch(3, b'invalid-final', RELIABLE | PARTIAL | FINAL))
        result = receiver.receive(bunch(2, b'middle'))
        self.assertEqual([item.payload for item in result.ready], [b'middle', b'last'])
        self.assertFalse(result.error)
        self.assertFalse(result.skip_ack)
        self.assertIn('queued_bunch_error:reliable_partial_sequence_or_shape_conflict', result.notices)
        self.assertFalse(receiver.failed)


if __name__ == '__main__':
    unittest.main()
