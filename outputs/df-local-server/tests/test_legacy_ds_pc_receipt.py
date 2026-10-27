import unittest
from dataclasses import replace

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, MAX_BITS
from dfserver.legacy_ds_pc_receipt import (
    MAX_ASSEMBLY_BYTES, PCReceiptLedger, PCReceiptReader, bounded_actor_fields,
)
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch


def bunch(sequence, payload=b'x', *, bits=None, **kwargs):
    return WireBunch(2, payload, len(payload) * 8 if bits is None else bits,
                     reliable=True, channel_sequence=sequence,
                     channel_name=ChannelName(hardcoded_index=102), **kwargs)


def append_bits(prefix, payload, bits):
    value = int.from_bytes(prefix.to_bytes(), 'little')
    value |= int.from_bytes(payload, 'little') << prefix.bit_count
    length = prefix.bit_count + bits
    return value.to_bytes((length + 7) // 8, 'little'), length


def actor_body(index, payload=b'', bits=None):
    bits = len(payload) * 8 if bits is None else bits
    field_header = BitWriter()
    field_header.write_bounded_int(index, 245)
    field_header.write_packed_int(bits)
    field, field_bits = append_bits(field_header, payload, bits)
    block_header = BitWriter()
    block_header.write_bool(False)
    block_header.write_bool(True)
    block_header.write_packed_int(field_bits)
    return append_bits(block_header, field, field_bits)


def join_regions(*regions):
    value, total = 0, 0
    for data, bits in regions:
        value |= int.from_bytes(data, 'little') << total
        total += bits
    return value.to_bytes((total + 7) // 8, 'little'), total


class PCReceiptTests(unittest.TestCase):
    def test_continuous_receipt_does_not_skip_a_missing_sequence(self):
        ledger = PCReceiptLedger(2, 392)
        self.assertFalse(ledger.receive(bunch(394)).received)
        self.assertEqual(ledger.expected_sequence, 392)
        self.assertTrue(ledger.receive(bunch(392)).received)
        self.assertFalse(ledger.receive(bunch(394)).received)
        self.assertEqual(ledger.expected_sequence, 393)
        self.assertTrue(ledger.receive(bunch(393)).received)
        self.assertTrue(ledger.receive(bunch(394)).received)

    def test_complete_retry_has_same_ready_body_without_advancing(self):
        ledger = PCReceiptLedger(2, 67)
        original = bunch(67, b'opaque', header_start_bit=10, payload_start_bit=40)
        self.assertEqual(ledger.receive(original).ready, (original,))
        retry = replace(original, header_start_bit=200, payload_start_bit=230)
        result = ledger.receive(retry)
        self.assertTrue(result.received)
        self.assertTrue(result.duplicate)
        self.assertEqual(result.ready, (original,))
        self.assertEqual(result.expected_sequence, 68)

    def test_conflicting_digest_rejects_flags_length_and_payload(self):
        ledger = PCReceiptLedger(2, 1)
        original = bunch(1, b'\x01')
        ledger.receive(original)
        for changed in (replace(original, payload=b'\x02'),
                        replace(original, payload_bits=1),
                        replace(original, partial=True, partial_initial=True)):
            result = ledger.receive(changed)
            self.assertFalse(result.received)
            self.assertFalse(result.duplicate)
            self.assertFalse(result.ready)
            self.assertEqual(result.reason, 'conflicting_reliable_digest')
            self.assertEqual(ledger.expected_sequence, 2)

    def test_partial_group_wraps_and_preserves_exact_final_bits(self):
        ledger = PCReceiptLedger(2, 1023)
        first = bunch(1023, b'ab', partial=True, partial_initial=True)
        middle = bunch(0, b'cd', partial=True)
        final = bunch(1, b'\x05', bits=3, partial=True, partial_final=True)
        self.assertFalse(ledger.receive(first).ready)
        self.assertFalse(ledger.receive(middle).ready)
        result = ledger.receive(final)
        self.assertEqual(len(result.ready), 1)
        ready = result.ready[0]
        self.assertEqual((ready.payload, ready.payload_bits), (b'abcd\x05', 35))
        self.assertEqual(ready.channel_sequence, 1)
        self.assertFalse(ready.partial or ready.partial_initial or ready.partial_final)
        self.assertEqual(ledger.expected_sequence, 2)
        for fragment in (first, middle, final):
            repeated = ledger.receive(fragment)
            self.assertTrue(repeated.duplicate)
            self.assertFalse(repeated.ready)
        self.assertEqual(ledger.expected_sequence, 2)

    def test_fragment_retry_does_not_append_payload_twice(self):
        ledger = PCReceiptLedger(2, 5)
        first = bunch(5, b'a', partial=True, partial_initial=True)
        ledger.receive(first)
        self.assertTrue(ledger.receive(first).duplicate)
        result = ledger.receive(bunch(6, b'b', partial=True, partial_final=True))
        self.assertEqual(result.ready[0].payload, b'ab')

    def test_partial_alignment_shape_errors_leave_pending_state_unchanged(self):
        ledger = PCReceiptLedger(2, 10)
        malformed = bunch(10, b'\x01', bits=1, partial=True, partial_initial=True)
        self.assertFalse(ledger.receive(malformed).received)
        self.assertEqual(ledger.expected_sequence, 10)
        first = bunch(10, b'a', partial=True, partial_initial=True)
        self.assertTrue(ledger.receive(first).received)
        for wrong in (bunch(11, b'\x01', bits=1, partial=True),
                      bunch(11, b'b', partial=True, partial_initial=True),
                      bunch(11, b'b'),
                      bunch(11, b'b', partial=True, partial_initial=True, partial_final=True)):
            self.assertFalse(ledger.receive(wrong).received)
            self.assertEqual(ledger.expected_sequence, 11)
        result = ledger.receive(bunch(11, b'\x01', bits=1, partial=True, partial_final=True))
        self.assertEqual((result.ready[0].payload, result.ready[0].payload_bits), (b'a\x01', 9))

    def test_continuation_without_initial_does_not_consume_sequence(self):
        ledger = PCReceiptLedger(2, 1)
        for final in (False, True):
            self.assertFalse(ledger.receive(bunch(1, partial=True, partial_final=final)).received)
        self.assertEqual(ledger.expected_sequence, 1)
        self.assertTrue(ledger.receive(bunch(1)).received)

    def test_assembly_limit_is_atomic_and_accepts_exact_bound(self):
        ledger = PCReceiptLedger(2, 1, max_assembly_bytes=2)
        ledger.receive(bunch(1, b'a', partial=True, partial_initial=True))
        self.assertFalse(ledger.receive(bunch(2, b'bc', partial=True, partial_final=True)).received)
        self.assertEqual(ledger.expected_sequence, 2)
        result = ledger.receive(bunch(2, b'b', partial=True, partial_final=True))
        self.assertEqual(result.ready[0].payload, b'ab')

    def test_14kb_body_reassembles_and_frames_above_global_reader_bound(self):
        body, bits = actor_body(84, bytes(range(256)) * 56 + b'\x05', 14336 * 8 + 3)
        self.assertGreater(bits, MAX_BITS)
        ledger = PCReceiptLedger(2, 392)
        offset, seq = 0, 392
        while bits - offset > 900 * 8:
            fragment = body[offset // 8:offset // 8 + 900]
            result = ledger.receive(bunch(seq, fragment, partial=True,
                                          partial_initial=offset == 0))
            self.assertTrue(result.received)
            self.assertFalse(result.ready)
            offset += 900 * 8
            seq = (seq + 1) & 1023
        final_bits = bits - offset
        result = ledger.receive(bunch(seq, body[offset // 8:], bits=final_bits,
                                      partial=True, partial_final=True))
        self.assertTrue(result.received)
        ready = result.ready[0]
        self.assertEqual((ready.payload, ready.payload_bits), (body, bits))
        fields = bounded_actor_fields(ready)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].rep_index, 84)
        self.assertEqual(fields[0].payload_bit_count, 14336 * 8 + 3)
        self.assertEqual(fields[0].payload, bytes(range(256)) * 56 + b'\x05')
        with self.assertRaises(ValueError):
            BitReader(ready.payload, bit_count=ready.payload_bits)

    def test_full_local_limit_and_overflow_do_not_change_global_budget(self):
        ledger = PCReceiptLedger(2, 0)
        first = b'a' * (MAX_ASSEMBLY_BYTES - 1)
        self.assertTrue(ledger.receive(bunch(0, first, partial=True, partial_initial=True)).received)
        self.assertFalse(ledger.receive(bunch(1, b'ab', partial=True, partial_final=True)).received)
        result = ledger.receive(bunch(1, b'b', partial=True, partial_final=True))
        self.assertEqual(len(result.ready[0].payload), MAX_ASSEMBLY_BYTES)
        self.assertEqual(PCReceiptReader(result.ready[0].payload).remaining, MAX_ASSEMBLY_BYTES * 8)
        with self.assertRaises(ValueError):
            PCReceiptReader(b'x' * (MAX_ASSEMBLY_BYTES + 1))
        with self.assertRaises(ValueError):
            BitReader(b'x' * (8192 + 1))

    def test_retry_window_eviction_and_full_wire_wrap_treat_expected_as_fresh(self):
        ledger = PCReceiptLedger(2, 0, window_size=3)
        for seq in range(4):
            self.assertTrue(ledger.receive(bunch(seq)).received)
        self.assertFalse(ledger.receive(bunch(0)).received)
        self.assertTrue(ledger.receive(bunch(1)).duplicate)
        for seq in range(4, 1024):
            self.assertTrue(ledger.receive(bunch(seq)).received)
        result = ledger.receive(bunch(0))
        self.assertTrue(result.received)
        self.assertFalse(result.duplicate)
        self.assertEqual(result.expected_sequence, 1)

    def test_clone_isolates_both_pending_assembly_and_history(self):
        original = PCReceiptLedger(2, 8)
        first = bunch(8, b'a', partial=True, partial_initial=True)
        original.receive(first)
        staged = original.clone()
        result = staged.receive(bunch(9, b'b', partial=True, partial_final=True))
        self.assertEqual(result.ready[0].payload, b'ab')
        self.assertEqual(original.expected_sequence, 9)
        self.assertEqual(staged.expected_sequence, 10)
        self.assertFalse(original.receive(bunch(10)).received)
        other = original.receive(bunch(9, b'c', partial=True, partial_final=True))
        self.assertEqual(other.ready[0].payload, b'ac')
        self.assertFalse(staged.receive(bunch(9, b'c', partial=True, partial_final=True)).received)

    def test_wrong_channel_or_unsupported_header_never_enters_history(self):
        ledger = PCReceiptLedger(2, 1)
        original = bunch(1)
        for malformed in (object(), replace(original, channel_index=3),
                          replace(original, reliable=False),
                          replace(original, channel_sequence=True),
                          replace(original, channel_name=ChannelName(hardcoded_index=101)),
                          replace(original, channel_name=ChannelName(hardcoded_index=102, number=False)),
                          replace(original, partial_initial=True),
                          replace(original, payload=b'\xff', payload_bits=1),
                          replace(original, payload=b'', payload_bits=8)):
            self.assertFalse(ledger.receive(malformed).received)
            self.assertEqual(ledger.expected_sequence, 1)
        for key in ('open', 'close', 'flag4', 'connection_flag',
                    'package_exports', 'must_be_mapped'):
            self.assertFalse(ledger.receive(replace(original, **{key: True})).received)
        self.assertTrue(ledger.receive(original).received)

    def test_constructor_and_reader_reject_invalid_types_and_bounds(self):
        for args in ((True, 1), (2, True), (2, -1), (2, 1024)):
            with self.assertRaises(ValueError):
                PCReceiptLedger(*args)
        for kwargs in ({'window_size': 0}, {'window_size': 513},
                       {'max_assembly_bytes': MAX_ASSEMBLY_BYTES + 1}):
            with self.assertRaises(ValueError):
                PCReceiptLedger(2, 1, **kwargs)
        for data, bits in ((bytearray(b'a'), 8), (b'a', True), (b'a', 9)):
            with self.assertRaises(ValueError):
                PCReceiptReader(data, bit_count=bits)


class PCEnvelopeTests(unittest.TestCase):
    def test_multiple_blocks_and_zero_length_field_have_no_terminal_marker(self):
        payload, bits = join_regions(actor_body(0), actor_body(85), actor_body(67, b'\x05', 3))
        fields = bounded_actor_fields(bunch(1, payload, bits=bits))
        self.assertEqual([(x.rep_index, x.payload_bit_count) for x in fields], [(0, 0), (85, 0), (67, 3)])
        self.assertEqual(fields[-1].payload, b'\x05')

    def test_truncation_suffix_and_unsupported_selector_reject_whole_body(self):
        payload, bits = actor_body(67, b'\x05', 3)
        for truncated in (bits - 1, bits - 3, 1):
            value = int.from_bytes(payload, 'little') & ((1 << truncated) - 1)
            with self.assertRaises(ValueError):
                bounded_actor_fields(bunch(1, value.to_bytes((truncated + 7) // 8, 'little'), bits=truncated))
        suffix, suffix_bits = join_regions((payload, bits), (b'\x00', 1))
        with self.assertRaises(ValueError):
            bounded_actor_fields(bunch(1, suffix, bits=suffix_bits))
        for altered in (payload[0] | 1, payload[0] & ~2):
            with self.assertRaises(ValueError):
                bounded_actor_fields(bunch(1, bytes([altered]) + payload[1:], bits=bits))
        with self.assertRaises(ValueError):
            bounded_actor_fields(bunch(1, payload, bits=bits, partial=True, partial_initial=True))

    def test_overlong_or_oversized_lengths_fail_closed(self):
        # Header bits false-RepLayout/true-Actor, followed by malformed packed size.
        for packed in (b'\x01\x00', b'\xff\xff\xff\xff\x20', b'\x04'):
            writer = BitWriter()
            writer.write_bool(False)
            writer.write_bool(True)
            writer.write_bytes(packed)
            with self.assertRaises(ValueError):
                bounded_actor_fields(bunch(1, writer.to_bytes(), bits=writer.bit_count))
        with self.assertRaises(ValueError):
            bounded_actor_fields(bunch(1, b'', bits=0), exclusive_index_maximum=True)


if __name__ == '__main__':
    unittest.main()
