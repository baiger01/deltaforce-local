import unittest
from dataclasses import FrozenInstanceError

from dfserver.legacy_ds_actor_content import (
    ActorContentBlock, ActorContentLimits, UnsupportedActorContentProfile,
    read_actor_content_block, read_actor_content_blocks,
    write_actor_content_block, write_actor_content_blocks,
)
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, MAX_BITS


EMPTY_FALSE = ActorContentBlock(False, b'', 0)
EMPTY_TRUE = ActorContentBlock(True, b'', 0)
THREE = ActorContentBlock(True, b'\x05', 3)
BYTE = ActorContentBlock(False, b'\xa5', 8)


class ActorContentTests(unittest.TestCase):
    def assert_fixed(self, block, raw, bits):
        writer = BitWriter()
        self.assertEqual(write_actor_content_block(writer, block), bits)
        self.assertEqual(writer.to_bytes(), raw)
        reader = BitReader(raw, bit_count=bits)
        self.assertEqual(read_actor_content_block(reader), block)
        self.assertEqual(reader.position, bits)

    def test_fixed_zero_bit_body_has_ten_bits_and_no_end_marker(self):
        # Literal bit0=RepLayout, bit1=Actor, eight length bits all zero.
        self.assert_fixed(EMPTY_FALSE, bytes.fromhex('0200'), 10)
        self.assert_fixed(EMPTY_TRUE, bytes.fromhex('0300'), 10)

    def test_fixed_unaligned_three_bit_body_and_raw_byte_body(self):
        # 3 + (packed group06 <<2) + (body05 <<10) =0x141b.
        self.assert_fixed(THREE, bytes.fromhex('1b14'), 13)
        # Actor bit02 + (group10 <<2) + (bytea5 <<10) =0x29442.
        self.assert_fixed(BYTE, bytes.fromhex('429402'), 18)

    def test_fixed_two_group_packed_length_without_byte_alignment(self):
        block = ActorContentBlock(False, b'\0' * 16, 128)
        # 128's literal native packed groups are01,02; payload starts at18.
        self.assert_fixed(block, bytes.fromhex('0608') + b'\0' * 17, 146)

    def test_fixed_sequence_has_parent_eof_not_zero_payload_terminator(self):
        raw = bytes.fromhex('1b5400')  #13-bit THREE followed by10-bit empty.
        reader = BitReader(raw, bit_count=23)
        self.assertEqual(read_actor_content_blocks(reader), (THREE, EMPTY_FALSE))
        self.assertEqual(reader.position, 23)
        writer = BitWriter()
        self.assertEqual(write_actor_content_blocks(writer, (THREE, EMPTY_FALSE)), 23)
        self.assertEqual(writer.to_bytes(), raw)

    def test_zero_bit_first_block_does_not_hide_following_nonempty_block(self):
        # Empty02 followed by byte0x29442 at bit10; literal arithmetic only.
        raw = (2 + (0x29442 << 10)).to_bytes(4, 'little')
        reader = BitReader(raw, bit_count=28)
        self.assertEqual(read_actor_content_blocks(reader), (EMPTY_FALSE, BYTE))

    def test_fixed_nonzero_caller_cursor_and_following_field(self):
        # Three leading bits101, THREE starts at3, suffixa5 starts at16.
        reader = BitReader(bytes.fromhex('dda0a5'), bit_count=24)
        self.assertEqual(reader.read_bits(3), 5)
        self.assertEqual(read_actor_content_block(reader), THREE)
        self.assertEqual(reader.position, 16)
        self.assertEqual(reader.read_bits(8), 0xa5)
        writer = BitWriter()
        writer.write_bits(5, 3)
        self.assertEqual(write_actor_content_block(writer, THREE), 13)
        writer.write_bits(0xa5, 8)
        self.assertEqual(writer.to_bytes(), bytes.fromhex('dda0a5'))

    def test_every_truncation_rolls_back_single_and_sequence_read(self):
        for bits in range(13):
            for read in (read_actor_content_block, read_actor_content_blocks):
                # Empty sequence has no fields and is legal.
                if read is read_actor_content_blocks and bits == 0:
                    continue
                reader = BitReader(bytes.fromhex('1b14'), bit_count=bits)
                with self.assertRaises(ValueError, msg=str((bits, read))):
                    read(reader)
                self.assertEqual(reader.position, 0)

    def test_invalid_second_block_rolls_back_entire_read_and_write(self):
        # Actor=false second block; no object GUID branch accepted here.
        value = 2 + (1 << 10)
        reader = BitReader(value.to_bytes(3, 'little'), bit_count=20)
        with self.assertRaises(UnsupportedActorContentProfile):
            read_actor_content_blocks(reader)
        self.assertEqual(reader.position, 0)
        writer = BitWriter()
        writer.write_bits(5, 3)
        before = writer.to_bytes(), writer.bit_count
        with self.assertRaises(ValueError):
            write_actor_content_blocks(writer, (EMPTY_FALSE, ActorContentBlock(1, b'', 0)))
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_false_selector_is_rejected_without_reading_any_object_fields(self):
        for prefix in (0, 1):
            reader = BitReader(bytes([prefix]), bit_count=2)
            with self.assertRaises(UnsupportedActorContentProfile):
                read_actor_content_block(reader)
            self.assertEqual(reader.position, 0)

    def test_false_selector_from_nonzero_position_restores_position(self):
        reader = BitReader(b'\x0d', bit_count=5)
        reader.read_bits(3)
        with self.assertRaises(UnsupportedActorContentProfile):
            read_actor_content_block(reader)
        self.assertEqual(reader.position, 3)

    def test_payload_budget_and_relative_total_budget(self):
        for limits in (ActorContentLimits(max_payload_bits=2),
                       ActorContentLimits(max_total_bits=12)):
            reader = BitReader(bytes.fromhex('dda0a5'), bit_count=24)
            reader.read_bits(3)
            with self.assertRaises(ValueError):
                read_actor_content_block(reader, limits=limits)
            self.assertEqual(reader.position, 3)
            writer = BitWriter()
            with self.assertRaises(ValueError):
                write_actor_content_block(writer, THREE, limits=limits)
            self.assertEqual(writer.bit_count, 0)
        reader = BitReader(bytes.fromhex('dda0a5'), bit_count=24)
        reader.read_bits(3)
        self.assertEqual(read_actor_content_block(reader,
            limits=ActorContentLimits(max_total_bits=13)), THREE)
        self.assertEqual(reader.position, 16)

    def test_sequence_total_count_budgets_and_remaining_padding_fail_atomically(self):
        for limits in (ActorContentLimits(max_blocks=1),
                       ActorContentLimits(max_total_bits=22)):
            reader = BitReader(bytes.fromhex('1b5400'), bit_count=23)
            with self.assertRaises(ValueError):
                read_actor_content_blocks(reader, limits=limits)
            self.assertEqual(reader.position, 0)
            writer = BitWriter()
            with self.assertRaises(ValueError):
                write_actor_content_blocks(writer, (THREE, EMPTY_FALSE), limits=limits)
            self.assertEqual(writer.bit_count, 0)
        # Byte padding is not a valid end marker; caller must supply true bit_count.
        reader = BitReader(bytes.fromhex('1b5400'))
        with self.assertRaises(ValueError):
            read_actor_content_blocks(reader)
        self.assertEqual(reader.position, 0)

    def test_zero_block_budget_and_empty_sequence(self):
        limits = ActorContentLimits(max_blocks=0, max_payload_bits=0, max_total_bits=1)
        reader = BitReader(b'', bit_count=0)
        self.assertEqual(read_actor_content_blocks(reader, limits=limits), ())
        writer = BitWriter()
        self.assertEqual(write_actor_content_blocks(writer, (), limits=limits), 0)
        for operation, target in ((read_actor_content_block, reader),
                                  (write_actor_content_block, writer)):
            with self.assertRaises(ValueError):
                if operation is read_actor_content_block:
                    operation(target, limits=limits)
                else:
                    operation(target, EMPTY_FALSE, limits=limits)

    def test_archive_capacity_failure_leaves_existing_writer_unchanged(self):
        writer = BitWriter(maximum_bits=15)
        writer.write_bits(5, 3)
        with self.assertRaises(ValueError):
            write_actor_content_block(writer, THREE)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (b'\x05', 3))

    def test_bad_payload_lengths_flags_and_unused_high_bits_are_atomic(self):
        invalid = (ActorContentBlock(False, b'\xff', 3),
                   ActorContentBlock(False, b'\0\0', 3),
                   ActorContentBlock(False, b'\0', 0),
                   ActorContentBlock(False, bytearray(b'\x05'), 3),
                   ActorContentBlock(False, b'', -1),
                   ActorContentBlock(False, b'', True),
                   ActorContentBlock(0, b'', 0), object())
        for block in invalid:
            writer = BitWriter()
            writer.write_bits(3, 2)
            with self.assertRaises(ValueError):
                write_actor_content_block(writer, block)
            self.assertEqual((writer.to_bytes(), writer.bit_count), (b'\x03', 2))

    def test_overflow_noncanonical_and_truncated_packed_lengths_roll_back(self):
        for groups in (bytes.fromhex('ffffffff20'), bytes.fromhex('0100'), b'\x01'):
            value = 2 + (int.from_bytes(groups, 'little') << 2)
            bits = 2 + len(groups) * 8
            reader = BitReader(value.to_bytes((bits+7)//8, 'little'), bit_count=bits)
            with self.assertRaises(ValueError):
                read_actor_content_block(reader)
            self.assertEqual(reader.position, 0)

    def test_native_uint32_length_exceeds_local_payload_bound_before_allocation(self):
        groups = bytes.fromhex('ffffffff1e')
        value = 2 + (int.from_bytes(groups, 'little') << 2)
        reader = BitReader(value.to_bytes(6, 'little'), bit_count=42)
        with self.assertRaisesRegex(ValueError, 'payload'):
            read_actor_content_block(reader)
        self.assertEqual(reader.position, 0)

    def test_maximum_local_count_has_exact_eof_and_next_block_exceeds(self):
        #256 copies of literal 10-bit value2, no terminal marker.
        value = sum(2 << (10*i) for i in range(256))
        raw = value.to_bytes(320, 'little')
        reader = BitReader(raw, bit_count=2560)
        self.assertEqual(read_actor_content_blocks(reader), (EMPTY_FALSE,) * 256)
        writer = BitWriter()
        self.assertEqual(write_actor_content_blocks(writer, (EMPTY_FALSE,) * 256), 2560)
        self.assertEqual(writer.to_bytes(), raw)
        with self.assertRaises(ValueError):
            write_actor_content_blocks(writer, (EMPTY_FALSE,) * 257)
        self.assertEqual(writer.bit_count, 2560)
        value += 2 << 2560
        reader = BitReader(value.to_bytes(322, 'little'), bit_count=2570)
        with self.assertRaisesRegex(ValueError, 'count'):
            read_actor_content_blocks(reader)
        self.assertEqual(reader.position, 0)

    def test_resource_bound_includes_header_and_exact_payload_not_just_bytes(self):
        #65510 has literal packed groupscd,ff,06:24 bits; flags2 +24 +65510
        #fill the local65536-bit archive exactly. No trailing byte marker.
        payload_bits = MAX_BITS - 26
        block = ActorContentBlock(False, b'\0' * ((payload_bits+7)//8), payload_bits)
        expected = (2 + (int.from_bytes(bytes.fromhex('cdff06'), 'little') << 2)).to_bytes(8192, 'little')
        writer = BitWriter()
        self.assertEqual(write_actor_content_block(writer, block), MAX_BITS)
        self.assertEqual(writer.to_bytes(), expected)
        reader = BitReader(expected, bit_count=MAX_BITS)
        self.assertEqual(read_actor_content_block(reader), block)
        oversized = ActorContentBlock(False, b'\0' * ((payload_bits+8)//8), payload_bits+1)
        with self.assertRaises(ValueError):
            write_actor_content_block(BitWriter(), oversized)

    def test_limits_and_archive_arguments_are_strict(self):
        for kwargs in ({'max_blocks':True}, {'max_blocks':-1}, {'max_blocks':257},
                       {'max_payload_bits':-1}, {'max_payload_bits':MAX_BITS+1},
                       {'max_total_bits':0}, {'max_total_bits':MAX_BITS+1}):
            with self.assertRaises(ValueError):
                ActorContentLimits(**kwargs)
        with self.assertRaises(ValueError):
            write_actor_content_blocks(BitWriter(), [EMPTY_FALSE])
        for operation, target in ((read_actor_content_block, object()),
                                  (read_actor_content_blocks, object())):
            with self.assertRaises(ValueError):
                operation(target)
        with self.assertRaises(ValueError):
            write_actor_content_block(object(), EMPTY_FALSE)
        with self.assertRaises(ValueError):
            read_actor_content_block(BitReader(b'\x02\0', bit_count=10), limits=object())

    def test_block_is_immutable_and_payload_is_opaque(self):
        with self.assertRaises(FrozenInstanceError):
            THREE.payload = b''
        self.assertEqual(read_actor_content_block(BitReader(bytes.fromhex('429402'), bit_count=18)), BYTE)


if __name__ == '__main__':
    unittest.main()
