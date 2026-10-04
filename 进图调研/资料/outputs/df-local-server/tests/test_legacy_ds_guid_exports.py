import unittest
from dataclasses import FrozenInstanceError

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_guid_exports import (
    GuidExportLimits, GuidExportNode, UnsupportedGuidExportProfile,
    read_guid_exports, write_guid_exports,
)


ASCII_BODY = bytes.fromhex('060100020000004100')
ASCII_FIXTURE = bytes.fromhex('020000000c020004000000820000')
CRC_FIXTURE = bytes.fromhex('020000000c0a00040000008200f0ac682400')
NESTED_FIXTURE = bytes.fromhex('02000000140a0c020004000000a000040000008600f0ac682400')
WIDE_FIXTURE = bytes.fromhex('020000000c0200faffffff4fb2baae000000')


def literal_frame(body, count=1):
    """Independent framing arithmetic, not an encoder/decoder helper call.

    The fixture body supplies every literal packed-GUID/flag/FString byte.
    Count is exactly32 bits after one false bit; all bytes follow at bit33.
    """
    bits = 33 + len(body) * 8
    value = ((count & 0xffffffff) << 1) | (int.from_bytes(body, 'little') << 33)
    return value.to_bytes((bits + 7) // 8, 'little'), bits


class RestrictedGuidExportTests(unittest.TestCase):
    def encode(self, exports, **kwargs):
        writer = BitWriter()
        bits = write_guid_exports(writer, exports, **kwargs)
        self.assertEqual(bits, writer.bit_count)
        return writer.to_bytes(), bits

    def decode(self, data, bits, **kwargs):
        reader = BitReader(data, bit_count=bits)
        result = read_guid_exports(reader, **kwargs)
        self.assertEqual(reader.remaining, 0)
        return result

    def assert_read_failure(self, data, bits, **kwargs):
        reader = BitReader(data, bit_count=bits)
        with self.assertRaises(ValueError):
            read_guid_exports(reader, **kwargs)
        self.assertEqual(reader.position, 0)

    def assert_write_failure(self, exports, **kwargs):
        writer = BitWriter()
        writer.write_bits(5, 3)
        before = writer.to_bytes(), writer.bit_count
        with self.assertRaises(ValueError):
            write_guid_exports(writer, exports, **kwargs)
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_fixed_empty_false_branch_uses_raw_int32_not_packed_count(self):
        self.assertEqual(self.encode(()), (bytes.fromhex('0000000000'), 33))
        self.assertEqual(self.decode(bytes.fromhex('0000000000'), 33), ())

    def test_fixed_static_path_fixture_and_null_outer_without_flags(self):
        expected = (GuidExportNode(3, 'A'),)
        self.assertEqual(self.encode(expected), (ASCII_FIXTURE, 105))
        self.assertEqual(self.decode(ASCII_FIXTURE, 105), expected)
        # Body is06|01|00|02000000|4100. The null outer has no flags byte.
        self.assertEqual(literal_frame(ASCII_BODY), (ASCII_FIXTURE, 105))

    def test_fixed_explicit_checksum_is_last_unaligned_raw_u32(self):
        expected = (GuidExportNode(3, 'A', checksum=0x12345678),)
        self.assertEqual(self.encode(expected), (CRC_FIXTURE, 137))
        self.assertEqual(self.decode(CRC_FIXTURE, 137), expected)

    def test_fixed_recursive_outer_precedes_child_path_and_checksum(self):
        expected = (GuidExportNode(5, 'C', GuidExportNode(3, 'P'), 0x12345678),)
        self.assertEqual(self.encode(expected), (NESTED_FIXTURE, 201))
        self.assertEqual(self.decode(NESTED_FIXTURE, 201), expected)

    def test_fixed_chinese_fstring_automatically_uses_utf16_not_utf8(self):
        expected = (GuidExportNode(3, '大坝'),)
        self.assertEqual(self.encode(expected, force_unicode=False), (WIDE_FIXTURE, 137))
        self.assertEqual(self.decode(WIDE_FIXTURE, 137), expected)

    def test_fixed_forced_unicode_empty_path_retains_negative_one_length(self):
        data = bytes.fromhex('020000000c0200feffffff010000')
        expected = (GuidExportNode(3, ''),)
        self.assertEqual(self.encode(expected, force_unicode=True), (data, 105))
        self.assertEqual(self.decode(data, 105), expected)

    def test_fixed_duplicate_identical_definition_is_allowed(self):
        data = bytes.fromhex('040000000c02000400000082000c020004000000820000')
        expected = (GuidExportNode(3, 'A'), GuidExportNode(3, 'A'))
        self.assertEqual(self.encode(expected), (data, 177))
        self.assertEqual(self.decode(data, 177), expected)

    def test_nonzero_caller_cursor_and_following_actor_bits_are_preserved(self):
        #3-bit prefix5, fixed105-bit export fixture, then8-bit suffixa5.
        value = 5 | (int.from_bytes(ASCII_FIXTURE, 'little') << 3) | (0xa5 << 108)
        data = value.to_bytes(15, 'little')
        reader = BitReader(data, bit_count=116)
        self.assertEqual(reader.read_bits(3), 5)
        self.assertEqual(read_guid_exports(reader), (GuidExportNode(3, 'A'),))
        self.assertEqual(reader.position, 108)
        self.assertEqual(reader.read_bits(8), 0xa5)
        writer = BitWriter()
        writer.write_bits(5, 3)
        self.assertEqual(write_guid_exports(writer, (GuidExportNode(3, 'A'),)), 105)
        writer.write_bits(0xa5, 8)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (data, 116))

    def test_every_truncation_of_fixed_ascii_fixture_restores_cursor(self):
        for bits in range(105):
            with self.subTest(bits=bits):
                self.assert_read_failure(ASCII_FIXTURE, bits)

    def test_true_discriminator_default_guid_dynamic_guid_and_unknown_flags_reject(self):
        self.assert_read_failure(b'\x01', 1)
        for body in (b'\x00', b'\x02', b'\x04', b'\x06\x00', b'\x06\x02',
                     b'\x06\x03', b'\x06\x07', b'\x06\x81'):
            data, bits = literal_frame(body)
            with self.subTest(body=body):
                self.assert_read_failure(data, bits)

    def test_negative_and_above_native_maximum_counts_are_local_rejections(self):
        for count in (-1, -(1 << 31), 2049):
            data, bits = literal_frame(b'', count)
            self.assert_read_failure(data, bits)
        self.assert_read_failure(ASCII_FIXTURE, 105, limits=GuidExportLimits(max_exports=0))

    def test_invalid_encoder_guids_and_top_level_null_are_atomic(self):
        for guid in (0, 1, 2, 4, -3, 1 << 32, True, '3', 3.0, None):
            with self.subTest(guid=guid):
                self.assert_write_failure((GuidExportNode(guid, 'A'),))
        for exports in ((None,), (object(),), [GuidExportNode(3, 'A')]):
            self.assert_write_failure(exports)

    def test_explicit_uint32_checksum_zero_is_distinct_from_omission(self):
        body = bytes.fromhex('06050002000000410000000000')
        fixture = literal_frame(body)
        expected = (GuidExportNode(3, 'A', checksum=0),)
        self.assertEqual(self.encode(expected), fixture)
        self.assertEqual(self.decode(*fixture), expected)
        for checksum in (True, -1, 1 << 32, '0', 0.0):
            self.assert_write_failure((GuidExportNode(3, 'A', checksum=checksum),))

    def test_conflicting_path_checksum_or_outer_rejects_without_committing(self):
        conflicts = (
            GuidExportNode(3, 'B'),
            GuidExportNode(3, 'A', checksum=0),
            GuidExportNode(3, 'A', outer=GuidExportNode(5, 'P')),
        )
        first = GuidExportNode(3, 'A')
        for conflicting in conflicts:
            self.assert_write_failure((first, conflicting))
        for second_body in (bytes.fromhex('060100020000004200'),
                            bytes.fromhex('06050002000000410000000000'),
                            bytes.fromhex('06010a0100020000005000020000004100')):
            data, bits = literal_frame(ASCII_BODY + second_body, 2)
            self.assert_read_failure(data, bits)

    def test_conflicting_recursive_definition_is_checked_across_top_nodes(self):
        first = GuidExportNode(5, 'C', GuidExportNode(3, 'P'))
        second = GuidExportNode(7, 'D', GuidExportNode(3, 'Q'))
        self.assert_write_failure((first, second))
        body = bytes.fromhex('0a01060100020000005000020000004300'
                             '0e01060100020000005100020000004400')
        self.assert_read_failure(*literal_frame(body, 2))

    def test_node_bound_counts_repeated_recursive_occurrences_not_unique_guids(self):
        node = GuidExportNode(5, 'C', GuidExportNode(3, 'P'))
        limits = GuidExportLimits(max_nodes=3)
        self.assert_write_failure((node, node), limits=limits)
        body = bytes.fromhex('0a01060100020000005000020000004300') * 2
        self.assert_read_failure(*literal_frame(body, 2), limits=limits)

    def test_depth_guard_applies_to_null_outer_before_reading_its_guid(self):
        self.assert_write_failure((GuidExportNode(3, 'A'),),
                                  limits=GuidExportLimits(max_depth=0))
        self.assert_read_failure(ASCII_FIXTURE, 105, limits=GuidExportLimits(max_depth=0))
        self.assertEqual(self.decode(bytes.fromhex('0000000000'), 33,
                                    limits=GuidExportLimits(max_depth=0)), ())

    def test_sixteen_path_nodes_plus_null_at_depth16_are_the_last_supported_chain(self):
        node = None
        for index in range(16):
            node = GuidExportNode(3 + 2 * index, 'A', node)
        data, bits = self.encode((node,))
        # Literal nesting is32.. as GUID bytes plus01, then a single00,
        # followed by16 independent ASCII FString fields while unwinding.
        body = b''.join(bytes((guid << 1, 1)) for guid in range(33, 2, -2))
        body += b'\x00' + bytes.fromhex('020000004100') * 16
        self.assertEqual((data, bits), literal_frame(body))
        self.assertEqual(self.decode(data, bits), (node,))
        too_deep = GuidExportNode(35, 'A', node)
        self.assert_write_failure((too_deep,))
        body = b'\x46\x01' + body + bytes.fromhex('020000004100')
        data, bits = literal_frame(body)
        reader = BitReader(data, bit_count=bits)
        with self.assertRaisesRegex(ValueError, 'nesting'):
            read_guid_exports(reader)
        self.assertEqual(reader.position, 0)

    def test_byte_budget_is_relative_to_current_cursor_and_every_staged_write(self):
        limits = GuidExportLimits(max_bytes=13)  #105-bit fixture needs14 bytes.
        self.assert_write_failure((GuidExportNode(3, 'A'),), limits=limits)
        self.assert_read_failure(ASCII_FIXTURE, 105, limits=limits)
        value = 5 | int.from_bytes(ASCII_FIXTURE, 'little') << 3
        reader = BitReader(value.to_bytes(14, 'little'), bit_count=108)
        reader.read_bits(3)
        with self.assertRaises(ValueError):
            read_guid_exports(reader, limits=limits)
        self.assertEqual(reader.position, 3)
        # Entire archive may exceed14 bytes; prefix consumption still105 bits.
        reader = BitReader(ASCII_FIXTURE + b'\xff' * 8, bit_count=169)
        self.assertEqual(read_guid_exports(reader, limits=GuidExportLimits(max_bytes=14)),
                         (GuidExportNode(3, 'A'),))
        self.assertEqual(reader.position, 105)

    def test_caller_capacity_failure_does_not_append_private_staging(self):
        writer = BitWriter(maximum_bits=105)
        writer.write_bool(True)
        before = writer.to_bytes(), writer.bit_count
        with self.assertRaises(ValueError):
            write_guid_exports(writer, (GuidExportNode(3, 'A'),))
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_fstring_native_terminator_and_ffff_normalization_are_shared(self):
        # Native forces the final byte toNUL, preserving the interior NUL.
        body = bytes.fromhex('0601000400000041004221')
        self.assertEqual(self.decode(*literal_frame(body)), (GuidExportNode(3, 'A\0B'),))
        body = bytes.fromhex('060100fdffffff4100ffff2100')
        self.assertEqual(self.decode(*literal_frame(body)), (GuidExportNode(3, 'A'),))
        self.assert_write_failure((GuidExportNode(3, 'A\0B'),))

    def test_fstring_lengths_path_unit_bounds_and_bad_node_fields_are_atomic(self):
        for header in ('00000080', '01100000', 'ffefffff'):
            self.assert_read_failure(*literal_frame(bytes.fromhex('060100' + header)))
        self.assert_read_failure(ASCII_FIXTURE, 105,
                                limits=GuidExportLimits(max_path_units=1))
        self.assert_write_failure((GuidExportNode(3, 'A'),),
                                 limits=GuidExportLimits(max_path_units=1))
        for node in (GuidExportNode(3, 1), GuidExportNode(3, 'A', outer=1)):
            self.assert_write_failure((node,))
        self.assert_write_failure((GuidExportNode(3, 'A'),), force_unicode=1)

    def test_limits_are_explicit_strict_local_bounds(self):
        for field, value in (('max_exports', -1), ('max_exports', 2049),
                             ('max_depth', -1), ('max_depth', 17),
                             ('max_nodes', 2049), ('max_bytes', 0),
                             ('max_bytes', 8193), ('max_path_units', 4097),
                             ('max_depth', True)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                GuidExportLimits(**{field: value})
        self.assert_write_failure((), limits=None)
        self.assert_read_failure(bytes.fromhex('0000000000'), 33, limits=None)

    def test_results_are_immutable_and_no_ids_or_checksums_are_allocated(self):
        node = self.decode(ASCII_FIXTURE, 105)[0]
        self.assertEqual((node.guid, node.outer, node.checksum), (3, None, None))
        with self.assertRaises(FrozenInstanceError):
            node.guid = 5
        expected = (GuidExportNode(UINT32_MAX, 'A'),)
        # Five-group packed GUID literal, followed immediately by flags/outer.
        fixture = literal_frame(bytes.fromhex('ffffffff1e0100020000004100'))
        self.assertEqual(self.encode(expected), fixture)
        self.assertEqual(self.decode(*fixture), expected)

    def test_wrong_archive_types_are_rejected(self):
        with self.assertRaises(ValueError):
            read_guid_exports(object())
        with self.assertRaises(ValueError):
            write_guid_exports(object(), ())


if __name__ == '__main__':
    unittest.main()
