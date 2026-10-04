import unittest
from unittest.mock import patch

from dfserver.legacy_ds_actor_open import MAX_ACTOR_OPEN_BITS, write_actor_open
from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.legacy_ds_quantized_vector import QuantizedVector10


class RestrictedActorOpenTests(unittest.TestCase):
    def arguments(self, version=12):
        return dict(actor_guid=2, archetype_guid=3, level_guid=5 if version >= 5 else None,
                    connection_network_version=version, archive_network_version=version,
                    references_resolvable=True)

    def encode(self, **changes):
        arguments = self.arguments()
        arguments.update(changes)
        writer = BitWriter()
        bits = write_actor_open(writer, **arguments)
        self.assertEqual(bits, writer.bit_count)
        return writer.to_bytes(), bits

    def assert_atomic_rejection(self, changes, error=ValueError):
        writer = BitWriter()
        writer.write_bits(5, 3)
        before = writer.to_bytes(), writer.bit_count, writer.maximum_bits
        arguments = self.arguments()
        arguments.update(changes)
        with self.assertRaises(error):
            write_actor_open(writer, **arguments)
        self.assertEqual((writer.to_bytes(), writer.bit_count, writer.maximum_bits), before)

    def vectors(self):
        return dict(location=QuantizedVector10((0, 1, -1)),
                    scale=QuantizedVector10((2, -3, 3)),
                    velocity=QuantizedVector10((0, 0, 0)))

    def test_fixed_generic_header_has_packed_refs_then_four_absent_bits(self):
        # Ordinary IDs2/3/5 encode as04/06/0a, with no flags byte per GUID.
        self.assertEqual(self.encode(), (bytes.fromhex('04060a00'), 28))

    def test_fixed_pre5_header_omits_level_instead_of_emitting_null(self):
        self.assertEqual(self.encode(connection_network_version=4,
            archive_network_version=4, level_guid=None), (bytes.fromhex('040600'), 20))

    def test_fixed_version12_interleaves_vectors_with_presence_and_pc_tail(self):
        # Independent field literals: location present+11b =0x781/12b;
        # rotation absent/1b; scale present+14b =0x7383/15b;
        # velocity present+11b =0xa81/12b; PC index0/8b.
        self.assertEqual(self.encode(**self.vectors(), local_player_index=0),
                         (bytes.fromhex('04060a8167701ea800'), 72))

    def test_fixed_version13_inserts_compression_bit_inside_each_vector(self):
        # Present+compressed+vector literals are0xf03/13b,0xe707/16b,
        # 0x1503/13b. The PC tail starts at bit67, not the next byte.
        self.assertEqual(self.encode(**self.vectors(), local_player_index=0,
            connection_network_version=13, archive_network_version=13),
            (bytes.fromhex('04060a03cfc1f9400500'), 75))

    def test_fixed_unaligned_caller_and_following_field_keep_exact_bits(self):
        writer = BitWriter()
        writer.write_bits(5, 3)
        arguments = self.arguments(13)
        arguments.update(self.vectors(), local_player_index=0)
        self.assertEqual(write_actor_open(writer, **arguments), 75)
        writer.write_bits(0xa5, 8)
        # Independent packing of3b prefix, fixed75b fixture,8b suffix.
        self.assertEqual((writer.to_bytes(), writer.bit_count),
                         (bytes.fromhex('25305018780ece072a4029'), 86))

    def test_fixed_packed_uint32_boundary_is_not_byte_aligned_guid_flags(self):
        self.assertEqual(self.encode(actor_guid=UINT32_MAX-1,
            archetype_guid=UINT32_MAX, connection_network_version=4,
            archive_network_version=4, level_guid=None),
            (bytes.fromhex('fdffffff1effffffff1e00'), 84))

    def test_pc_tail_is_only_emitted_when_explicit(self):
        self.assertEqual(self.encode(local_player_index=0),
                         (bytes.fromhex('04060a0000'), 36))

    def test_actor_must_be_a_nonzero_even_uint32(self):
        for guid in (0, 1, 3, UINT32_MAX, True, -2, 1 << 32, '2', 2.0, None):
            with self.subTest(guid=guid):
                self.assert_atomic_rejection({'actor_guid': guid})

    def test_default_path_and_null_archetype_references_are_rejected(self):
        for guid in (0, 1, True, -1, 1 << 32, '3', 3.0, None):
            with self.subTest(guid=guid):
                self.assert_atomic_rejection({'archetype_guid': guid})

    def test_all_different_object_types_require_distinct_guids(self):
        for changes in ({'actor_guid': 6, 'archetype_guid': 6},
                        {'actor_guid': 6, 'level_guid': 6},
                        {'archetype_guid': 5, 'level_guid': 5}):
            with self.subTest(changes=changes):
                self.assert_atomic_rejection(changes)

    def test_ge5_level_must_be_explicit_nonnull_ordinary_reference(self):
        for guid in (None, 0, 1, True, -1, 1 << 32, '5', 5.0):
            with self.subTest(guid=guid):
                self.assert_atomic_rejection({'level_guid': guid})

    def test_pre5_rejects_even_an_explicit_null_level_field(self):
        for guid in (0, 5):
            self.assert_atomic_rejection(dict(connection_network_version=4,
                archive_network_version=4, level_guid=guid))

    def test_versions_are_explicit_uint32_and_must_match(self):
        for version in (None, True, -1, 1 << 32, '12', 12.0):
            for field in ('connection_network_version', 'archive_network_version'):
                with self.subTest(field=field, version=version):
                    self.assert_atomic_rejection({field: version})
        self.assert_atomic_rejection({'archive_network_version': 13})

    def test_reference_declaration_is_required_exact_true_not_verification(self):
        for value in (False, None, 1, 'True', [], {}):
            with self.subTest(value=value):
                self.assert_atomic_rejection({'references_resolvable': value})

    def test_pc_local_player_index_only_accepts_strict_int_zero(self):
        for value in (False, True, -1, 1, 255, 256, '0', 0.0):
            with self.subTest(value=value):
                self.assert_atomic_rejection({'local_player_index': value})

    def test_raw_float_vectors_and_unverified_rotation_export_modes_are_unrepresentable(self):
        for field in ('location', 'scale', 'velocity'):
            for value in ((0, 0, 0), (0.0, 1.0, 2.0), [0, 0, 0], True):
                self.assert_atomic_rejection({field: value})
        for field in ('rotation_present', 'rotation', 'export_mode', 'guid_flags'):
            self.assert_atomic_rejection({field: True}, TypeError)

    def test_late_helper_failure_does_not_commit_partial_guids_or_vectors(self):
        writer = BitWriter()
        writer.write_bits(3, 2)
        before = writer.to_bytes(), writer.bit_count
        arguments = self.arguments()
        arguments.update(self.vectors())
        with patch('dfserver.legacy_ds_actor_open.write_compressed_vector10',
                   side_effect=[None, ValueError('unverified vector branch')]):
            with self.assertRaisesRegex(ValueError, 'unverified vector'):
                write_actor_open(writer, **arguments)
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_insufficient_output_capacity_is_atomic_after_full_staging(self):
        writer = BitWriter(maximum_bits=74)
        writer.write_bits(1, 1)
        before = writer.to_bytes(), writer.bit_count
        arguments = self.arguments(13)
        arguments.update(self.vectors(), local_player_index=0)
        with self.assertRaisesRegex(ValueError, 'local bound'):
            write_actor_open(writer, **arguments)
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_wrong_writer_and_missing_reference_contract_are_rejected(self):
        with self.assertRaises(ValueError):
            write_actor_open(object(), **self.arguments())
        arguments = self.arguments()
        del arguments['references_resolvable']
        writer = BitWriter()
        with self.assertRaises(TypeError):
            write_actor_open(writer, **arguments)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (b'', 0))

    def test_local_subset_bound_is_derived_from_known_field_maxima(self):
        self.assertEqual(MAX_ACTOR_OPEN_BITS, 383)
        large = QuantizedVector10((-(1 << 24), 0, (1 << 24)-1))
        data, bits = self.encode(actor_guid=UINT32_MAX-1,
            archetype_guid=UINT32_MAX, level_guid=UINT32_MAX-2,
            connection_network_version=13, archive_network_version=13,
            location=large, scale=large, velocity=large, local_player_index=0)
        self.assertEqual(bits, 375)
        self.assertEqual(len(data), 47)


if __name__ == '__main__':
    unittest.main()
