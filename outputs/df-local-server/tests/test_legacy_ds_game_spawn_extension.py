"""Independent bit/cursor checks for the opt-in game spawn byte.

All GUIDs and paths below are artificial fixtures. These tests establish
pure format composition, not native interface qualification or Actor acceptance.
"""

import unittest

from dfserver.legacy_ds_actor_bunch import build_actor_bunch
from dfserver.legacy_ds_actor_content import ActorContentBlock, read_actor_content_blocks
from dfserver.legacy_ds_actor_manifest import (
    ActorManifest, CLIENT_SHA256, GuidPathBinding, preflight_actor_manifest,
)
from dfserver.legacy_ds_actor_open import MAX_ACTOR_OPEN_BITS, write_actor_open
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_guid_exports import GuidExportNode, read_guid_exports
from dfserver.legacy_ds_quantized_vector import QuantizedVector10
from dfserver.legacy_ds_wire_codec import WirePacket, encode_native_packet


def actor_arguments(**changes):
    arguments = dict(actor_guid=2, archetype_guid=3, level_guid=5,
                     connection_network_version=13, archive_network_version=13,
                     references_resolvable=True)
    arguments.update(changes)
    return arguments


def bunch_arguments(**changes):
    arguments = dict(exports=(GuidExportNode(3, 'A'), GuidExportNode(5, 'L')),
                     actor_guid=2, archetype_guid=3, level_guid=5,
                     connection_network_version=13, archive_network_version=13,
                     references_resolvable=True, channel_index=4, channel_sequence=7,
                     max_packet_bytes=128, location=None, scale=None, velocity=None)
    arguments.update(changes)
    return arguments


def manifest_fixture(**changes):
    # A real Level has a package, World, then colon-separated Level Outer.
    package = GuidExportNode(3, '/Game/Test/BP_Pawn')
    cls = GuidExportNode(5, 'BP_Pawn_C', package)
    template = GuidExportNode(7, 'Default__BP_Pawn_C', package)
    map_package = GuidExportNode(25, '/Game/Test/Map')
    world = GuidExportNode(9, 'Map', map_package)
    level = GuidExportNode(11, 'PersistentLevel', world)
    arguments = dict(client_sha256=CLIENT_SHA256,
        source_relative_path='work/test-spawn-extension.json', source_sha256='a' * 64,
        class_guid=5, class_path='/Game/Test/BP_Pawn.BP_Pawn_C',
        archetype_guid=7, archetype_path='/Game/Test/BP_Pawn.Default__BP_Pawn_C',
        archetype_qualification='named_default_object_candidate',
        level_guid=11, level_path='/Game/Test/Map.Map:PersistentLevel',
        path_bindings=(GuidPathBinding(3, package.path),
                       GuidPathBinding(5, '/Game/Test/BP_Pawn.BP_Pawn_C', '.'),
                       GuidPathBinding(7, '/Game/Test/BP_Pawn.Default__BP_Pawn_C', '.'),
                       GuidPathBinding(25, map_package.path),
                       GuidPathBinding(9, '/Game/Test/Map.Map', '.'),
                       GuidPathBinding(11, '/Game/Test/Map.Map:PersistentLevel', ':')),
        exports=(cls, template, level), actor_guid=2,
        connection_network_version=13, archive_network_version=13,
        references_resolvable=True, channel_index=4,
        location=None, scale=None, velocity=None)
    arguments.update(changes)
    return ActorManifest(**arguments)


def literal_fields(*fields):
    """Concatenate literal (value, bit_count) pairs without using BitWriter."""
    value, total = 0, 0
    for field, bits in fields:
        value |= field << total
        total += bits
    return value.to_bytes((total + 7) // 8, 'little'), total


class GameSpawnExtensionTests(unittest.TestCase):
    def encode_actor(self, **changes):
        writer = BitWriter()
        added = write_actor_open(writer, **actor_arguments(**changes))
        self.assertEqual(added, writer.bit_count)
        return writer.to_bytes(), added

    def read_refs_and_absent_transforms(self, reader, *, archetype=3, level=5):
        self.assertEqual(reader.read_packed_int(), 2)
        self.assertEqual(reader.read_packed_int(), archetype)
        self.assertEqual(reader.read_packed_int(), level)
        self.assertEqual(tuple(reader.read_bool() for _ in range(4)), (False,) * 4)

    def read_present_vector(self, reader, expected):
        # Parse primitives directly, rather than using the actor/vector reader.
        self.assertTrue(reader.read_bool())  # presence
        self.assertTrue(reader.read_bool())  # version13 compressed branch
        width = reader.read_bounded_int(24)
        bias = 1 << (width + 1)
        steps = tuple(reader.read_bounded_int(1 << (width + 2)) - bias
                      for _ in range(3))
        self.assertEqual(steps, expected)

    def test_all_explicit_flags_are_raw_u8_at_bit28(self):
        for flags in (0, 1, 2, 3):
            with self.subTest(flags=flags):
                data, bits = self.encode_actor(game_replication_flags=flags)
                # Packed GUID literals04/06/0a, four zero bits, then raw byte.
                self.assertEqual((data, bits),
                    literal_fields((0x0a0604, 24), (0, 4), (flags, 8)))
                reader = BitReader(data, bit_count=bits)
                self.read_refs_and_absent_transforms(reader)
                self.assertEqual(reader.position, 28)
                self.assertEqual(reader.read_bytes(1), bytes((flags,)))
                self.assertEqual(reader.remaining, 0)

    def test_explicit_zero_is_not_omission_and_none_keeps_old_fixture(self):
        omitted = self.encode_actor()
        none = self.encode_actor(game_replication_flags=None)
        zero = self.encode_actor(game_replication_flags=0)
        self.assertEqual(omitted, (bytes.fromhex('04060a00'), 28))
        self.assertEqual(none, omitted)
        self.assertEqual(zero, (bytes.fromhex('04060a0000'), 36))
        self.assertNotEqual(zero, omitted)

    def test_extension_precedes_pc_tail_without_alignment(self):
        data, bits = self.encode_actor(game_replication_flags=3, local_player_index=0)
        self.assertEqual((data, bits),
            literal_fields((0x0a0604, 24), (0, 4), (3, 8), (0, 8)))
        reader = BitReader(data, bit_count=bits)
        self.read_refs_and_absent_transforms(reader)
        self.assertEqual(reader.read_bits(8), 3)
        self.assertEqual(reader.position, 36)
        self.assertEqual(reader.read_bits(8), 0)
        self.assertEqual(reader.remaining, 0)

    def test_present_vector_data_is_consumed_before_extension_and_pc(self):
        data, bits = self.encode_actor(
            location=QuantizedVector10((0, 1, -1)),
            scale=QuantizedVector10((2, -3, 3)),
            velocity=QuantizedVector10((0, 0, 0)),
            game_replication_flags=2, local_player_index=0)
        # Independent version13 transform fixture has67 meaningful bits.
        transform_header = int.from_bytes(bytes.fromhex('04060a03cfc1f9400500'), 'little')
        self.assertEqual((data, bits),
            literal_fields((transform_header & ((1 << 67) - 1), 67), (2, 8), (0, 8)))
        reader = BitReader(data, bit_count=bits)
        self.assertEqual(tuple(reader.read_packed_int() for _ in range(3)), (2, 3, 5))
        self.read_present_vector(reader, (0, 1, -1))
        self.assertFalse(reader.read_bool())  # rotation remains absent
        self.read_present_vector(reader, (2, -3, 3))
        self.read_present_vector(reader, (0, 0, 0))
        self.assertEqual(reader.position, 67)
        self.assertEqual(reader.read_bits(8), 2)
        self.assertEqual(reader.read_bits(8), 0)
        self.assertEqual(reader.remaining, 0)

    def test_unaligned_caller_prefix_and_following_field_stay_exact(self):
        writer = BitWriter()
        writer.write_bits(5, 3)
        self.assertEqual(write_actor_open(writer, **actor_arguments(
            game_replication_flags=3, local_player_index=0)), 44)
        writer.write_bits(0xa5, 8)
        expected = literal_fields((5, 3), (0x0a0604, 24), (0, 4), (3, 8), (0, 8), (0xa5, 8))
        self.assertEqual((writer.to_bytes(), writer.bit_count), expected)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertEqual(reader.read_bits(3), 5)
        self.read_refs_and_absent_transforms(reader)
        self.assertEqual(reader.position, 31)
        self.assertEqual(reader.read_bytes(1), b'\x03')
        self.assertEqual(reader.read_bytes(1), b'\x00')
        self.assertEqual(reader.read_bytes(1), b'\xa5')
        self.assertEqual(reader.remaining, 0)

    def test_invalid_extension_rejects_atomically_before_any_caller_bits(self):
        for flags in (True, False, -1, 4, 255, 256, '1', 1.0, [], {}):
            with self.subTest(flags=flags):
                writer = BitWriter(maximum_bits=128)
                writer.write_bits(0x15, 5)
                before = writer.to_bytes(), writer.bit_count, writer.maximum_bits
                with self.assertRaisesRegex(ValueError, 'replication flags'):
                    write_actor_open(writer, **actor_arguments(game_replication_flags=flags))
                self.assertEqual((writer.to_bytes(), writer.bit_count, writer.maximum_bits), before)

    def test_maximum_header_capacity_includes_both_raw_byte_extensions(self):
        large = QuantizedVector10((-(1 << 24), 0, (1 << 24) - 1))
        arguments = actor_arguments(actor_guid=UINT32_MAX - 1,
            archetype_guid=UINT32_MAX, level_guid=UINT32_MAX - 2,
            location=large, scale=large, velocity=large,
            game_replication_flags=3, local_player_index=0)
        self.assertEqual(MAX_ACTOR_OPEN_BITS, 383)
        writer = BitWriter(maximum_bits=383)
        self.assertEqual(write_actor_open(writer, **arguments), 383)
        reader = BitReader(writer.to_bytes(), bit_count=383)
        reader.read_bits(367)
        self.assertEqual(reader.read_bits(8), 3)
        self.assertEqual(reader.read_bits(8), 0)
        self.assertEqual(reader.remaining, 0)
        undersized = BitWriter(maximum_bits=385)
        undersized.write_bits(5, 3)  # only382bits remain
        before = undersized.to_bytes(), undersized.bit_count
        with self.assertRaisesRegex(ValueError, 'local bound'):
            write_actor_open(undersized, **arguments)
        self.assertEqual((undersized.to_bytes(), undersized.bit_count), before)

    def test_bunch_composition_places_byte_after_export_prefix_before_content(self):
        blocks = (ActorContentBlock(True, b'\x05', 3),)
        bunch = build_actor_bunch(**bunch_arguments(game_replication_flags=1,
                                                   local_player_index=0, content_blocks=blocks))
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader), bunch_arguments()['exports'])
        self.assertEqual(reader.position, 177)
        self.read_refs_and_absent_transforms(reader)
        self.assertEqual(reader.position, 205)
        self.assertEqual(reader.read_bits(8), 1)
        self.assertEqual(reader.read_bits(8), 0)
        self.assertEqual(read_actor_content_blocks(reader), blocks)
        self.assertEqual(reader.remaining, 0)

    def test_bunch_payload_capacity_includes_explicit_zero_but_not_packet_headers(self):
        # Export177+header28=205bits fits26bytes; extension raises it to213.
        without = build_actor_bunch(**bunch_arguments(max_packet_bytes=26))
        self.assertEqual(without.payload_bits, 205)
        with self.assertRaisesRegex(ValueError, 'local bound'):
            build_actor_bunch(**bunch_arguments(max_packet_bytes=26, game_replication_flags=0))
        bunch = build_actor_bunch(**bunch_arguments(max_packet_bytes=27, game_replication_flags=0))
        self.assertEqual(bunch.payload_bits, 213)
        packet = WirePacket(1, 0, (0,), False, 0, None, (bunch,), 0)
        with self.assertRaises(ValueError):
            encode_native_packet(packet, max_packet_bytes=27, received_by_server=False)

    def test_manifest_passes_explicit_flags_without_claiming_native_acceptance(self):
        for flags in (None, 0, 3):
            with self.subTest(flags=flags):
                manifest = manifest_fixture(game_replication_flags=flags, local_player_index=0)
                result = preflight_actor_manifest(manifest, channel_sequence=7, max_packet_bytes=1024)
                self.assertIs(result.actor_fields['game_replication_flags'], flags)
                self.assertFalse(result.native_acceptance)
                reader = BitReader(result.bunch.payload, bit_count=result.bunch.payload_bits)
                self.assertEqual(read_guid_exports(reader), manifest.exports)
                self.read_refs_and_absent_transforms(reader, archetype=7, level=11)
                if flags is not None:
                    self.assertEqual(reader.read_bytes(1), bytes((flags,)))
                self.assertEqual(reader.read_bytes(1), b'\x00')
                self.assertEqual(reader.remaining, 0)

    def test_invalid_extension_cannot_escape_bunch_or_manifest_validation(self):
        for flags in (True, False, -1, 4):
            with self.subTest(flags=flags):
                with self.assertRaisesRegex(ValueError, 'replication flags'):
                    build_actor_bunch(**bunch_arguments(game_replication_flags=flags))
                with self.assertRaisesRegex(ValueError, 'replication flags'):
                    preflight_actor_manifest(manifest_fixture(game_replication_flags=flags),
                                             channel_sequence=7, max_packet_bytes=1024)


if __name__ == '__main__':
    unittest.main()
