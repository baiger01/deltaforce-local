"""Independent bit fixtures for the pure export/Actor bunch composition."""

import unittest

from dfserver.legacy_ds_actor_bunch import build_actor_bunch
from dfserver.legacy_ds_actor_content import ActorContentBlock, read_actor_content_blocks
from dfserver.legacy_ds_bit_archive import BitReader, UINT32_MAX
from dfserver.legacy_ds_guid_exports import GuidExportNode, read_guid_exports
from dfserver.legacy_ds_quantized_vector import QuantizedVector10
from dfserver.legacy_ds_wire_codec import (
    ChannelName, WirePacket, decode_native_packet, encode_native_packet,
)


# Two caller-defined artificial paths, not claimed game class/CDO paths.
EXPORTS = (GuidExportNode(3, 'A'), GuidExportNode(5, 'L'))
# false discriminator + unaligned int32 count2 + two literal path definitions.
EXPORT_PREFIX = bytes.fromhex('040000000c020004000000820014020004000000980000')
EXPORT_BITS = 177
ACTOR_HEADER = bytes.fromhex('04060a00')
ACTOR_BITS = 28
COMBINED = bytes.fromhex('040000000c0200040000008200140200040000009800080c1400')


def literal_join(prefix, prefix_bits, suffix, suffix_bits):
    """Independent LSB-first integer concatenation, with no native writer."""
    value = int.from_bytes(prefix, 'little') & ((1 << prefix_bits) - 1)
    tail = int.from_bytes(suffix, 'little') & ((1 << suffix_bits) - 1)
    bits = prefix_bits + suffix_bits
    return (value | (tail << prefix_bits)).to_bytes((bits + 7) // 8, 'little')


def build(**changes):
    args = dict(exports=EXPORTS, actor_guid=2, archetype_guid=3, level_guid=5,
                connection_network_version=12, archive_network_version=12,
                references_resolvable=True, channel_index=1, channel_sequence=7,
                max_packet_bytes=128, location=None, scale=None, velocity=None)
    args.update(changes)
    return build_actor_bunch(**args)


def packet(bunch):
    return WirePacket(sequence=1, acknowledged_sequence=0, history=(0,),
                      packet_info=False, frame=0, server_frame_time=None,
                      bunches=(bunch,), consumed_bits=0)


class ActorBunchTests(unittest.TestCase):
    def test_literal_unaligned_boundary_and_flags(self):
        bunch = build()
        self.assertEqual(bunch.payload, COMBINED)
        self.assertEqual(bunch.payload_bits, 205)
        self.assertEqual(COMBINED, literal_join(EXPORT_PREFIX, EXPORT_BITS,
                                               ACTOR_HEADER, ACTOR_BITS))
        self.assertEqual(bunch.channel_name, ChannelName(hardcoded_index=102))
        self.assertTrue(bunch.open and bunch.reliable and bunch.package_exports)
        self.assertFalse(bunch.close or bunch.partial or bunch.must_be_mapped)
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader), EXPORTS)
        self.assertEqual(reader.position, EXPORT_BITS)
        self.assertEqual(reader.read_payload(reader.remaining), ACTOR_HEADER)
        self.assertEqual(reader.remaining, 0)

    def test_vector_and_pc_tail_remain_unaligned(self):
        # Independent actor-only fixture from the version13 integer-vector
        # profile; the four presence bits interleave with vector values.
        actor = bytes.fromhex('04060a03cfc1f9400500')
        expected = bytes.fromhex(
            '040000000c0200040000008200140200040000009800080c14069e83f3810a00')
        bunch = build(connection_network_version=13, archive_network_version=13,
                      location=QuantizedVector10((0, 1, -1)),
                      scale=QuantizedVector10((2, -3, 3)),
                      velocity=QuantizedVector10((0, 0, 0)), local_player_index=0)
        self.assertEqual(bunch.payload_bits, 252)
        self.assertEqual(bunch.payload, expected)
        self.assertEqual(expected, literal_join(EXPORT_PREFIX, EXPORT_BITS, actor, 75))
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader), EXPORTS)
        self.assertEqual(reader.position, 177)
        self.assertEqual(reader.read_payload(reader.remaining), actor)

    def test_recursive_outer_satisfies_reference_membership(self):
        outer = GuidExportNode(3, 'P')
        root = GuidExportNode(5, 'C', outer, 0x12345678)
        bunch = build(exports=(root,), archetype_guid=3, level_guid=5)
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader), (root,))
        self.assertEqual(reader.position, 201)
        self.assertEqual(reader.read_payload(reader.remaining), ACTOR_HEADER)

    def test_pre5_header_omits_level_and_keeps_prefix_boundary(self):
        node = GuidExportNode(5, 'C', GuidExportNode(3, 'P'), 0x12345678)
        bunch = build(exports=(node,), archetype_guid=5, level_guid=None,
                      connection_network_version=4, archive_network_version=4)
        prefix = bytes.fromhex('02000000140a0c020004000000a000040000008600f0ac682400')
        actor = bytes.fromhex('040a00')
        expected = bytes.fromhex('02000000140a0c020004000000a000040000008600f0ac6824081400')
        self.assertEqual(bunch.payload_bits, 221)
        self.assertEqual(bunch.payload, expected)
        self.assertEqual(expected, literal_join(prefix, 201, actor, 20))

    def test_missing_references_do_not_return_a_bunch(self):
        for exports, message in (((), 'archetype'), ((EXPORTS[1],), 'archetype'),
                                 ((EXPORTS[0],), 'Level')):
            with self.subTest(exports=exports):
                with self.assertRaisesRegex(ValueError, message):
                    build(exports=exports)

    def test_new_actor_must_not_reuse_an_export_guid(self):
        # Valid export GUIDs are static odd values, so the delegated dynamic
        # kind check also rejects every possible collision in this subset.
        for actor in (3, 5):
            with self.subTest(actor=actor), self.assertRaises(ValueError):
                build(actor_guid=actor)

    def test_invalid_export_graph_rejected_before_outer_walk(self):
        cycle = GuidExportNode(3, 'cycle')
        object.__setattr__(cycle, 'outer', cycle)
        with self.assertRaisesRegex(ValueError, 'depth'):
            build(exports=(cycle,))
        conflicting = (GuidExportNode(3, 'A'), GuidExportNode(3, 'other'), EXPORTS[1])
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            build(exports=conflicting)

    def test_channel_index_and_sequence_are_strict_wire_values(self):
        for index in (0, -1, UINT32_MAX + 1, True, 1.0, None):
            with self.subTest(index=index), self.assertRaises(ValueError):
                build(channel_index=index)
        for sequence in (-1, 1024, True, 7.0, None):
            with self.subTest(sequence=sequence), self.assertRaises(ValueError):
                build(channel_sequence=sequence)
        bunch = build(channel_index=UINT32_MAX, channel_sequence=1023)
        self.assertEqual(bunch.channel_index, UINT32_MAX)
        self.assertEqual(bunch.channel_sequence, 1023)

    def test_delegates_version_level_and_profile_contract(self):
        for changes in (dict(archive_network_version=13), dict(level_guid=0),
                        dict(level_guid=None), dict(references_resolvable=False),
                        dict(connection_network_version=4, archive_network_version=4),
                        dict(local_player_index=1)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build(**changes)

    def test_packet_envelope_is_separate_from_payload_storage_bound(self):
        for bound in (0, 1493, True, 128.0):
            with self.subTest(bound=bound), self.assertRaises(ValueError):
                build(max_packet_bytes=bound)
        with self.assertRaises(ValueError):
            build(max_packet_bytes=25)
        bunch = build(max_packet_bytes=32)
        self.assertLess(bunch.payload_bits, 32 * 8)
        # The payload alone fits the temporary writer, but its packet and
        # bunch headers do not fit. Composition must not claim packet fits.
        with self.assertRaises(ValueError):
            encode_native_packet(packet(bunch), max_packet_bytes=32, received_by_server=False)

    def test_complete_native_packet_roundtrip_preserves_composed_bits(self):
        bunch = build(channel_index=UINT32_MAX, channel_sequence=1023)
        raw, bits = encode_native_packet(packet(bunch), max_packet_bytes=128,
                                         received_by_server=False)
        decoded = decode_native_packet(raw, bit_count=bits, max_packet_bytes=128,
                                       received_by_server=False)
        actual = decoded.bunches[0]
        self.assertEqual(actual.payload, bunch.payload)
        self.assertEqual(actual.payload_bits, 205)
        self.assertEqual(actual.channel_index, UINT32_MAX)
        self.assertEqual(actual.channel_sequence, 1023)
        self.assertEqual(actual.channel_name, ChannelName(hardcoded_index=102))
        self.assertTrue(actual.open and actual.reliable and actual.package_exports)
        self.assertEqual(encode_native_packet(decoded, max_packet_bytes=128,
                                              received_by_server=False), (raw, bits))

    def test_explicit_replication_body_follows_header_without_alignment(self):
        # Literal bits: RepLayout1, Actor1, packed length3 = byte06, body101.
        content = bytes.fromhex('1b14')
        blocks = (ActorContentBlock(True, b'\x05', 3),)
        bunch = build(content_blocks=blocks)
        self.assertEqual(bunch.payload_bits, 218)
        self.assertEqual(bunch.payload, literal_join(COMBINED, 205, content, 13))
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader), EXPORTS)
        self.assertEqual(reader.read_payload(28), ACTOR_HEADER)
        self.assertEqual(read_actor_content_blocks(reader), blocks)

    def test_zero_body_is_a_block_and_does_not_terminate_the_sequence(self):
        blocks = (ActorContentBlock(False, b'', 0), ActorContentBlock(True, b'\x05', 3))
        content = literal_join(b'\x02\x00', 10, bytes.fromhex('1b14'), 13)
        bunch = build(content_blocks=blocks)
        self.assertEqual(bunch.payload_bits, 228)
        self.assertEqual(bunch.payload, literal_join(COMBINED, 205, content, 23))
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        read_guid_exports(reader)
        reader.read_payload(28)
        self.assertEqual(read_actor_content_blocks(reader), blocks)

    def test_base_pc_tail_precedes_content(self):
        prefix = build(connection_network_version=13, archive_network_version=13, local_player_index=0)
        blocks = (ActorContentBlock(True, b'\x05', 3),)
        bunch = build(connection_network_version=13, archive_network_version=13,
                      local_player_index=0, content_blocks=blocks)
        self.assertEqual(bunch.payload_bits, prefix.payload_bits + 13)
        self.assertEqual(bunch.payload,
            literal_join(prefix.payload, prefix.payload_bits, bytes.fromhex('1b14'), 13))

    def test_invalid_or_oversized_content_cannot_return_a_bunch(self):
        for blocks in ([ActorContentBlock(True, b'', 0)],
                       (ActorContentBlock(True, b'\x08', 3),),
                       (ActorContentBlock(True, bytes(100), 800),)):
            with self.subTest(blocks=blocks), self.assertRaises(ValueError):
                build(content_blocks=blocks, max_packet_bytes=64)


if __name__ == '__main__':
    unittest.main()
