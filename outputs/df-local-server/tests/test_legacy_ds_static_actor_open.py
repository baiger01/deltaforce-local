import unittest

from dfserver.legacy_ds_actor_open import write_static_actor_open
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_actor_bunch import build_static_actor_bunch
from dfserver.legacy_ds_guid_exports import GuidExportNode, read_guid_exports
from dfserver.legacy_ds_bit_archive import BitReader


class StaticActorOpenTests(unittest.TestCase):
    def test_ordinary_static_guid_uses_only_packed_reference(self):
        # Independent native packed-u32 oracle: seven data bits per byte,
        # shifted left once; low bit means another byte follows.
        for guid in (3, 257, 0xffffffff):
            remaining, expected = guid, bytearray()
            while True:
                group = remaining & 0x7f
                remaining >>= 7
                expected.append((group << 1) | bool(remaining))
                if not remaining:
                    break
            writer = BitWriter(maximum_bits=40)
            bits = write_static_actor_open(writer, actor_guid=guid, references_resolvable=True)
            self.assertEqual(bits, len(expected) * 8)
            self.assertEqual(writer.to_bytes(), bytes(expected))

    def test_unaligned_reference_does_not_add_alignment_or_spawn_fields(self):
        writer = BitWriter(maximum_bits=17)
        writer.write_bool(True)
        self.assertEqual(write_static_actor_open(writer, actor_guid=257,
            references_resolvable=True), 16)
        self.assertEqual(writer.bit_count, 17)
        self.assertEqual(writer.to_bytes(), bytes((7, 8, 0)))

    def test_null_default_dynamic_and_noninteger_guids_refused_atomically(self):
        for guid in (0, 1, 2, 4, -1, 0x100000000, True, '257'):
            writer = BitWriter(maximum_bits=40)
            writer.write_bool(True)
            with self.assertRaises(ValueError):
                write_static_actor_open(writer, actor_guid=guid, references_resolvable=True)
            self.assertEqual((writer.bit_count, writer.to_bytes()), (1, b'\x01'))

    def test_unqualified_reference_and_capacity_failure_are_atomic(self):
        for resolved in (False, None, 1):
            writer = BitWriter(maximum_bits=40)
            with self.assertRaises(ValueError):
                write_static_actor_open(writer, actor_guid=257, references_resolvable=resolved)
            self.assertEqual(writer.bit_count, 0)
        writer = BitWriter(maximum_bits=8)
        writer.write_bool(True)
        with self.assertRaises(ValueError):
            write_static_actor_open(writer, actor_guid=257, references_resolvable=True)
        self.assertEqual((writer.bit_count, writer.to_bytes()), (1, b'\x01'))

    def test_static_bunch_exports_actor_then_only_its_reference(self):
        outer = GuidExportNode(3, '/Game/Example/Entry')
        actor = GuidExportNode(5, 'ExistingActor', outer)
        bunch = build_static_actor_bunch(exports=(actor,), actor_guid=5,
            actor_open_hook_has_no_extra_fields=True,
            references_resolvable=True, channel_index=7, channel_sequence=1,
            max_packet_bytes=1200)
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader), (actor,))
        self.assertEqual(reader.read_packed_int(), 5)
        self.assertEqual(reader.position, bunch.payload_bits)
        self.assertTrue(bunch.open and bunch.reliable and bunch.package_exports)

    def test_unexported_static_actor_cannot_open(self):
        with self.assertRaisesRegex(ValueError, 'missing from the export graph'):
            build_static_actor_bunch(exports=(GuidExportNode(3, '/Game/Example/Entry'),),
                actor_open_hook_has_no_extra_fields=True,
                actor_guid=5, references_resolvable=True, channel_index=7,
                channel_sequence=1, max_packet_bytes=1200)

    def test_unknown_actor_channel_hook_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'no-extra-fields'):
            build_static_actor_bunch(exports=(GuidExportNode(5, 'ExistingActor'),),
                actor_guid=5, references_resolvable=True,
                actor_open_hook_has_no_extra_fields=False, channel_index=7,
                channel_sequence=1, max_packet_bytes=1200)


if __name__ == '__main__':
    unittest.main()
