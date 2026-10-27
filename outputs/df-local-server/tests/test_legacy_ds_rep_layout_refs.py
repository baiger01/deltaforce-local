"""Literal consumer-inverse fixtures; no native acceptance is inferred."""
import unittest

from dfserver.legacy_ds_actor_content import ActorContentBlock, write_actor_content_block
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_rep_layout_refs import (
    MAX_REFERENCES, ObjectReference, build_object_reference_content,
    read_object_reference_content,
)


class OrdinaryReferenceTests(unittest.TestCase):
    def test_pinned_literal_consumer_fixtures(self):
        # Spec literal_fixtures: exact 25-bit property and 35-bit Actor slices.
        for handle, guid, payload, envelope in (
                (18, 2, '48080000', 'cb20210000'),
                (19, 4, '4c100000', 'cb30410000')):
            with self.subTest(handle=handle):
                block = build_object_reference_content((ObjectReference(handle, guid),))
                self.assertEqual(block, ActorContentBlock(True, bytes.fromhex(payload), 25))
                self.assertEqual(read_object_reference_content(block), (ObjectReference(handle, guid),))
                writer = BitWriter()
                write_actor_content_block(writer, block)
                self.assertEqual(writer.bit_count, 35)
                self.assertEqual(writer.to_bytes().hex(), envelope)

    def test_unaligned_streams_preserve_prefix_and_suffix(self):
        block = build_object_reference_content((ObjectReference(18, 2), ObjectReference(19, 4)))
        for prefix in range(16):
            writer = BitWriter()
            writer.write_bits((1 << prefix) - 1, prefix)
            writer.write_payload(block.payload, block.payload_bit_count)
            writer.write_bits(5, 3)
            reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
            self.assertEqual(reader.read_bits(prefix), (1 << prefix) - 1)
            read = ActorContentBlock(True, reader.read_payload(block.payload_bit_count), block.payload_bit_count)
            self.assertEqual(read_object_reference_content(read),
                             (ObjectReference(18, 2), ObjectReference(19, 4)))
            self.assertEqual(reader.read_bits(3), 5)
            self.assertEqual(reader.remaining, 0)

    def test_every_truncation_is_rejected(self):
        block = build_object_reference_content((ObjectReference(18, 2),))
        for bits in range(block.payload_bit_count):
            data = (int.from_bytes(block.payload, 'little') & ((1 << bits) - 1)).to_bytes((bits + 7) // 8, 'little')
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                read_object_reference_content(ActorContentBlock(True, data, bits))

    def test_rejects_ambiguous_handles_and_non_instance_guids(self):
        for refs in ((), [], (ObjectReference(True, 2),), (ObjectReference(0, 2),),
                     (ObjectReference(65536, 2),), (ObjectReference(18, 1),),
                     (ObjectReference(18, 0),), (ObjectReference(18, 3),),
                     (ObjectReference(18, True),), (ObjectReference(18, 1 << 32),),
                     (ObjectReference(19, 2), ObjectReference(18, 4)),
                     (ObjectReference(18, 2), ObjectReference(18, 4)),
                     tuple(ObjectReference(index + 1, 2) for index in range(MAX_REFERENCES + 1))):
            with self.subTest(refs=refs), self.assertRaises(ValueError):
                build_object_reference_content(refs)

    def test_rejects_alternate_options_and_trailing_content(self):
        block = build_object_reference_content((ObjectReference(18, 2),))
        for invalid in (ActorContentBlock(False, block.payload, block.payload_bit_count),
                        ActorContentBlock(True, bytes([block.payload[0] | 1]) + block.payload[1:], 25),
                        ActorContentBlock(True, block.payload, 26)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                read_object_reference_content(invalid)

    def test_uint32_and_uint16_boundaries(self):
        refs = (ObjectReference(65535, 0xfffffffe),)
        self.assertEqual(read_object_reference_content(build_object_reference_content(refs)), refs)


if __name__ == '__main__':
    unittest.main()
