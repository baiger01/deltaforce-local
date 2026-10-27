"""Wire literal and rejection tests; never evidence of native acceptance."""
import unittest
from dataclasses import replace

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_byte_scalar import (
    BYTE_SERIALIZER_RVA, NativeByteEnumBinding, qualified_byte_bit_count,
    write_byte_enum_value,
    ByteEnumField, build_byte_reference_content,
)
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256
from dfserver.legacy_ds_rep_layout_refs import ObjectReference


class NativeByteEnumTests(unittest.TestCase):
    def binding(self, maximum=4):
        return NativeByteEnumBinding(SHIPPING_SHA256, BYTE_SERIALIZER_RVA,
                                     maximum is not None, maximum)

    def rejected(self, value, binding):
        writer = BitWriter(); writer.write_bits(5, 3)
        previous = writer.to_bytes(), writer.bit_count
        with self.assertRaises(ValueError):
            write_byte_enum_value(writer, value, binding=binding)
        self.assertEqual((writer.to_bytes(), writer.bit_count), previous)

    def test_ceil_log2_native_literal_widths(self):
        for maximum, width in ((0,0),(1,0),(2,1),(3,2),(4,2),(5,3),(128,7),(129,8),(256,8),(None,8)):
            self.assertEqual(qualified_byte_bit_count(self.binding(maximum)), width)

    def test_every_cursor_offset_matches_independent_literal_and_suffix(self):
        for maximum, value, width in ((4,2,2),(5,4,3),(None,0xa5,8),(1,0,0)):
            for prefix_width in range(8):
                writer = BitWriter(); prefix = (1 << prefix_width)-1
                writer.write_bits(prefix, prefix_width)
                self.assertEqual(write_byte_enum_value(writer, value, binding=self.binding(maximum)), width)
                writer.write_bits(0x15,5)
                literal = prefix | value << prefix_width | 0x15 << (prefix_width+width)
                total = prefix_width+width+5
                self.assertEqual((writer.to_bytes(),writer.bit_count), (literal.to_bytes((total+7)//8,'little'),total))
                reader = BitReader(writer.to_bytes(),bit_count=total)
                self.assertEqual(reader.read_bits(prefix_width),prefix)
                self.assertEqual(reader.read_bits(width),value)
                self.assertEqual(reader.read_bits(5),0x15)
                self.assertEqual(reader.remaining,0)

    def test_invalid_and_lossy_values_are_atomic(self):
        for maximum, values in ((4,(True,-1,4,255,256,1.0,None)),(1,(1,)),(None,(256,-1,False))):
            for value in values: self.rejected(value,self.binding(maximum))

    def test_enum_metadata_and_exact_source_are_required(self):
        binding = self.binding()
        for change in ({'client_sha256':'0'*64},{'serializer_target_rva':6},
                       {'serializer_target_rva':str(BYTE_SERIALIZER_RVA)},
                       {'enum_present':1},{'enum_maximum':True},{'enum_maximum':-1},
                       {'enum_maximum':257},{'enum_maximum':None},
                       {'enum_present':False,'enum_maximum':4}):
            self.rejected(0,replace(binding,**change))
        self.rejected(0,{'serializer_target_rva':BYTE_SERIALIZER_RVA})

    def test_capacity_rejection_does_not_modify_cursor(self):
        writer=BitWriter(maximum_bits=4); writer.write_bits(5,3)
        previous=writer.to_bytes(),writer.bit_count
        with self.assertRaises(ValueError): write_byte_enum_value(writer,2,binding=self.binding())
        self.assertEqual((writer.to_bytes(),writer.bit_count),previous)

    def test_mixed_stream_matches_independent_unaligned_field_literal(self):
        block=build_byte_reference_content((ByteEnumField(6,2,self.binding()),),
            (ObjectReference(18,6),ObjectReference(19,2)))
        # Independent native packed bytes: handle6=0c, value2=two bits,
        # handle18=24,guid6=0c,handle19=26,guid2=04,terminal=00.
        literal=0x0c<<1 | 2<<9 | 0x24<<11 | 0x0c<<19 | 0x26<<27 | 0x04<<35
        self.assertEqual((block.has_rep_layout,block.payload,block.payload_bit_count),
            (True,literal.to_bytes(7,'little'),51))
        reader=BitReader(block.payload,bit_count=51)
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_packed_int(),6)
        self.assertEqual(reader.read_bits(2),2)
        self.assertEqual((reader.read_packed_int(),reader.read_packed_int()),(18,6))
        self.assertEqual((reader.read_packed_int(),reader.read_packed_int()),(19,2))
        self.assertEqual(reader.read_packed_int(),0)
        self.assertEqual(reader.remaining,0)

    def test_mixed_stream_duplicate_unknown_and_array_like_handles_refused(self):
        for fields, refs in (
            ((),()),([ByteEnumField(6,0,self.binding())],()),
            ((ByteEnumField(0,0,self.binding()),),()),
            ((ByteEnumField(True,0,self.binding()),),()),
            ((ByteEnumField(6,0,self.binding()),ByteEnumField(6,1,self.binding())),()),
            ((ByteEnumField(6,0,self.binding()),),(ObjectReference(6,2),)),
            ((ByteEnumField(6,0,self.binding()),),(ObjectReference(18,1),)),
            ((ByteEnumField(6,4,self.binding()),),()),
        ):
            with self.subTest(fields=fields,refs=refs), self.assertRaises(ValueError):
                build_byte_reference_content(fields,refs)


if __name__ == '__main__': unittest.main()
