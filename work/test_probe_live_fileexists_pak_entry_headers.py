import struct
import unittest

import probe_live_fileexists_pak_entry_headers as tool
import test_probe_live_fileexists_pak_entries as fixtures


class CompactEntryTests(fixtures.PakEntryTests):
    def setUp(self):
        super().setUp()
        for rva,raw in tool.code_pins().items():
            self.memory[(self.BASE+rva,len(raw))]=raw

    def compact_capture(self):
        return tool.capture(self.read,self.new_query,self.BASE,self.SIZE,
                            source_digest=tool.SOURCE_CAPTURE_SHA,
                            actual_created=self.CREATED,expected_created=self.CREATED)

    def test_uncompressed_size_flag_is_not_read_as_an_extra_size(self):
        raw=struct.pack('<III',0xe0000000,1234,5678)
        self.assertEqual(tool.compact_header_size(0xe0000000),12)
        row=tool.decode_primary_header(raw)
        self.assertEqual(row['file_offset'],1234)
        self.assertEqual(row['compressed_size'],5678)
        self.assertFalse(row['encrypted'])

    def test_compressed_encrypted_and_explicit_block_size(self):
        flags=(1<<31)|(1<<30)|(1<<29)|(1<<22)|(3<<23)|(2<<6)|63
        raw=struct.pack('<IIIII',flags,65536,4321,8000,1234)
        row=tool.decode_primary_header(raw)
        self.assertEqual(row['compression_method_index'],3)
        self.assertEqual(row['compression_block_count'],2)
        self.assertEqual(row['compression_block_size'],65536)
        self.assertTrue(row['encrypted'])

    def test_only_matching_location_primary_header_is_read(self):
        records=self.RECEIVER+0x1b00;table=self.RECEIVER+0x1d00;buffer=self.RECEIVER+0x1e00
        filename=next(iter(tool.prior.prior.prior.source_filenames().values()))[0]['filename']
        hashed=tool.prior.prior.prior.native_directory_hash(filename)
        for off,size,value in ((0,8,records),(8,4,1),(0x40,8,table),(0x48,4,1)):
            self.memory[(self.map+off,size)]=value.to_bytes(size,'little')
        self.memory[(table,4)]=struct.pack('<i',0)
        self.memory[(records,24)]=struct.pack('<QiIii',hashed,100,0,-1,0)
        self.memory[(self.pak+0x218,16)]=struct.pack('<Qii',buffer,1024,1024)
        self.memory[(buffer+100,4)]=struct.pack('<I',0xc0000000)
        self.memory[(buffer+104,8)]=struct.pack('<II',1234,512)
        self.memory[(buffer+100,12)]=struct.pack('<III',0xc0000000,1234,512)
        result=self.compact_capture()
        self.assertEqual(len(result['compact_entry_headers']),1)
        self.assertEqual(result['compact_entry_headers'][0]['file_offset'],1234)
        self.assertFalse(result['actual_render_proven'])
        self.assertNotIn((buffer,1024),self.reads)

    def test_changed_decoder_stops_before_new_heap_fields(self):
        self.memory[(self.BASE+0x12463a90,702)]=b'\x90'*702
        with self.assertRaisesRegex(ValueError,'fresh_decoder_changed'):
            self.compact_capture()
        self.assertNotIn((self.RECEIVER+8,8),self.reads)


if __name__=='__main__':
    unittest.main()
