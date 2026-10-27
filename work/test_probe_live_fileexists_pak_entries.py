import json
import struct
import unittest

import probe_live_fileexists_pak_entries as tool
import test_probe_live_fileexists_pak_headers as fixtures


class PakEntryTests(fixtures.PakHeaderTests):
    def setUp(self):
        super().setUp()
        saved=json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        block=saved['pak_helper_code']['FilenameMapLookup']
        self.memory[(self.BASE+block['rva'],block['size'])]=bytes.fromhex(block['bytes'])
        self.map=self.pak+0x1c8
        for off,size in ((0,8),(8,4),(0x34,4),(0x40,8),(0x48,4)):
            self.memory[(self.map+off,size)]=bytes(size)

    def entry_capture(self):
        return tool.capture(self.read,self.new_query,self.BASE,self.SIZE,
                            source_digest=tool.SOURCE_CAPTURE_SHA,
                            actual_created=self.CREATED,expected_created=self.CREATED)

    def test_empty_map_is_only_candidate_hash_miss(self):
        result=self.entry_capture()
        self.assertEqual(len(result['pak_filename_queries']),12)
        self.assertTrue(all(row['exact_hash_match'] is None for row in result['pak_filename_queries']))
        self.assertFalse(result['filename_normalization_observed'])
        self.assertFalse(result['actual_archive_entry_resolved'])
        self.assertFalse(result['native_FileExists_result_observed'])

    def test_source_selected_hash_collision_chain_and_matching_location(self):
        records=self.RECEIVER+0x1b00
        table=self.RECEIVER+0x1d00
        files=[item for images in tool.prior.prior.source_filenames().values() for item in images]
        for off,size,value in ((0,8,records),(8,4,12),(0x40,8,table),(0x48,4,1)):
            self.memory[(self.map+off,size)]=value.to_bytes(size,'little')
        self.memory[(table,4)]=struct.pack('<i',0)
        for i,item in enumerate(files):
            hashed=tool.prior.prior.native_directory_hash(item['filename'])
            self.memory[(records+i*24,24)]=struct.pack('<QiIiI',hashed,100+i,0,i+1 if i<11 else -1,0)
        result=self.entry_capture()
        self.assertEqual([row['exact_hash_match']['location_i32'] for row in result['pak_filename_queries']],list(range(100,112)))
        self.assertFalse(result['actual_render_proven'])

    def test_cyclic_hash_chain_is_refused(self):
        records=self.RECEIVER+0x1b00
        table=self.RECEIVER+0x1d00
        for off,size,value in ((0,8,records),(8,4,1),(0x40,8,table),(0x48,4,1)):
            self.memory[(self.map+off,size)]=value.to_bytes(size,'little')
        self.memory[(table,4)]=struct.pack('<i',0)
        self.memory[(records,24)]=struct.pack('<QQii',0,1,0,0)
        with self.assertRaisesRegex(ValueError,'hash_chain'):
            self.entry_capture()

    def test_changed_map_code_blocks_first_index_read(self):
        self.memory[(self.BASE+tool.LOOKUP_RVA,tool.LOOKUP_SIZE)]=b'\x90'*tool.LOOKUP_SIZE
        with self.assertRaisesRegex(ValueError,'fresh_map_lookup_code_changed'):
            self.entry_capture()
        self.assertNotIn((self.RECEIVER+8,8),self.reads)

    def test_entry_source_is_pinned(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE),tool.SOURCE_CAPTURE_SHA)


if __name__=='__main__':
    unittest.main()
