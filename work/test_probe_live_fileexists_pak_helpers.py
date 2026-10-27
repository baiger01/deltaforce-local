import json
import unittest

import probe_live_fileexists_pak_helpers as tool
import test_probe_live_fileexists_pak_lookup as fixtures


class PakHelperTests(fixtures.PakLookupScopeTests):
    def setUp(self):
        super().setUp()
        saved = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        for block in saved['pak_lookup_code'].values():
            self.memory[(self.BASE + block['rva'],block['size'])] = bytes.fromhex(block['bytes'])
        for rva,size in tool.EXTRA_SPANS:
            self.memory[(self.BASE+rva,size)] = b'\x90'*size

    def helper_capture(self):
        return tool.capture(self.read,self.query,self.BASE,self.SIZE,
                            source_digest=tool.SOURCE_CAPTURE_SHA,
                            actual_created=self.CREATED,expected_created=self.CREATED)

    def test_three_direct_helpers_only(self):
        result=self.helper_capture()
        self.assertEqual(result['captured_bytes'],5364)
        self.assertEqual(self.reads[-3:],[(self.BASE+rva,size) for rva,size in tool.EXTRA_SPANS])
        self.assertEqual(result['data_qword_reads'],6)
        self.assertFalse(result['native_called'])
        self.assertFalse(result['pak_helper_code']['DecodeEntryPrefix']['function_complete'])

    def test_parent_hash_gates_new_helpers(self):
        key=(self.BASE+0x12467fe8,718)
        self.memory[key]=b'\x90'*718
        with self.assertRaisesRegex(ValueError,'parent_code_changed'):
            self.helper_capture()
        self.assertNotIn((self.BASE+0xdb8360,194),self.reads)

    def test_exact_source_is_accepted(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE),tool.SOURCE_CAPTURE_SHA)


if __name__=='__main__':
    unittest.main()
