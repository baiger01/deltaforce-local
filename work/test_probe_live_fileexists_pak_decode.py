import json
import unittest

import probe_live_fileexists_pak_decode as tool
import test_probe_live_fileexists_pak_helpers as fixtures


class PakDecodeTests(fixtures.PakHelperTests):
    def setUp(self):
        super().setUp()
        saved=json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        for block in saved['pak_helper_code'].values():
            self.memory[(self.BASE+block['rva'],block['size'])]=bytes.fromhex(block['bytes'])
        for rva,size in tool.EXTRA_SPANS:
            self.memory[(self.BASE+rva,size)]=b'\x90'*size

    def test_decoder_scope_preserves_no_new_heap_reads(self):
        result=tool.capture(self.read,self.query,self.BASE,self.SIZE,source_digest=tool.SOURCE_CAPTURE_SHA,
                            actual_created=self.CREATED,expected_created=self.CREATED)
        self.assertEqual(result['captured_bytes'],6339)
        self.assertEqual(result['data_qword_reads'],6)
        self.assertFalse(result['native_called'])
        self.assertFalse(result['actual_render_proven'])

    def test_changed_prefix_gates_decoder_read(self):
        self.memory[(self.BASE+0x1246ac20,118)]=b'\x90'*118
        with self.assertRaisesRegex(ValueError,'parent_helpers_changed'):
            tool.capture(self.read,self.query,self.BASE,self.SIZE,source_digest=tool.SOURCE_CAPTURE_SHA,
                         actual_created=self.CREATED,expected_created=self.CREATED)
        self.assertNotIn((self.BASE+0x12463a90,702),self.reads)

    def test_decoder_source_is_pinned(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE),tool.SOURCE_CAPTURE_SHA)


if __name__=='__main__':
    unittest.main()
