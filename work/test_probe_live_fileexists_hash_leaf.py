import json
import unittest

import test_probe_live_fileexists_index_code as fixtures
import probe_live_fileexists_hash_leaf as tool


class HashLeafScopeTests(fixtures.IndexCodeScopeTests):
    def setUp(self):
        super().setUp()
        d = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        for b in d['index_code'].values():
            self.memory[(self.BASE + b['rva'], b['size'])] = bytes.fromhex(b['bytes'])
        for rva, size in tool.EXTRA_SPANS:
            self.memory[(self.BASE + rva, size)] = b'\x90' * size

    def new_capture(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.query, self.BASE, self.SIZE, **options)

    def test_hash_leaf_exact_scope_no_new_data(self):
        d = self.new_capture()
        self.assertEqual(self.reads[-2:], [(self.BASE + rva, size) for rva, size in tool.EXTRA_SPANS])
        self.assertEqual(d['captured_bytes'], 3063)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertFalse(d['native_called'])
        self.assertFalse(d['actual_render_proven'])

    def test_index_change_blocks_leaf_read(self):
        for rva, size in tool.prior.EXTRA_SPANS:
            key = self.BASE + rva, size
            original = self.memory[key]
            self.memory[key] = original[:-1] + bytes([original[-1] ^ 1])
            with self.assertRaises(ValueError):
                self.new_capture()
            self.assertNotIn((self.BASE + 0x10b08d50, 64), self.reads)
            self.memory[key] = original
            self.reads.clear()

    def test_pinned_source_and_original(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        path = r'F:\WeGameApps\rail_apps\DeltaForce(2001918)\DeltaForce\Binaries\Win64\DeltaForceClient-Win64-Shipping.exe'
        self.assertFalse(tool.verify_original(path)['hash_leaf']['hash_leaf_pdata_coverage'])


if __name__ == '__main__':
    unittest.main()
