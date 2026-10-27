import json
import unittest

import probe_live_fileexists_package_candidates as tool
import test_probe_live_fileexists_hash_leaf as fixtures


class CandidateScopeTests(fixtures.HashLeafScopeTests):
    def setUp(self):
        super().setUp()
        d = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        for b in d['hash_leaf_code'].values():
            self.memory[(self.BASE + b['rva'], b['size'])] = bytes.fromhex(b['bytes'])
        for rva, size in tool.EXTRA_SPANS:
            self.memory[(self.BASE + rva, size)] = b'\x90' * size

    def test_candidate_scope_and_fresh_hash_gate(self):
        kwargs = dict(source_digest=tool.SOURCE_CAPTURE_SHA, actual_created=self.CREATED, expected_created=self.CREATED)
        d = tool.capture(self.read, self.query, self.BASE, self.SIZE, **kwargs)
        self.assertEqual(d['captured_bytes'], 3287)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertEqual(self.reads[-2:], [(self.BASE + rva, size) for rva, size in tool.EXTRA_SPANS])
        self.reads.clear()
        key = self.BASE + 0x10b08d50, 64
        self.memory[key] = b'\x90' * 64
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, self.SIZE, **kwargs)
        self.assertNotIn((self.BASE + 0x12467d7d, 203), self.reads)

    def test_candidate_source_and_disk(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        path = r'F:\WeGameApps\rail_apps\DeltaForce(2001918)\DeltaForce\Binaries\Win64\DeltaForceClient-Win64-Shipping.exe'
        self.assertIn('package_candidate_consumer', tool.verify_original(path))


if __name__ == '__main__':
    unittest.main()
