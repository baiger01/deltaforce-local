import json
import unittest

import probe_live_fileexists_candidate_tail as tool
import test_probe_live_fileexists_package_candidates as fixtures


class CandidateTailTests(fixtures.CandidateScopeTests):
    def setUp(self):
        super().setUp()
        d = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        for b in d['package_candidate_code'].values():
            self.memory[(self.BASE + b['rva'], b['size'])] = bytes.fromhex(b['bytes'])
        self.memory[(self.BASE + 0x12467e5d, 73)] = b'\x90' * 73

    def test_final_fixed_scope_and_source_gate(self):
        opts = dict(source_digest=tool.SOURCE_CAPTURE_SHA, actual_created=self.CREATED, expected_created=self.CREATED)
        d = tool.capture(self.read, self.query, self.BASE, self.SIZE, **opts)
        self.assertEqual(d['captured_bytes'], 3360)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertEqual(self.reads[-1], (self.BASE + 0x12467e5d, 73))
        self.reads.clear()
        self.memory[(self.BASE + 0x12467e48, 21)] = b'\x90'*21
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, self.SIZE, **opts)
        self.assertNotIn((self.BASE + 0x12467e5d, 73), self.reads)
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)


if __name__ == '__main__':
    unittest.main()
