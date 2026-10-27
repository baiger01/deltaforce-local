import json
import unittest

import probe_live_fileexists_pak_lookup as tool
import test_probe_live_fileexists_candidate_tail as fixtures


class PakLookupScopeTests(fixtures.CandidateTailTests):
    def setUp(self):
        super().setUp()
        d = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        b = d['candidate_tail_code']
        self.memory[(self.BASE + b['rva'], b['size'])] = bytes.fromhex(b['bytes'])
        for rva, size in tool.EXTRA_SPANS:
            self.memory[(self.BASE + rva, size)] = b'\x90'*size

    def test_exact_two_spans_after_fresh_source_call(self):
        opts = dict(source_digest=tool.SOURCE_CAPTURE_SHA,actual_created=self.CREATED,expected_created=self.CREATED)
        d = tool.capture(self.read,self.query,self.BASE,self.SIZE,**opts)
        self.assertEqual(d['captured_bytes'],4390)
        self.assertEqual(d['data_qword_reads'],6)
        self.assertEqual(self.reads[-2:],[(self.BASE+rva,size) for rva,size in tool.EXTRA_SPANS])
        self.assertFalse(d['actual_render_proven'])
        self.reads.clear()
        self.memory[(self.BASE+0x12467e5d,73)]=b'\x90'*73
        with self.assertRaises(ValueError):
            tool.capture(self.read,self.query,self.BASE,self.SIZE,**opts)
        self.assertNotIn((self.BASE+0x12467eb0,312),self.reads)
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE),tool.SOURCE_CAPTURE_SHA)
        path=r'F:\WeGameApps\rail_apps\DeltaForce(2001918)\DeltaForce\Binaries\Win64\DeltaForceClient-Win64-Shipping.exe'
        self.assertIn('pak_lookup',tool.verify_original(path))


if __name__=='__main__':
    unittest.main()
