import struct
import unittest

from research_updated_header_cells import displacement_candidates


class DisplacementCandidatesTest(unittest.TestCase):
    def test_rip_displacement_with_trailing_immediate(self):
        first, target = 0x1000, 0x2000
        raw = b'\xc6\x05'+struct.pack('<i', target-(first+7))+b'\x01'
        self.assertIn((2, 1), displacement_candidates(raw, first, target))

    def test_rip_displacement_without_trailing_immediate(self):
        first, target = 0x1000, 0x2000
        raw = b'\x48\x8d\x0d'+struct.pack('<i', target-(first+7))
        self.assertIn((3, 0), displacement_candidates(raw, first, target))

    def test_negative_displacement_and_absent_target(self):
        raw = b'\xc6\x05'+struct.pack('<i', 0x800-0x1007)+b'\x02'
        self.assertIn((2, 1), displacement_candidates(raw, 0x1000, 0x800))
        self.assertEqual(displacement_candidates(raw, 0x1000, 0x3000), [])


if __name__ == '__main__':
    unittest.main()
