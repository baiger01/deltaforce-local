"""Pure byte-boundary tests for the offline exact-RIP discovery helper."""
import struct
import unittest

from offline_received_packet_xrefs import literal_candidates


class Tests(unittest.TestCase):
    @staticmethod
    def lea(at, target):
        return b'\x4c\x8d\x05' + struct.pack('<i', target - at - 7)

    def test_exact_rip_displacement(self):
        at, target = 0x12801000, 0x1b1d96f0
        code = b'\x90' * 3 + self.lea(at + 3, target) + b'\xc3'
        self.assertEqual(literal_candidates(code, at, {target}), [(at + 3, target, code[3:10])])

    def test_negative_displacement(self):
        at, target = 0x12801000, 0x12700000
        code = self.lea(at, target)
        self.assertEqual(literal_candidates(code, at, {target})[0][:2], (at, target))

    def test_unrelated_literal_not_reported(self):
        self.assertEqual(literal_candidates(self.lea(0x1000, 0x2222), 0x1000, {0x2223}), [])

    def test_truncated_instruction_not_reported(self):
        self.assertEqual(literal_candidates(b'\x4c\x8d\x05\x00\x00', 0x1000, {0x1007}), [])

    def test_non_rip_modrm_not_reported(self):
        self.assertEqual(literal_candidates(b'\x4c\x8d\x04' + b'\0' * 4, 0x1000, {0x1007}), [])


if __name__ == '__main__':
    unittest.main()
