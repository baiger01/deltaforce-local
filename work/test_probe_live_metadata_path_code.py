import unittest

import probe_live_metadata_path_code as probe


class FixedPathCodeTests(unittest.TestCase):
    def read(self, address, size):
        self.reads.append((address, size))
        return bytes(size)

    def setUp(self):
        self.reads = []

    def test_exact_one_code_span(self):
        report = probe.capture(self.read, 0x140000000, probe.MODULE_SIZE, 10.0, 10.0)
        self.assertEqual(self.reads, [(0x140000000 + probe.CODE_RVA, 1024)])
        self.assertEqual(report['captured_bytes'], 1024)
        self.assertFalse(report['object_fields_read'])
        self.assertFalse(report['schema_verified'])

    def test_wrong_module_size_has_no_reads(self):
        with self.assertRaisesRegex(ValueError, 'module_size'):
            probe.capture(self.read, 0x140000000, probe.MODULE_SIZE - 1, 10.0, 10.0)
        self.assertEqual(self.reads, [])

    def test_wrong_creation_has_no_reads(self):
        with self.assertRaises(ValueError):
            probe.capture(self.read, 0x140000000, probe.MODULE_SIZE, 11.0, 10.0)
        self.assertEqual(self.reads, [])

    def test_invalid_base_has_no_reads(self):
        for base in (0, -1, 0x800000000000, True):
            with self.assertRaises(ValueError):
                probe.capture(self.read, base, probe.MODULE_SIZE, 10.0, 10.0)
        self.assertEqual(self.reads, [])

    def test_short_read_rejected(self):
        with self.assertRaisesRegex(ValueError, 'short'):
            probe.capture(lambda a, n: bytes(n - 1), 0x140000000, probe.MODULE_SIZE, 10.0, 10.0)

    def test_reader_exception_propagates(self):
        def denied(address, size):
            raise PermissionError('denied')
        with self.assertRaises(PermissionError):
            probe.capture(denied, 0x140000000, probe.MODULE_SIZE, 10.0, 10.0)


if __name__ == '__main__':
    unittest.main()
