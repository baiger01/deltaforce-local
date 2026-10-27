"""Synthetic byte readers verify fixed native code capture boundaries."""

import inspect
import struct
import unittest
from unittest import mock

import probe_live_resource_implementations as probe


BASE = 0x140000000
MODULE_SIZE = 0x1ff8f000
CALLS = {
    'record_from_input_string': ('FastRequestAsyncLoad', 0x0d4cf651, 0x10ebb460, 1024),
    'key_string_from_record': ('OnFastLoadComplete', 0x0d4e1107, 0x10ec0870, 512),
    'object_from_record': ('OnFastLoadComplete', 0x0d4e110f, 0x10eba6f0, 512),
}
HELPERS = {
    'non_slash_string_transform': ('record_from_input_string', 0x10ebb5b5, 0x10cc77c0, 1024),
}
PARSERS = {
    'typed_string_parser': ('non_slash_string_transform', 0x10cc77eb, 0x10cd5b10, 1024),
}


def fixture():
    records = {}
    for name, (rva, row) in probe.registration_probe.REGISTRATIONS.items():
        values = tuple(BASE + offset for offset in row[:5]) + (row[5],)
        records[rva, 48] = struct.pack('<6Q', *values)
        records[row[0], 32] = name.encode('ascii').ljust(32, b'\0')
    for rva, size in probe.registration_probe.FIXED_CODE.values():
        records[rva, size] = bytes(size)
    for entry, target in probe.IMPLEMENTATIONS.values():
        size = next(size for rva, size in probe.registration_probe.FIXED_CODE.values() if rva == entry)
        records[entry, size] = b'\xe9' + struct.pack('<i', target - entry - 5) + bytes(size - 5)
        records[target, probe.IMPLEMENTATION_SIZE] = bytes(probe.IMPLEMENTATION_SIZE)
    for owner, callsite, target, size in CALLS.values():
        source_rva = probe.IMPLEMENTATIONS[owner][1]
        code = bytearray(records[source_rva, probe.IMPLEMENTATION_SIZE])
        offset = callsite - source_rva
        code[offset:offset + 5] = b'\xe8' + struct.pack('<i', target - callsite - 5)
        records[source_rva, probe.IMPLEMENTATION_SIZE] = bytes(code)
        records[target, size] = b'\xc3' + bytes(size - 1)
    for owner, callsite, target, size in HELPERS.values():
        source_rva, source_size = CALLS[owner][2:]
        code = bytearray(records[source_rva, source_size])
        offset = callsite - source_rva
        code[offset:offset + 5] = b'\xe8' + struct.pack('<i', target - callsite - 5)
        records[source_rva, source_size] = bytes(code)
        records[target, size] = b'\xc3' + bytes(size - 1)
    for owner, callsite, target, size in PARSERS.values():
        source_rva, source_size = HELPERS[owner][2:]
        code = bytearray(records[source_rva, source_size])
        offset = callsite - source_rva
        code[offset:offset + 5] = b'\xe8' + struct.pack('<i', target - callsite - 5)
        records[source_rva, source_size] = bytes(code)
        records[target, size] = b'\xc3' + bytes(size - 1)
    return records


class ObjectPathWitnessTests(unittest.TestCase):
    def reader(self, records):
        observed = []

        def read(address, size):
            key = address - BASE, size
            observed.append(key)
            if key not in records:
                raise AssertionError(f'Unapproved synthetic range: {key}')
            return records[key]

        return read, observed

    def test_default_capture_does_not_read_optional_targets(self):
        read, observed = self.reader(fixture())
        report = probe.capture_implementations(read, BASE, MODULE_SIZE)
        self.assertNotIn('object_path_calls', report)
        self.assertNotIn('object_path_helpers', report)
        self.assertNotIn('object_path_parsers', report)
        self.assertEqual(report['captured_bytes'], 7248)
        self.assertFalse(any((target, size) in observed for _, _, target, size in CALLS.values()))
        self.assertFalse(any((target, size) in observed for _, _, target, size in HELPERS.values()))
        self.assertFalse(any((target, size) in observed for _, _, target, size in PARSERS.values()))

    def test_optional_capture_verifies_three_calls_and_counts_exact_bytes(self):
        self.assertIn('object_path_calls', inspect.signature(probe.capture_implementations).parameters)
        read, observed = self.reader(fixture())
        report = probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertEqual(set(report['object_path_calls']), set(CALLS))
        self.assertEqual(report['captured_bytes'], 11344)
        for name, (_, callsite, target, size) in CALLS.items():
            witness = report['object_path_calls'][name]
            self.assertTrue(witness['direct_call_target_verified'])
            self.assertEqual(witness['source_callsite_rva'], callsite)
            self.assertEqual((witness['rva'], witness['size']), (target, size))
            self.assertIn((target, size), observed)
        self.assertEqual(set(report['object_path_helpers']), set(HELPERS))
        helper = report['object_path_helpers']['non_slash_string_transform']
        self.assertTrue(helper['direct_call_target_verified'])
        self.assertEqual(helper['source_callsite_rva'], 0x10ebb5b5)
        self.assertEqual((helper['rva'], helper['size']), (0x10cc77c0, 1024))
        self.assertEqual(observed[-2], (0x10cc77c0, 1024))
        self.assertEqual(set(report['object_path_parsers']), set(PARSERS))
        parser = report['object_path_parsers']['typed_string_parser']
        self.assertTrue(parser['direct_call_target_verified'])
        self.assertEqual(parser['source_callsite_rva'], 0x10cc77eb)
        self.assertEqual((parser['rva'], parser['size']), (0x10cd5b10, 1024))
        self.assertEqual(observed[-1], (0x10cd5b10, 1024))
        self.assertEqual(probe.allowed_spans(True) - probe.allowed_spans(),
                         {(target, size) for _, _, target, size in
                          (*CALLS.values(), *HELPERS.values(), *PARSERS.values())})

    def test_wrong_call_opcode_is_rejected_before_any_optional_read(self):
        self.assertIn('object_path_calls', inspect.signature(probe.capture_implementations).parameters)
        records = fixture()
        owner, callsite, _, _ = CALLS['key_string_from_record']
        source_rva = probe.IMPLEMENTATIONS[owner][1]
        code = bytearray(records[source_rva, probe.IMPLEMENTATION_SIZE])
        code[callsite - source_rva] = 0xe9
        records[source_rva, probe.IMPLEMENTATION_SIZE] = bytes(code)
        read, observed = self.reader(records)
        with self.assertRaisesRegex(ValueError, 'direct E8 call'):
            probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertFalse(any((target, size) in observed for _, _, target, size in CALLS.values()))

    def test_wrong_call_target_is_rejected_before_any_optional_read(self):
        self.assertIn('object_path_calls', inspect.signature(probe.capture_implementations).parameters)
        records = fixture()
        owner, callsite, target, _ = CALLS['object_from_record']
        source_rva = probe.IMPLEMENTATIONS[owner][1]
        code = bytearray(records[source_rva, probe.IMPLEMENTATION_SIZE])
        offset = callsite - source_rva
        code[offset:offset + 5] = b'\xe8' + struct.pack('<i', target + 16 - callsite - 5)
        records[source_rva, probe.IMPLEMENTATION_SIZE] = bytes(code)
        read, observed = self.reader(records)
        with self.assertRaisesRegex(ValueError, 'call target differs'):
            probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertFalse(any((target, size) in observed for _, _, target, size in CALLS.values()))

    def test_optional_target_outside_module_is_rejected_before_reads(self):
        read, observed = self.reader(fixture())
        with self.assertRaisesRegex(ValueError, 'exceeds the main module'):
            probe.capture_implementations(read, BASE, 0x10ec0870, object_path_calls=True)
        self.assertEqual(observed, [])

    def test_wrong_helper_opcode_is_rejected_before_helper_read(self):
        records = fixture()
        source_rva, source_size = CALLS['record_from_input_string'][2:]
        code = bytearray(records[source_rva, source_size])
        code[0x10ebb5b5 - source_rva] = 0xe9
        records[source_rva, source_size] = bytes(code)
        read, observed = self.reader(records)
        with self.assertRaisesRegex(ValueError, 'direct E8 call'):
            probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertTrue(all((target, size) in observed for _, _, target, size in CALLS.values()))
        self.assertNotIn((0x10cc77c0, 1024), observed)

    def test_wrong_helper_target_is_rejected_before_helper_read(self):
        records = fixture()
        source_rva, source_size = CALLS['record_from_input_string'][2:]
        code = bytearray(records[source_rva, source_size])
        offset = 0x10ebb5b5 - source_rva
        code[offset:offset + 5] = b'\xe8' + struct.pack('<i', 0x10cc77d0 - 0x10ebb5b5 - 5)
        records[source_rva, source_size] = bytes(code)
        read, observed = self.reader(records)
        with self.assertRaisesRegex(ValueError, 'call target differs'):
            probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertNotIn((0x10cc77c0, 1024), observed)

    def test_helper_callsite_outside_source_is_rejected_before_helper_read(self):
        read, observed = self.reader(fixture())
        invalid = ('record_from_input_string', 0x10ebb460 + 1024 - 4, 0x10cc77c0, 1024)
        with mock.patch.dict(probe.OBJECT_PATH_HELPERS, non_slash_string_transform=invalid):
            with self.assertRaisesRegex(ValueError, 'direct E8 call'):
                probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertNotIn((0x10cc77c0, 1024), observed)

    def test_helper_target_outside_module_is_rejected_before_reads(self):
        read, observed = self.reader(fixture())
        invalid = ('record_from_input_string', 0x10ebb5b5, MODULE_SIZE - 512, 1024)
        with mock.patch.dict(probe.OBJECT_PATH_HELPERS, non_slash_string_transform=invalid):
            with self.assertRaisesRegex(ValueError, 'exceeds the main module'):
                probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertEqual(observed, [])

    def test_wrong_parser_opcode_is_rejected_before_parser_read(self):
        records = fixture()
        source_rva, source_size = HELPERS['non_slash_string_transform'][2:]
        code = bytearray(records[source_rva, source_size])
        code[0x10cc77eb - source_rva] = 0xe9
        records[source_rva, source_size] = bytes(code)
        read, observed = self.reader(records)
        with self.assertRaisesRegex(ValueError, 'direct E8 call'):
            probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertIn((0x10cc77c0, 1024), observed)
        self.assertNotIn((0x10cd5b10, 1024), observed)

    def test_wrong_parser_target_is_rejected_before_parser_read(self):
        records = fixture()
        source_rva, source_size = HELPERS['non_slash_string_transform'][2:]
        code = bytearray(records[source_rva, source_size])
        offset = 0x10cc77eb - source_rva
        code[offset:offset + 5] = b'\xe8' + struct.pack('<i', 0x10cd5b20 - 0x10cc77eb - 5)
        records[source_rva, source_size] = bytes(code)
        read, observed = self.reader(records)
        with self.assertRaisesRegex(ValueError, 'call target differs'):
            probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertNotIn((0x10cd5b10, 1024), observed)

    def test_parser_callsite_outside_source_is_rejected_before_parser_read(self):
        read, observed = self.reader(fixture())
        invalid = ('non_slash_string_transform', 0x10cc77c0 + 1024 - 4, 0x10cd5b10, 1024)
        with mock.patch.dict(probe.OBJECT_PATH_PARSERS, typed_string_parser=invalid):
            with self.assertRaisesRegex(ValueError, 'direct E8 call'):
                probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertNotIn((0x10cd5b10, 1024), observed)

    def test_parser_target_outside_module_is_rejected_before_reads(self):
        read, observed = self.reader(fixture())
        invalid = ('non_slash_string_transform', 0x10cc77eb, MODULE_SIZE - 512, 1024)
        with mock.patch.dict(probe.OBJECT_PATH_PARSERS, typed_string_parser=invalid):
            with self.assertRaisesRegex(ValueError, 'exceeds the main module'):
                probe.capture_implementations(read, BASE, MODULE_SIZE, object_path_calls=True)
        self.assertEqual(observed, [])


if __name__ == '__main__':
    unittest.main()
