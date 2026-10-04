import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[3]
SCRIPT = PROJECT / 'work/probe_live_resource_loader.py'
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location('live_resource_loader_probe', SCRIPT)
    probe = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(PROJECT / 'work'), *sys.path]):
        spec.loader.exec_module(probe)
else:
    probe = None


SOURCE_ROWS = {
    'Get': (0x18bdd6d0, (0x14ee5fa0, 0xd50d080, 0xd50d8c0,
                         0x18bdd9c8, 0x1d2d8340, 0x100000001)),
    'RequestAsyncLoad': (0x18bdd760, (0x169e0e50, 0xd50d090, 0xd50d7b0,
                                      0x14ee202c, 0x1d2d8360, 3)),
    'FastRequestAsyncLoad': (0x18bdd850, (0x18bc7848, 0xd50d150, 0xe050d0,
                                          0x14ee202c, 0x1d2d83b8, 2)),
    'OnFastLoadComplete': (0x18bdd910, (0x18bdda48, 0xd50d190, 0xe07100,
                                       0x14edf3dc, 0x1d2d83f8, 2)),
}
CODE_SPANS = {
    'Get_callback': (0xd50d080, 16),
    'RequestAsyncLoad_callback': (0xd50d090, 192),
    'FastRequestAsyncLoad_callback': (0xd50d150, 64),
    'OnFastLoadComplete_callback': (0xd50d190, 512),
    'Get_binding': (0xd50d8c0, 512),
    'RequestAsyncLoad_binding': (0xd50d7b0, 512),
    'FastRequestAsyncLoad_binding': (0xe050d0, 512),
    'OnFastLoadComplete_binding': (0xe07100, 512),
}


class LiveResourceLoaderProbeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(probe, 'The bounded resource loader witness is missing')
        self.base = 0x7ff600000000
        self.size = 0x1ff8f000
        self.reads = []
        self.memory = {}
        for name, (rva, row) in SOURCE_ROWS.items():
            actual = [self.base + value for value in row[:5]] + [row[5]]
            self.memory[self.base + rva, 48] = struct.pack('<6Q', *actual)
            self.memory[self.base + row[0], 32] = name.encode('ascii').ljust(32, b'\0')
        for name, (rva, size) in CODE_SPANS.items():
            self.memory[self.base + rva, size] = b'\x90' * (size - 1) + b'\xc3'

    def read(self, address, size):
        self.reads.append((address, size))
        return self.memory[address, size]

    def test_capture_keeps_four_verified_names_and_both_named_code_bindings(self):
        report = probe.capture(self.read, self.base, self.size)
        self.assertEqual(set(report['registrations']), set(SOURCE_ROWS))
        self.assertEqual(set(report['fixed_code']), set(CODE_SPANS))
        for name, (rva, row) in SOURCE_ROWS.items():
            entry = report['registrations'][name]
            self.assertEqual(entry['registration_rva'], rva)
            self.assertEqual(entry['name_rva'], row[0])
            self.assertEqual(entry['callback_rva'], row[1])
            self.assertEqual(entry['binding_rva'], row[2])
        self.assertEqual(report['fixed_code']['Get_callback']['size'], 16)
        self.assertEqual(report['fixed_code']['Get_callback']['bytes'], '90' * 15 + 'c3')

    def test_only_fixed_registration_names_and_code_are_read(self):
        report = probe.capture(self.read, self.base, self.size)
        expected = {(self.base + rva, 48) for rva, _ in SOURCE_ROWS.values()}
        expected.update((self.base + row[0], 32) for _, row in SOURCE_ROWS.values())
        expected.update((self.base + rva, size) for rva, size in CODE_SPANS.values())
        self.assertEqual(set(self.reads), expected)
        self.assertEqual(len(self.reads), len(expected))
        self.assertEqual(sum(size for _, size in self.reads), 3152)
        self.assertEqual(report['captured_bytes'], 3152)

    def test_changed_callback_is_refused_before_any_code_is_read(self):
        rva, row = SOURCE_ROWS['Get']
        changed = [self.base + value for value in row[:5]] + [row[5]]
        changed[1] = 0x11111111
        self.memory[self.base + rva, 48] = struct.pack('<6Q', *changed)
        with self.assertRaisesRegex(ValueError, 'registration'):
            probe.capture(self.read, self.base, self.size)
        self.assertEqual(self.reads, [(self.base + rva, 48)])

    def test_unknown_binding_pointer_is_never_followed(self):
        rva, row = SOURCE_ROWS['FastRequestAsyncLoad']
        changed = [self.base + value for value in row[:5]] + [row[5]]
        changed[2] = 0x100000000
        self.memory[self.base + rva, 48] = struct.pack('<6Q', *changed)
        with self.assertRaisesRegex(ValueError, 'registration'):
            probe.capture(self.read, self.base, self.size)
        self.assertTrue(all(address >= self.base for address, _ in self.reads))
        self.assertFalse(any(size > 48 for _, size in self.reads))

    def test_changed_registration_label_is_refused(self):
        self.memory[self.base + SOURCE_ROWS['Get'][1][0], 32] = b'Other\0'.ljust(32, b'\0')
        with self.assertRaisesRegex(ValueError, 'name'):
            probe.capture(self.read, self.base, self.size)

    def test_truncated_read_is_refused(self):
        rva, _ = SOURCE_ROWS['Get']
        self.memory[self.base + rva, 48] = b'\0' * 47
        with self.assertRaisesRegex(ValueError, 'length'):
            probe.capture(self.read, self.base, self.size)

    def test_module_boundary_is_validated_before_reads(self):
        with self.assertRaisesRegex(ValueError, 'module'):
            probe.capture(self.read, self.base, 0x1000)
        self.assertEqual(self.reads, [])

    def test_shadow_path_and_hash_must_match_before_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shadow, installed = root / 'shadow.exe', root / 'installed.exe'
            shadow.write_bytes(b'known source executable')
            digest = hashlib.sha256(shadow.read_bytes()).hexdigest()
            with patch.object(probe, 'EXPECTED_PE', digest):
                self.assertEqual(probe.verify_shadow_executable(shadow, shadow, installed), digest)
                shadow.write_bytes(b'changed executable')
                with self.assertRaisesRegex(ValueError, 'source'):
                    probe.verify_shadow_executable(shadow, shadow, installed)
            with self.assertRaisesRegex(ValueError, 'shadow'):
                probe.verify_shadow_executable(installed, shadow, installed)

    def test_installed_source_itself_is_not_an_authorized_shadow(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.exe'
            with self.assertRaisesRegex(ValueError, 'separate'):
                probe.verify_shadow_executable(source, source, source)


if __name__ == '__main__':
    unittest.main()
