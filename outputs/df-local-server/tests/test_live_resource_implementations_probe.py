import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

from test_live_resource_loader_probe import SOURCE_ROWS, CODE_SPANS


PROJECT = Path(__file__).resolve().parents[3]
SCRIPT = PROJECT / 'work/probe_live_resource_implementations.py'
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location('live_resource_implementations_probe', SCRIPT)
    probe = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(PROJECT / 'work'), *sys.path]):
        spec.loader.exec_module(probe)
else:
    probe = None


IMPLEMENTATIONS = {
    'FastRequestAsyncLoad': (0xd50d150, 0xd4cf330),
    'OnFastLoadComplete': (0xd50d190, 0xd4e0f20),
}


class LiveResourceImplementationsProbeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(probe, 'The verified direct-entry implementation witness is missing')
        self.base, self.size = 0x7ff600000000, 0x1ff8f000
        self.memory, self.reads = {}, []
        for name, (rva, row) in SOURCE_ROWS.items():
            actual = [self.base + value for value in row[:5]] + [row[5]]
            self.memory[self.base + rva, 48] = struct.pack('<6Q', *actual)
            self.memory[self.base + row[0], 32] = name.encode('ascii').ljust(32, b'\0')
        for name, (rva, size) in CODE_SPANS.items():
            self.memory[self.base + rva, size] = b'\x90' * (size - 1) + b'\xc3'
        for name, (entry, target) in IMPLEMENTATIONS.items():
            size = CODE_SPANS[name + '_callback'][1]
            jump = b'\xe9' + struct.pack('<i', target - entry - 5)
            self.memory[self.base + entry, size] = jump.ljust(size, b'\xcc')
            self.memory[self.base + target, 2048] = b'\x90' * 2047 + b'\xc3'

    def read(self, address, size):
        self.reads.append((address, size))
        return self.memory[address, size]

    def test_only_two_verified_direct_targets_are_added_to_existing_witness(self):
        report = probe.capture_implementations(self.read, self.base, self.size)
        self.assertEqual(set(report['implementations']), set(IMPLEMENTATIONS))
        for name, (entry, target) in IMPLEMENTATIONS.items():
            block = report['implementations'][name]
            self.assertEqual(block['rva'], target)
            self.assertEqual(block['entry_rva'], entry)
            self.assertEqual(block['size'], 2048)
        self.assertEqual(report['captured_bytes'], 7248)
        self.assertEqual([item for item in self.reads if item[1] > 512],
                         [(self.base + 0xd4cf330, 2048), (self.base + 0xd4e0f20, 2048)])

    def test_changed_first_entry_target_is_rejected_before_implementation_reads(self):
        entry, _ = IMPLEMENTATIONS['FastRequestAsyncLoad']
        jump = b'\xe9' + struct.pack('<i', 0xd4cf331 - entry - 5)
        self.memory[self.base + entry, 64] = jump.ljust(64, b'\xcc')
        with self.assertRaisesRegex(ValueError, 'target'):
            probe.capture_implementations(self.read, self.base, self.size)
        self.assertFalse(any(size > 512 for _, size in self.reads))

    def test_both_entry_targets_are_checked_before_either_implementation_read(self):
        entry, _ = IMPLEMENTATIONS['OnFastLoadComplete']
        jump = b'\xe9' + struct.pack('<i', 0xd4e0f21 - entry - 5)
        self.memory[self.base + entry, 512] = jump.ljust(512, b'\xcc')
        with self.assertRaisesRegex(ValueError, 'target'):
            probe.capture_implementations(self.read, self.base, self.size)
        self.assertFalse(any(size > 512 for _, size in self.reads))

    def test_indirect_entry_jump_is_not_followed(self):
        entry, _ = IMPLEMENTATIONS['FastRequestAsyncLoad']
        self.memory[self.base + entry, 64] = b'\xff\x25\0\0\0\0'.ljust(64, b'\xcc')
        with self.assertRaisesRegex(ValueError, 'direct'):
            probe.capture_implementations(self.read, self.base, self.size)
        self.assertFalse(any(size > 512 for _, size in self.reads))

    def test_changed_registration_is_rejected_without_any_code_read(self):
        rva, row = SOURCE_ROWS['Get']
        actual = [self.base + value for value in row[:5]] + [row[5] + 1]
        self.memory[self.base + rva, 48] = struct.pack('<6Q', *actual)
        with self.assertRaisesRegex(ValueError, 'registration'):
            probe.capture_implementations(self.read, self.base, self.size)
        self.assertEqual(self.reads, [(self.base + rva, 48)])

    def test_truncated_implementation_read_is_rejected(self):
        self.memory[self.base + 0xd4cf330, 2048] = b'\x90' * 2047
        with self.assertRaisesRegex(ValueError, 'length'):
            probe.capture_implementations(self.read, self.base, self.size)

    def test_module_boundary_is_validated_before_any_read(self):
        with self.assertRaisesRegex(ValueError, 'module'):
            probe.capture_implementations(self.read, self.base, 0x1000)
        self.assertEqual(self.reads, [])


if __name__ == '__main__':
    unittest.main()
