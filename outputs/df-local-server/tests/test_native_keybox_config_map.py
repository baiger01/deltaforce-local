import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch


WORK = Path(__file__).resolve().parents[3] / 'work'
sys.path.insert(0, str(WORK))
spec = importlib.util.spec_from_file_location('read_keybox_config_map', WORK / 'read_keybox_config_map.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class ConfigMapCaptureTests(unittest.TestCase):
    def fixture(self):
        base = 0x140000000
        manager = 0x13fb62e00
        getter = base + 0x123000
        memory = {base + rva: code for rva, code in native.CODE_WITNESSES}
        memory[base + native.ALLOCATION_ACCESSOR_RVA] = struct.pack('<Q', getter)
        memory[getter] = bytes.fromhex('488b01c3') + bytes(native.ACCESSOR_CODE_SIZE - 4)
        memory[manager + 0x190] = bytes(80)
        reads = []

        def read(address, size, *, module_only=True):
            reads.append((address, size, module_only))
            value = memory[address]
            self.assertEqual(len(value), size)
            return value

        fresh = {'status': 'captured', 'manager_address': manager,
                 'target_rva': 0xdbf7f0, 'interface_address': manager + 0x30}
        return base, manager, getter, memory, reads, read, fresh

    def test_fresh_manager_and_exact_cache_header(self):
        base, manager, getter, _, reads, read, fresh = self.fixture()
        with patch.object(native, 'capture_manager', return_value=fresh) as acquire:
            result = native.capture(read, base)
        acquire.assert_called_once_with(read, base)
        self.assertEqual(result['status'], 'captured')
        self.assertIn((manager + 0x190, 80, False), reads)
        self.assertIn((getter, native.ACCESSOR_CODE_SIZE, True), reads)
        self.assertEqual(result['allocation_accessor_rva'], 0x123000)
        self.assertEqual([call for call in reads if not call[2]], [(manager + 0x190, 80, False)])

    def test_invalid_manager_skips_all_further_reads(self):
        with patch.object(native, 'capture_manager', return_value={'status': 'skipped', 'reason': 'stale_serial'}):
            result = native.capture(lambda *_a, **_kw: self.fail('unexpected read'), 0x140000000)
        self.assertEqual(result['reason'], 'manager_unavailable')

    def test_changed_implementation_stops_before_cache_read(self):
        base, manager, _, memory, reads, read, fresh = self.fixture()
        rva, expected = native.CODE_WITNESSES[0]
        memory[base + rva] = bytes(len(expected))
        with patch.object(native, 'capture_manager', return_value=fresh):
            result = native.capture(read, base)
        self.assertEqual(result['reason'], 'cache_code_witness_mismatch')
        self.assertFalse(any(not call[2] for call in reads))

    def test_accessor_outside_module_is_not_followed(self):
        base, manager, _, memory, reads, read, fresh = self.fixture()
        memory[base + native.ALLOCATION_ACCESSOR_RVA] = struct.pack('<Q', manager)
        with patch.object(native, 'capture_manager', return_value=fresh):
            result = native.capture(read, base)
        self.assertEqual(result['reason'], 'allocation_accessor_outside_module')
        self.assertFalse(any(not call[2] for call in reads))

    def test_hash_chains_read_only_live_configuration_entries(self):
        base, manager, _, memory, reads, read, fresh = self.fixture()
        slots, buckets = 0x80000000, 0x81000000
        header = bytearray(80)
        struct.pack_into('<Qii', header, 0, slots, 3, 3)
        struct.pack_into('<i', header, 0x34, 1)
        struct.pack_into('<Q', header, 0x40, buckets)
        struct.pack_into('<i', header, 0x48, 2)
        memory[manager + 0x190] = bytes(header)
        memory[buckets] = struct.pack('<ii', 0, 2)
        memory[slots] = struct.pack('<QQii', 0x1234, 0x90000000, -1, 0)
        memory[slots + 48] = struct.pack('<QQii', 0x5678, 0x92000000, -1, 1)
        with patch.object(native, 'capture_manager', return_value=fresh):
            result = native.capture(read, base)
        self.assertEqual(result['entries_status'], 'captured_configuration_keys')
        self.assertEqual([entry['slot_index'] for entry in result['entries']], [0, 2])
        self.assertNotIn((slots + 24, 24, False), reads)
        self.assertFalse(any(address in (0x90000000, 0x92000000) for address, _, _ in reads))

    def test_hash_cycle_is_rejected_without_repeating_slot_read(self):
        base, manager, _, memory, reads, read, fresh = self.fixture()
        slots = 0x80000000
        header = bytearray(80)
        struct.pack_into('<Qii', header, 0, slots, 1, 1)
        struct.pack_into('<i', header, 0x38, 0)
        struct.pack_into('<i', header, 0x48, 1)
        memory[manager + 0x190] = bytes(header)
        memory[slots] = struct.pack('<QQii', 0x1234, 0x90000000, 0, 0)
        with patch.object(native, 'capture_manager', return_value=fresh):
            result = native.capture(read, base)
        self.assertEqual(result['entries_status'], 'skipped')
        self.assertEqual(result['entries_reason'], 'invalid_hash_chain')
        self.assertEqual(reads.count((slots, 24, False)), 1)


if __name__ == '__main__':
    unittest.main()
