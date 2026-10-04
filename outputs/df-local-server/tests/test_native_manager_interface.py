import importlib.util
import struct
import unittest
from pathlib import Path


HELPER = Path(__file__).resolve().parents[3] / 'work' / 'read_keybox_manager_interface.py'
spec = importlib.util.spec_from_file_location('read_keybox_manager_interface', HELPER)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class Memory:
    def __init__(self, index=101933, serial=2610, flags=0):
        self.base = 0x140000000
        self.reads = []
        self.data = {self.base + rva: code for rva, code in native.CODE_WITNESSES}
        self.array = 0x3e74be60
        self.chunk = 0x60000000
        self.manager = 0x70000000
        self.vtable = self.base + 0x14f00000
        self.target = self.base + 0xe40000
        self.item = self.chunk + (index % 65536) * 24
        self.data.update({
            self.base + native.SELECTOR_RVA: struct.pack('<I', 0),
            self.base + native.STORAGE_RVA: struct.pack('<iiQQ', index, serial, 0, 0)[:16],
            self.base + native.ARRAY_RVA: struct.pack('<QiiQQ', 101096, 13, 104559, 2, self.array),
            self.base + native.OVERRIDE_RVA: bytes(8),
            self.array + (index // 65536) * 8: struct.pack('<Q', self.chunk),
            self.item: struct.pack('<QIIII', self.manager, flags, 0, 0, serial),
            self.manager: bytes(0x30) + struct.pack('<Q', self.vtable) + bytes(8),
            self.vtable + 0x68: struct.pack('<Q', self.target),
            self.target: b'\x90' * 1536,
        })

    def __call__(self, address, size, *, module_only=True):
        self.reads.append((address, size, module_only))
        data = self.data[address]
        if len(data) != size:
            raise OSError('unexpected read size')
        return data


class NativeManagerInterfaceTests(unittest.TestCase):
    def test_real_index_chunk_math_and_bounded_interface(self):
        mem = Memory()
        result = native.capture(mem, mem.base)
        self.assertEqual(result['status'], 'captured')
        self.assertEqual((result['chunk_index'], result['item_index']), (1, 36397))
        self.assertEqual(result['item_address'], mem.chunk + 0xd5438)
        self.assertIn((mem.array + 8, 8, False), mem.reads)
        self.assertIn((mem.item, 24, False), mem.reads)
        self.assertIn((mem.manager, 0x40, False), mem.reads)
        self.assertIn((mem.vtable + 0x68, 8, True), mem.reads)
        self.assertIn((mem.target, 1536, True), mem.reads)
        self.assertEqual(result['target_rva'], 0xe40000)

    def test_invalid_selector_stops_before_any_heap_read(self):
        mem = Memory()
        mem.data[mem.base + native.SELECTOR_RVA] = struct.pack('<I', 1)
        self.assertEqual(native.capture(mem, mem.base)['reason'], 'unsupported_selector')
        self.assertFalse(any(not module for _, _, module in mem.reads))

    def test_stale_serial_stops_before_manager_read(self):
        mem = Memory()
        mem.data[mem.item] = struct.pack('<QIIII', mem.manager, 0, 0, 0, 2611)
        self.assertEqual(native.capture(mem, mem.base)['reason'], 'stale_serial')
        self.assertNotIn((mem.manager, 0x40, False), mem.reads)

    def test_invalid_flags_stop_before_manager_read(self):
        for flags in (0x10000000, 0x20000000):
            with self.subTest(flags=flags):
                mem = Memory(flags=flags)
                self.assertEqual(native.capture(mem, mem.base)['reason'], 'invalid_object_flags')
                self.assertNotIn((mem.manager, 0x40, False), mem.reads)

    def test_override_stops_before_any_heap_read(self):
        mem = Memory()
        mem.data[mem.base + native.OVERRIDE_RVA] = struct.pack('<Q', mem.base + 0x1234)
        self.assertEqual(native.capture(mem, mem.base)['reason'], 'unsupported_accessor_override')
        self.assertFalse(any(not module for _, _, module in mem.reads))

    def test_outside_module_target_is_not_read(self):
        mem = Memory()
        mem.data[mem.vtable + 0x68] = struct.pack('<Q', mem.manager)
        self.assertEqual(native.capture(mem, mem.base)['reason'], 'target_outside_module')
        self.assertNotIn((mem.manager, 1536, True), mem.reads)

    def test_vtable_base_outside_module_stops_before_slot_read(self):
        mem = Memory()
        vtable = mem.base - 0x68
        mem.data[mem.manager] = bytes(0x30) + struct.pack('<Q', vtable) + bytes(8)
        self.assertEqual(native.capture(mem, mem.base)['reason'], 'vtable_outside_module')
        self.assertNotIn((mem.base, 8, True), mem.reads)

    def test_each_capture_reads_fresh_selector_and_storage(self):
        mem = Memory()
        self.assertEqual(native.capture(mem, mem.base)['status'], 'captured')
        mem.data[mem.base + native.SELECTOR_RVA] = struct.pack('<I', 4)
        self.assertEqual(native.capture(mem, mem.base)['reason'], 'unsupported_selector')

    def test_changed_code_stops_before_heap_reads(self):
        mem = Memory()
        rva, code = native.CODE_WITNESSES[0]
        mem.data[mem.base + rva] = bytes(len(code))
        self.assertEqual(native.capture(mem, mem.base)['reason'], 'code_witness_mismatch')
        self.assertFalse(any(not module for _, _, module in mem.reads))


if __name__ == '__main__':
    unittest.main()
