import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

WORK = Path(__file__).resolve().parents[3] / 'work'
sys.path.insert(0, str(WORK))
spec = importlib.util.spec_from_file_location('read_keybox_rowmap', WORK / 'read_keybox_rowmap.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class KeyBoxRowMapSourceTests(unittest.TestCase):
    def test_allocated_flags_select_only_live_native_rows(self):
        table, slots, bits, row = 0x80000000, 0x81000000, 0x82000000, 0x83000000
        header = bytearray(56)
        struct.pack_into('<Qii', header, 0, slots, 3, 4)
        struct.pack_into('<Qii', header, 0x20, bits, 3, 128)
        struct.pack_into('<i', header, 0x34, 1)
        values = bytearray(56)
        struct.pack_into('<i', values, 16, 1)
        values[20:28] = struct.pack('<II', 0x12345, 0)
        struct.pack_into('<7i', values, 28, 19, 4, 5, 6, 7, 8, 4)
        memory = {table + 0x30: bytes(header), bits: struct.pack('<I', 5),
                  slots: struct.pack('<QQii', 9, row, -1, 0),
                  slots + 48: struct.pack('<QQii', 10, row + 56, -1, 0),
                  row: bytes(values), row + 56: bytes(values)}
        reads = []

        def read(address, size, *, module_only=True):
            reads.append((address, size, module_only))
            self.assertEqual(len(memory[address]), size)
            return memory[address]

        result = {'rowmap_accessor_code_hex': '488d4130c3', 'source_table_address': table}
        native.capture_rows(read, result)
        self.assertEqual(result['rowmap_status'], 'captured_rows')
        self.assertEqual([value['slot_index'] for value in result['rows']], [0, 2])
        self.assertNotIn((slots + 24, 24, False), reads)
        self.assertEqual(result['rows'][0]['scalar_fingerprint'], [1, 19, 4, 5, 6, 7, 8, 4])

    def test_missing_exact_keybox_skips_all_reads(self):
        result = native.capture(lambda *_a, **_k: self.fail('unexpected read'), 0x140000000,
                                {'entries_status': 'captured_configuration_keys', 'entries': []})
        self.assertEqual(result['reason'], 'keybox_not_uniquely_identified')

    def test_not_ready_stops_before_table_read(self):
        base, manager, content = 0x140000000, 0x70000000, 0x80000000
        cache = bytes(80)
        fname = struct.pack('<II', 0x12345, 0)
        slot = fname + struct.pack('<Qii', content, -1, 0)
        memory = {base + rva: value for rva, value in native.CODE_WITNESSES}
        memory.update({base + 0x1d59de58: struct.pack('<Q', base + 0xd968d0),
                       base + 0xd968d0: bytes.fromhex('488b01c3'),
                       manager + 0x190: cache, 0x81000000: slot,
                       content + 0x20c: b'\x01'})
        reads = []

        def read(address, size, *, module_only=True):
            reads.append((address, size, module_only))
            value = memory[address]
            self.assertEqual(len(value), size)
            return value

        config = {'entries_status': 'captured_configuration_keys', 'cache_address': manager + 0x190,
                  'cache_header_hex': cache.hex(), 'manager_interface': {'manager_address': manager},
                  'entries': [{'name': 'KeyBox', 'content_address': content, 'slot_address': 0x81000000,
                               'fname_hex': fname.hex()}]}
        with patch.object(native, 'capture_manager', return_value={'status': 'captured', 'manager_address': manager}):
            result = native.capture(read, base, config, table_name='KeyBox')
        self.assertEqual(result['reason'], 'keybox_content_not_ready')
        self.assertFalse(any(address == content + 0x1d8 for address, _, _ in reads))


if __name__ == '__main__':
    unittest.main()
