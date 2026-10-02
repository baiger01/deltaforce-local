import importlib.util
from pathlib import Path
import sys
import struct
import unittest
from unittest.mock import patch

WORK = Path(__file__).resolve().parents[3] / 'work'
sys.path.insert(0, str(WORK))
spec = importlib.util.spec_from_file_location('read_keybox_rows', WORK / 'read_keybox_rows.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class KeyBoxRowsTests(unittest.TestCase):
    def fixture(self, row_count=1):
        base, manager, content = 0x140000000, 0x70000000, 0x80000000
        slots, pointers, row_pointer = 0x81000000, 0x82000000, 0x83000000
        fname = struct.pack('<II', 0x12345, 0)
        slot = fname + struct.pack('<Qii', content, -1, 0)
        header = struct.pack('<Qii', pointers, row_count, 1)
        cache = bytes(80)
        memory = {base + rva: code for rva, code in native.CODE_WITNESSES}
        row = bytearray(56)
        struct.pack_into('<i', row, 16, 1)
        row[20:28] = struct.pack('<II', 0x56789, 0)
        struct.pack_into('<7i', row, 28, 19, 4, 5, 6, 7, 8, 4)
        memory.update({manager + 0x190: cache, slots: slot,
                       content + 0x1c8: header, pointers: struct.pack('<Q', row_pointer),
                       row_pointer: bytes(row)})
        calls = []

        def read(address, size, *, module_only=True):
            calls.append((address, size, module_only))
            value = memory[address]
            self.assertEqual(len(value), size)
            return value

        config = {'entries_status': 'captured_configuration_keys', 'cache_address': manager + 0x190,
                  'cache_header_hex': cache.hex(), 'manager_interface': {'manager_address': manager},
                  'entries': [{'name': 'KeyBox', 'content_address': content, 'slot_address': slots,
                               'fname_hex': fname.hex()}]}
        fresh = {'status': 'captured', 'manager_address': manager}
        return base, pointers, calls, read, config, fresh

    def test_true_native_field_offsets_and_exact_row_reads(self):
        base, _, calls, read, config, fresh = self.fixture()
        with patch.object(native, 'capture_manager', return_value=fresh):
            result = native.capture(read, base, config)
        self.assertEqual(result['status'], 'captured')
        self.assertEqual(result['rows'][0]['scalar_fingerprint'], [1, 19, 4, 5, 6, 7, 8, 4])
        self.assertEqual(result['rows'][0]['item_id_fname_hex'], '8967050000000000')
        self.assertIn((0x83000000, 56, False), calls)

    def test_zero_rows_skip_before_reading_row_array(self):
        base, pointers, calls, read, config, fresh = self.fixture(row_count=0)
        with patch.object(native, 'capture_manager', return_value=fresh):
            result = native.capture(read, base, config)
        self.assertEqual(result['reason'], 'keybox_rows_not_populated')
        self.assertFalse(any(address == pointers for address, _, _ in calls))

    def test_missing_name_skips_without_any_pointer_reads(self):
        result = native.capture(lambda *_a, **_kw: self.fail('unexpected read'),
                                0x140000000, {'entries_status': 'captured_configuration_keys',
                                             'entries': [{'name': 'GameItem'}]})
        self.assertEqual(result['reason'], 'keybox_not_uniquely_identified')

    def test_stale_manager_skips_before_content_read(self):
        config = {'entries_status': 'captured_configuration_keys',
                  'entries': [{'name': 'KeyBox', 'content_address': 0x80000000}],
                  'manager_interface': {'manager_address': 0x70000000}}
        with patch.object(native, 'capture_manager', return_value={'status': 'skipped'}):
            result = native.capture(lambda *_a, **_kw: self.fail('unexpected read'), 0x140000000, config)
        self.assertEqual(result['reason'], 'manager_changed_or_unavailable')


if __name__ == '__main__':
    unittest.main()
