import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'work'))
from native_config_names import ConfigNameCodec, EXPECTED_PE, POOL_RVA, read_config_name


class NativeConfigNameTests(unittest.TestCase):
    def setUp(self):
        self.codec = ConfigNameCodec.__new__(ConfigNameCodec)

    def fixture(self, *, changed=False, length=6):
        base, block, comparison_id = 0x140000000, 0x16d10000, (3 << 18) + 0x12345
        pointer_address = base + POOL_RVA + 8 + 3 * 8
        entry_address = block + 2 * 0x12345
        pointer = struct.pack('<Q', block)
        header = struct.pack('<H', length << 6)
        # Actual ASCII loop applies key 0xff for a six-character name.
        memory = {pointer_address: pointer, entry_address: header,
                  entry_address + 2: bytes.fromhex('b49a86bd9087')}
        calls = []

        def read(address, size, *, module_only=True):
            calls.append((address, size, module_only))
            data = memory[address]
            if changed and address == pointer_address and len(calls) > 1:
                data = struct.pack('<Q', block + 2)
            self.assertEqual(len(data), size)
            return data

        return base, comparison_id, entry_address, calls, read

    def test_actual_pool_bit_partition_and_entry_header(self):
        base, comparison_id, entry_address, calls, read = self.fixture()
        self.assertEqual(read_config_name(read, base, self.codec, comparison_id), 'KeyBox')
        self.assertEqual(calls[1], (entry_address, 2, False))
        self.assertEqual([size for _, size, _ in calls], [8, 2, 6, 8, 2])

    def test_changed_block_cannot_bind_a_name(self):
        base, comparison_id, _, _, read = self.fixture(changed=True)
        with self.assertRaisesRegex(ValueError, 'changed during capture'):
            read_config_name(read, base, self.codec, comparison_id)

    def test_oversized_header_stops_before_payload(self):
        base, comparison_id, _, calls, read = self.fixture(length=97)
        with self.assertRaisesRegex(ValueError, 'bounded read'):
            read_config_name(read, base, self.codec, comparison_id)
        self.assertEqual(len(calls), 2)

    def test_numbered_and_invalid_names_stop_without_reads(self):
        def read(*_args, **_kwargs):
            self.fail('Unsupported name must not read memory')

        for comparison_id, number in ((0x80000000, 0), (-1, 0), (True, 0), (1, 1)):
            with self.assertRaises(ValueError):
                read_config_name(read, 0x140000000, self.codec, comparison_id, number)

    def test_wrong_native_build_and_modified_code_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported native build'):
            ConfigNameCodec({'native_pe_sha256': '0' * 64, 'module_base': 0x140000000})
        with self.assertRaisesRegex(ValueError, 'code witness changed'):
            ConfigNameCodec({'native_pe_sha256': EXPECTED_PE, 'module_base': 0x140000000,
                             'fixed_code': {'registration_name_ascii_copy':
                                            {'rva': 0x10b5fd00, 'size': 0x210,
                                             'bytes': '00' * 0x210}}})

    def test_wide_source_loop_leaves_alternating_units_untouched(self):
        result = self.codec.transform('ABCDEFG'.encode('utf-16le'), 7, wide=True)
        self.assertEqual(result.hex(), 'be004200bc004400ba004600b800')
        with self.assertRaises(ValueError):
            self.codec.decode_config_name(b'\x00\x00')


if __name__ == '__main__':
    unittest.main()
