import struct
import unittest
from native_metadata_names import (BLOCK_BYTES, MAX_BLOCKS, NAME_POOL_RVA,
    NAME_POOL_INITIALIZED_RVA, NameResolutionError, object_name, resolve_name)

BASE = 0x140000000
BLOCK = 0x20000000
ENTRY_ID = (2 << 18) | 0x33

class Memory:
    def __init__(self, raw, length, wide=False, number=0):
        self.token = struct.pack('<II', ENTRY_ID, number)
        self.slot = BASE + NAME_POOL_RVA + 8 + 2 * 8
        self.entry = BLOCK + 0x66
        self.regions = {BASE + NAME_POOL_INITIALIZED_RVA: b'\1',
                        self.slot: struct.pack('<Q', BLOCK),
                        self.entry: struct.pack('<H', (length << 6) | wide),
                        self.entry + 2: raw}
        self.calls = []
    def read(self, address, count):
        self.calls.append((address, count))
        value = self.regions[address]
        if len(value) != count:
            raise NameResolutionError('Fixture request length mismatch')
        return value

class NativeMetadataNamesTests(unittest.TestCase):
    def test_fixed_narrow_case_literals(self):
        # Independent explicit byte literals, not bytes made by this codec.
        cases = [(1, '3e'), (2, '3e3d'), (3, 'bebdbc'),
                 (4, 'bebdbcbb'), (5, 'bebdbcbbba'),
                 (6, 'bebdbcbbbab9'), (7, 'bebdbcbbbab9b8'),
                 (8, 'bebdbcbbbab9b8b7'), (9, 'bebdbcbbbab9b8b7b6')]
        for count, raw in cases:
            with self.subTest(count=count):
                mem = Memory(bytes.fromhex(raw), count)
                value = resolve_name(mem.read, BASE, mem.token)
                self.assertEqual(value.display_text, 'ABCDEFGHI'[:count])
                self.assertEqual(len(mem.calls), 6)
                self.assertLessEqual(max(n for _, n in mem.calls), 9)
    def test_narrow_pawn_literal(self):
        mem = Memory(bytes.fromhex('af9e8891'), 4)
        self.assertEqual(str(resolve_name(mem.read, BASE, mem.token)), 'Pawn')
    def test_wide_only_even_units_transformed(self):
        mem = Memory(bytes.fromhex('be004200bc00'), 3, True)
        self.assertEqual(str(resolve_name(mem.read, BASE, mem.token)), 'ABC')
    def test_chinese_wide_literal(self):
        mem = Memory(bytes.fromhex('d672b65b'), 2, True)
        self.assertEqual(str(resolve_name(mem.read, BASE, mem.token)), '玩家')
    def test_wide_case5_16bit_key(self):
        # Forty-one units: remainder5 uses (3*41+0x85)|0x7f == 0x17f.
        mem = Memory(bytes.fromhex('3e014100' * 20 + '3e01'), 41, True)
        self.assertEqual(str(resolve_name(mem.read, BASE, mem.token)), 'A' * 41)
    def test_number_signed_decimal_literals(self):
        for number, suffix in [(1, '_0'), (43, '_42'), (0xffffffff, '_-2')]:
            mem = Memory(bytes.fromhex('af9e8891'), 4, number=number)
            value = resolve_name(mem.read, BASE, mem.token)
            self.assertEqual(str(value), 'Pawn' + suffix)
            self.assertEqual(value.number, number)
            self.assertEqual(resolve_name(mem.read, BASE, mem.token, with_number=False).display_text, 'Pawn')
    def test_native_narrow_high_byte_branch_difference(self):
        mem = Memory(bytes.fromhex('96'), 1)
        self.assertEqual(str(resolve_name(mem.read, BASE, mem.token)), '?')
        mem.token = struct.pack('<II', ENTRY_ID, 1)
        self.assertEqual(str(resolve_name(mem.read, BASE, mem.token)), '\uffe9_0')
    def test_object_representation_offsets(self):
        for representation, offset in [(None, 0x1c), (1, 0x1c), (0, 0x28)]:
            mem = Memory(bytes.fromhex('af9e8891'), 4)
            mem.regions[0x30000000 + offset] = mem.token
            self.assertEqual(str(object_name(mem.read, BASE, 0x30000000, field_representation=representation)), 'Pawn')
            self.assertEqual(mem.calls[0], (0x30000000 + offset, 8))
    def test_uninitialized_rejected_before_pointer(self):
        mem = Memory(b'\xff', 1)
        mem.regions[BASE + NAME_POOL_INITIALIZED_RVA] = b'\0'
        with self.assertRaises(NameResolutionError):
            resolve_name(mem.read, BASE, mem.token)
        self.assertEqual(len(mem.calls), 1)
    def test_block_index_bound(self):
        mem = Memory(b'\xff', 1)
        with self.assertRaises(NameResolutionError):
            resolve_name(mem.read, BASE, struct.pack('<II', MAX_BLOCKS << 18, 0))
        self.assertEqual(mem.calls, [])
    def test_cross_block_payload_rejected_before_payload(self):
        mem = Memory(b'\xff', 1)
        mem.token = struct.pack('<II', (2 << 18) | 0x3ffff, 0)
        mem.regions[BLOCK + BLOCK_BYTES - 2] = struct.pack('<H', 1 << 6)
        with self.assertRaises(NameResolutionError):
            resolve_name(mem.read, BASE, mem.token)
        self.assertEqual(len(mem.calls), 3)
    def test_changed_header_rejected(self):
        mem = Memory(bytes.fromhex('af9e8891'), 4)
        def changed(address, count):
            if address == mem.entry and len(mem.calls) >= 4:
                mem.calls.append((address, count))
                return b'\0\0'
            return mem.read(address, count)
        with self.assertRaises(NameResolutionError):
            resolve_name(changed, BASE, mem.token)
    def test_bad_input_contracts(self):
        mem = Memory(bytes.fromhex('af9e8891'), 4)
        for token in [b'', bytearray(mem.token), mem.token + b'\0']:
            with self.assertRaises(NameResolutionError):
                resolve_name(mem.read, BASE, token)
        for representation in [True, 2, '0']:
            with self.assertRaises(NameResolutionError):
                object_name(mem.read, BASE, 0x30000000, field_representation=representation)
        with self.assertRaises(NameResolutionError):
            resolve_name(lambda a,n: b'', BASE, mem.token)
    def test_empty_and_nul_names_rejected(self):
        for raw, length in [(b'', 0), (b'\0', 1), (b'\x7f', 1)]:
            mem = Memory(raw, length)
            with self.assertRaises(NameResolutionError):
                resolve_name(mem.read, BASE, mem.token)

if __name__ == '__main__':
    unittest.main()
