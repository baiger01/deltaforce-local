import hashlib
import json
import struct
import unittest
from unittest.mock import patch


import probe_live_fileexists_receiver as tool


class FileExistsReceiverScopeTests(unittest.TestCase):
    BASE = 0x140000000
    SIZE = 0x1ff8f000
    CREATED = 1791193939.407797
    RECEIVER = 0x20000000
    VTABLE = BASE + 0x18000000
    TARGET = BASE + 0x100000

    def setUp(self):
        d = json.loads(tool.SOURCE_CAPTURE.read_bytes())
        names = ('FileExistsFirstGetterLeaf', 'FileExistsSecondGetter')
        blocks = [d['source_code'], *(d['fixed_code'][n] for n in names)]
        self.memory = {(self.BASE + b['rva'], b['size']): bytes.fromhex(b['bytes']) for b in blocks}
        self.slot = self.BASE + tool.prior.SLOT_RVA
        self.virtual_slot = self.VTABLE + tool.VIRTUAL_OFFSET
        self.memory[(self.slot, 8)] = struct.pack('<Q', self.RECEIVER)
        self.memory[(self.RECEIVER, 8)] = struct.pack('<Q', self.VTABLE)
        self.memory[(self.virtual_slot, 8)] = struct.pack('<Q', self.TARGET)
        self.reads, self.queries = [], []

    def read(self, address, size):
        self.reads.append((address, size))
        return self.memory[(address, size)]

    def query(self, address):
        self.queries.append(address)
        return {'base': address & ~0xfff, 'size': 4096, 'state': 0x1000, 'protect': 0x04}

    def capture(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.query, self.BASE, self.SIZE, **options)

    def test_exact_six_qwords_and_target_code_not_read(self):
        d = self.capture()
        expected = [(self.BASE + tool.prior.prior.CALLER_RVA, 1024),
                    (self.BASE + tool.prior.prior.FIRST_RVA, 16),
                    (self.BASE + tool.prior.prior.SECOND_RVA, 31),
                    (self.slot, 8), (self.RECEIVER, 8), (self.virtual_slot, 8),
                    (self.slot, 8), (self.RECEIVER, 8), (self.virtual_slot, 8)]
        self.assertEqual(self.reads, expected)
        self.assertEqual(self.queries, [a for a, _ in expected[3:]])
        self.assertEqual(d['captured_bytes'], 1119)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertEqual(d['virtual_target_rva'], self.TARGET - self.BASE)
        self.assertTrue(d['receiver_chain_rechecked'])
        self.assertTrue(d['heap_read'])
        for key in ('target_code_read', 'native_called', 'game_launched',
                    'filesystem_class_identity_proven', 'fileexists_outcome_proven'):
            self.assertFalse(d[key])

    def test_every_code_hash_gates_first_data_and_region_query(self):
        for key in list(self.memory)[:3]:
            old = self.memory[key]
            self.memory[key] = bytes([old[0] ^ 1]) + old[1:]
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture()
            self.assertEqual(self.queries, [])
            self.assertNotIn((self.slot, 8), self.reads)
            self.memory[key] = old

    def test_virtual_callsite_must_match_even_if_hash_is_overridden(self):
        key = (self.BASE + tool.prior.prior.CALLER_RVA, 1024)
        raw = bytearray(self.memory[key])
        raw[tool.VIRTUAL_SITE - tool.prior.prior.CALLER_RVA] ^= 1
        self.memory[key] = bytes(raw)
        with patch.object(tool.prior.prior, 'CALLER_SHA', hashlib.sha256(raw).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'virtual_callsite'):
                self.capture()
        self.assertEqual(self.queries, [])

    def test_invalid_receiver_pointer_stops_before_receiver_query(self):
        for pointer in (0, 1, self.RECEIVER + 1, 0x800000000000, 0xfffffffffffffff8):
            self.memory[(self.slot, 8)] = struct.pack('<Q', pointer)
            self.queries.clear()
            with self.subTest(pointer=pointer), self.assertRaises(ValueError):
                self.capture()
            self.assertEqual(self.queries, [self.slot])

    def test_vtable_must_be_aligned_module_data_with_bounded_slot(self):
        for pointer in (0, self.VTABLE + 1, self.BASE - 8,
                        self.BASE + self.SIZE - 0x78, 0x800000000000):
            self.memory[(self.RECEIVER, 8)] = struct.pack('<Q', pointer)
            self.queries.clear()
            with self.subTest(pointer=pointer), self.assertRaises(ValueError):
                self.capture()
            self.assertEqual(self.queries, [self.slot, self.RECEIVER])

    def test_target_must_be_canonical_and_inside_source_module(self):
        for pointer in (0, self.BASE - 1, self.BASE + self.SIZE, 0x800000000000):
            self.memory[(self.virtual_slot, 8)] = struct.pack('<Q', pointer)
            with self.subTest(pointer=pointer), self.assertRaises(ValueError):
                self.capture()

    def test_readable_region_state_protection_and_size_gate_reads(self):
        invalid = ({'state': 0x2000}, {'protect': 0x01}, {'protect': 0x104},
                   {'protect': 0x10}, {'size': 7}, {'base': self.slot + 1})
        for address in (self.slot, self.RECEIVER, self.virtual_slot):
            for overrides in invalid:
                self.reads.clear()
                def query(candidate):
                    r = {'base': candidate, 'size': 8, 'state': 0x1000, 'protect': 0x04}
                    if candidate == address:
                        r.update(overrides)
                    return r
                with self.subTest(address=address, overrides=overrides), self.assertRaises(ValueError):
                    tool.capture(self.read, query, self.BASE, self.SIZE,
                                 source_digest=tool.SOURCE_CAPTURE_SHA,
                                 actual_created=self.CREATED, expected_created=self.CREATED)
                self.assertNotIn((address, 8), self.reads)

    def test_each_chain_qword_recheck_detects_change(self):
        for changed_address in (self.slot, self.RECEIVER, self.virtual_slot):
            counts = {}
            def changing(address, size):
                counts[address] = counts.get(address, 0) + 1
                raw = self.read(address, size)
                return bytes([raw[0] ^ 1]) + raw[1:] if address == changed_address and counts[address] == 2 else raw
            with self.subTest(address=changed_address), self.assertRaisesRegex(ValueError, 'chain_changed'):
                tool.capture(changing, self.query, self.BASE, self.SIZE,
                             source_digest=tool.SOURCE_CAPTURE_SHA,
                             actual_created=self.CREATED, expected_created=self.CREATED)

    def test_short_or_nonbyte_reads_are_rejected(self):
        for key in self.memory:
            old = self.memory[key]
            for raw in (old[:-1], bytearray(old)):
                self.memory[key] = raw
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'short_receiver'):
                    self.capture()
            self.memory[key] = old

    def test_source_timestamp_modulebounds_gate_first_read(self):
        for options in ({'source_digest': '0' * 64}, {'actual_created': self.CREATED + 1}):
            with self.assertRaises(ValueError):
                self.capture(**options)
            self.assertEqual(self.reads, [])
            self.assertEqual(self.queries, [])
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, tool.prior.SLOT_RVA + 7,
                         source_digest=tool.SOURCE_CAPTURE_SHA,
                         actual_created=self.CREATED, expected_created=self.CREATED)
        self.assertEqual(self.reads, [])

    def test_saved_source_is_qualified_without_reusing_snapshot_pointer(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        self.assertNotEqual(self.RECEIVER, 0x36fcf000)
        self.assertEqual(self.capture()['receiver_pointer'], hex(self.RECEIVER))


if __name__ == '__main__':
    unittest.main()
