import hashlib
import json
import struct
import unittest
from unittest.mock import patch


import probe_live_fileexists_state as tool


class FileExistsStateScopeTests(unittest.TestCase):
    BASE = 0x140000000
    SIZE = 0x1ff8f000
    CREATED = 1791193939.407797

    def setUp(self):
        d = json.loads(tool.SOURCE_CAPTURE.read_bytes())
        blocks = [d['source_code'], *d['fixed_code'].values()]
        self.memory = {(b['rva'], b['size']): bytes.fromhex(b['bytes']) for b in blocks}
        self.memory[(tool.INIT_RVA, tool.INIT_SIZE)] = bytes(tool.INIT_SIZE)
        self.memory[(tool.SLOT_RVA, 8)] = struct.pack('<Q', 0xdeadbeef12345678)
        self.reads = []

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **kwargs):
        kwargs.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        kwargs.setdefault('actual_created', self.CREATED)
        kwargs.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.BASE, self.SIZE, **kwargs)

    def test_exact_scope_and_pointer_is_never_followed(self):
        report = self.capture()
        self.assertEqual(self.reads, [(tool.prior.CALLER_RVA, 1024),
                                     (tool.prior.FIRST_RVA, 16), (tool.prior.SECOND_RVA, 31),
                                     (tool.INIT_RVA, 98), (tool.SLOT_RVA, 8), (tool.SLOT_RVA, 8)])
        self.assertEqual(report['captured_bytes'], 1185)
        self.assertEqual(report['receiver_slot']['first_qword'], '0xdeadbeef12345678')
        self.assertTrue(report['receiver_slot_rechecked'])
        for key in ('heap_read', 'pointer_followed', 'native_called', 'game_launched',
                    'filesystem_object_identity_proven', 'fileexists_outcome_proven'):
            self.assertFalse(report[key])

    def test_source_creation_bounds_gate_all_reads(self):
        for kwargs in ({'source_digest': '0' * 64}, {'actual_created': self.CREATED + 1}):
            with self.assertRaises(ValueError):
                self.capture(**kwargs)
            self.assertEqual(self.reads, [])
        for rva, size in tool.allowed_spans():
            with self.assertRaises(ValueError):
                tool.capture(self.read, self.BASE, rva + size - 1,
                             source_digest=tool.SOURCE_CAPTURE_SHA,
                             actual_created=self.CREATED, expected_created=self.CREATED)
            self.assertEqual(self.reads, [])

    def test_every_fresh_source_hash_gates_initializer_and_slot(self):
        for key in [(tool.prior.CALLER_RVA, 1024), (tool.prior.FIRST_RVA, 16),
                    (tool.prior.SECOND_RVA, 31)]:
            old = self.memory[key]
            self.memory[key] = bytes([old[0] ^ 1]) + old[1:]
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture()
            self.assertNotIn((tool.INIT_RVA, 98), self.reads)
            self.assertNotIn((tool.SLOT_RVA, 8), self.reads)
            self.memory[key] = old

    def test_exact_lea_call_and_qword_contract_are_verified(self):
        first = self.memory[(tool.prior.FIRST_RVA, 16)]
        second = self.memory[(tool.prior.SECOND_RVA, 31)]
        for field, delta in [('first', 0), ('first', 3), ('second', 6),
                             ('second', 17), ('second', 18), ('second', 22)]:
            raw = bytearray(first if field == 'first' else second)
            raw[delta] ^= 1
            a, b = (bytes(raw), second) if field == 'first' else (first, bytes(raw))
            with patch.object(tool, 'FIRST_SHA', hashlib.sha256(a).hexdigest()), \
                    patch.object(tool, 'SECOND_SHA', hashlib.sha256(b).hexdigest()):
                with self.assertRaises(ValueError):
                    tool.verify_getters(a, b)

    def test_short_reads_and_unstable_slot_are_rejected(self):
        for key in self.memory:
            old = self.memory[key]
            self.memory[key] = old[:-1]
            with self.assertRaisesRegex(ValueError, 'short_fixed'):
                self.capture()
            self.memory[key] = old
        counts = {}
        def changing(address, size):
            key = (address - self.BASE, size)
            counts[key] = counts.get(key, 0) + 1
            raw = self.read(address, size)
            return bytes([raw[0] ^ 1]) + raw[1:] if key == (tool.SLOT_RVA, 8) and counts[key] == 2 else raw
        with self.assertRaisesRegex(ValueError, 'receiver_slot_changed'):
            tool.capture(changing, self.BASE, self.SIZE, source_digest=tool.SOURCE_CAPTURE_SHA,
                         actual_created=self.CREATED, expected_created=self.CREATED)

    def test_actual_saved_source_qualifies_getter_chain(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)

    def test_initializer_metadata_and_disk_span_gates(self):
        memory = {(offset, len(bytes.fromhex(raw))): bytes.fromhex(raw)
                  for _, offset, raw, _ in tool.INIT_METADATA}
        memory[(tool.INIT_DISK_OFFSET, 98)] = bytes(98)
        def read_at(offset, size):
            return memory[(offset, size)]
        with patch.object(tool, 'INIT_DISK_SHA', hashlib.sha256(bytes(98)).hexdigest()):
            report = tool.verify_init_metadata(read_at)
            self.assertEqual(report['end_exclusive_rva'], 0x10b68bb2)
            for key in memory:
                old = memory[key]
                memory[key] = bytes([old[0] ^ 1]) + old[1:]
                with self.assertRaises(ValueError):
                    tool.verify_init_metadata(read_at)
                memory[key] = old


if __name__ == '__main__':
    unittest.main()
