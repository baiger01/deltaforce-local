import copy
import json
import struct
import unittest

import probe_live_datatable_rowstruct_code as probe


class RowStructCodeTests(unittest.TestCase):
    def setUp(self):
        self.records = {
            494607384: struct.pack('<3Q', 0x15b3f7ee0, 0x154ed3790, 368),
            457143008: struct.pack('<Q', 0x1531a0830),
            457150752: struct.pack('<3Q', 0x156bbca88, 0x154ee6620, 40),
            458071472: struct.pack('<6Q', 0x156bbca88, 0, 0x10000000020001,
                                   0x4500000012, 0x2800000001, 0x150e06b20),
        }
        self.labels = {0x154ed3790: 'UDataTable', 0x156bbca88: 'RowStruct',
                       0x154ee6620: 'UScriptStruct *'}
        self.proof = probe.verify_records(
            lambda offset, size: self.records[offset][:size], self.labels.__getitem__)
        self.base = 0x140000000
        self.reads = []

    def reader(self, address, size):
        self.reads.append((address, size))
        return b'\xc3' * size

    def test_exact_two_source_gated_module_spans(self):
        result = probe.capture(self.reader, self.base, probe.MODULE_SIZE, 42., 42., self.proof)
        self.assertEqual(self.reads, [(self.base + 0x131a0830, 1024),
                                     (self.base + 0x10e06b20, 1024)])
        self.assertEqual(result['captured_bytes'], 2048)
        self.assertFalse(result['rowstruct_owner_verified'])
        self.assertFalse(result['heap_read'])
        self.assertFalse(result['native_called'])

    def test_changed_source_record_rejected(self):
        self.records[458071472] = self.records[458071472][:-1] + b'\xff'
        with self.assertRaises(ValueError):
            probe.verify_records(lambda offset, size: self.records[offset][:size], self.labels.__getitem__)

    def test_wrong_named_source_type_rejected(self):
        self.labels[0x154ee6620] = 'UObject *'
        with self.assertRaises(ValueError):
            probe.verify_records(lambda offset, size: self.records[offset][:size], self.labels.__getitem__)

    def test_short_source_record_rejected(self):
        with self.assertRaises(ValueError):
            probe.verify_records(lambda offset, size: self.records[offset][:size-1], self.labels.__getitem__)

    def test_source_proof_mismatch_prevents_reads(self):
        proof = copy.deepcopy(self.proof)
        proof['records'][3]['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            probe.capture(self.reader, self.base, probe.MODULE_SIZE, 42., 42., proof)
        self.assertEqual(self.reads, [])

    def test_creation_mismatch_prevents_reads(self):
        with self.assertRaises(ValueError):
            probe.capture(self.reader, self.base, probe.MODULE_SIZE, 43., 42., self.proof)
        self.assertEqual(self.reads, [])

    def test_module_mismatch_prevents_reads(self):
        for base, size in [(self.base, probe.MODULE_SIZE-1), (0, probe.MODULE_SIZE),
                           (0x800000000000, probe.MODULE_SIZE)]:
            with self.subTest(base=base, size=size), self.assertRaises(ValueError):
                probe.capture(self.reader, base, size, 42., 42., self.proof)
        self.assertEqual(self.reads, [])

    def test_short_code_read_stops_without_second(self):
        def short(address, size):
            self.reads.append((address, size))
            return b'x' * (size-1)
        with self.assertRaises(ValueError):
            probe.capture(short, self.base, probe.MODULE_SIZE, 42., 42., self.proof)
        self.assertEqual(len(self.reads), 1)

    def owner_proof(self):
        raw = struct.pack('<6Q', 0x140d5c590, 0x153254570, 0x140d5c590,
                          0x140e16270, 0x140d5f350, 0x153287f10)
        proof = copy.deepcopy(self.proof)
        proof['owner_vtable'] = probe.verify_owner_vtable(lambda offset, size: raw[:size])
        return proof

    def test_owner_followup_fixed_two_methods_after_fresh_lea(self):
        proof = self.owner_proof()
        def reader(address, size):
            self.reads.append((address, size))
            raw = bytearray(size)
            if address == self.base + 0x131a0830:
                raw[0x1f:0x26] = bytes.fromhex('488d0dca2b2d08')
            return bytes(raw)
        result = probe.capture(reader, self.base, probe.MODULE_SIZE, 42., 42., proof,
                               owner_bindings=True)
        self.assertEqual(result['captured_bytes'], 2304)
        self.assertEqual(self.reads[2:], [(self.base + 0x13254570, 128),
                                        (self.base + 0x13287f10, 128)])
        self.assertFalse(result['rowstruct_owner_verified'])

    def test_wrong_fresh_owner_lea_stops_before_methods(self):
        proof = self.owner_proof()
        with self.assertRaises(ValueError):
            probe.capture(self.reader, self.base, probe.MODULE_SIZE, 42., 42., proof,
                          owner_bindings=True)
        self.assertEqual(len(self.reads), 2)

    def test_wrong_owner_vtable_proof_stops_before_any_read(self):
        proof = self.owner_proof()
        proof['owner_vtable']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            probe.capture(self.reader, self.base, probe.MODULE_SIZE, 42., 42., proof,
                          owner_bindings=True)
        self.assertEqual(self.reads, [])

    def test_owner_vtable_source_pointer_change_rejected(self):
        raw = struct.pack('<6Q', 0x140d5c590, 0x153254570, 0x140d5c590,
                          0x140e16270, 0x140d5f350, 0x153287f11)
        with self.assertRaises(ValueError):
            probe.verify_owner_vtable(lambda offset, size: raw[:size])

    def binding_proof(self):
        descriptor = bytes.fromhex('b0913f5b0100000090933f5b01000000209d3f5b01000000'
                                   '38a03f5b010000000100250009000100')
        fields = bytes.fromhex(
            '88cabb56010000002066ee54010000002800000000000000'
            '608d405b0100000008f4ed54010000000001000000000000'
            'e08d405b010000007848ee54010000001101000000000000'
            '108f405b010000007848ee54010000001201000000000000'
            'f08f405b010000007848ee54010000001301000000000000'
            '2891405b010000007848ee54010000001401000000000000'
            'c091405b010000007848ee54010000001501000000000000'
            'a092405b010000007848ee54010000001601000000000000'
            'a893405b0100000078b06355010000001801000000000000')
        def exact(offset, size):
            if offset == probe.BINDING_DESCRIPTOR_RECORD['file_offset']:
                return descriptor[:size]
            start = offset - probe.BINDING_FIELDS_RECORD['file_offset']
            return fields[start:start + size]
        proof = self.owner_proof()
        proof['binding_descriptor'] = probe.verify_binding_descriptor(exact)
        return proof

    def binding_reader(self, address, size):
        self.reads.append((address, size))
        raw = bytearray(size)
        if address == self.base + 0x131a0830:
            raw[0x1f:0x26] = probe.OWNER_LEA
        elif address == self.base + 0x13287f10:
            raw[:15] = probe.BINDING_ENTRY
        return bytes(raw)

    def test_shared_binder_fixed_followup_after_both_source_entries(self):
        result = probe.capture(self.binding_reader, self.base, probe.MODULE_SIZE,
                               42., 42., self.binding_proof(), shared_binder=True)
        self.assertEqual(result['captured_bytes'], 3328)
        self.assertEqual(len(self.reads), 5)
        self.assertEqual(self.reads[-1], (self.base + 0x10c8ff60, 1024))
        self.assertFalse(result['rowstruct_owner_verified'])
        self.assertFalse(result['heap_read'])

    def test_shared_binder_proof_mismatch_prevents_any_read(self):
        proof = self.binding_proof()
        proof['binding_descriptor']['fields']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            probe.capture(self.binding_reader, self.base, probe.MODULE_SIZE,
                          42., 42., proof, shared_binder=True)
        self.assertEqual(self.reads, [])

    def test_shared_binder_fresh_entry_change_stops_before_followup(self):
        def wrong(address, size):
            raw = bytearray(self.binding_reader(address, size))
            if address == self.base + 0x13287f10:
                raw[14] ^= 1
            return bytes(raw)
        with self.assertRaises(ValueError):
            probe.capture(wrong, self.base, probe.MODULE_SIZE, 42., 42.,
                          self.binding_proof(), shared_binder=True)
        self.assertEqual(len(self.reads), 4)

    def test_owned_descriptor_changed_rejected(self):
        with self.assertRaises(ValueError):
            probe.verify_binding_descriptor(lambda offset, size: bytes(size))


class PinnedOwnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owner = json.loads((probe.ROOT / probe.OWNER_REPORT).read_bytes())
        cls.binder = json.loads((probe.ROOT / probe.BINDER_REPORT).read_bytes())

    def test_pinned_owner_and_field_loop_bind_exact_metadata(self):
        blocks = probe.owner_code_blocks(self.owner)
        self.assertEqual([rva for rva, _ in blocks], [0x131a0830, 0x10e06b20, 0x13287f10])
        rva, raw = probe.shared_binder_code_block(self.binder)
        self.assertEqual((rva, len(raw)), (0x10c8ff60, 1024))

    def test_heap_scope_report_rejected_before_owner_usage(self):
        report = copy.deepcopy(self.owner)
        report['heap_read'] = True
        with self.assertRaises(ValueError):
            probe.owner_code_blocks(report)

    def test_source_type_getter_replacement_rejected(self):
        report = copy.deepcopy(self.owner)
        code = report['code']['RowStruct_UScriptStruct_type_getter']
        raw = bytearray.fromhex(code['bytes'])
        raw[10] ^= 1
        code['bytes'] = raw.hex()
        with self.assertRaises(ValueError):
            probe.owner_code_blocks(report)

    def test_binding_field_array_identity_rejected(self):
        report = copy.deepcopy(self.binder)
        report['source_records']['binding_descriptor']['fields']['file_offset'] += 24
        with self.assertRaises(ValueError):
            probe.shared_binder_code_block(report)

    def test_source_field_stride_change_rejected(self):
        report = copy.deepcopy(self.binder)
        code = report['code']['UDataTable_shared_native_binder']
        raw = bytearray.fromhex(code['bytes'])
        raw[0x10c902e4 - 0x10c8ff60] ^= 1
        code['bytes'] = raw.hex()
        with self.assertRaises(ValueError):
            probe.shared_binder_code_block(report)


if __name__ == '__main__':
    unittest.main()
