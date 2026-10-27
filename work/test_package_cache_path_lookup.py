from dataclasses import replace
import json
import struct
import unittest

import package_cache_path_lookup as tool


def fixture_contract():
    reports = [tool._json(tool.ROOT, relative, digest) for relative, digest in tool.SOURCE_FILES]
    package, child, compare, crc, _ = reports
    blocks = [package['source_code'], *package['fixed_code'].values(),
              child['fixed_code']['CacheChildMapFind'],
              compare['fixed_code']['CacheFStringCompare'],
              crc['image_processing_helpers']['Disk_BasenameHash']]
    blocks = [(b['rva'], bytes.fromhex(b['bytes'])) for b in blocks]
    blocks.append((tool.ALLOCATOR_RVA, bytes.fromhex('488b01c3')))
    catalog = tool._json(tool.ROOT, tool.CATALOG_PATH, tool.CATALOG_SHA, 4 * 1024 * 1024)
    paths = tuple(tool.SourcePath(row['tab_id'], field, row['row'], row['offset'], row[field])
                  for row in catalog['recommendations'] if row['tab_id'] in tool.SOURCE_ROWS
                  for field in tool.IMAGE_FIELDS)
    lower = bytes(i + 32 if 65 <= i <= 90 else i for i in range(128))
    return tool.Contract(tuple(blocks), lower, bytes.fromhex(crc['image_crc_table']['bytes']),
                         paths, tool.SOURCE_FILES, tool.CATALOG_SHA, tool.SOURCE_PE)


class Memory:
    """Synthetic implementation fixture, never a live address provider."""

    def __init__(self, contract, base):
        self.blocks = {}
        self.reads = []
        self.cursor = 0x250000000
        self.mutate = None
        self.crc = struct.unpack('<256I', contract.crc)
        for rva, code in contract.blocks:
            self.put(base + rva, code)
        self.put(base + tool.LOWER_RVA, contract.lower)
        self.put(base + tool.CRC_RVA, contract.crc)
        self.put(base + tool.ALLOCATOR_SLOT, struct.pack('<Q', base + tool.ALLOCATOR_RVA))
        self.put(base + tool.DELIMITER_SLOT, struct.pack('<Q', base + tool.DELIMITER_RVA))
        self.put(base + tool.DELIMITER_RVA, b'/\x00\x00\x00')
        tree = {'children': {}}
        for source_path in contract.paths:
            node = tree
            for part in [p for p in source_path.package().split('/') if p]:
                node = node['children'].setdefault(part, {'children': {}})
        self.root = self.node(tree)
        self.put(base + tool.ROOT_SLOT, struct.pack('<Q', self.root))

    def put(self, address, data):
        self.blocks[address] = bytes(data)

    def alloc(self, size):
        result = self.cursor
        self.cursor += (size + 255) & ~255
        return result

    def string(self, name):
        data = (name + '\x00').encode('utf-16le')
        pointer = self.alloc(len(data))
        self.put(pointer, data)
        # The diagnostic reads only pointer/Num, never labels or uses Max.
        return struct.pack('<Qii', pointer, len(data) // 2, 0)

    def node(self, tree):
        child_pairs = [(name, self.node(child)) for name, child in tree['children'].items()]
        address = self.alloc(0xb0)
        node = bytearray(0xb0)
        if child_pairs:
            data = self.alloc(len(child_pairs) * 32)
            slots = bytearray(len(child_pairs) * 32)
            hash_size = 1
            while hash_size < len(child_pairs) * 2:
                hash_size *= 2
            buckets = [-1] * hash_size
            for index, (name, child) in enumerate(child_pairs):
                slot = index * 32
                slots[slot:slot + 16] = self.string(name)
                bucket = tool.native_hash(name, self.crc) & (hash_size - 1)
                struct.pack_into('<Qi', slots, slot + 0x10, child, buckets[bucket])
                buckets[bucket] = index
            self.put(data, slots)
            struct.pack_into('<Qi', node, 0, data, len(child_pairs))
            struct.pack_into('<i', node, 0x34, 0)
            if hash_size <= 2:
                struct.pack_into('<' + 'i' * hash_size, node, 0x38, *buckets)
            else:
                pointer = self.alloc(hash_size * 4)
                self.put(pointer, struct.pack('<' + 'i' * hash_size, *buckets))
                struct.pack_into('<Q', node, 0x40, pointer)
            struct.pack_into('<i', node, 0x48, hash_size)
        else:
            node[0xa0:0xb0] = self.string('synthetic-test-package.uasset')
        self.put(address, node)
        return address

    def read(self, address, size):
        self.reads.append((address, size))
        if self.mutate:
            self.mutate(self, address, size)
        for begin, data in self.blocks.items():
            if begin <= address < address + size <= begin + len(data):
                return data[address - begin:address - begin + size]
        raise AssertionError('Read outside synthetic blocks: ' + hex(address) + '/' + str(size))

    def root_change(self, offset, fmt, value):
        data = bytearray(self.blocks[self.root])
        struct.pack_into(fmt, data, offset, value)
        self.put(self.root, data)


class PackageCacheLookupTests(unittest.TestCase):
    BASE = 0x140000000

    @classmethod
    def setUpClass(cls):
        cls.contract = fixture_contract()

    def setUp(self):
        self.memory = Memory(self.contract, self.BASE)

    def capture(self, **options):
        return tool.capture(self.memory.read, self.BASE, self.contract, enabled=True, **options)

    def test_disabled_default_never_reads_even_invalid_inputs(self):
        result = tool.capture(self.memory.read, 0, None)
        self.assertEqual(result['status'], 'disabled')
        self.assertEqual(result['captured_bytes'], 0)
        self.assertEqual(self.memory.reads, [])

    def test_twelve_closed_source_paths_lookup_inline_and_heap_buckets(self):
        result = self.capture()
        self.assertEqual(result['status'], 'captured_hash_chain_metadata', result)
        self.assertEqual(len(result['paths']), 12)
        self.assertEqual({p['lookup_status'] for p in result['paths']}, {'cached_terminal_node'})
        self.assertTrue(all(p['native_length_exceeds_terminator'] for p in result['paths']))
        self.assertTrue(all(size <= 1024 for _, size in self.memory.reads))
        self.assertLess(result['captured_bytes'], tool.MAX_TOTAL_READ)
        for flag in ('map_enumerated', 'native_called', 'independent_sparse_bits_verified',
                     'allocation_membership_certified', 'native_CheckPathValid_called',
                     'file_exists_verified', 'texture_or_brush_verified'):
            self.assertFalse(result[flag])

    def test_native_ascii_case_rules_do_not_unicode_fold(self):
        table = struct.unpack('<256I', self.contract.crc)
        self.assertEqual(tool.native_hash('Game', table), tool.native_hash('gAME', table))
        self.assertNotEqual(tool.native_hash('\u00e9', table), tool.native_hash('\u00c9', table))
        self.assertTrue(tool.native_key_equal(tuple(map(ord, 'GAME')), 'game', self.contract.lower))
        self.assertFalse(tool.native_key_equal((0x00c9,), '\u00e9', self.contract.lower))

    def test_changed_known_path_or_extra_path_refused_before_any_read(self):
        path = self.contract.paths[0]
        for altered in (
                replace(self.contract, paths=(replace(path, reference=path.reference.replace('/Game/', '/Unknown/')),
                                               *self.contract.paths[1:])),
                replace(self.contract, paths=(*self.contract.paths, path)),
                replace(self.contract, catalog_sha256='0' * 64),
                replace(self.contract, source_hashes=())):
            with self.subTest(altered=altered.catalog_sha256):
                self.memory.reads.clear()
                result = tool.capture(self.memory.read, self.BASE, altered, enabled=True)
                self.assertEqual(result['status'], 'skipped')
                self.assertNotIn('paths', result)
                self.assertEqual(self.memory.reads, [])

    def test_changed_fresh_code_prevents_any_typed_heap_read(self):
        rva, code = self.contract.blocks[-1]
        self.memory.put(self.BASE + rva, code[:-1] + bytes([code[-1] ^ 1]))
        result = self.capture()
        self.assertEqual(result['status'], 'skipped')
        self.assertIn('fresh_package_cache_code_changed', result['reason'])
        self.assertFalse(result['typed_heap_read'])
        self.assertFalse(any(address >= 0x250000000 for address, _ in self.memory.reads))

    def test_changed_allocator_or_delimiter_is_refused_before_heap(self):
        for rva, value in ((tool.ALLOCATOR_SLOT, self.BASE + tool.ALLOCATOR_RVA + 1),
                           (tool.DELIMITER_SLOT, 0x250000000)):
            with self.subTest(rva=rva):
                self.memory = Memory(self.contract, self.BASE)
                self.memory.put(self.BASE + rva, struct.pack('<Q', value))
                result = self.capture()
                self.assertEqual(result['status'], 'skipped')
                self.assertFalse(result['typed_heap_read'])

    def test_empty_root_or_empty_map_report_no_cache_and_no_final_predicate_claim(self):
        self.memory.put(self.BASE + tool.ROOT_SLOT, bytes(8))
        result = self.capture()
        self.assertEqual({p['lookup_status'] for p in result['paths']}, {'cache_root_not_created'})
        self.assertFalse(result['typed_heap_read'])
        self.memory.put(self.BASE + tool.ROOT_SLOT, struct.pack('<Q', self.memory.root))
        self.memory.root_change(0x34, '<i', 1)
        result = self.capture()
        self.assertEqual({p['lookup_status'] for p in result['paths']}, {'cache_key_missing'})
        self.assertFalse(result['file_exists_verified'])

    def test_invalid_slot_hash_or_bucket_index_discards_all_paths(self):
        cases = [(0x08, '<i', -1), (0x34, '<i', -1), (0x34, '<i', 2),
                 (0x48, '<i', 0), (0x48, '<i', 3), (0x48, '<i', 4),
                 (0x3c, '<i', 100)]
        for offset, fmt, value in cases:
            with self.subTest(offset=offset, value=value):
                self.memory = Memory(self.contract, self.BASE)
                self.memory.root_change(offset, fmt, value)
                result = self.capture()
                self.assertEqual(result['status'], 'skipped')
                self.assertNotIn('paths', result)

    def test_collision_chain_loop_or_out_of_range_discards_all_paths(self):
        raw = bytearray(self.memory.blocks[self.memory.root])
        slot_data = struct.unpack_from('<Q', raw)[0]
        entry = bytearray(self.memory.blocks[slot_data])
        entry[:16] = self.memory.string('not-the-requested-component')
        for next_slot in (0, 1):
            with self.subTest(next_slot=next_slot):
                struct.pack_into('<i', entry, 0x18, next_slot)
                self.memory.put(slot_data, entry)
                result = self.capture()
                self.assertEqual(result['status'], 'skipped')
                self.assertIn('hash_chain_bounds_or_cycle', result['reason'])
                self.assertNotIn('paths', result)

    def test_string_count_or_nul_invalid_discards_batch(self):
        slot_data = struct.unpack_from('<Q', self.memory.blocks[self.memory.root])[0]
        original = self.memory.blocks[slot_data]
        for count in (-1, tool.MAX_KEY_UNITS + 1):
            with self.subTest(count=count):
                changed = bytearray(original)
                struct.pack_into('<i', changed, 8, count)
                self.memory.put(slot_data, changed)
                result = self.capture()
                self.assertEqual(result['status'], 'skipped')
                self.assertIn('FString_count_exceeded', result['reason'])
                self.assertNotIn('paths', result)
        self.memory.put(slot_data, original)
        pointer = struct.unpack_from('<Q', original)[0]
        self.memory.put(pointer, self.memory.blocks[pointer][:-2] + b'x\x00')
        result = self.capture()
        self.assertEqual(result['status'], 'skipped')
        self.assertIn('FString_termination_changed', result['reason'])

    def test_final_root_change_discards_complete_results(self):
        root_slot = self.BASE + tool.ROOT_SLOT
        observed = [0]

        def mutate(memory, address, size):
            if address == root_slot:
                observed[0] += 1
                if observed[0] == 2:
                    memory.put(root_slot, struct.pack('<Q', memory.root + 256))

        self.memory.mutate = mutate
        result = self.capture()
        self.assertEqual(result['status'], 'skipped')
        self.assertIn('changed_during_recheck', result['reason'])
        self.assertNotIn('paths', result)

    def test_read_budget_and_short_metadata_refuse_without_partial_rows(self):
        session = tool.Session(self.memory.read, self.BASE, self.contract, enabled=True)
        session.total = tool.MAX_TOTAL_READ - 1
        result = session.capture()
        self.assertEqual(result['status'], 'skipped')
        self.assertIn('read_budget_exceeded', result['reason'])
        self.assertNotIn('paths', result)
        original = self.memory.read

        def short(address, size):
            raw = original(address, size)
            return raw[:-1] if address == self.memory.root else raw

        result = tool.capture(short, self.BASE, self.contract, enabled=True)
        self.assertEqual(result['status'], 'skipped')
        self.assertIn('short_package_cache_metadata_read', result['reason'])
        self.assertNotIn('paths', result)


if __name__ == '__main__':
    unittest.main()
