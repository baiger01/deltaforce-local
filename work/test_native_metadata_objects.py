"""Offline synthetic memory fixtures for the source-proven registry reader."""
import struct
import unittest

import native_metadata_objects as objects


class Memory:
    base = 0x140000000
    table = 0x500000000
    chunk0 = 0x500100000
    chunk1 = 0x500200000
    obj = 0x600000000

    def __init__(self, count=2, outer=0, inner=0, parameter=0, decoder=0):
        self.bytes = {}
        self.reads = []
        self.write(self.base+objects.COUNT_RVA, struct.pack('<i', count))
        self.write(self.base+objects.CHUNKS_RVA, struct.pack('<Q', self.table))
        self.write(self.base+objects.POINTER_DECODER_RVA, struct.pack('<Q', decoder))
        self.write(self.base+objects.OUTER_SELECTOR_RVA, struct.pack('<I', outer))
        if 1 <= outer <= 10:
            self.write(self.base+objects.INNER_SELECTORS_RVA+4*(outer-1), struct.pack('<I', inner))
            self.write(self.base+objects.PARAMETER_RVA, struct.pack('<I', parameter))
        self.write(self.table, struct.pack('<QQ', self.chunk0, self.chunk1))

    def write(self, address, data):
        self.bytes.update({address+i: value for i, value in enumerate(data)})

    def read(self, address, size):
        self.reads.append((address, size))
        try:
            return bytes(self.bytes[address+i] for i in range(size))
        except KeyError as error:
            raise objects.ObjectMetadataError('unmapped synthetic metadata') from error

    def entry(self, index, pointer, serial, *, chunk=None, within=None, flags=0):
        if chunk is None:
            chunk, within = self.chunk0, index
        self.write(chunk+objects.ENTRY_SIZE*within, struct.pack('<QIIII', pointer, flags, 0, 0, serial))
        if pointer:
            self.write(pointer+objects.OBJECT_INDEX_OFFSET, struct.pack('<i', index))


class RegistryTests(unittest.TestCase):
    def test_records_and_actual_weak_key(self):
        memory = Memory()
        memory.entry(0, 0, 0)
        memory.entry(1, memory.obj, 1007)
        self.assertEqual(list(objects.iter_object_records(memory.read, memory.base)),
                         [objects.ObjectRecord(1, memory.obj, 1007)])
        self.assertEqual(objects.weak_object_key(memory.read, memory.base, memory.obj),
                         bytes.fromhex('01000000ef030000'))
        self.assertTrue(all(size <= objects.MAX_BATCH_BYTES for _, size in memory.reads))

    def test_selected_native_chunk_boundary_uses_parameter(self):
        # Outer 2 chooses only inner-selector cell +4. Inner7, parameter1 =>
        # ((1&7)<<3|1)<<10 = 9216. Index9216 belongs to second chunk at offset0.
        memory = Memory(count=9217, outer=2, inner=7, parameter=1)
        memory.entry(9216, memory.obj, 2048, chunk=memory.chunk1, within=0)
        self.assertEqual(objects.weak_object_key(memory.read, memory.base, memory.obj),
                         bytes.fromhex('0024000000080000'))
        self.assertIn((memory.table+8, 8), memory.reads)
        self.assertNotIn((memory.base+objects.INNER_SELECTORS_RVA, 4), memory.reads)

    def test_default_outer_does_not_read_unselected_parameters(self):
        memory = Memory(count=65537, outer=11)
        memory.entry(65536, memory.obj, 2001, chunk=memory.chunk1, within=0)
        self.assertEqual(objects.weak_object_key(memory.read, memory.base, memory.obj),
                         struct.pack('<iI', 65536, 2001))
        self.assertNotIn((memory.base+objects.PARAMETER_RVA, 4), memory.reads)

    def test_decoder_refuses_before_any_entry_read(self):
        memory = Memory(decoder=0x700000000)
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'pointer_decoder_required'):
            list(objects.iter_object_records(memory.read, memory.base))
        self.assertNotIn((memory.table, 8), memory.reads)

    def test_dead_flags_filtered_but_zero_serial_live_object_discovered(self):
        memory = Memory(count=3)
        memory.entry(0, memory.obj, 1011, flags=0x10000000)
        memory.entry(1, memory.obj+0x100, 1012, flags=0x20000000)
        memory.entry(2, memory.obj+0x200, 0)
        self.assertEqual(list(objects.iter_object_records(memory.read, memory.base)),
                         [objects.ObjectRecord(2, memory.obj+0x200, 0)])
        self.assertEqual(objects.validate_object_record(memory.read, memory.base, memory.obj+0x200),
                         objects.ObjectRecord(2, memory.obj+0x200, 0))
        for address in (memory.obj, memory.obj+0x100, memory.obj+0x200):
            with self.assertRaises(objects.ObjectMetadataError):
                objects.weak_object_key(memory.read, memory.base, address)

    def test_zero_serial_is_valid_identity_but_no_weak_key_is_created(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 0)
        self.assertEqual(objects.validate_object_record(memory.read, memory.base, memory.obj),
                         objects.ObjectRecord(0, memory.obj, 0))
        self.assertEqual(list(objects.iter_object_records(memory.read, memory.base)),
                         [objects.ObjectRecord(0, memory.obj, 0)])
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'no_native_weak_key'):
            objects.weak_object_key(memory.read, memory.base, memory.obj)
        self.assertEqual(struct.unpack('<I', memory.read(memory.chunk0+0x14, 4))[0], 0)

    def test_budget_and_negative_count_rejected_before_entries(self):
        for count, budget in ((3, 2), (-1, 2)):
            memory = Memory(count=count)
            with self.assertRaises(objects.ObjectMetadataError):
                list(objects.iter_object_records(memory.read, memory.base, max_objects=budget))
            self.assertEqual(len(memory.reads), 1)

    def test_backreference_and_slot_identity_fail_closed(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 1001)
        memory.write(memory.obj+objects.OBJECT_INDEX_OFFSET, struct.pack('<i', 1))
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'backreference'):
            list(objects.iter_object_records(memory.read, memory.base))
        memory.write(memory.obj+objects.OBJECT_INDEX_OFFSET, struct.pack('<i', 0))
        memory.write(memory.obj+0x100+objects.OBJECT_INDEX_OFFSET, struct.pack('<i', 0))
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'identity_mismatch'):
            objects.weak_object_key(memory.read, memory.base, memory.obj+0x100)

    def test_zero_native_divisor_and_unknown_inner_rejected(self):
        for inner, parameter in ((4, 1), (0, 62), (21, 1)):
            memory = Memory(count=0, outer=1, inner=inner, parameter=parameter)
            with self.assertRaisesRegex(objects.ObjectMetadataError, 'divisor_would_be_zero'):
                list(objects.iter_object_records(memory.read, memory.base))

    def test_snapshot_change_discards_result_and_short_read_fails(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 1001)
        def changing(address, size):
            data = memory.read(address, size)
            if address == memory.obj+objects.OBJECT_INDEX_OFFSET:
                memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 0))
            return data
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'changed'):
            list(objects.iter_object_records(changing, memory.base))
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'incomplete'):
            list(objects.iter_object_records(lambda a, n: b'\0'*(n-1), memory.base))

    def test_growing_count_preserves_initial_range_and_reports_only_after_exhaustion(self):
        memory = Memory(count=2)
        memory.entry(0, memory.obj, 1001)
        memory.entry(1, memory.obj+0x100, 1002)
        block_reads = 0
        def growing(address, size):
            nonlocal block_reads
            data = memory.read(address, size)
            if address == memory.obj+objects.OBJECT_INDEX_OFFSET:
                memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 3))
            elif address == memory.obj+0x100+objects.OBJECT_INDEX_OFFSET:
                memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 4))
            elif address == memory.chunk0 and size == 48:
                block_reads += 1
                if block_reads == 2:
                    memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 5))
            return data
        scope = {}
        iterator = objects.iter_object_records(growing, memory.base, max_objects=8, scan_metadata=scope)
        self.assertEqual(next(iterator), objects.ObjectRecord(0, memory.obj, 1001))
        self.assertEqual(scope, {})
        self.assertEqual(next(iterator), objects.ObjectRecord(1, memory.obj+0x100, 1002))
        self.assertEqual(scope, {})
        with self.assertRaises(StopIteration):
            next(iterator)
        self.assertEqual(scope, {
            'initial_count': 2, 'final_observed_count': 5, 'entries_per_chunk': 65536,
            'maximum_count': 8, 'initial_index_range': [0, 2],
            'source_scope': 'initial_bounded_registry_entries', 'initial_range_exhausted': True,
            'complete_global_inventory': False, 'snapshot_atomic': False,
        })
        # Appended slots are deliberately unmapped: attempting to inventory
        # their contents would fail, whereas the original two slots are stable.
        self.assertNotIn((memory.chunk0+48, objects.ENTRY_SIZE), memory.reads)

    def test_stable_selected_identity_and_weak_key_survive_bounded_count_growth(self):
        for operation in (objects.validate_object_record, objects.weak_object_key):
            memory = Memory(count=1)
            memory.entry(0, memory.obj, 1001)
            def growing(address, size):
                data = memory.read(address, size)
                if address == memory.obj+objects.OBJECT_INDEX_OFFSET:
                    memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 3))
                return data
            result = operation(growing, memory.base, memory.obj, max_objects=3)
            self.assertEqual(result, objects.ObjectRecord(0, memory.obj, 1001)
                             if operation is objects.validate_object_record else struct.pack('<iI', 0, 1001))

    def test_count_fall_after_prior_growth_is_refused_without_scope_completion(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 1001)
        count_reads = 0
        def rise_then_fall(address, size):
            nonlocal count_reads
            if address == memory.base+objects.COUNT_RVA:
                count_reads += 1
                memory.write(address, struct.pack('<i', (1, 3, 2)[min(count_reads-1, 2)]))
            return memory.read(address, size)
        scope = {}
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'changed'):
            next(objects.iter_object_records(rise_then_fall, memory.base, scan_metadata=scope))
        self.assertEqual(scope, {})

    def test_growth_beyond_explicit_budget_is_refused(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 1001)
        def over_budget(address, size):
            data = memory.read(address, size)
            if address == memory.obj+objects.OBJECT_INDEX_OFFSET:
                memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 3))
            return data
        scope = {}
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'exceeds_budget'):
            next(objects.iter_object_records(over_budget, memory.base, max_objects=2, scan_metadata=scope))
        self.assertEqual(scope, {})

    def test_growth_does_not_relax_registry_layout_checks(self):
        for cell, replacement in ((objects.CHUNKS_RVA, struct.pack('<Q', Memory.table+0x100)),
                (objects.POINTER_DECODER_RVA, struct.pack('<Q', 0x700000000)),
                (objects.OUTER_SELECTOR_RVA, struct.pack('<I', 2)),
                (objects.INNER_SELECTORS_RVA, struct.pack('<I', 6)),
                (objects.PARAMETER_RVA, struct.pack('<I', 2))):
            with self.subTest(cell=hex(cell)):
                memory = Memory(count=1, outer=1, inner=7, parameter=1)
                memory.write(memory.base+objects.INNER_SELECTORS_RVA+4, struct.pack('<I', 7))
                memory.entry(0, memory.obj, 1001)
                def changed(address, size):
                    data = memory.read(address, size)
                    if address == memory.obj+objects.OBJECT_INDEX_OFFSET:
                        memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 2))
                        memory.write(memory.base+cell, replacement)
                    return data
                scope = {}
                with self.assertRaises(objects.ObjectMetadataError):
                    next(objects.iter_object_records(changed, memory.base, scan_metadata=scope))
                self.assertEqual(scope, {})

    def test_slot_recycling_without_header_change_is_rejected(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 1001)
        def recycling(address, size):
            data = memory.read(address, size)
            if address == memory.chunk0 and size == objects.ENTRY_SIZE:
                memory.entry(0, memory.obj, 1002)
            return data
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'slot_changed'):
            objects.weak_object_key(recycling, memory.base, memory.obj)

    def test_changed_batch_yields_no_partial_records(self):
        memory = Memory(count=2)
        memory.entry(0, memory.obj, 1001)
        memory.entry(1, memory.obj+0x100, 1002)
        def recycling(address, size):
            data = memory.read(address, size)
            if address == memory.obj+0x100+objects.OBJECT_INDEX_OFFSET:
                memory.entry(0, memory.obj, 1003)
                memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 3))
            return data
        scope = {}
        iterator = objects.iter_object_records(recycling, memory.base, scan_metadata=scope)
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'slot_changed'):
            next(iterator)
        self.assertEqual(scope, {})

    def test_changed_chunk_pointer_yields_no_partial_records(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 1001)
        def replace_chunk(address, size):
            data = memory.read(address, size)
            if address == memory.obj+objects.OBJECT_INDEX_OFFSET:
                memory.write(memory.table, struct.pack('<Q', memory.chunk1))
            return data
        with self.assertRaisesRegex(objects.ObjectMetadataError, 'chunk_pointer_changed'):
            next(objects.iter_object_records(replace_chunk, memory.base))

    def test_large_registry_has_per_batch_global_reads_and_bounded_blocks(self):
        memory = Memory(count=400)
        for index in range(400):
            memory.entry(index, memory.obj+0x100*index, 1001+index)
        records = list(objects.iter_object_records(memory.read, memory.base))
        self.assertEqual(len(records), 400)
        self.assertTrue(all(size <= objects.MAX_BATCH_BYTES for _, size in memory.reads))
        count_reads = [1 for address, size in memory.reads
                       if address == memory.base+objects.COUNT_RVA]
        self.assertEqual(len(count_reads), 6)  # initial, twice per two batches, final.
        object_reads = [1 for address, size in memory.reads
                        if memory.obj <= address < memory.obj+0x100*400]
        self.assertEqual(len(object_reads), 400)
        self.assertLess(len(memory.reads), 450)

    def test_serial_high_bit_is_not_a_native_invalidity_test(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 0xF1234567)
        self.assertEqual(list(objects.iter_object_records(memory.read, memory.base)),
                         [objects.ObjectRecord(0, memory.obj, 0xF1234567)])
        self.assertEqual(objects.weak_object_key(memory.read, memory.base, memory.obj),
                         bytes.fromhex('00000000674523f1'))

    def test_frozen_tail_starts_mid_chunk_and_stops_across_chunk_boundary(self):
        memory = Memory(count=9219, outer=2, inner=7, parameter=1)
        for index in range(9214, 9218):
            chunk, within = (memory.chunk0, index) if index < 9216 else (memory.chunk1, index-9216)
            memory.entry(index, memory.obj+index*0x100, 2000+index, chunk=chunk, within=within)
        scope = {}
        rows = list(objects.iter_object_records(memory.read, memory.base,
                    start_index=9214, stop_index=9218, scan_metadata=scope))
        self.assertEqual([row.index for row in rows], [9214, 9215, 9216, 9217])
        self.assertEqual(scope['initial_index_range'], [9214, 9218])
        self.assertEqual(scope['source_scope'], 'explicit_bounded_registry_entries')
        block_reads = [(at, size) for at, size in memory.reads
                       if memory.chunk0 <= at < memory.chunk0+9216*24 or
                          memory.chunk1 <= at < memory.chunk1+24*3]
        self.assertEqual(block_reads, [(memory.chunk0+9214*24, 48)]*2 + [(memory.chunk1, 48)]*2)

    def test_tail_growth_is_observed_but_never_expands_requested_stop(self):
        memory = Memory(count=3)
        memory.entry(2, memory.obj, 1001)
        def growing(address, size):
            data = memory.read(address, size)
            if address == memory.obj+objects.OBJECT_INDEX_OFFSET:
                memory.write(memory.base+objects.COUNT_RVA, struct.pack('<i', 8))
            return data
        scope = {}
        self.assertEqual(list(objects.iter_object_records(growing, memory.base,
            start_index=2, stop_index=3, scan_metadata=scope)), [objects.ObjectRecord(2, memory.obj, 1001)])
        self.assertEqual(scope['initial_index_range'], [2, 3])
        self.assertEqual(scope['final_observed_count'], 8)
        self.assertNotIn((memory.chunk0+3*24, 24), memory.reads)

    def test_invalid_tail_bounds_fail_before_entry_reads(self):
        for start, stop in ((True, 2), (0, True), (-1, 1), (2, 1), (0, 3), (3, None)):
            with self.subTest(start=start, stop=stop):
                memory = Memory(count=2)
                with self.assertRaises(objects.ObjectMetadataError):
                    list(objects.iter_object_records(memory.read, memory.base,
                        start_index=start, stop_index=stop))
                self.assertNotIn((memory.table, 8), memory.reads)

    def test_empty_explicit_tail_has_no_entry_reads(self):
        memory = Memory(count=2)
        scope = {}
        self.assertEqual(list(objects.iter_object_records(memory.read, memory.base,
            start_index=2, stop_index=2, scan_metadata=scope)), [])
        self.assertEqual(scope['initial_index_range'], [2, 2])
        self.assertNotIn((memory.table, 8), memory.reads)

    def test_batch_change_diagnostic_identifies_exact_slot_without_yielding(self):
        memory = Memory(count=2)
        memory.entry(0, memory.obj, 1001)
        memory.entry(1, memory.obj+0x100, 0)
        def changing(address, size):
            data = memory.read(address, size)
            if address == memory.obj+0x100+objects.OBJECT_INDEX_OFFSET:
                memory.entry(1, memory.obj+0x100, 1002)
            return data
        scope = {}
        with self.assertRaisesRegex(objects.ObjectMetadataError, '^object_slot_changed_during_metadata_read$') as failed:
            next(objects.iter_object_records(changing, memory.base, scan_metadata=scope))
        self.assertEqual(scope, {})
        context = failed.exception.metadata_failure_context
        self.assertEqual(context['phase'], 'registry_batch_recheck')
        self.assertEqual(context['index_range'], [0, 2])
        self.assertEqual(context['first_changed_object_index'], 1)
        self.assertEqual(context['changed_slot_count'], 1)
        self.assertFalse(context['batch_records_yielded'])
        row, = context['changes']
        self.assertEqual(row['changed_fields'], ['serial'])
        self.assertEqual(row['before']['serial_state'], 'uninitialized')
        self.assertEqual(row['after']['serial_state'], 'initialized')
        self.assertNotIn('serial', row['before'])

    def test_batch_auxiliary_only_changes_remain_refused_and_context_is_bounded(self):
        memory = Memory(count=10)
        for index in range(10):
            memory.entry(index, 0, 0)
        block_reads = 0
        def changing(address, size):
            nonlocal block_reads
            data = memory.read(address, size)
            if address == memory.chunk0 and size == 240:
                block_reads += 1
                if block_reads == 1:
                    for index in range(10):
                        memory.write(memory.chunk0+index*24+12, struct.pack('<I', 7))
            return data
        with self.assertRaises(objects.ObjectMetadataError) as failed:
            list(objects.iter_object_records(changing, memory.base))
        context = failed.exception.metadata_failure_context
        self.assertEqual(context['changed_slot_count'], 10)
        self.assertEqual(len(context['changes']), 8)
        self.assertTrue(context['changes_truncated'])
        self.assertEqual([row['object_index'] for row in context['changes']], list(range(8)))
        self.assertTrue(all(row['changed_fields'] == ['auxiliary_words'] for row in context['changes']))

    def test_single_identity_change_context_has_index_and_categories_without_pointers(self):
        memory = Memory(count=1)
        memory.entry(0, memory.obj, 1001)
        entry_reads = 0
        def changing(address, size):
            nonlocal entry_reads
            data = memory.read(address, size)
            if address == memory.chunk0 and size == 24:
                entry_reads += 1
                if entry_reads == 1:
                    memory.entry(0, memory.obj+0x100, 0, flags=0x10000000)
            return data
        with self.assertRaisesRegex(objects.ObjectMetadataError, '^object_slot_changed_during_metadata_read$') as failed:
            objects.validate_object_record(changing, memory.base, memory.obj)
        context = failed.exception.metadata_failure_context
        self.assertEqual(context, {
            'phase': 'single_object_identity_recheck', 'object_index': 0,
            'changed_fields': ['object_pointer', 'flags', 'serial'],
            'before': {'pointer_state': 'non_null', 'flag_state': 'not_excluded', 'serial_state': 'initialized'},
            'after': {'pointer_state': 'non_null', 'flag_state': 'excluded', 'serial_state': 'uninitialized'}})


if __name__ == '__main__':
    unittest.main()
