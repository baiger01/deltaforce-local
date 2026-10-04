"""Independent native-layout fixtures; these are not actual game-class schemas."""
from dataclasses import FrozenInstanceError, replace
import struct
import unittest

from dfserver.legacy_ds_class_net_cache import (
    CacheSnapshotLimits, CachedField, ClassCacheGraph, ClassCacheSnapshot,
    ENTRY_BYTES, HEADER_BYTES, MAX_FIELDS_PER_CACHE, MAX_PARENT_DEPTH,
    MAX_TOTAL_FIELDS, UINT64_MAX, decode_class_cache_snapshot,
)


# Hand-written layout fixture: nonzero uninitialized padding is intentional.
LITERAL_HEADER = bytes.fromhex(
    '00000000 deadbeef 0000000000000000 1122334455667788 '
    '78563412 aabbccdd 0020000000000000 02000000 03000000')
LITERAL_ENTRIES = bytes.fromhex(
    '0080000000000000 00 91929394959697 00000000 00000000 00 a1a2a3a4a5a6a7 '
    '0090000000000000 01 91929394959697 01000000 ffffffff 01 a1a2a3a4a5a6a7')


def header(*, start=0, parent=0, storage=0x2000, count=1, capacity=None):
    raw = bytearray(48)
    struct.pack_into('<I', raw, 0, start)
    struct.pack_into('<Q', raw, 8, parent)
    raw[0x10:0x18] = bytes.fromhex('1122334455667788')
    struct.pack_into('<I', raw, 0x18, 0x12345678)
    struct.pack_into('<Qii', raw, 0x20, storage, count,
                     count if capacity is None else capacity)
    return bytes(raw)


def entry(*, index=0, descriptor=0x8000, representation=0,
          checksum=0, incompatible=0):
    raw = bytearray(32)
    struct.pack_into('<Q', raw, 0, descriptor)
    raw[8] = representation
    struct.pack_into('<II', raw, 0x10, index, checksum)
    raw[0x18] = incompatible
    return bytes(raw)


def snapshot(*, address=0x1000, start=0, parent=0, count=1,
             storage=0x2000, capacity=None, entries=None, limits=None):
    if entries is None:
        entries = b''.join(entry(index=start+i) for i in range(count))
    kwargs = {} if limits is None else {'limits': limits}
    return decode_class_cache_snapshot(
        address=address,
        header=header(start=start, parent=parent, storage=storage,
                      count=count, capacity=capacity),
        entry_bytes=entries, **kwargs)


class ClassNetCacheTests(unittest.TestCase):
    def graph(self, node, **kwargs):
        return ClassCacheGraph(leaf_address=node.address, snapshots=(node,), **kwargs)

    def test_literal_native_offsets_and_ignored_uninitialized_padding(self):
        self.assertEqual((HEADER_BYTES, ENTRY_BYTES), (48, 32))
        self.assertEqual((len(LITERAL_HEADER), len(LITERAL_ENTRIES)), (48, 64))
        node = decode_class_cache_snapshot(address=0x1000, header=LITERAL_HEADER,
                                           entry_bytes=LITERAL_ENTRIES)
        self.assertEqual(node, ClassCacheSnapshot(
            0x1000, 0, 0, bytes.fromhex('1122334455667788'), 0x12345678,
            0x2000, 3, (
                CachedField(0x8000, 0, 0, 0, False, 0x1000),
                CachedField(0x9000, 1, 1, 0xffffffff, True, 0x1000))))

    def test_decoded_snapshot_and_field_are_frozen(self):
        node = snapshot()
        with self.assertRaises(FrozenInstanceError):
            node.index_start = 1
        with self.assertRaises(FrozenInstanceError):
            node.fields[0].checksum = 1

    def test_inherited_intervals_include_empty_middle_cache(self):
        root = snapshot(address=0x1000, count=2)
        middle = snapshot(address=0x1100, start=2, parent=root.address, count=0)
        leaf = snapshot(address=0x1200, start=2, parent=middle.address)
        graph = ClassCacheGraph(leaf_address=leaf.address,
                                snapshots=(leaf, root, middle))
        self.assertEqual(graph.nodes, (root, middle, leaf))
        self.assertEqual(graph.exclusive_index_maximum, 4)
        self.assertEqual(graph.normal_field_profile().exclusive_index_maximum, 4)
        self.assertIs(graph.normal_field_profile().internal_ack, False)
        self.assertEqual(graph.field_for_index(0).declaring_cache_address, root.address)
        self.assertEqual(graph.field_for_index(1).declaring_cache_address, root.address)
        self.assertEqual(graph.field_for_index(2).declaring_cache_address, leaf.address)
        for index in (3, 4, -1, True, 0.0):
            with self.subTest(index=index), self.assertRaises(ValueError):
                graph.field_for_index(index)

    def test_empty_root_has_framing_maximum_one_but_no_declared_field(self):
        node = snapshot(count=0, storage=UINT64_MAX, capacity=3)
        graph = self.graph(node)
        self.assertEqual(graph.exclusive_index_maximum, 1)
        with self.assertRaises(ValueError):
            graph.field_for_index(0)

    def test_null_or_incompatible_descriptors_are_not_authorized_fields(self):
        node = snapshot(count=3, entries=(entry(descriptor=0) +
            entry(index=1, incompatible=1) + entry(index=2, representation=1)))
        graph = self.graph(node)
        self.assertEqual(graph.field_for_index(0).descriptor_address, 0)
        self.assertIs(graph.field_for_index(1).incompatible, True)
        for index in (0, 1):
            with self.subTest(index=index), self.assertRaises(ValueError):
                graph.require_compatible_descriptor(index)
        self.assertEqual(graph.require_compatible_descriptor(2).descriptor_representation, 1)

    def test_checksum_zero_and_duplicates_do_not_invent_identity_or_schema(self):
        graph = self.graph(snapshot(count=2))
        self.assertEqual(tuple(field.checksum for field in graph.nodes[0].fields), (0, 0))
        self.assertEqual(graph.require_compatible_descriptor(0).descriptor_address, 0x8000)
        self.assertEqual(graph.require_compatible_descriptor(1).descriptor_address, 0x8000)

    def test_raw_header_and_entries_must_be_exact_immutable_bytes(self):
        for bad_header in (LITERAL_HEADER[:-1], LITERAL_HEADER+b'\0',
                           bytearray(LITERAL_HEADER), memoryview(LITERAL_HEADER), None):
            with self.subTest(header_type=type(bad_header)), self.assertRaises(ValueError):
                decode_class_cache_snapshot(address=0x1000, header=bad_header,
                                             entry_bytes=LITERAL_ENTRIES)
        for bad_entries in (LITERAL_ENTRIES[:-1], LITERAL_ENTRIES+b'\0',
                            bytearray(LITERAL_ENTRIES), memoryview(LITERAL_ENTRIES), None):
            with self.subTest(entries_type=type(bad_entries)), self.assertRaises(ValueError):
                decode_class_cache_snapshot(address=0x1000, header=LITERAL_HEADER,
                                             entry_bytes=bad_entries)

    def test_signed_array_counts_capacity_and_null_storage_rejected(self):
        for count, capacity, storage in ((-1, 1, 0x2000), (0, -1, 0),
                (2, 1, 0x2000), (1, 1, 0),
                (MAX_FIELDS_PER_CACHE+1, MAX_FIELDS_PER_CACHE+1, 0x2000),
                (0, MAX_FIELDS_PER_CACHE+1, 0x2000)):
            with self.subTest(count=count, capacity=capacity, storage=storage):
                with self.assertRaises(ValueError):
                    decode_class_cache_snapshot(address=0x1000,
                        header=header(count=count, capacity=capacity, storage=storage),
                        entry_bytes=b'')

    def test_absolute_entry_order_and_unsupported_flag_bytes_rejected(self):
        for raw in (entry(index=1), entry(representation=2), entry(incompatible=2),
                    entry(representation=255), entry(incompatible=255)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                snapshot(entries=raw)
        with self.assertRaises(ValueError):
            snapshot(start=2, count=2, entries=entry(index=3)+entry(index=2))

    def test_strict_addresses_and_complete_header_span(self):
        for address in (0, -1, True, 0.5, UINT64_MAX+1, UINT64_MAX,
                        UINT64_MAX-46):
            with self.subTest(address=address), self.assertRaises(ValueError):
                snapshot(address=address)
        node = snapshot(address=UINT64_MAX-47)
        self.assertEqual(self.graph(node).exclusive_index_maximum, 2)
        # Empty fields keep this public-constructor regression independent of
        # declaring-field or missing-leaf validation.
        forged = replace(snapshot(count=0), address=UINT64_MAX)
        with self.assertRaises(ValueError):
            self.graph(forged)

    def test_exact_used_entry_address_span_and_empty_storage_exception(self):
        for storage, count in ((UINT64_MAX, 1), (UINT64_MAX-30, 1),
                               (UINT64_MAX-31, 2)):
            with self.subTest(storage=storage, count=count), self.assertRaises(ValueError):
                snapshot(storage=storage, count=count)
        self.graph(snapshot(storage=UINT64_MAX-31))
        # Only used entries are supplied; spare capacity is not a claimed readable span.
        self.graph(snapshot(storage=UINT64_MAX-31, capacity=4096))
        self.graph(snapshot(storage=UINT64_MAX, count=0, capacity=4096))

    def test_self_parent_and_multi_node_cycles_rejected(self):
        with self.assertRaises(ValueError):
            snapshot(parent=0x1000)
        first = snapshot(address=0x1000, parent=0x1100, count=0)
        second = snapshot(address=0x1100, parent=0x1000, count=0)
        with self.assertRaises(ValueError):
            ClassCacheGraph(leaf_address=first.address, snapshots=(first, second))
        with self.assertRaises(ValueError):
            self.graph(replace(snapshot(), parent_address=0x1000))

    def test_missing_parent_leaf_duplicate_and_unrelated_nodes_rejected(self):
        root = snapshot(address=0x1000)
        leaf = snapshot(address=0x1100, start=1, parent=root.address)
        unrelated = snapshot(address=0x1200)
        for leaf_address, nodes in ((leaf.address, (leaf,)),
                (0x1300, (root,)), (root.address, (root, root)),
                (leaf.address, (root, leaf, unrelated))):
            with self.subTest(leaf=leaf_address, nodes=nodes), self.assertRaises(ValueError):
                ClassCacheGraph(leaf_address=leaf_address, snapshots=nodes)

    def test_parent_and_child_intervals_must_be_contiguous(self):
        root = snapshot(address=0x1000)
        for start in (0, 2):
            leaf = snapshot(address=0x1100, start=start, parent=root.address)
            with self.subTest(start=start), self.assertRaises(ValueError):
                ClassCacheGraph(leaf_address=leaf.address, snapshots=(root, leaf))
        with self.assertRaises(ValueError):
            self.graph(snapshot(start=1))

    def test_snapshot_collection_requires_bounded_nonempty_tuple(self):
        node = snapshot()
        for nodes in ((), [node], (object(),), None):
            with self.subTest(nodes=nodes), self.assertRaises(ValueError):
                ClassCacheGraph(leaf_address=node.address, snapshots=nodes)
        for leaf in (True, 0, UINT64_MAX+1):
            with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                ClassCacheGraph(leaf_address=leaf, snapshots=(node,))

    def test_per_cache_total_and_depth_limits_are_checked_again_on_graph(self):
        limits = CacheSnapshotLimits(max_fields_per_cache=2, max_total_fields=3,
                                     max_parent_depth=3)
        root = snapshot(address=0x1000, count=2, limits=limits)
        middle = snapshot(address=0x1100, start=2, parent=root.address, count=0,
                          limits=limits)
        leaf = snapshot(address=0x1200, start=2, parent=middle.address, limits=limits)
        graph = ClassCacheGraph(leaf_address=leaf.address,
                                snapshots=(root, middle, leaf), limits=limits)
        self.assertEqual(graph.exclusive_index_maximum, 4)
        with self.assertRaises(ValueError):
            snapshot(count=3, limits=limits)
        with self.assertRaises(ValueError):
            snapshot(start=3, limits=limits)
        for smaller in (replace(limits, max_fields_per_cache=1),
                        replace(limits, max_total_fields=2),
                        replace(limits, max_parent_depth=2)):
            with self.subTest(limits=smaller), self.assertRaises(ValueError):
                ClassCacheGraph(leaf_address=leaf.address,
                                snapshots=(root, middle, leaf), limits=smaller)
        zero = CacheSnapshotLimits(max_fields_per_cache=0, max_total_fields=0)
        self.assertEqual(self.graph(snapshot(count=0, limits=zero), limits=zero)
                         .exclusive_index_maximum, 1)

    def test_limit_types_ranges_and_frozen_dataclass_bypass_rejected(self):
        for kwargs in ({'max_fields_per_cache':True}, {'max_fields_per_cache':-1},
                {'max_fields_per_cache':MAX_FIELDS_PER_CACHE+1},
                {'max_total_fields':True}, {'max_total_fields':MAX_TOTAL_FIELDS+1},
                {'max_parent_depth':0}, {'max_parent_depth':MAX_PARENT_DEPTH+1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                CacheSnapshotLimits(**kwargs)
        with self.assertRaises(ValueError):
            snapshot(limits=object())
        corrupt = CacheSnapshotLimits()
        object.__setattr__(corrupt, 'max_parent_depth', True)
        with self.assertRaises(ValueError):
            self.graph(snapshot(), limits=corrupt)

    def test_limit_subclass_cannot_replace_boundary_validation(self):
        class OverridesValidation(CacheSnapshotLimits):
            def __post_init__(self):
                pass

        for kwargs in ({'max_parent_depth':MAX_PARENT_DEPTH+1},
                       {'max_fields_per_cache':MAX_FIELDS_PER_CACHE+1},
                       {'max_total_fields':MAX_TOTAL_FIELDS+1}):
            limits = OverridesValidation(**kwargs)
            with self.subTest(kwargs=kwargs, operation='decode'), self.assertRaises(ValueError):
                snapshot(count=0, limits=limits)
            with self.subTest(kwargs=kwargs, operation='graph'), self.assertRaises(ValueError):
                self.graph(snapshot(count=0), limits=limits)

    def test_constructed_node_revalidates_header_storage_interval_and_key(self):
        node = snapshot()
        mutations = (
            {'address':True}, {'address':UINT64_MAX}, {'parent_address':True},
            {'parent_address':UINT64_MAX+1}, {'field_storage_address':True},
            {'field_storage_address':UINT64_MAX}, {'field_storage_address':0},
            {'index_start':True}, {'index_start':-1}, {'index_start':MAX_TOTAL_FIELDS},
            {'fields':list(node.fields)}, {'fields':(object(),)},
            {'field_capacity':True}, {'field_capacity':0},
            {'field_capacity':MAX_FIELDS_PER_CACHE+1},
            {'opaque_object_key':bytearray(8)}, {'opaque_object_key':b''},
            {'aggregate_checksum':True}, {'aggregate_checksum':-1},
            {'aggregate_checksum':1<<32},
        )
        for mutation in mutations:
            bad = replace(node, **mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ClassCacheGraph(leaf_address=0x1000, snapshots=(bad,))

    def test_constructed_field_revalidates_strict_values_and_declaring_cache(self):
        node = snapshot()
        field = node.fields[0]
        for mutation in ({'descriptor_address':True}, {'descriptor_address':-1},
                {'descriptor_address':UINT64_MAX+1}, {'descriptor_representation':True},
                {'descriptor_representation':2}, {'rep_index':True}, {'rep_index':1},
                {'checksum':True}, {'checksum':-1}, {'checksum':1<<32},
                {'incompatible':0}, {'incompatible':1},
                {'declaring_cache_address':True}, {'declaring_cache_address':0x1100}):
            bad = replace(node, fields=(replace(field, **mutation),))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.graph(bad)


if __name__ == '__main__':
    unittest.main()
