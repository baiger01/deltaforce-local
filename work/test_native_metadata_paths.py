"""Independent name/registry literals; no process, native code, or launches."""
import struct
import unittest

import native_metadata_names as names
import native_metadata_objects as objects
from native_metadata_paths import PACKAGE_CLASS_RVA, PathResolutionError, object_path


class Memory:
    base = 0x140000000
    table = 0x500000000
    chunk = 0x500100000
    block = 0x510000000
    package_class = 0x600000000
    package = 0x600000100
    owner = 0x600000200
    child = 0x600000300
    inner = 0x600000400
    meta_class = 0x600001000
    # These literals are independent source-compatible XOR bytes, not generated
    # by the name resolver under test. All lengths3..7 use native key0xff here.
    labels = {
        'Package': ('af9e9c949e989a', 7), '/Root': ('d0ad90908b', 5),
        'Outer': ('b08a8b9a8d', 5), 'Inner': ('b691919a8d', 5),
        'Child': ('bc9796939b', 5), 'Pawn': ('af9e8891', 4),
        'Class': ('bc939e8c8c', 5),
    }

    def __init__(self):
        self.data = {}
        self.calls = []
        self.tokens = {}
        self.write(self.base + objects.COUNT_RVA, struct.pack('<i', 128))
        self.write(self.base + objects.CHUNKS_RVA, struct.pack('<Q', self.table))
        self.write(self.base + objects.POINTER_DECODER_RVA, b'\0' * 8)
        self.write(self.base + objects.OUTER_SELECTOR_RVA, b'\0' * 4)
        self.write(self.table, struct.pack('<Q', self.chunk))
        self.write(self.base + names.NAME_POOL_INITIALIZED_RVA, b'\1')
        self.write(self.base + names.NAME_POOL_RVA + 8, struct.pack('<Q', self.block))
        for index, (label, (raw, length)) in enumerate(self.labels.items(), 1):
            offset = index * 0x40
            self.tokens[label] = struct.pack('<II', offset // 2, 0)
            self.write(self.block + offset, struct.pack('<H', length << 6) + bytes.fromhex(raw))
        self.write(self.base + PACKAGE_CLASS_RVA, struct.pack('<Q', self.package_class))
        self.node(0, self.package_class, 'Package', 0, serial=0)
        self.node(1, self.package, '/Root', 0, class_address=self.package_class, serial=0)
        self.node(2, self.owner, 'Outer', self.package)
        self.node(3, self.child, 'Child', self.owner)
        self.node(4, self.inner, 'Inner', self.child)

    def write(self, address, value):
        self.data.update({address + i: byte for i, byte in enumerate(value)})

    def read(self, address, size):
        self.calls.append((address, size))
        try:
            return bytes(self.data[address + i] for i in range(size))
        except KeyError as error:
            raise PathResolutionError('Unmapped bounded fixture') from error

    def node(self, index, address, label, outer, *, class_address=None, serial=7, flags=0):
        class_address = self.meta_class if class_address is None else class_address
        self.write(self.chunk + objects.ENTRY_SIZE * index,
                   struct.pack('<QIIII', address, flags, 0, 0, serial))
        self.write(address + 8, struct.pack('<Q', class_address))
        self.write(address + 0x10, struct.pack('<Q', outer))
        self.write(address + 0x1c, self.tokens[label])
        self.write(address + 0x24, struct.pack('<i', index))


class MetadataPathTests(unittest.TestCase):
    def test_package_direct_child_dot_and_zero_serial(self):
        mem = Memory()
        self.assertEqual(object_path(mem.read, mem.base, mem.owner), '/Root.Outer')
        self.assertLessEqual(max(size for _, size in mem.calls), 24)

    def test_subobject_boundary_colon_then_dot(self):
        mem = Memory()
        self.assertEqual(object_path(mem.read, mem.base, mem.child), '/Root.Outer:Child')
        self.assertEqual(object_path(mem.read, mem.base, mem.inner), '/Root.Outer:Child.Inner')

    def test_nonpackage_null_root_has_no_prefix(self):
        mem = Memory()
        self.assertEqual(object_path(mem.read, mem.base, mem.package_class), 'Package')

    def test_null_object_literal_has_no_reads(self):
        mem = Memory()
        self.assertEqual(object_path(mem.read, mem.base, 0), 'None')
        self.assertEqual(mem.calls, [])

    def test_package_singleton_name_and_nonzero_are_required(self):
        for pointer, wrong_name in ((0, False), (Memory.package_class, True)):
            with self.subTest(pointer=pointer, wrong_name=wrong_name):
                mem = Memory()
                mem.write(mem.base + PACKAGE_CLASS_RVA, struct.pack('<Q', pointer))
                if wrong_name:
                    mem.write(mem.package_class + 0x1c, mem.tokens['Pawn'])
                with self.assertRaises(PathResolutionError):
                    object_path(mem.read, mem.base, mem.owner)

    def test_package_and_each_outer_registry_identity_are_required(self):
        for index in (0, 1, 2):
            with self.subTest(index=index):
                mem = Memory()
                mem.write(mem.chunk + objects.ENTRY_SIZE * index + 8,
                          struct.pack('<I', 0x10000000))
                with self.assertRaises(objects.ObjectMetadataError):
                    object_path(mem.read, mem.base, mem.owner)

    def test_cycle_and_depth_fail_closed(self):
        mem = Memory()
        mem.write(mem.owner + 0x10, struct.pack('<Q', mem.child))
        with self.assertRaisesRegex(PathResolutionError, 'cycle'):
            object_path(mem.read, mem.base, mem.owner)
        mem = Memory()
        with self.assertRaisesRegex(PathResolutionError, 'depth'):
            object_path(mem.read, mem.base, mem.owner, 1)

    def test_exact_32_nodes_supported_and_33_rejected(self):
        for total in (32, 33):
            with self.subTest(nodes=total):
                mem = Memory()
                previous = mem.package
                for index in range(2, total + 1):
                    address = 0x600010000 + index * 0x100
                    mem.node(index, address, 'Inner', previous)
                    previous = address
                if total == 32:
                    result = object_path(mem.read, mem.base, previous)
                    self.assertEqual(result, '/Root.Inner:' + '.'.join(['Inner'] * 30))
                    self.assertLess(len(mem.calls), 4096)
                else:
                    with self.assertRaisesRegex(PathResolutionError, 'depth'):
                        object_path(mem.read, mem.base, previous)

    def test_final_outer_class_token_and_serial_changes_are_rejected(self):
        mutations = ((Memory.owner + 0x10, struct.pack('<Q', 0)),
                     (Memory.owner + 8, struct.pack('<Q', Memory.package_class)),
                     (Memory.owner + 0x1c, None),
                     (Memory.chunk + 2 * objects.ENTRY_SIZE + 0x14, struct.pack('<I', 8)))
        for address, value in mutations:
            with self.subTest(address=address):
                mem = Memory()
                changed = False
                def reader(at, size):
                    nonlocal changed
                    data = mem.read(at, size)
                    # The root node's name resolution occurs after collecting
                    # the supplied child. Mutate earlier metadata at that point.
                    if not changed and at == mem.package + 0x1c:
                        changed = True
                        mem.write(address, mem.tokens['Pawn'] if value is None else value)
                    return data
                with self.assertRaisesRegex(ValueError, 'changed'):
                    object_path(reader, mem.base, mem.owner)

    def test_package_singleton_change_is_rejected(self):
        mem = Memory()
        changed = False
        def reader(at, size):
            nonlocal changed
            data = mem.read(at, size)
            if not changed and at == mem.package + 0x1c:
                changed = True
                mem.write(mem.base + PACKAGE_CLASS_RVA, struct.pack('<Q', mem.owner))
            return data
        with self.assertRaisesRegex(PathResolutionError, 'singleton changed'):
            object_path(reader, mem.base, mem.owner)

    def test_malformed_nonpackage_outer_root_rejected(self):
        mem = Memory()
        mem.write(mem.package + 8, struct.pack('<Q', mem.meta_class))
        with self.assertRaisesRegex(PathResolutionError, 'Non-Package'):
            object_path(mem.read, mem.base, mem.owner)

    def test_truncated_callback_and_bad_arguments(self):
        mem = Memory()
        with self.assertRaises(PathResolutionError):
            object_path(lambda address, size: b'\0' * (size - 1), mem.base, mem.owner)
        for depth in (0, 33, True, 1.0):
            with self.subTest(depth=depth), self.assertRaises(PathResolutionError):
                object_path(mem.read, mem.base, mem.owner, depth)
        for address in (-1, True, 1.0, 1 << 63):
            with self.subTest(address=address), self.assertRaises(PathResolutionError):
                object_path(mem.read, mem.base, address)


if __name__ == '__main__':
    unittest.main()
