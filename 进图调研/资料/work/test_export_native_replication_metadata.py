"""Independent offline registry/name fixtures; every process API is mocked."""
from dataclasses import asdict
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import ctypes as C
import hashlib
import io
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import export_native_replication_metadata as export
import native_metadata_names as names
from native_metadata_objects import ObjectMetadataError, weak_object_key
from native_replication_metadata_core import MetadataSession, export_replayout
from dfserver.legacy_ds_class_net_cache import CachedField, ClassCacheSnapshot
from test_native_metadata_objects import Memory as RegistryMemory


# Explicit encoded bytes, independently fixed for these ASCII labels. No name
# encoder or production key helper is used to construct a fixture.
LITERALS = {
    'Class': 'bc939e8c8c',
    'BlueprintGeneratedClass': 'bd938a9a8f8d96918bb89a919a8d9e8b9a9bbc939e8c8c',
    'Object': 'b09d959a9c8b',
    'Actor': 'be9c8b908d',
    'NetDriver': 'b19a8bbb8d96899a8d',
    'IpNetDriver': '360f311a0b3b0d16091a0d',
    'BP_DFMPlayerController_C': 'bdafa0bbb9b2af939e869a8dbc90918b8d9093939a8da0bc',
    'BP_DFMCharacter_C': 'bdafa0bbb9b2bc979e8d9e9c8b9a8da0bc',
    'BP_GameState_PVPVE_C': '3d2f20381e121a2c0b1e0b1a202f292f293a203c',
    'Health': 'b79a9e938b97',
    'Pawn': 'af9e8891',
    'Package': 'af9e9c949e989a',
    '/Game/Test/PC': 'd0b89e929ad0ab9a8c8bd0afbc',
    '/Game/Test/Pawn': 'd0b89e929ad0ab9a8c8bd0af9e8891',
    '/Game/Test/GS': 'd0b89e929ad0ab9a8c8bd0b8ac',
    '/Game/Test/Pawn2': 'd0b89e929ad0ab9a8c8bd0af9e8891cd',
}


class Fixture:
    block = 0x680000000
    field0, field1 = 0x700000000, 0x700001000

    def __init__(self, *, driver=True, duplicate=False):
        self.memory = RegistryMemory(count=0)
        self.base = self.memory.base
        self.memory.write(self.base+names.NAME_POOL_INITIALIZED_RVA, b'\1')
        self.memory.write(self.base+names.NAME_POOL_RVA+8, struct.pack('<Q', self.block))
        self.tokens = {}
        for ordinal, (text, encoded) in enumerate(LITERALS.items()):
            offset = 0x100+ordinal*64
            raw = bytes.fromhex(encoded)
            assert len(raw) == len(text)
            self.memory.write(self.block+offset, struct.pack('<H', len(raw)<<6)+raw)
            self.tokens[text] = struct.pack('<II', offset//2, 0)
        self.rows = []
        self.class_type = self.allocate()
        self.blueprint_type = self.allocate()
        self.object_type = self.allocate()
        self.actor_type = self.allocate()
        self.netdriver_type = self.allocate()
        self.ipdriver_type = self.allocate()
        self.package_type = self.allocate()
        self.pc, self.pawn, self.gs = self.allocate(), self.allocate(), self.allocate()
        self.describe(self.class_type, 'Class', self.class_type, 0)
        self.describe(self.blueprint_type, 'BlueprintGeneratedClass', self.class_type, self.class_type)
        self.describe(self.object_type, 'Object', self.class_type, 0)
        self.describe(self.actor_type, 'Actor', self.class_type, self.object_type)
        self.describe(self.netdriver_type, 'NetDriver', self.class_type, self.object_type)
        self.describe(self.ipdriver_type, 'IpNetDriver', self.class_type, self.netdriver_type)
        self.describe(self.package_type, 'Package', self.class_type, self.object_type)
        self.memory.write(self.base+0x1E34CA90, struct.pack('<Q', self.package_type))
        self.packages = {}
        for address, label, package_label in ((self.pc, 'BP_DFMPlayerController_C', '/Game/Test/PC'),
                               (self.pawn, 'BP_DFMCharacter_C', '/Game/Test/Pawn'),
                               (self.gs, 'BP_GameState_PVPVE_C', '/Game/Test/GS')):
            package = self.allocate()
            self.describe(package, package_label, self.package_type, 0)
            self.packages[package_label] = package
            self.describe(address, label, self.blueprint_type, self.actor_type, outer=package)
        self.duplicate = None
        if duplicate:
            package = self.allocate()
            self.describe(package, '/Game/Test/Pawn2', self.package_type, 0)
            self.packages['/Game/Test/Pawn2'] = package
            self.duplicate = self.allocate()
            self.describe(self.duplicate, 'BP_DFMCharacter_C', self.blueprint_type, self.actor_type, outer=package)
        # This ordinary Actor instance has a target's exact own shortname. Its
        # metaclass is Actor/Object, so the name must never be used as a class.
        self.false_target = self.allocate()
        self.describe(self.false_target, 'BP_DFMPlayerController_C', self.actor_type, 0)
        self.instances = []
        for klass in (self.pc, self.pawn, self.gs):
            address = self.allocate()
            self.memory.write(address+8, struct.pack('<Q', klass))
            self.memory.write(address+0x10, struct.pack('<Q', 0))
            self.instances.append(address)  # No own-name bytes are mapped.
        self.driver = self.allocate() if driver else None
        if self.driver:
            self.memory.write(self.driver+8, struct.pack('<Q', self.ipdriver_type))
        self.memory.write(self.field0+0x28, self.tokens['Health'])
        self.memory.write(self.field0, struct.pack('<Q', 0))
        self.memory.write(self.field1, struct.pack('<Q', 0))
        self.memory.write(self.field1+0x1C, self.tokens['Pawn'])
        self.memory.write(self.base+0x1E34EE5C, struct.pack('<i', len(self.rows)))

    def allocate(self):
        index = len(self.rows)
        address = self.memory.obj+0x1000*index
        self.memory.entry(index, address, 1001+index)
        self.rows.append(address)
        return address

    def describe(self, address, name, klass, parent, *, outer=0):
        self.memory.write(address+8, struct.pack('<Q', klass))
        self.memory.write(address+0x10, struct.pack('<Q', outer))
        self.memory.write(address+0x1C, self.tokens[name])
        self.memory.write(address+0x48, struct.pack('<Q', parent))

    def session(self):
        return MetadataSession(self.memory.read)

    def serial(self, address, serial):
        self.memory.entry(self.rows.index(address), address, serial)

    def cache_result(self, session, driver, key):
        # A real asdict(ClassCacheSnapshot) shape, including tuple-of-dict fields.
        node = ClassCacheSnapshot(
            0x710000000, 0, 0, key, 0x1234, 0x710001000, 2,
            (CachedField(self.field0, 0, 0, 0x123, False, 0x710000000),
             CachedField(self.field1, 1, 1, 0x124, False, 0x710000000)),
        )
        return {
            'driver_address': driver, 'class_key': key.hex(),
            'cache_status': 'exported_existing', 'layout_status': 'exported_existing',
            'cache_nodes': [{**asdict(node), 'opaque_object_key': key.hex()}],
            'layout': {'property_serializer_schema_recovered': False, 'parents': [], 'commands': []},
        }


class DiscoveryTests(unittest.TestCase):
    def test_real_registry_and_literal_names_bind_three_classes_and_driver(self):
        fixture = Fixture()
        result = export.discover_roots(fixture.session(), fixture.base)
        self.assertEqual({row['name'] for row in result['classes']}, export.TARGET_CLASSES)
        self.assertEqual(result['missing_target_classes'], [])
        self.assertEqual(result['records_scanned'], len(fixture.rows))
        self.assertEqual([row['address'] for row in result['drivers']], [fixture.driver])
        self.assertEqual(result['drivers'][0]['class_chain'], ['IpNetDriver', 'NetDriver', 'Object'])
        for row in result['classes']:
            self.assertEqual(row['metaclass_chain'], ['BlueprintGeneratedClass', 'Class'])
        self.assertEqual({row['asset_path'] for row in result['classes']}, {
            '/Game/Test/PC.BP_DFMPlayerController_C',
            '/Game/Test/Pawn.BP_DFMCharacter_C',
            '/Game/Test/GS.BP_GameState_PVPVE_C',
        })
        self.assertIn((fixture.base+0x1E34CA90, 8), fixture.memory.reads)
        forbidden = [fixture.false_target, *fixture.instances, fixture.driver]
        for address in forbidden:
            self.assertNotIn((address+0x1C, 8), fixture.memory.reads)

    def test_non_class_object_with_same_name_is_not_selected(self):
        fixture = Fixture()
        result = export.discover_roots(fixture.session(), fixture.base)
        self.assertNotIn(fixture.false_target, {row['address'] for row in result['classes']})
        self.assertNotIn((fixture.false_target+0x1C, 8), fixture.memory.reads)

    def test_duplicate_target_shortnames_keep_distinct_class_identities(self):
        fixture = Fixture(duplicate=True)
        result = export.discover_roots(fixture.session(), fixture.base)
        pawn_rows = [row for row in result['classes'] if row['name'] == 'BP_DFMCharacter_C']
        self.assertEqual({row['address'] for row in pawn_rows}, {fixture.pawn, fixture.duplicate})
        self.assertEqual(len({row['key'] for row in pawn_rows}), 2)
        self.assertEqual({row['asset_path'] for row in pawn_rows}, {
            '/Game/Test/Pawn.BP_DFMCharacter_C',
            '/Game/Test/Pawn2.BP_DFMCharacter_C',
        })

    def test_all_classes_without_driver_are_found_but_tables_not_recovered(self):
        fixture = Fixture(driver=False)
        with patch.object(export, 'export_existing_driver_class') as core:
            result = export.export_metadata(fixture.session(), fixture.base)
        self.assertEqual({row['name'] for row in result['roots']['classes']}, export.TARGET_CLASSES)
        self.assertEqual(result['roots']['drivers'], [])
        self.assertEqual(result['class_cache_exports'], 0)
        self.assertEqual(result['replication_layout_exports'], 0)
        core.assert_not_called()

    def test_real_asdict_fields_get_correct_representation_names(self):
        fixture = Fixture()
        with patch.object(export, 'export_existing_driver_class', side_effect=fixture.cache_result):
            result = export.export_metadata(fixture.session(), fixture.base)
        self.assertEqual(result['class_cache_exports'], 3)
        self.assertEqual(result['replication_layout_exports'], 3)
        for row in result['driver_class_exports']:
            fields = row['cache_nodes'][0]['fields']
            self.assertIsInstance(fields, tuple)
            self.assertTrue(all(type(field) is dict for field in fields))
            self.assertEqual([field['descriptor_name'] for field in fields], ['Health', 'Pawn'])
            self.assertEqual([field['descriptor_representation'] for field in fields], [0, 1])
        self.assertIn((fixture.field0+0x28, 8), fixture.memory.reads)
        self.assertIn((fixture.field1+0x1C, 8), fixture.memory.reads)

    def test_real_core_layout_records_resolve_names_handles_and_skip_null_special(self):
        # Build literal native records, then use the actual bounded core decoder
        # and actual FName resolver. The driver lookup alone remains mocked.
        for handles in ((0x83, 0x205), (0x4012, 0xEE00)):
            with self.subTest(handles=handles):
                fixture = Fixture()
                layout, parent_storage, command_storage = 0x720000000, 0x720001000, 0x720002000
                pawn_descriptor = 0x700002000
                serializer_table = fixture.base + 0x1800
                fixture.memory.write(pawn_descriptor, struct.pack('<Q', serializer_table))
                fixture.memory.write(serializer_table + 0x90, struct.pack('<Q', fixture.base + 0x1234560))
                fixture.memory.write(pawn_descriptor+0x28, fixture.tokens['Pawn'])
                parent_records = bytearray(128)
                struct.pack_into('<Q', parent_records, 0, fixture.field0)
                # Deliberately use a different record FName from its descriptor.
                pawn_token = struct.pack('<II', struct.unpack('<II', fixture.tokens['Pawn'])[0], 7)
                parent_records[8:16] = pawn_token
                struct.pack_into('<Q', parent_records, 64, pawn_descriptor)
                parent_records[72:80] = fixture.tokens['Health']
                command_records = bytearray(96)
                for index, (descriptor, handle) in enumerate(zip(
                        (fixture.field0, pawn_descriptor), handles)):
                    at = index*32
                    struct.pack_into('<Q', command_records, at, descriptor)
                    struct.pack_into('<iiHH', command_records, at+0xC,
                                     -13+index, 97+index, handle, 1-index)
                    command_records[at+0x1C] = 7+index
                # Opcode 1 is a native empty special record, not a descriptor.
                struct.pack_into('<HH', command_records, 64+0x14, 0xBEEF, 0xFFFF)
                command_records[64+0x1C] = 1
                fixture.memory.write(layout+0x40, struct.pack('<QiiQii',
                    parent_storage, 2, 2, command_storage, 3, 3))
                fixture.memory.write(parent_storage, bytes(parent_records))
                fixture.memory.write(command_storage, bytes(command_records))

                def core_result(session, driver, key):
                    result = fixture.cache_result(session, driver, key)
                    result['layout'] = export_replayout(session, layout)
                    return result

                with patch.object(export, 'export_existing_driver_class', side_effect=core_result), \
                     patch.object(export, 'object_name', wraps=export.object_name) as labels:
                    result = export.export_metadata(fixture.session(), fixture.base)
                self.assertEqual(result['replication_layout_exports'], 3)
                for row in result['driver_class_exports']:
                    actual = row['layout']
                    self.assertEqual([record['descriptor_name'] for record in actual['parents']],
                                     ['Health', 'Pawn'])
                    self.assertEqual([record['record_name'] for record in actual['parents']],
                                     ['Pawn_6', 'Health'])
                    commands = actual['commands']
                    self.assertEqual([command['relative_handle'] for command in commands],
                                     [*handles, 0xBEEF])
                    self.assertEqual([command['parent_index'] for command in commands], [1, 0, 0xFFFF])
                    self.assertEqual([command['dispatch_opcode'] for command in commands], [7, 8, 1])
                    self.assertEqual([command['descriptor_name'] for command in commands[:2]],
                                     ['Health', 'Pawn'])
                    self.assertNotIn('descriptor_name', commands[2])
                    self.assertEqual(commands[2]['descriptor_name_status'], 'native_empty_special_record')
                    self.assertEqual(commands[1]['property_serializer_hook']['target_rva'], 0x1234560)
                    self.assertTrue(commands[1]['property_serializer_hook']['identity_rechecked'])
                    self.assertNotIn('property_serializer_hook', commands[2])
                    self.assertFalse(actual['property_serializer_schema_recovered'])
                self.assertTrue(all(call.args[2] != 0 for call in labels.call_args_list))
                self.assertIn((layout+0x40, 32), fixture.memory.reads)
                self.assertIn((parent_storage, 128), fixture.memory.reads)
                self.assertIn((command_storage, 96), fixture.memory.reads)
                self.assertIn((pawn_descriptor+0x28, 8), fixture.memory.reads)

    def test_recycled_metaclass_descriptor_refuses_complete_discovery(self):
        fixture = Fixture()
        original_read = fixture.memory.read
        def recycle_ancestor(address, size):
            data = original_read(address, size)
            if address == fixture.driver+8:
                fixture.memory.entry(0, fixture.class_type, 2001)
            return data
        with self.assertRaises(ValueError):
            export.discover_roots(MetadataSession(recycle_ancestor), fixture.base)

    def test_driver_class_binding_changed_after_read_refuses_discovery(self):
        fixture = Fixture()
        original_read = fixture.memory.read
        def replace_driver_class(address, size):
            data = original_read(address, size)
            if address == fixture.driver+8:
                fixture.memory.write(fixture.driver+8, struct.pack('<Q', fixture.actor_type))
            return data
        with self.assertRaises(ValueError):
            export.discover_roots(MetadataSession(replace_driver_class), fixture.base)

    def test_zero_serial_metaclasses_and_parents_still_bind_real_targets(self):
        fixture = Fixture()
        for address in (fixture.class_type, fixture.blueprint_type, fixture.object_type,
                        fixture.actor_type, fixture.netdriver_type, fixture.ipdriver_type):
            fixture.serial(address, 0)
        with patch.object(export, 'export_existing_driver_class', side_effect=fixture.cache_result):
            result = export.export_metadata(fixture.session(), fixture.base)
        self.assertEqual({row['name'] for row in result['roots']['classes']}, export.TARGET_CLASSES)
        self.assertEqual(result['class_cache_exports'], 3)
        self.assertEqual(result['replication_layout_exports'], 3)
        with self.assertRaisesRegex(ObjectMetadataError, 'no_native_weak_key'):
            weak_object_key(fixture.memory.read, fixture.base, fixture.class_type)

    def test_zero_serial_target_is_found_but_native_key_lookup_is_not_called(self):
        fixture = Fixture()
        fixture.serial(fixture.pc, 0)
        with patch.object(export, 'export_existing_driver_class', side_effect=fixture.cache_result) as core:
            result = export.export_metadata(fixture.session(), fixture.base)
        pc = next(row for row in result['roots']['classes'] if row['address'] == fixture.pc)
        self.assertEqual(pc['name'], 'BP_DFMPlayerController_C')
        self.assertIsNone(pc['key'])
        self.assertEqual(pc['serial'], 0)
        self.assertEqual(result['class_cache_exports'], 2)
        self.assertEqual(result['replication_layout_exports'], 2)
        self.assertEqual(core.call_count, 2)
        self.assertTrue(all(struct.unpack('<iI', call.args[2])[1] != 0 for call in core.call_args_list))
        pc_export = next(row for row in result['driver_class_exports'] if row['class_address'] == fixture.pc)
        self.assertIn('missing_uninitialized_native_serial', str(pc_export))
        with self.assertRaisesRegex(ObjectMetadataError, 'no_native_weak_key'):
            weak_object_key(fixture.memory.read, fixture.base, fixture.pc)


class CollectTests(unittest.TestCase):
    def collect_with_fake_reader(self, fixture, *, core_effect=None, verify_effect=None):
        reader = SimpleNamespace(
            read_exact=fixture.memory.read, module_base=fixture.base,
            verify_identity=Mock(side_effect=verify_effect),
            find_module=Mock(return_value=fixture.base), close=Mock(),
        )
        with patch.object(export, 'validate_source', return_value=(Path('fake-client.exe'), 0x20000000)), \
             patch.object(export, 'Win32MetadataReader', return_value=reader), \
             patch.object(export, 'save') as save, \
             patch.object(export, 'export_existing_driver_class', side_effect=core_effect or fixture.cache_result):
            report = export.collect('fake-root', 'fake-output', pid=123, created_at=5000.0)
        reader.close.assert_called_once()
        save.assert_called_once_with('fake-output', report)
        return report

    def test_collected_metadata_does_not_claim_player_spawn_or_serializers(self):
        report = self.collect_with_fake_reader(Fixture())
        self.assertEqual(report['status'], 'metadata_export_complete')
        self.assertTrue(report['runtime_class_cache_recovered'])
        self.assertTrue(report['runtime_replication_layout_recovered'])
        self.assertFalse(report['property_serializer_schema_recovered'])
        self.assertFalse(report['player_spawn_verified'])
        self.assertFalse(report['playable_map_verified'])
        self.assertFalse(report['native_getter_invoked'])

    def test_collected_classes_without_driver_are_not_recovered(self):
        report = self.collect_with_fake_reader(Fixture(driver=False))
        self.assertEqual(report['status'], 'metadata_export_complete')
        self.assertFalse(report['runtime_class_cache_recovered'])
        self.assertFalse(report['runtime_replication_layout_recovered'])

    def test_malformed_field_shape_never_reports_partial_recovery(self):
        fixture = Fixture()
        def malformed(session, driver, key):
            result = fixture.cache_result(session, driver, key)
            del result['cache_nodes'][0]['fields'][0]['descriptor_representation']
            return result
        report = self.collect_with_fake_reader(fixture, core_effect=malformed)
        self.assertEqual(report['status'], 'metadata_export_failed')
        self.assertFalse(report['runtime_class_cache_recovered'])
        self.assertFalse(report['runtime_replication_layout_recovered'])
        self.assertNotIn('driver_class_exports', report)

    def test_partial_export_exception_never_reports_recovered(self):
        fixture = Fixture()
        calls = []
        def partial(session, driver, key):
            calls.append(key)
            if len(calls) == 2:
                raise ValueError('partial native metadata')
            return fixture.cache_result(session, driver, key)
        report = self.collect_with_fake_reader(fixture, core_effect=partial)
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertFalse(report['runtime_class_cache_recovered'])
        self.assertFalse(report['runtime_replication_layout_recovered'])
        self.assertNotIn('driver_class_exports', report)
        self.assertNotIn('class_cache_exports', report)

    def test_identity_changed_after_export_discards_all_results(self):
        report = self.collect_with_fake_reader(Fixture(), verify_effect=ValueError('stale PID'))
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertFalse(report['runtime_class_cache_recovered'])
        self.assertNotIn('driver_class_exports', report)

    def test_root_identity_refusal_keeps_bounded_diagnostic_context(self):
        error = ValueError('Selected metadata root identity changed after discovery')
        error.metadata_failure_context = {'phase': 'selected_root_identity_recheck',
            'address': 0x140020000, 'expected_object_index': 7, 'observed_object_index': 7,
            'expected_serial': 12, 'observed_serial': 15}
        report = self.collect_with_fake_reader(Fixture(), verify_effect=error)
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertEqual(report['failure_context'], error.metadata_failure_context)
        self.assertNotIn('driver_class_exports', report)

    def test_stale_pid_preflight_never_calls_export_or_reports_recovered(self):
        with patch.object(export, 'validate_source', return_value=(Path('fake-client.exe'), 0x20000000)), \
             patch.object(export, 'Win32MetadataReader', side_effect=ValueError('Client process identity changed')), \
             patch.object(export, 'export_metadata') as operation, \
             patch.object(export, 'save') as save:
            report = export.collect('fake-root', 'fake-output', pid=123, created_at=5000.0)
        operation.assert_not_called()
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertFalse(report['runtime_class_cache_recovered'])
        self.assertFalse(report['runtime_replication_layout_recovered'])
        save.assert_called_once_with('fake-output', report)


class BackendTests(unittest.TestCase):
    def test_readable_region_refuses_guard_noaccess_uncommitted_and_executeonly(self):
        for state, protect in ((0x1000, 1), (0x1000, 0x104), (0x2000, 4), (0x10000, 4), (0x1000, 0x10)):
            memory = SimpleNamespace(BaseAddress=0x20000000, RegionSize=4096,
                                     State=state, Type=0x20000, Protect=protect)
            with self.assertRaises(ValueError):
                export.readable_region(memory, 0x20000000, 4)
        good = SimpleNamespace(BaseAddress=0x20000000, RegionSize=4096,
                               State=0x1000, Type=0x1000000, Protect=4)
        self.assertEqual(export.readable_region(good, 0x20000FFE, 4), 2)

    def fake_backend(self, *, created=5000.0, partial=False, protect=4):
        events = []
        executable = Path('fake-client.exe').resolve()
        process = SimpleNamespace(create_time=lambda: events.append('identity') or created,
                                  exe=lambda: str(executable))
        api = SimpleNamespace(
            OpenProcess=Mock(side_effect=lambda *args: events.append('open') or 0x99),
            CloseHandle=Mock(return_value=True), GetProcessId=Mock(return_value=123),
            WaitForSingleObject=Mock(side_effect=lambda *args: events.append('alive') or 0x102),
        )
        def query(handle, address, output, size):
            events.append('query')
            memory = C.cast(output, C.POINTER(export.Memory)).contents
            memory.BaseAddress = address.value & ~0xFFF
            memory.RegionSize = 4096
            memory.State, memory.Protect, memory.Type = 0x1000, protect, 0x20000
            return C.sizeof(export.Memory)
        def rpm(handle, address, output, size, received):
            events.append('rpm')
            C.memmove(output, b'\xA5'*size, size)
            C.cast(received, C.POINTER(C.c_size_t)).contents.value = size-1 if partial else size
            return True
        api.VirtualQueryEx = Mock(side_effect=query)
        api.ReadProcessMemory = Mock(side_effect=rpm)
        patches = (patch.object(export, 'kernel', return_value=api),
                   patch.object(export.psutil, 'Process', return_value=process),
                   patch.object(export.Win32MetadataReader, 'find_module', return_value=0x140000000))
        return executable, api, events, patches

    def test_exact_readonly_rights_and_identity_precede_any_rpm(self):
        executable, api, events, patches = self.fake_backend()
        with patches[0], patches[1], patches[2]:
            reader = export.Win32MetadataReader(executable, 0x20000000, 123, 5000.0)
            self.assertEqual(reader.read_exact(0x20000000, 4), b'\xA5'*4)
            reader.close()
        api.OpenProcess.assert_called_once_with(0x100410, False, 123)
        self.assertLess(events.index('identity'), events.index('open'))
        self.assertLess(events.index('alive'), events.index('rpm'))
        self.assertLess(events.index('query'), events.index('rpm'))
        api.CloseHandle.assert_called_once_with(0x99)

    def test_stale_creation_time_rejected_before_openprocess(self):
        executable, api, events, patches = self.fake_backend(created=5001.0)
        with patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                export.Win32MetadataReader(executable, 0x20000000, 123, 5000.0)
        api.OpenProcess.assert_not_called()
        api.ReadProcessMemory.assert_not_called()

    def test_partial_rpm_and_guard_refused_handle_closes(self):
        for partial, protect, expected in ((True, 4, OSError), (False, 0x104, ValueError)):
            executable, api, events, patches = self.fake_backend(partial=partial, protect=protect)
            with patches[0], patches[1], patches[2]:
                reader = export.Win32MetadataReader(executable, 0x20000000, 123, 5000.0)
                try:
                    with self.assertRaises(expected):
                        reader.read_exact(0x20000000, 4)
                finally:
                    reader.close()
            api.CloseHandle.assert_called_once_with(0x99)
            if protect & 0x100:
                api.ReadProcessMemory.assert_not_called()


class ElevationTests(unittest.TestCase):
    def setUp(self):
        # Worker preflight failures are recorded to a file in production.
        self.record_patch = patch.object(export, 'save')
        self.record_patch.start()
        self.addCleanup(self.record_patch.stop)

    @staticmethod
    def split_windows_arguments(text):
        # Independent CRT-style quote/backslash parsing of the generated argv.
        # It never invokes a shell, CommandLineToArgvW, or any Windows API.
        arguments, at = [], 0
        while at < len(text):
            while at < len(text) and text[at] in ' \t':
                at += 1
            if at == len(text):
                break
            value, quoted = [], False
            while at < len(text) and (quoted or text[at] not in ' \t'):
                if text[at] == '\\':
                    begin = at
                    while at < len(text) and text[at] == '\\':
                        at += 1
                    count = at-begin
                    if at < len(text) and text[at] == '"':
                        value.extend('\\'*(count//2))
                        if count % 2:
                            value.append('"')
                        else:
                            quoted = not quoted
                        at += 1
                    else:
                        value.extend('\\'*count)
                elif text[at] == '"':
                    quoted = not quoted
                    at += 1
                else:
                    value.append(text[at])
                    at += 1
            arguments.append(''.join(value))
        return arguments

    @contextmanager
    def mocked_parent(self, *, success=True, handle=0x99, created=5000.125,
                      wrong_executable=False, outside_output=False, pid_error=None):
        args = SimpleNamespace(game_root=Path('mock game 目录'),
            output=(export.ROOT/'outside mock output' if outside_output
                    else export.ROOT/'work/mock output 目录'), pid=123, created_at=5000.125)
        executable = (args.game_root/'client with space.exe').resolve()
        process = SimpleNamespace(create_time=Mock(return_value=created),
            exe=Mock(return_value=str(executable.parent/'wrong.exe' if wrong_executable else executable)))
        pins = {'work/file with space.py': 'a'*64, 'work/另一个.py': 'b'*64}
        capture = {}
        def shell_execute(pointer):
            info = pointer._obj
            capture.update(verb=info.lpVerb, file=info.lpFile, parameters=info.lpParameters,
                           directory=info.lpDirectory, show=info.nShow, mask=info.fMask)
            info.hProcess = handle if success else None
            return success
        shell = Mock(side_effect=shell_execute)
        api = SimpleNamespace(GetProcessId=Mock(return_value=777, side_effect=pid_error),
                              CloseHandle=Mock(return_value=True))
        with ExitStack() as stack:
            stack.enter_context(patch.object(Path, 'mkdir'))
            stack.enter_context(patch.object(Path, 'write_text'))
            validate = stack.enter_context(patch.object(export, 'validate_source', return_value=(executable, 0x20000000)))
            identity = stack.enter_context(patch.object(export.psutil, 'Process', return_value=process))
            stack.enter_context(patch.object(export, 'source_pins', return_value=pins))
            stack.enter_context(patch.object(export, 'monitor_reader_exit', return_value={
                'status': 'metadata_reader_exited', 'exit_code': 0,
                'reader_result_status': 'metadata_export_complete'}))
            stack.enter_context(patch.object(export.C, 'WinDLL', return_value=SimpleNamespace(ShellExecuteExW=shell)))
            stack.enter_context(patch.object(export, 'kernel', return_value=api))
            stack.enter_context(patch.object(export.C, 'get_last_error', return_value=1223))
            save = stack.enter_context(patch.object(export, 'save'))
            stdout = stack.enter_context(redirect_stdout(io.StringIO()))
            yield SimpleNamespace(args=args, executable=executable, pins=pins, capture=capture,
                shell=shell, api=api, validate=validate, identity=identity, save=save, stdout=stdout)

    def test_parent_quotes_exact_paths_identity_and_source_pins_and_closes_helper_handle(self):
        with self.mocked_parent() as env:
            export.request_read_only_elevation(env.args)
        argv = self.split_windows_arguments(env.capture['parameters'])
        self.assertEqual(argv[:9], [str(Path(export.__file__).resolve()),
            '--game-root', str(env.args.game_root.resolve()), '--output', str(env.args.output.resolve()),
            '--pid', '123', '--created-at', '5000.125'])
        self.assertEqual(argv[9], '--elevated-source-pins')
        self.assertEqual(len(argv), 11)
        self.assertEqual(json.loads(argv[10]), env.pins)
        self.assertNotIn('--elevate', argv)
        self.assertEqual(env.capture['verb'], 'runas')
        self.assertEqual(env.capture['directory'], str(export.ROOT))
        self.assertEqual(env.capture['show'], 0)
        self.assertEqual(env.capture['mask'], 0x140)
        env.validate.assert_called_once_with(env.args.game_root)
        env.identity.assert_called_once_with(123)
        env.api.GetProcessId.assert_called_once_with(0x99)
        env.api.CloseHandle.assert_called_once_with(0x99)
        env.save.assert_not_called()

    def test_parent_stale_time_wrong_executable_and_outside_output_never_request_uac(self):
        for kwargs in ({'created': 5001.125}, {'wrong_executable': True}, {'outside_output': True}):
            with self.subTest(kwargs=kwargs), self.mocked_parent(**kwargs) as env:
                with self.assertRaises(ValueError):
                    export.request_read_only_elevation(env.args)
                env.shell.assert_not_called()
                env.api.GetProcessId.assert_not_called()
                env.api.CloseHandle.assert_not_called()
                env.save.assert_not_called()

    def test_parent_uac_cancel_reports_1223_without_claiming_authorization(self):
        with self.mocked_parent(success=False) as env:
            with self.assertRaises(OSError) as error:
                export.request_read_only_elevation(env.args)
            self.assertIn(1223, error.exception.args)
            report = env.save.call_args.args[1]
            self.assertEqual(report['status'], 'metadata_reader_uac_not_granted')
            self.assertEqual(report['windows_error'], 1223)
            self.assertFalse(report['process_memory_written'])
            self.assertFalse(report['game_launched'])
            self.assertFalse(report['playable_map_verified'])
            self.assertNotIn('metadata_reader_authorized', env.stdout.getvalue())
            env.api.GetProcessId.assert_not_called()
            env.api.CloseHandle.assert_not_called()

    def test_parent_helper_diagnostic_error_always_closes_returned_handle(self):
        with self.mocked_parent(pid_error=ValueError('helper identity unavailable')) as env:
            with self.assertRaisesRegex(ValueError, 'identity unavailable'):
                export.request_read_only_elevation(env.args)
            env.api.CloseHandle.assert_called_once_with(0x99)
            self.assertNotIn('metadata_reader_authorized', env.stdout.getvalue())

    def test_parent_api_initialization_failure_cannot_leave_untracked_helper_handle(self):
        with self.mocked_parent() as env, \
             patch.object(export, 'kernel', side_effect=OSError('metadata API unavailable')):
            with self.assertRaisesRegex(OSError, 'API unavailable'):
                export.request_read_only_elevation(env.args)
            # Resolve the cleanup API before asking Shell to start the worker.
            env.shell.assert_not_called()
            self.assertNotIn('metadata_reader_authorized', env.stdout.getvalue())

    def test_parent_null_handle_does_not_claim_verified_helper_identity(self):
        with self.mocked_parent(handle=None) as env:
            try:
                export.request_read_only_elevation(env.args)
            except (ValueError, OSError):
                pass  # Shell success may still have started the worker.
            self.assertNotIn('metadata_reader_authorized', env.stdout.getvalue())
            env.api.GetProcessId.assert_not_called()
            env.api.CloseHandle.assert_not_called()

    def test_source_pins_cover_exact_metadata_reader_dependency_files(self):
        expected = {
            'work/export_native_replication_metadata.py', 'work/native_metadata_objects.py',
            'work/native_metadata_names.py', 'work/native_metadata_paths.py',
            'work/native_replication_metadata_core.py',
            'outputs/df-local-server/dfserver/legacy_ds_class_net_cache.py',
        }
        actual = export.source_pins()
        self.assertEqual(set(actual), expected)
        for relative, digest in actual.items():
            self.assertEqual(digest, hashlib.sha256((export.ROOT/relative).read_bytes()).hexdigest())

    def worker_arguments(self, *, output=None, pins=None, extra=()):
        return [export.__file__, '--game-root', 'mock game 目录',
            '--output', str(output or export.ROOT/'work/mock worker output'),
            '--pid', '123', '--created-at', '5000.125',
            '--elevated-source-pins', pins or json.dumps({'fixed-source': 'a'*64}), *extra]

    def test_elevated_worker_exact_source_scope_identity_parameters_reach_collect(self):
        argv = self.worker_arguments()
        with patch.object(export.sys, 'argv', argv), \
             patch.object(export.C, 'windll', SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=Mock(return_value=True)))), \
             patch.object(export, 'source_pins', return_value={'fixed-source': 'a'*64}), \
             patch.object(export, 'collect', return_value={'status':'metadata_export_complete'}) as collect, \
             patch.object(export, 'request_read_only_elevation') as elevation, \
             redirect_stdout(io.StringIO()):
            export.main()
        collect.assert_called_once_with(Path('mock game 目录'), Path(argv[4]), pid=123, created_at=5000.125)
        elevation.assert_not_called()

    def test_elevated_worker_changed_pins_admin_or_output_scope_refuse_before_collect(self):
        for admin, output, pins in ((False, None, None),
                (True, None, json.dumps({'changed-source':'a'*64})),
                (True, export.ROOT/'outside worker output', None)):
            argv = self.worker_arguments(output=output, pins=pins)
            with self.subTest(admin=admin, output=output, pins=pins), \
                 patch.object(export.sys, 'argv', argv), \
                 patch.object(export.C, 'windll', SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=Mock(return_value=admin)))), \
                 patch.object(export, 'source_pins', return_value={'fixed-source': 'a'*64}), \
                 patch.object(export, 'collect') as collect, \
                 patch.object(export, 'request_read_only_elevation') as elevation, \
                 redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    export.main()
                self.assertEqual(error.exception.code, 2)
                collect.assert_not_called()
                elevation.assert_not_called()

    def test_elevated_worker_malformed_pins_refuses_without_collect_or_recursive_uac(self):
        with patch.object(export.sys, 'argv', self.worker_arguments(pins='{bad-json')), \
             patch.object(export.C, 'windll', SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=Mock(return_value=True)))), \
             patch.object(export, 'source_pins') as pins, \
             patch.object(export, 'collect') as collect, \
             patch.object(export, 'request_read_only_elevation') as elevation, \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                export.main()
            self.assertEqual(error.exception.code, 2)
            pins.assert_not_called()
            collect.assert_not_called()
            elevation.assert_not_called()

    def test_parent_and_worker_flags_are_mutually_exclusive(self):
        with patch.object(export.sys, 'argv', self.worker_arguments(extra=('--elevate',))), \
             patch.object(export, 'collect') as collect, \
             patch.object(export, 'request_read_only_elevation') as elevation, \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                export.main()
            self.assertEqual(error.exception.code, 2)
            collect.assert_not_called()
            elevation.assert_not_called()


if __name__ == '__main__':
    unittest.main()
