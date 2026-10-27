"""Read current map defaults, interaction registration and existing metadata.

The local GameState is selected through the current primary PackageMap GUID6.
PlayerState is the current primary PC reference. No native method, layout
construction, launch, live-code sampling, process write or packet is used.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from observe_owned_gameplay_metadata import (ROOT, SHIPPING_SHA256, BindingObservation,
    address, owned_trial_identity, source_pins as gameplay_source_pins, typed_declarations,
    label_existing, write_exclusive_report)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, request_elevation, observed_virtual_method,
    recheck_virtual_method, object_name)
from native_guid_object_metadata import observe_connection_guid_mappings
from native_metadata_paths import object_path
from portable_native_code_cache import CodeCache
from portable_map_marker_probe import qualify_schema, map_marker_probe_source_pins
from runtime_declaration_supplement import exact_runtime_variant, source_pins as runtime_source_pins

SCHEMA = 'outputs/df-local-server/protocol/portable-map-spawn/map-marker-probe-schema.json'
EXTRA_PINS = {
    'work/evidence/interaction-array-link-flags-20261021.json':
        '5770977d014c9e2042163e5126475e15887f5ca2d9a22ce2c836fd5fff6ff0ae',
    'work/evidence/map-system-audit-20261018/native-economy-lobby-world-initialization-audit-v3.json':
        'da66b00592122f25c54bbf5a32b1dc1579afc325467f707d5009e58a5d4436a7',
    'work/evidence/map-system-audit-20261018/native-economy-interactor-game-state-declaration-v3.json':
        '39a11401c7f2e9708ae981fabdefd9ff0b08d8a48733f384fbd7a11b216b482c',
    'work/evidence/map-system-audit-20261018/native-economy-interact-system-typed-fields.json':
        'e4975a90293a0f0d72e80465fbcf064791424e5abbe30bc0d6f799df33201c76',
    'work/evidence/map-system-audit-20261018/native-map-observer-interact-class-getters.json':
        'cfdfda14e9d65334420c0ad35fa4a006e6dc091d20475ecd93fcd445b557bd1f',
    'work/evidence/map-system-audit-20261018/native-owning-weapon-bool-property-mask-v1.json':
        'f9b0cb0b567d06fe183a74f1ea549b4a54706d389661cd71cc407d85f93fb616',
    'work/evidence/map-system-audit-20261018/native-default-subobject-flags.json':
        '2a02b44011001d41dbe3d2f66a633066db9c227a9e467721062d44602e3ca9bc',
    'work/evidence/model-init-chain-20261018/native-map-marker-system-uht-properties.json':
        'b748eee900bb5729ac5dc9764f29ff2c8b8cb5e130c93d8ce841f515bf1b425a',
    'work/evidence/model-init-chain-20261018/native-map-marker-player-component-uht-properties.json':
        '45569cd65944be5bb057040ca805342d6bd5c3688d73f5404e3d5c8f62b306d1',
    'work/evidence/model-init-chain-20261018/native-map-marker-exit-initialization.json':
        '04d4f42362bdf1f9c9b850826497c93ffa5c8c92655e4834b3ade8066b3e02cd',
    'work/native-client-tests/1792297548603201600/owned-gameplay-metadata-recheck.json':
        'a53833a56b5e31978fa6dbc17d996f6fc2b3d6358c55186d3d0bd0bfeab26e11',
    'work/evidence/model-init-chain-20261018/native-map-marker-guid-lookup.json':
        '467917bcf328517641977770aa7351ae9a290b453166de5ca43b5bb4db7f6627',
    'work/evidence/model-init-chain-20261018/native-map-marker-guid-hash-lookup.json':
        'e704b5ccb521f7a2571b359b7ea881d5a410504f8dec43ab677fa3be6e27842d',
}
MANIFEST_SHA256 = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
ARRAY_SCOPES = {
    'InteractSystemComponent': (
        ('CachedInteractableComponents', 0x640, 0x20088100000028),
        ('MapDoorInfoArray', 0x590, 0x10000100000020)),
    'MapInfoSystemComponent': (
        ('HighValueBoxInfoArray', 0x430, 0x10000100000020),
        ('AZHighValueZoneInfoArray', 0xad0, 0x20080100000020)),
    'MapInfoComp': (('MapQuestLocationDataArray', 0x410, 0x10000000000020),),
}
BOOL_SCOPES = {
    'InteractSystemComponent': (
        ('bUseGridBasedManagement', 0x168, 0x10000000000005),
        ('bUseSceneQuery', 0x944, 0x10000000000001)),
    'MapInfoComp': (('bQuestInited', 0x3f8, 0x10000000000024),),
}


def source_pins(game_root):
    schema_raw = (ROOT/SCHEMA).read_bytes()
    schema = json.loads(schema_raw)
    pins = gameplay_source_pins()
    pins.update(runtime_source_pins())
    pins.update(map_marker_probe_source_pins(ROOT, schema))
    pins[SCHEMA] = hashlib.sha256(schema_raw).hexdigest()
    for relative, expected in EXTRA_PINS.items():
        digest = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
        if expected is not None and digest != expected:
            raise ValueError('Map marker observation source changed: '+relative)
        pins[relative] = digest
    # Requalify the unchanged bounded GUID reader against the available current
    # code cache, without inventing the absent historical private source ledger.
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600', MANIFEST_SHA256, game_root)
    for relative in EXTRA_PINS:
        if 'native-map-marker-guid-' not in relative:
            continue
        for function in json.loads((ROOT/relative).read_bytes())['functions']:
            first, amount = int(function['span_start'], 16), function['span_bytes']
            raw = cache.read(first, amount)
            if hashlib.sha256(raw).hexdigest() != function['code_sha256']:
                raise ValueError('Cached current native GUID lookup changed')
    relative = 'work/native-code-cache/1792259162856698600/manifest.json'
    pins[relative] = MANIFEST_SHA256
    for relative in ('work/observe_owned_map_marker_metadata.py', 'work/portable_map_marker_probe.py',
            'work/native_guid_object_metadata.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def selected_field(declarations, name, offset, *, expected_class=None, size=8):
    fields = [dict(f, declaring_class=d['class_name']) for d in declarations
        for f in d['fields'] if f['name'] == name]
    if (len(fields) != 1 or fields[0]['storage_offset'] != offset or
            fields[0]['element_bytes'] != size or fields[0]['array_dimension'] != 1 or
            expected_class is not None and (fields[0].get('native_property_type') != 'FObjectProperty' or
                fields[0].get('declared_native_class') != expected_class)):
        raise ValueError('Current scoped map declaration differs: '+name)
    return fields[0]


def qualify_component(identity, class_path, parent, row):
    if (identity['name'] != row['name'] or class_path != row['class_path'] or
            address(identity['outer_address']) != parent or 'ActorComponent' not in identity['class_ancestry']):
        raise ValueError('Current map default name, class or typed parent Outer differs')


def interaction_field(declarations, *, runtime_root_class_path=None):
    field = selected_field(declarations, 'InteractSystemComponent', 0x848,
        expected_class='InteractSystem')
    if (field.get('field_vtable_rva') != 0x15a86b80 or
            field.get('declared_native_class_path') != '/Script/DFMGameplay.InteractSystem' or
            (int(field.get('property_flags', '0'), 16) != 0x100000000a000d and
                not exact_runtime_variant('map_interact', runtime_root_class_path, field))):
        raise ValueError('Current non-Net InteractSystemComponent declaration differs')
    return field


def guarded_scope(record, name, read):
    """Retain a refused declaration; publication still requires all final rechecks."""
    try:
        return read()
    except ValueError as error:
        actual = [dict(field, declaring_class=declaration['class_name'])
            for declaration in record['declarations'] for field in declaration['fields']
            if field['name'] == name]
        return dict(status='refused', name=name, reason=str(error),
            actual_declarations=actual, instance_value_published=False)


def plunder_reference(observation, pointer, record):
    field = selected_field(record['declarations'], 'BlueprintPlunder', 0x1078)
    if field.get('native_property_type') != 'FObjectProperty' or not field.get('declared_native_class'):
        raise ValueError('Current GameState BlueprintPlunder is not a typed ordinary object reference')
    return observation.reference(pointer, field)


def allocated_exits(session, pointer, record, reads):
    field = selected_field(record['declarations'], 'AllocatedExits', 0xf18, size=16)
    if field['field_vtable_rva'] != 0x1ab5b730:
        raise ValueError('Current PlayerState AllocatedExits is not the observed FArrayProperty')
    raw = keep(session, pointer+0xf18, 16, reads)
    data, count, capacity = struct.unpack('<Qii', raw)
    if (not 0 <= count <= capacity <= 4096 or capacity and not data or
            data and (not 0x10000 <= data < 1 << 47 or data & 7)):
        raise ValueError('Current allocated exits array header is invalid')
    return dict(status='observed', field=field, count=count, capacity=capacity,
        data_pointer_nonnull=bool(data), elements_read=False)


def keep(session, at, size, reads):
    raw = session.stable(at, size)
    reads.append((at, raw))
    return raw


def recheck_fields(session, reads):
    if any(session.stable(at, len(raw)) != raw for at, raw in reads):
        raise ValueError('Current map marker selected fields changed')


def array_observation(session, pointer, declarations, name, offset, flags, reads, *,
        runtime_root_class_path=None):
    field = selected_field(declarations, name, offset, size=16)
    linked = False
    if (runtime_root_class_path == '/Script/DFMGameplay.InteractSystem' and
            field.get('declaring_class') == 'InteractSystem' and
            (name, offset, flags) in ARRAY_SCOPES['InteractSystemComponent'] and
            int(field.get('property_flags', '0'), 16) == flags | 0x200):
        path = 'work/evidence/interaction-array-link-flags-20261021.json'
        raw = (ROOT/path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != EXTRA_PINS[path]:
            raise ValueError('The original FArrayProperty link source changed')
        function, = json.loads(raw)['functions']
        instruction = next(i for i in function['instructions'] if i['rva'] == '0x10e5b268')
        if instruction['bytes'] != '48814e4800020000':
            raise ValueError('The original FArrayProperty link flag assignment changed')
        linked = True
    if (field.get('field_vtable_rva') != 0x1ab5b730 or
            (int(field.get('property_flags', '0'), 16) != flags and not linked and
                not exact_runtime_variant('map_array', runtime_root_class_path, field))):
        raise ValueError('Current scoped map array type or flags differ: ' + name)
    raw = keep(session, pointer + offset, 16, reads)
    data, count, capacity = struct.unpack('<Qii', raw)
    if (not 0 <= count <= capacity <= 4096 or capacity and not data or
            data and (not 0x10000 <= data < 1 << 47 or data & 7)):
        raise ValueError('Current scoped map array header exceeds its bound: ' + name)
    return dict(field=field, raw=raw.hex(), count=count, capacity=capacity,
        data_pointer_nonnull=bool(data), elements_read=False,
        network_serialization_inferred=False)


def decode_bool(storage, masks):
    """Apply current FBoolProperty ByteOffset/ByteMask/FieldMask, never guessed masks."""
    if type(storage) is not bytes or type(masks) is not bytes or len(masks) != 3:
        raise ValueError('Exact bounded boolean storage and property masks are required')
    offset, byte_mask, field_mask = masks
    if (offset >= len(storage) or not byte_mask or byte_mask & (byte_mask-1) or
            field_mask not in (byte_mask, 255)):
        raise ValueError('Current native boolean property masks are invalid')
    return dict(value=bool(storage[offset] & field_mask), raw=storage.hex(),
        byte_offset=offset, byte_mask=byte_mask, field_mask=field_mask)


def bool_descriptor(session, base, klass, field, identity, reads):
    """Locate the exact already declared FBoolProperty, without creating any metadata."""
    classes, nodes = set(), set()
    while klass:
        klass = address(klass)
        if klass in classes or len(classes) >= 32:
            raise ValueError('Current scoped bool class chain exceeds its bound')
        classes.add(klass)
        before = identity(klass, 'Class')
        parent, = struct.unpack('<Q', keep(session, klass + 0x48, 8, reads))
        if before['name'] == field['declaring_class']:
            node, = struct.unpack('<Q', keep(session, klass + 0x70, 8, reads))
            while node:
                node = address(node)
                if node in nodes or len(nodes) >= 1024:
                    raise ValueError('Current scoped bool field chain exceeds its bound')
                nodes.add(node)
                raw = keep(session, node, 0x60, reads)
                following, = struct.unpack_from('<Q', raw, 0x18)
                name = object_name(session.read, base, node, field_representation=0).display_text
                if name == field['name']:
                    table, owner = struct.unpack_from('<QQ', raw)
                    if (owner != klass or not raw[0x10] or table != base + 0x15a868a0 or
                            struct.unpack_from('<ii', raw, 0x3c) != (1, 1) or
                            struct.unpack_from('<i', raw, 0x54)[0] != field['storage_offset'] or
                            struct.unpack_from('<Q', raw, 0x48)[0] != int(field['property_flags'], 16)):
                        raise ValueError('Current scoped bool descriptor differs from its declaration')
                    if identity(klass, 'Class') != before:
                        raise ValueError('Current scoped bool declaring class changed')
                    return node
                node = following
            raise ValueError('Current scoped bool descriptor was not found')
        if identity(klass, 'Class') != before:
            raise ValueError('Current scoped bool class identity changed')
        klass = parent
    raise ValueError('Current scoped bool declaring class was not found')


def bool_observation(session, base, pointer, record, name, offset, flags, identity, reads):
    field = selected_field(record['declarations'], name, offset, size=1)
    hook = field.get('hooks', {}).get('0x90', {})
    if (field.get('field_vtable_rva') != 0x15a868a0 or
            (int(field.get('property_flags', '0'), 16) != flags and
                not exact_runtime_variant('map_bool', record.get('class_path'), field)) or
            hook.get('target_rva') != 0x10e8ebe0 or hook.get('identity_rechecked') is not True or
            hook.get('inside_pinned_image') is not True):
        raise ValueError('Current scoped bool type, flags or serializer differ: ' + name)
    descriptor = bool_descriptor(session, base, address(record['identity']['class_address']),
        field, identity, reads)
    masks = keep(session, descriptor + 0x8a, 3, reads)
    storage = keep(session, pointer + offset, 1, reads)
    return dict(field=field, descriptor_address=descriptor,
        masks_raw=masks.hex(), **decode_bool(storage, masks),
        network_serialization_inferred=False)


def object_metadata(session, pointer, before, observation, reads):
    flags, = struct.unpack('<I', keep(session, pointer + 0x18, 4, reads))
    outer_at = int(before['outer_address'], 16)
    outer = dict(status='null_reference')
    if outer_at:
        value = observation.identify(address(outer_at), 'Object')
        initialized = value['serial'] != 0
        outer = dict(status='typed_existing_reference' if initialized else
            'typed_reference_weak_identity_uninitialized', identity=value,
            weak_identity_initialized=initialized)
    return dict(typed_name=before['name'], object_flags=hex(flags), outer=outer,
        weak_identity_initialized=before['serial'] != 0,
        default_subobject_flag_present=bool(flags & 0x40000), name_stability_inferred=False)


class MapBindingObservation(BindingObservation):
    def reference(self, owner, field, *, expected_base='Object'):
        result = super().reference(owner, field, expected_base=expected_base)
        if 'property_flags' in field:
            result['property_flags'] = field['property_flags']
            result['is_net_property'] = bool(int(field['property_flags'], 16) & 0x20)
        if result['status'] == 'typed_existing_reference':
            initialized = result['identity']['serial'] != 0
            result['weak_identity_initialized'] = initialized
            if not initialized:
                result['status'] = 'typed_reference_weak_identity_uninitialized'
        return result


def scoped_state(session, base, pointer, record, scope, identity, reads):
    if record['object_metadata']['weak_identity_initialized'] is not True:
        return dict(status='not_read_uninitialized_native_weak_identity', arrays=[], booleans=[])
    def bounded_field(reader, name, offset, flags):
        try:
            return reader(name, offset, flags)
        except ValueError as error:
            actual = [field for declaration in record['declarations']
                      for field in declaration['fields'] if field['name'] == name]
            return dict(status='refused', name=name, reason=str(error),
                        actual_declarations=actual, instance_value_published=False)
    arrays = [bounded_field(lambda n, o, f: array_observation(session, pointer,
        record['declarations'], n, o, f, reads, runtime_root_class_path=record.get('class_path')),
        *field) for field in ARRAY_SCOPES.get(scope, ())]
    booleans = [bounded_field(lambda n, o, f: bool_observation(session, base, pointer,
        record, n, o, f, identity, reads), *field) for field in BOOL_SCOPES.get(scope, ())]
    status = 'partial' if any(row.get('status') == 'refused' for row in arrays+booleans) else 'observed'
    return dict(status=status, arrays=arrays, booleans=booleans,
        gameplay_initialization_inferred=False)


def observe(game_root, trial_report):
    trial_raw = Path(trial_report).read_bytes()
    pid, created = owned_trial_identity(json.loads(trial_raw), game_root)
    pins = source_pins(game_root)
    schema = json.loads((ROOT/SCHEMA).read_bytes())
    qualify_schema(schema)
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True, first_player_state=True,
            _binding_identity_sink=sink, unpublished_batch_retry=True)
        identity = sink['callback']
        pcs = [p for p in roots['connection_binding_observations']['player_controllers']
            if p.get('status') == 'observed' and p.get('identity_and_fields_rechecked') is True and
            p.get('driver_primary_matches_original_connection') is True and p.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One current primary owned controller is required')
        pc = pcs[0]
        pc_at, driver, connection = (address(pc[k]) for k in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_at, object_identity=identity)
        if binding.get('status') != 'observed' or binding['pc_player_state_reference'].get('status') != 'typed_existing_reference':
            raise ValueError('The current primary PlayerState reference is unavailable')
        ps = address(binding['pc_player_state_reference']['address'])
        bound_identities = [(p, cls, identity(p, cls)) for p, cls in
            ((pc_at, 'PlayerController'), (driver, 'NetDriver'), (connection, 'NetConnection'), (ps, 'PlayerState'))]

        def recheck_binding():
            sink['recheck_roots']()
            if any(identity(p, cls) != before for p, cls, before in bound_identities):
                raise ValueError('Current owned map binding identity changed')
            now = observe_first_player_state(session, base, driver_address=driver,
                connection_address=connection, pc_address=pc_at, object_identity=identity)
            if now != binding:
                raise ValueError('Current owned PlayerState binding changed')

        mapping = observe_connection_guid_mappings(session, base, driver_address=driver,
            connection_address=connection, recheck_binding=recheck_binding)
        gs_row, = [r for r in mapping['mappings'] if r['guid'] == 6]
        if gs_row['status'] != 'existing_object_observed':
            raise ValueError('Current local GameState allocation GUID6 is not mapped')
        gs = address(gs_row['object_address'])
        gs_identity = identity(gs, 'GameStateBase')
        if gs_identity['class_ancestry'][0] != 'BP_GameState_PVPVE_C' or 'GameState_SOL' not in gs_identity['class_ancestry']:
            raise ValueError('Current local GameState class differs from the cooked probe parent')
        classes, hooks, fields_read = {}, [], []

        def metadata(pointer, expected):
            before = observation.identify(pointer, expected)
            klass = address(before['class_address'])
            if klass not in classes:
                existing = label_existing(session, base, driver, klass)
                for command in existing.get('layout', {}).get('commands', []):
                    descriptor = command['descriptor_address']
                    if not descriptor:
                        continue
                    raw = session.stable(descriptor, 0x60)
                    fields_read.append((descriptor, raw))
                    command['current_property_declaration'] = dict(
                        array_dimension=struct.unpack_from('<i', raw, 0x3c)[0],
                        element_bytes=struct.unpack_from('<i', raw, 0x40)[0],
                        storage_offset=struct.unpack_from('<i', raw, 0x54)[0],
                        property_flags=hex(struct.unpack_from('<Q', raw, 0x48)[0]))
                    for slot, key in ((0x90, 'property_serializer_hook'), (0x88, 'property_scalar_leaf_hook')):
                        command[key] = observed_virtual_method(session, base, descriptor, slot)
                        hooks.append((descriptor, command[key]))
                classes[klass] = dict(class_identity=identity(klass, 'Class'),
                    class_path=object_path(session.read, base, klass),
                    declarations=typed_declarations(session, base, klass, identity), existing_driver_class=existing)
            return dict(classes[klass], identity=before,
                object_metadata=object_metadata(session, pointer, before, observation, fields_read))

        observation = MapBindingObservation(session, base, identity, metadata)
        parents = {'game_state': gs, 'player_state': ps}
        objects, references = [], []
        for row in schema['components']:
            parent = parents[row['parent']]
            parent_kind = 'GameStateBase' if row['parent'] == 'game_state' else 'PlayerState'
            parent_record = metadata(parent, parent_kind)
            if parent_record['class_path'] != row['parent_class_path']:
                raise ValueError('Current parent class path differs from the cooked source')
            field = selected_field(parent_record['declarations'], row['field'],
                0x858 if row['parent'] == 'game_state' else 0xb30,
                expected_class='MapInfoSystem' if row['parent'] == 'game_state' else 'MapInfoComponent')
            link = observation.reference(parent, field, expected_base='ActorComponent')
            references.append(dict(parent=row['parent'], **link))
            objects.append(dict(**parent_record, scope=row['parent']))
            if link['status'] not in ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized'):
                continue
            component = address(link['identity']['address'])
            record = metadata(component, 'ActorComponent')
            qualify_component(record['identity'], record['class_path'], parent, row)
            state = scoped_state(session, base, component, record, row['field'], identity, fields_read)
            if link['status'] == 'typed_reference_weak_identity_uninitialized':
                objects.append(dict(**record, scope=row['field'], scoped_map_state=state,
                    actual_stable_name=row['name'], name_stable_native_method_invoked=False))
                continue
            creation = selected_field(record['declarations'], 'CreationMethod', 0xce, size=1)
            creation_raw = session.stable(component+0xce, 1)
            flags = session.stable(component+0x18, 4)
            fields_read.extend(((component+0xce, creation_raw), (component+0x18, flags)))
            objects.append(dict(**record, scope=row['field'], actual_stable_name=row['name'],
                scoped_map_state=state,
                outer_matches_typed_parent=True, object_flags=hex(struct.unpack('<I', flags)[0]),
                default_subobject_flag_present=bool(struct.unpack('<I', flags)[0] & 0x40000),
                creation_method=dict(field=creation, value=creation_raw[0], native_value_is_zero=creation_raw == b'\0'),
                name_stable_native_method_invoked=False))
        gs_record = metadata(gs, 'GameStateBase')
        ps_record = metadata(ps, 'PlayerState')
        interact = guarded_scope(gs_record, 'InteractSystemComponent', lambda:
            observation.reference(gs, interaction_field(gs_record['declarations'],
                runtime_root_class_path=gs_record['class_path']),
                expected_base='ActorComponent'))
        if interact['status'] in ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized'):
            component = address(interact['identity']['address'])
            record = metadata(component, 'ActorComponent')
            state = scoped_state(session, base, component, record, 'InteractSystemComponent', identity, fields_read)
            objects.append(dict(**record, scope='InteractSystemComponent', scoped_map_state=state,
                fixed_default_name_assumed=False))
        plunder = guarded_scope(gs_record, 'BlueprintPlunder', lambda:
            plunder_reference(observation, gs, gs_record))
        allocated = guarded_scope(ps_record, 'AllocatedExits', lambda:
            allocated_exits(session, ps, ps_record, fields_read))
        observation.finish()
        for descriptor, hook in hooks:
            recheck_virtual_method(session, base, descriptor, hook)
        for klass, record in classes.items():
            if (identity(klass, 'Class') != record['class_identity'] or
                    typed_declarations(session, base, klass, identity) != record['declarations']):
                raise ValueError('Current map marker class declarations changed')
        recheck_fields(session, fields_read)
        recheck_binding()
        repeated = observe_connection_guid_mappings(session, base, driver_address=driver,
            connection_address=connection, recheck_binding=recheck_binding)
        if repeated['mappings'] != mapping['mappings'] or identity(gs, 'GameStateBase') != gs_identity:
            raise ValueError('Current GameState PackageMap association changed')
        reader.verify_identity()
        if reader.find_module() != base or source_pins(game_root) != pins:
            raise ValueError('Map marker helper source or module changed')
        recheck_fields(session, fields_read)
        observation.finish()
        partial = (any(row.get('status') == 'refused' for row in (interact, plunder, allocated)) or
            any(row.get('scoped_map_state', {}).get('status') == 'partial' for row in objects))
        return dict(kind='owned_map_marker_existing_metadata_observation', status='partial' if partial else 'observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc, first_player_binding=binding, game_state_guid_mapping=gs_row,
            default_component_references=references, objects=objects, blueprint_plunder_reference=plunder,
            interact_system_reference=interact,
            root_metadata=dict(game_state=gs_record, player_state=ps_record),
            allocated_exits=allocated,
            read_calls=session.calls, read_bytes=session.bytes_read, identities_and_fields_rechecked=True,
            selected_roots_rechecked=True, process_identity_rechecked=True, process_memory_written=False,
            native_methods_invoked=False, native_layouts_constructed=False, packets_sent=False,
            code_sampled=False, historical_process_pointers_reused=False, snapshot_atomic=False,
            map_marker_initialization_verified=False)
    finally:
        reader.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    opts = parser.parse_args()
    output = opts.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work').resolve()):
        parser.error('Use an exclusive new project work output')
    owned_trial_identity(json.loads(opts.trial_report.read_bytes()), opts.game_root)
    source_pins(opts.game_root)
    if opts.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(opts.game_root.resolve()),
            '--trial-report', str(opts.trial_report.resolve()), '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(opts.game_root, opts.trial_report)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False, native_layouts_constructed=False,
                packets_sent=False, code_sampled=False, historical_process_pointers_reused=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))
