"""Independent bounded activation and typed weapon mesh observations, read only.

Actor fields and the activation byte have pinned native/capture sources. Mesh
asset and visibility offsets come from the current typed, rechecked reflection;
no historical component pointers or assumed mesh layouts are used.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import observe_owned_weapon_state as old
import observe_weapon_initialization_followup as followup
import observe_weapon_owner_current_metadata as current
import weapon_appearance_qualified_scope as appearance_scope
from observe_owned_gameplay_metadata import (BindingObservation, address, label_existing,
    object_path, owned_trial_identity, typed_declarations, write_exclusive_report)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, request_elevation)
from portable_native_code_cache import CodeCache

ROOT = old.ROOT
BASE = 'work/evidence/map-system-audit-20261018/'
CAPTURE = 'work/native-client-tests/1792376752204334900/owned-weapon-state.json'
CAPTURE_SHA = '6535bba737ac4d20ce3502586fba8b9f06a7c0863599690d666121ce88562207'
PINS = {
    BASE+'native-owned-weapon-dfm-constructor-v1.json':
        '736e79773c2d2a56ff2efcc045873ea117fc6bfd48c8d1680fd397459c665f7f',
    BASE+'native-owned-weapon-dfm-equip-position-vslot-v1.json':
        'b0e7b545e87b84edb8edd9af7e814603a537a4e6821bf490100bd5a0929a86ce',
    BASE+'native-owned-weapon-actual-activation-interface-targets-v1.json':
        '334be720041902bf468d245f66378bd4f5bd7b2f8dc7d7d817d8a04aedaefb91',
    BASE+'native-owned-weapon-activation-state-and-render-branch-v1.json':
        '5bdb26b61b60daba64841434568761d7b7144c8a1b11ce30062196a0d139d927',
    BASE+'native-owned-weapon-late-owner-rebind-hooks-v1.json':
        'b998ee11d2581fd849b826d2e54ec390ba272b9d83242c68e21beb48e24ba9cc',
    CAPTURE: CAPTURE_SHA,
}
ACTOR_FIELDS = {
    'WeaponMesh': ('GPWeaponBase', 0x370, 8),
    'WeaponMode': ('WeaponBase', 0xa9a, 1),
    'bHidden': ('Actor', 0x90, 1),
}
MESH_FIELDS = {
    'SkeletalMesh': ('SkinnedMeshComponent', 'object', 'SkeletalMesh'),
    'AttachParent': ('SceneComponent', 'object', 'SceneComponent'),
    'bVisible': ('SceneComponent', 'bool', None),
    'bHiddenInGame': ('SceneComponent', 'bool', None),
    'bOwnerNoSee': ('PrimitiveComponent', 'bool', None),
    'bOnlyOwnerSee': ('PrimitiveComponent', 'bool', None),
}


def _document(relative, expected):
    raw = (ROOT/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('The independent weapon mesh source changed: '+relative)
    return json.loads(raw)


def source_pins(game_root, profile_path):
    pins = current.source_pins(game_root, profile_path)
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600', old.MANIFEST_SHA256, game_root)
    documents = {path: _document(path, digest) for path, digest in PINS.items()}
    instructions = {}
    for document in documents.values():
        for function in document.get('functions', ()):
            first, amount = int(function['span_start'], 16), function['span_bytes']
            if type(amount) is not int or not 1 <= amount <= 65536:
                raise ValueError('The weapon mesh native function exceeds the fixed scope')
            code = b''.join(cache.read(at, min(8192, first+amount-at))
                for at in range(first, first+amount, 8192))
            if hashlib.sha256(code).hexdigest() != function['code_sha256']:
                raise ValueError('The weapon mesh cached native code changed')
            instructions.update({i['rva']: i['bytes'] for i in function['instructions']})
    for at, expected in (('0xc732f2f', '488d051a627b0a'),
            ('0xc732f3d', '48898388030000'), ('0xc7cca6f', 'e8dc9812f9'),
            ('0x58f63f7', '88970a070000'), ('0x5878ceb', '4438af920a0000')):
        if instructions.get(at) != expected:
            raise ValueError('The native activation byte or actual setter changed: '+at)
    table = documents[BASE+'native-owned-weapon-dfm-equip-position-vslot-v1.json']['vtables'][0]
    if (table['rva'] != '0x16ee9570' or
            next(r['target_rva'] for r in table['entries'] if r['slot'] == '0x1d0') != '0xc7cca00'):
        raise ValueError('The actual DFM activation interface target changed')
    pins = old.merge_source_pins(pins, PINS)
    pins = old.merge_source_pins(pins, appearance_scope.source_pins(game_root))
    pins['work/observe_weapon_mesh_followup.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return pins


def actor_field(record, name):
    if name not in ACTOR_FIELDS or record.get('class_path') not in (old.MODULAR_CLASS, old.EMPTY_HAND_CLASS):
        raise ValueError('The weapon mesh Actor field is outside the fixed scope')
    source = next(r for r in _document(CAPTURE, CAPTURE_SHA)['actual_manager_weapon_actors']
        if r['class_path'] == old.MODULAR_CLASS)
    def matches(row):
        return [dict(f, declaring_class=c['class_name']) for c in row['declarations']
            for f in c['fields'] if f['name'] == name]
    expected, actual = matches(source), matches(record)
    owner, offset, size = ACTOR_FIELDS[name]
    if (len(expected) != 1 or len(actual) != 1 or
            (expected[0]['declaring_class'], expected[0]['storage_offset'], expected[0]['element_bytes']) !=
                (owner, offset, size) or any(actual[0].get(k) != expected[0].get(k)
                    for k in (*old.FIELD_KEYS, 'declaring_class'))):
        raise ValueError('The current pinned weapon mesh Actor declaration changed: '+name)
    return actual[0]


def activation_state(pointer, *, base, facts):
    pointer = address(pointer)
    table = struct.unpack('<Q', facts.fact(pointer+0x388, 8))[0]
    if table != base+0x16ee9150:
        raise ValueError('The actual weapon interface differs from the qualified DFM constructor')
    target = struct.unpack('<Q', facts.fact(table+0x5f0, 8))[0]
    if target != base+0xc7cca00:
        raise ValueError('The current native activation setter target changed')
    raw = facts.fact(pointer+0xa92, 1)
    if raw[0] not in (0, 1):
        raise ValueError('The native activated byte is not bool')
    return dict(value=bool(raw[0]), native_member_offset=0xa92,
        actual_native_interface_observed=True, setter_rva='0xc7cca00 -> 0x58f6350',
        reflected_property=False, net_property=False, rendering_verified=False)


def mesh_field(record, name):
    if name not in MESH_FIELDS:
        raise ValueError('The requested mesh field is outside the fixed named scope')
    owner, kind, expected = MESH_FIELDS[name]
    matches = [dict(f, declaring_class=c['class_name']) for c in record['declarations']
        for f in c['fields'] if f['name'] == name and c['class_name'] == owner]
    if (len(matches) != 1 or matches[0].get('array_dimension') != 1 or
            matches[0].get('element_bytes') != (8 if kind == 'object' else 1) or
            type(matches[0].get('storage_offset')) is not int or
            not 0 <= matches[0]['storage_offset'] < 0x4000):
        raise ValueError('The current typed mesh declaration exceeds the fixed scope: '+name)
    selected = matches[0]
    if (kind == 'object' and (selected.get('native_property_type') != 'FObjectProperty' or
            selected.get('declared_native_class') != expected)):
        raise ValueError('The mesh reference is not the expected current native object property: '+name)
    return selected


def read_mesh(pointer, record, *, fields, facts, observation, metadata):
    if (record['identity'].get('is_cdo') is not False or
            'SkeletalMeshComponent' not in record['identity'].get('class_ancestry', ())):
        raise ValueError('The actual weapon mesh is not an existing skeletal component')
    result = dict(identity=record['identity'], class_path=record['class_path'], state={},
        field_source='current typed reflection, independently rechecked descriptors and native serializers',
        asset_geometry_read=False, rendering_verified=False)
    for name, (_, kind, expected) in MESH_FIELDS.items():
        def read(n=name, k=kind, e=expected):
            selected = mesh_field(record, n)
            current_field = fields.field(address(record['identity']['class_address']), selected)
            if k == 'bool':
                return fields.boolean(pointer, current_field)
            fields.hook(current_field['descriptor_address'], 0x10e8ed20)
            fields.hook(current_field['descriptor_address'], 0x10e95370, slot=0x88)
            value = observation.reference(pointer, selected, expected_base=e)
            if value['status'] == 'typed_existing_reference' and n == 'SkeletalMesh':
                value['asset_path'] = object_path(fields.session.read, fields.base,
                    address(value['identity']['address']))
            return value
        current.read_field(result, name, read)
    return result


def read_actor_mesh(record, *, pawn_record, level, fields, facts, observation, metadata):
    row = followup.read_actor(record, pawn_record=pawn_record, level=level,
        fields=fields, facts=facts, observation=observation)
    pointer, klass = (address(record['identity'][key]) for key in ('address', 'class_address'))
    if record['class_path'] == old.MODULAR_CLASS:
        current.read_field(row, 'activated_internal', lambda: activation_state(pointer, base=fields.base, facts=facts))
    for name in ('bHidden', 'WeaponMode'):
        def read(n=name):
            selected = fields.field(klass, actor_field(record, n))
            if n == 'bHidden':
                return fields.boolean(pointer, selected)
            return dict(field=selected, value=facts.fact(pointer+selected['storage_offset'], 1)[0],
                enum=fields.enum(selected, enum_property=True))
        current.read_field(row, name, read)
    def mesh():
        selected = actor_field(record, 'WeaponMesh')
        actual = fields.field(klass, selected)
        fields.hook(actual['descriptor_address'], 0x10e8ed20)
        fields.hook(actual['descriptor_address'], 0x10e95370, slot=0x88)
        link = observation.reference(pointer, selected, expected_base='SkeletalMeshComponent')
        if link['status'] != 'typed_existing_reference':
            return link
        if not link['outer_is_selected_owner'] or link['identity'].get('is_cdo') is not False:
            raise ValueError('The typed weapon mesh is outside its actual carried Actor')
        mesh_pointer = address(link['identity']['address'])
        mesh_record = metadata(mesh_pointer, 'SkeletalMeshComponent')
        if mesh_record['identity'] != link['identity']:
            raise ValueError('The current typed weapon mesh identity changed')
        return dict(reference=link, **read_mesh(mesh_pointer, mesh_record,
            fields=fields, facts=facts, observation=observation, metadata=metadata))
    current.read_field(row, 'WeaponMesh', mesh)
    current.read_field(row, 'WeaponAppearanceScope', lambda: appearance_scope.observe_actor(record,
        fields=fields, facts=facts, observation=observation, metadata=metadata))
    if record['class_path'] == old.MODULAR_CLASS:
        current.read_field(row, 'native_visibility_predicate', lambda: appearance_scope.visibility_predicate(record,
            pawn_record=pawn_record, fields=fields, facts=facts, observation=observation, metadata=metadata))
    return row


def observe(game_root, trial_report):
    from portable_map_bootstrap import load_plan
    trial_raw = Path(trial_report).read_bytes()
    trial = json.loads(trial_raw)
    pid, created = owned_trial_identity(trial, game_root)
    profile_path = old._profile_path(trial)
    pins = source_pins(game_root, profile_path)
    if load_plan(ROOT, profile_path).sources != trial['portable_map_bootstrap']['source_pins']:
        raise ValueError('The mesh reader differs from the exact active original plan')
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = old.SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True,
            first_player_state=True, _binding_identity_sink=sink, unpublished_batch_retry=True)
        callback = sink['callback']
        pcs = [p for p in roots['connection_binding_observations']['player_controllers']
            if p.get('status') == 'observed' and p.get('identity_and_fields_rechecked') is True and
                p.get('driver_primary_matches_original_connection') is True and p.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One current primary owned controller is required')
        pc = pcs[0]
        pc_at, driver, connection = (address(pc[k]) for k in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_at, object_identity=callback)
        if binding.get('status') != 'observed' or binding['pc_pawn_reference'].get('status') != 'typed_existing_reference':
            raise ValueError('The actual current primary Pawn is unavailable')
        pawn = address(binding['pc_pawn_reference']['address'])
        classes = {}
        def metadata(pointer, expected):
            identity = callback(pointer, expected)
            klass = address(identity['class_address'])
            if klass not in classes:
                classes[klass] = dict(class_identity=callback(klass, 'Class'),
                    class_path=object_path(session.read, base, klass),
                    declarations=typed_declarations(session, base, klass, callback),
                    existing_driver_class=label_existing(session, base, driver, klass))
            return dict(classes[klass], identity=identity)
        observation = BindingObservation(session, base, callback, metadata)
        facts = old.ReadFacts(session)
        fields = followup.FollowupFields(session, base, observation.identify, facts)
        pawn_record = metadata(pawn, 'Pawn')
        if not pawn_record['class_path'].endswith('.BP_DFMCharacter_C'):
            raise ValueError('The current Pawn is outside the qualified DFM profile')
        level = address(pawn_record['identity']['outer_address'])
        observation.identify(level, 'Level')
        link_field = current.select_field(pawn_record, 'pawn', 'WeaponManagerComponent')
        fields.field(address(pawn_record['identity']['class_address']), link_field)
        manager_link = observation.reference(pawn, link_field, expected_base='MultiWeaponManagerComponent')
        if manager_link['status'] != 'typed_existing_reference':
            raise ValueError('The actual Pawn manager reference is unavailable')
        manager = address(manager_link['identity']['address'])
        manager_record = metadata(manager, 'MultiWeaponManagerComponent')
        if (manager_record['identity'] != manager_link['identity'] or
                manager_record['identity']['name'] != 'WeaponManager' or
                address(manager_record['identity']['outer_address']) != pawn or
                manager_record['class_path'] != current.timeline_schema()['manager']['class_path']):
            raise ValueError('The current WeaponManager identity/Name/class/Outer differs')
        selected = current.select_field(manager_record, 'manager', 'WeaponList')
        actual = fields.field(address(manager_record['identity']['class_address']), selected)
        header, payload, _ = fields.array(manager, actual, 8, kind='object')
        entries = [None if not at else observation.identify(address(at), 'WeaponBase')
            for (at,) in struct.iter_unpack('<Q', payload)]
        pointers = [i['address'] for i in entries if i is not None]
        if len(pointers) > 3 or len(set(pointers)) != len(pointers):
            raise ValueError('The current weapon mesh scope exceeds EmptyHand plus two Modular Actors')
        actors = []
        counts = {}
        for index, identity in enumerate(entries):
            if identity is None:
                continue
            try:
                record = metadata(address(identity['address']), 'WeaponBase')
                if record['identity'] != identity:
                    raise ValueError('The manager-bound weapon metadata identity changed')
                counts[record['class_path']] = counts.get(record['class_path'], 0)+1
                if counts[record['class_path']] > (2 if record['class_path'] == old.MODULAR_CLASS else 1):
                    raise ValueError('The current manager weapon class count exceeds the fixed scope')
                row = read_actor_mesh(record, pawn_record=pawn_record, level=level,
                    fields=fields, facts=facts, observation=observation, metadata=metadata)
                row['manager_list_index'] = index
                actors.append(row)
            except ValueError as error:
                actors.append(dict(manager_list_index=index, identity=identity, status='refused', reason=str(error)))
        observation.finish()
        fields.finish()
        for klass, record in classes.items():
            if callback(klass, 'Class') != record['class_identity'] or typed_declarations(session, base, klass, callback) != record['declarations']:
                raise ValueError('The mesh selected declarations changed before publication')
        facts.finish()
        sink['recheck_roots']()
        if observe_first_player_state(session, base, driver_address=driver,
                connection_address=connection, pc_address=pc_at, object_identity=callback) != binding:
            raise ValueError('The mesh current PC/Pawn binding changed before publication')
        reader.verify_identity()
        if reader.find_module() != base or source_pins(game_root, profile_path) != pins:
            raise ValueError('The mesh pinned sources or module changed before publication')
        partial = any(r.get('status') != 'observed' for r in actors)
        partial |= any(r.get('state', {}).get('WeaponMesh', {}).get('status') == 'partial' for r in actors)
        partial |= any(r.get('state', {}).get('WeaponAppearanceScope', {}).get('status') == 'partial' for r in actors)
        return dict(kind='owned_weapon_mesh_readonly_followup_v1', status='partial' if partial else 'observed',
            pid=pid, created_at=created, observed_at_utc=datetime.now(timezone.utc).isoformat(),
            client_sha256=old.SHIPPING_SHA256, source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(), primary_connection_binding=pc,
            first_player_binding=binding, pawn_manager_reference=manager_link,
            manager_weapon_list=dict(**header, entries=entries), actual_manager_weapon_actors=actors,
            identities_and_fields_rechecked=True, selected_roots_rechecked=True, process_identity_rechecked=True,
            read_calls=session.calls, read_bytes=session.bytes_read, process_memory_written=False,
            native_methods_invoked=False, native_layouts_constructed=False, packets_sent=False, code_sampled=False,
            historical_process_pointers_reused=False, snapshot_atomic=False, native_weapon_gameplay_verified=False)
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work').resolve()):
        parser.error('Use an exclusive new project work output')
    trial = json.loads(args.trial_report.read_bytes())
    owned_trial_identity(trial, args.game_root)
    source_pins(args.game_root, old._profile_path(trial))
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(args.game_root.resolve()),
            '--trial-report', str(args.trial_report.resolve()), '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root, args.trial_report)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False, native_layouts_constructed=False,
                packets_sent=False, code_sampled=False, historical_process_pointers_reused=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
