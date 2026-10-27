"""Independent bounded current-weapon/context/timeline observation, read only."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import observe_weapon_initialization_followup as followup
import observe_owned_weapon_state as old
from observe_owned_gameplay_metadata import (BindingObservation, address, label_existing,
    object_path, owned_trial_identity, typed_declarations, write_exclusive_report)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, request_elevation)
from portable_native_code_cache import CodeCache
from weapon_switch_timeline_codec import schema_binding as timeline_schema, source_pins as timeline_pins

ROOT = old.ROOT
PAWN_CAPTURE = 'work/native-client-tests/1792328560808149500/owned-gameplay-metadata.json'
PAWN_CAPTURE_SHA = '18fcdea26eba57403bc94e712e07906aef38e5a641e8a140012d2d4504233a31'
MANAGER_CAPTURE = 'work/native-client-tests/1792343957590810500/owned-weapon-state.json'
MANAGER_CAPTURE_SHA = 'e9a923c075c5a462b7dec9a38bc4fd2fc233c519a7b3dacda89e8809233aaf63'
FOLLOWUP_SHA = 'a975bba530e40c0fe4c787109a27cfc0207eb09a72e34c64607f7034de2478b7'
SCOPE = {
    'pawn': {'WeaponManagerComponent': ('DFMPlayerCharacter', 0x3910, 8),
        'CacheCurWeapon': ('GPCharacterBase', 0x1788, 8),
        'bCurrentWeaponDirty': ('GPCharacterBase', 0x1785, 1)},
    'manager': {'WeaponList': ('WeaponManagerComponent', 0x198, 16),
        'RuntimeContext': ('WeaponManagerComponent', 0x1e8, 96),
        'TimeLineRepData': ('WeaponManagerComponent', 0x360, 32)},
}


def read_field(row, name, operation):
    followup.read_field(row, name, operation)
    result = row.get('state', {}).get(name)
    if isinstance(result, dict) and result.get('status') not in (None, 'observed',
            'typed_existing_reference', 'null_reference'):
        row.setdefault('field_errors', []).append(dict(field=name,
            reason=result.get('reason', 'The nested owner-current field was refused'),
            error_type='NestedFieldRefusal'))
        row['status'] = 'partial'


def source_pins(game_root, profile_path):
    pins = old.merge_source_pins(followup.source_pins(game_root, profile_path), timeline_pins())
    extra = {PAWN_CAPTURE: PAWN_CAPTURE_SHA, MANAGER_CAPTURE: MANAGER_CAPTURE_SHA,
        'work/observe_weapon_initialization_followup.py': FOLLOWUP_SHA}
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600', old.MANIFEST_SHA256, game_root)
    for relative, expected in old.merge_source_pins(extra, timeline_schema()['sources']).items():
        raw = (ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('The bounded owner-current source changed: ' + relative)
        pins = old.merge_source_pins(pins, {relative: expected})
        if relative.endswith('.json'):
            for function in json.loads(raw).get('functions', []):
                first, amount = int(function['span_start'], 16), function['span_bytes']
                if type(amount) is not int or not 1 <= amount <= 65536:
                    raise ValueError('The owner-current native source exceeds its fixed function bound')
                code = b''.join(cache.read(at, min(8192, first+amount-at))
                    for at in range(first, first+amount, 8192))
                if hashlib.sha256(code).hexdigest() != function['code_sha256']:
                    raise ValueError('The bounded owner-current cached native code changed')
    pins['work/observe_weapon_owner_current_metadata.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return pins


def select_field(record, scope, name):
    if scope not in SCOPE or name not in SCOPE[scope]:
        raise ValueError('The requested owner-current field is outside the fixed scope')
    relative, digest = ((PAWN_CAPTURE, PAWN_CAPTURE_SHA) if scope == 'pawn' else
                        (MANAGER_CAPTURE, MANAGER_CAPTURE_SHA))
    raw = (ROOT/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('The owner-current declaration source changed')
    source = next(o for o in json.loads(raw)['objects'] if o['scope'] == scope)
    declared_class, offset, size = SCOPE[scope][name]
    def matches(obj):
        return [dict(f, declaring_class=c['class_name']) for c in obj['declarations']
                for f in c['fields'] if f['name'] == name]
    expected, actual = matches(source), matches(record)
    if (record['class_path'] != source['class_path'] or len(expected) != 1 or len(actual) != 1 or
            (expected[0]['declaring_class'], expected[0]['storage_offset'], expected[0]['element_bytes']) !=
                (declared_class, offset, size) or any(actual[0].get(k) != expected[0].get(k)
                for k in (*old.FIELD_KEYS, 'declaring_class'))):
        raise ValueError('The current source-qualified owner field changed: ' + name)
    for slot in ('0x88', '0x90'):
        before, now = expected[0].get('hooks', {}).get(slot), actual[0].get('hooks', {}).get(slot)
        if (before is None or now is None or any(now.get(key) != before.get(key)
                for key in ('slot', 'vtable_rva', 'target_rva', 'target_module_sha256')) or
                now.get('inside_pinned_image') is not True or now.get('identity_rechecked') is not True):
            raise ValueError('The current source-qualified owner method changed: ' + name)
    return actual[0]


def qualified_weapon_reference(instance, field, *, level, observation, metadata, manager_entries):
    result = observation.reference(instance, field, expected_base='WeaponBase')
    if result['status'] != 'typed_existing_reference':
        return result
    identity = result['identity']
    if identity.get('is_cdo') is not False or address(identity['outer_address']) != level:
        return dict(result, status='refused', reason='The typed weapon reference is outside the current Pawn Level')
    record = metadata(address(identity['address']), 'WeaponBase')
    if record['identity'] != identity or record['class_path'] not in (old.EMPTY_HAND_CLASS, old.MODULAR_CLASS):
        return dict(result, status='refused', reason='The typed weapon reference has an unqualified class or changed identity')
    if record['class_path'] == old.EMPTY_HAND_CLASS:
        old.qualify_weapon_actor(identity, record['class_path'], level)
    else:
        schema, _ = old.modular_actor_source()
        if (record['class_path'] != schema['actor']['class_path'] or
                not identity.get('name', '').startswith('BP_WeaponModular_C_')):
            raise ValueError('The current weapon is outside the qualified Modular class/CDO source')
    member = None if manager_entries is None else identity['address'] in {
        i['address'] for i in manager_entries if i is not None}
    return dict(result, class_path=record['class_path'], in_actual_manager_weapon_list=member,
                actor_values_or_interface_methods_read=False)


def _numeric(fields, field, *, floating=False):
    expected_table = 0x15a86700 if floating else 0x15a863c0
    if field['field_vtable_rva'] != expected_table or field['element_bytes'] != 4:
        raise ValueError('The current timeline scalar type differs: ' + field['name'])
    fields.hook(field['descriptor_address'], 0x10e5ce20)
    fields.hook(field['descriptor_address'], 0x286bf70, slot=0x88)


def _array_inner(fields, facts, field, stride, *, expected_struct=None):
    if field['field_vtable_rva'] != 0x1ab5b730 or field['element_bytes'] != 16:
        raise ValueError('The fixed owner-current array type changed: ' + field['name'])
    inner = address(struct.unpack('<Q', facts.fact(field['descriptor_address']+0x90, 8))[0])
    raw = facts.fact(inner, 0x60)
    if struct.unpack_from('<ii', raw, 0x3c) != (1, stride) or struct.unpack_from('<i', raw, 0x54)[0] != 0:
        raise ValueError('The fixed owner-current array element extent changed')
    if expected_struct is not None:
        return fields.struct_type(dict(descriptor_address=inner), expected_struct)
    return inner


def read_timeline(pointer, record, *, fields, facts):
    selected = select_field(record, 'manager', 'TimeLineRepData')
    current = fields.field(address(record['identity']['class_address']), selected)
    kind = fields.struct_type(current, 'SwitchWeaponTimeLineRepData')
    data_field = fields.nested(kind, 'Data', 0, 16)
    frame_type = _array_inner(fields, facts, data_field, 56, expected_struct='SwitchWeaponFrame')
    scalar_fields = {}
    for name, offset in (('LocalFrameNo', 8), ('RemoteFrameNo', 12), ('DepFrameNo', 16), ('WorldTime', 32)):
        field = fields.nested(frame_type, name, offset, 4)
        _numeric(fields, field, floating=name == 'WorldTime')
        scalar_fields[name] = field
    for name, offset in (('LastWeaponIdentity', 40), ('PendingWeaponIdentity', 44)):
        identity = fields.struct_type(fields.nested(frame_type, name, offset, 4), 'WeaponIdentity')
        fields.uint32(fields.nested(identity, 'UniqueId', 0, 4))
    enums = {}
    for name, offset, expected in (('SwitchType', 48, 'EWeaponSwitchType'),
            ('Operation', 49, 'ESwitchWeaponOperation'), ('SwitchWeaponContext', 50, 'ESwitchWeaponContext')):
        enums[name] = fields.enum(fields.nested(frame_type, name, offset, 1),
            enum_property=True, expected_name=expected)
    for name, offset in (('Front', 16), ('Rear', 20), ('MaxSize', 24)):
        _numeric(fields, fields.nested(kind, name, offset, 4))
    storage = pointer + selected['storage_offset']
    header = facts.fact(storage, 16)
    data, count, capacity = struct.unpack('<Qii', header)
    front, rear, maximum = struct.unpack('<iii', facts.fact(storage+16, 12))
    if (not 0 <= count <= capacity <= 128 or not 0 <= maximum <= 127 or
            not 0 <= front <= maximum or not 0 <= rear <= maximum or capacity and not data or
            data and (not 0x10000 <= data < 1 << 47 or data & 7 or data+count*56 >= 1 << 47)):
        raise ValueError('The current native timeline ring exceeds the fixed read scope')
    indices = [(front+1+i) % (maximum+1) for i in range((rear-front) % (maximum+1))]
    if any(i >= count for i in indices):
        raise ValueError('The native timeline ring refers past its actual Data array')
    payload = facts.fact(data, count*56) if count else b''
    frames = []
    for index in range(count):
        raw = payload[index*56:(index+1)*56]
        local, remote, dependency = struct.unpack_from('<iii', raw, 8)
        last, pending = struct.unpack_from('<II', raw, 40)
        frames.append(dict(index=index, LocalFrameNo=local, RemoteFrameNo=remote,
            DepFrameNo=dependency, WorldTime=struct.unpack_from('<f', raw, 32)[0],
            LastWeaponIdentity=last, PendingWeaponIdentity=pending,
            SwitchType=raw[48], Operation=raw[49], SwitchWeaponContext=raw[50]))
    latest = frames[indices[-1]] if indices else None
    return dict(field=selected, header_raw_hex=header.hex(), count=count, capacity=capacity,
        ring=dict(front=front, rear=rear, max_size=maximum), frames=frames, active_indices=indices,
        latest_frame=latest, enums=enums, current_local_prediction_timeline_read=False,
        latest_frame_native_import_numbers=None if latest is None else dict(
            local_frame_no=latest['RemoteFrameNo'], remote_frame_no=latest['LocalFrameNo']))


def read_runtime_context(pointer, record, *, fields, facts, observation, metadata, level, manager_entries):
    selected = select_field(record, 'manager', 'RuntimeContext')
    current = fields.field(address(record['identity']['class_address']), selected)
    kind = fields.struct_type(current, 'SwitchWeaponContext')
    storage = pointer + selected['storage_offset']
    result = dict(field=selected, state={})
    for name, offset in (('CurrentActiveWeapon', 48), ('PendingActiveWeapon', 64)):
        def read_reference(n=name, at=offset):
            field = fields.nested(kind, n, at, 8)
            if field['field_vtable_rva'] != 0x15a86b80:
                raise ValueError('The runtime weapon reference is not the actual FObjectProperty')
            fields.hook(field['descriptor_address'], 0x10e8ed20)
            declared = address(struct.unpack('<Q', facts.fact(field['descriptor_address']+0x90, 8))[0])
            if observation.identify(declared, 'Class')['name'] != 'WeaponBase':
                raise ValueError('The runtime weapon reference target class changed')
            typed = dict(field, native_property_type='FObjectProperty', declared_native_class='WeaponBase')
            return qualified_weapon_reference(storage, typed, level=level, observation=observation,
                metadata=metadata, manager_entries=manager_entries)
        read_field(result, name, read_reference)
    def all_weapons_header():
        field = fields.nested(kind, 'AllWeapons', 0, 16)
        _array_inner(fields, facts, field, 16)
        header = facts.fact(storage, 16)
        data, count, capacity = struct.unpack('<Qii', header)
        if (not 0 <= count <= capacity <= 32 or capacity and not data or
                data and (not 0x10000 <= data < 1 << 47 or data & 7)):
            raise ValueError('The current AllWeapons interface array exceeds its fixed header scope')
        return dict(count=count, capacity=capacity, element_bytes=16, header_raw_hex=header.hex(),
                    interface_payload_read=False, interface_methods_invoked=False)
    read_field(result, 'AllWeapons', all_weapons_header)
    return result


def observe(game_root, trial_report):
    from portable_map_bootstrap import load_plan
    trial_raw = Path(trial_report).read_bytes()
    trial = json.loads(trial_raw)
    pid, created = owned_trial_identity(trial, game_root)
    profile_path = old._profile_path(trial)
    pins = source_pins(game_root, profile_path)
    if load_plan(ROOT, profile_path).sources != trial['portable_map_bootstrap']['source_pins']:
        raise ValueError('The owner-current reader differs from the exact active original plan')
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
        if observation.identify(pawn, 'Pawn') != pawn_record['identity']:
            raise ValueError('The current Pawn metadata identity changed')
        level = address(pawn_record['identity']['outer_address'])
        observation.identify(level, 'Level')
        pawn_scope = dict(scope='pawn_weapon_cache', state={})
        manager_scope = dict(scope='manager_owner_current', state={})
        try:
            link_field = select_field(pawn_record, 'pawn', 'WeaponManagerComponent')
            fields.field(address(pawn_record['identity']['class_address']), link_field)
            link = observation.reference(pawn, link_field, expected_base='MultiWeaponManagerComponent')
        except ValueError as error:
            link = dict(status='refused', reason=str(error), field_name='WeaponManagerComponent')
        manager_entries = None
        if link['status'] == 'typed_existing_reference':
            manager = address(link['identity']['address'])
            record = metadata(manager, 'MultiWeaponManagerComponent')
            if (record['identity'] != link['identity'] or record['identity']['name'] != 'WeaponManager' or
                    address(record['identity']['outer_address']) != pawn or
                    record['class_path'] != timeline_schema()['manager']['class_path']):
                link = dict(link, status='refused', reason='The current manager identity/Name/class/Outer differs')
                manager_scope.update(status='partial', manager_reference=link)
                record = None
        else:
            record = None
        if record is not None:
            manager_scope.update(record)
            def weapon_list():
                selected = select_field(record, 'manager', 'WeaponList')
                current = fields.field(address(record['identity']['class_address']), selected)
                header, payload, _ = fields.array(manager, current, 8, kind='object')
                entries = [None if not at else observation.identify(address(at), 'WeaponBase')
                    for (at,) in struct.iter_unpack('<Q', payload)]
                pointers = [i['address'] for i in entries if i is not None]
                if len(pointers) > 3 or len(set(pointers)) != len(pointers):
                    raise ValueError('The current manager weapon scope exceeds EmptyHand plus two Modular Actors')
                return dict(**header, entries=entries)
            read_field(manager_scope, 'WeaponList', weapon_list)
            manager_entries = manager_scope['state'].get('WeaponList', {}).get('entries')
            read_field(manager_scope, 'RuntimeContext', lambda: read_runtime_context(manager, record,
                fields=fields, facts=facts, observation=observation, metadata=metadata,
                level=level, manager_entries=manager_entries))
            read_field(manager_scope, 'TimeLineRepData', lambda: read_timeline(manager, record, fields=fields, facts=facts))
        else:
            manager_scope.update(status='partial', manager_reference=link)
        def cached():
            selected = select_field(pawn_record, 'pawn', 'CacheCurWeapon')
            current = fields.field(address(pawn_record['identity']['class_address']), selected)
            fields.hook(current['descriptor_address'], 0x10e8ed20)
            return qualified_weapon_reference(pawn, selected, level=level, observation=observation,
                metadata=metadata, manager_entries=manager_entries)
        read_field(pawn_scope, 'CacheCurWeapon', cached)
        def dirty():
            selected = select_field(pawn_record, 'pawn', 'bCurrentWeaponDirty')
            current = fields.field(address(pawn_record['identity']['class_address']), selected)
            return fields.boolean(pawn, current)
        read_field(pawn_scope, 'bCurrentWeaponDirty', dirty)
        observation.finish()
        fields.finish()
        for klass, record in classes.items():
            if callback(klass, 'Class') != record['class_identity'] or typed_declarations(session, base, klass, callback) != record['declarations']:
                raise ValueError('The owner-current selected declarations changed before publication')
        facts.finish()
        sink['recheck_roots']()
        if observe_first_player_state(session, base, driver_address=driver,
                connection_address=connection, pc_address=pc_at, object_identity=callback) != binding:
            raise ValueError('The owner-current PC/Pawn binding changed before publication')
        reader.verify_identity()
        if reader.find_module() != base or source_pins(game_root, profile_path) != pins:
            raise ValueError('The owner-current sources or module changed before publication')
        partial = any(row.get('status') != 'observed' for row in (pawn_scope, manager_scope))
        context = manager_scope['state'].get('RuntimeContext', {})
        partial |= context.get('status') == 'partial'
        return dict(kind='owned_weapon_current_context_readonly_v1', status='partial' if partial else 'observed',
            pid=pid, created_at=created, observed_at_utc=datetime.now(timezone.utc).isoformat(),
            client_sha256=old.SHIPPING_SHA256, source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(), primary_connection_binding=pc,
            first_player_binding=binding, pawn_manager_reference=link, objects=[pawn_scope, manager_scope],
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
