"""Read one active owned trial's weapon initialization state without client calls.

The original cohort reader stays unchanged. Selection follows only the current
primary PC/Pawn and its typed default components/WeaponList. This script adds
source-correct enum metadata and separately rechecked, field-scoped results.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import observe_owned_weapon_state as old
from observe_owned_gameplay_metadata import (BindingObservation, address,
    label_existing, object_path, owned_trial_identity, typed_declarations,
    write_exclusive_report)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession,
    validate_source, discover_roots, observe_first_player_state, request_elevation)
from portable_native_code_cache import CodeCache

ROOT = old.ROOT
EVIDENCE = 'work/evidence/map-system-audit-20261018/'
SOURCES = {
    'work/observe_owned_weapon_state.py':
        'd11d97cda7e4d93aa7ba222b933da270bf95e14453125e1118dc09ac3ab8a0b6',
    EVIDENCE+'native-game-mode-uenum-property-wire-width.json':
        '827a4fa8a6a4df3adb1bd90c9e8790cf276271cf4028a1b4ce634a4b6a6a5ae4',
    EVIDENCE+'native-owning-weapon-actor-property-serializers-v1.json':
        'dd600b28177bccef60437b6c4fa1db516271adfbfe383ea7f720dd6a9e648158',
    EVIDENCE+'native-owned-weapon-initialization-ready-flag-writers-v1.json':
        '38693123aab5b3f7f4f54e2d37d5a7c9fd5b27ec2615d186ef2b51cf5d5d22c0',
    EVIDENCE+'native-owned-weapon-ready-init-virtual-caller-v1.json':
        '937b474287b54baa32f8e169a5aeb40f7b89d212a593a037819ec88434234d32',
    EVIDENCE+'native-owned-weapon-model-lifecycle-contract-v4.json':
        '9d675d256cc1577557ae932dbd32ec6d857a05873461913f55009afc9acbc0b2',
    EVIDENCE+'native-owned-weapon-modular-replicate-info-fields-v1.json':
        'a78c9c75e865e6fdbc2c4d1033aea562504bc44612f93b79b46e72ae4af440a4',
}


class FollowupFields(old.WeaponFields):
    def enum(self, field, *, enum_property=False, expected_name=None):
        descriptor = field['descriptor_address']
        context = f'{field.get("name", "unnamed")} descriptor={hex(descriptor)}'
        self.hook(descriptor, 0x10e29fa0 if enum_property else 0x10e8ec50)
        # Both actual native serializers load their UEnum from descriptor+90.
        pointer = struct.unpack('<Q', self.facts.fact(descriptor+0x90, 8))[0]
        if not pointer:
            if expected_name is not None:
                raise ValueError(context+': required native UEnum is null')
            return dict(status='null_enum_pointer', property_kind='FByteProperty')
        pointer = address(pointer)
        before = self.identity(pointer, 'Enum')
        if expected_name is not None and before['name'] != expected_name:
            raise ValueError(context+': current enum type differs from '+expected_name)
        data, count = struct.unpack('<Qi', self.facts.fact(pointer+0x40, 12))
        if not 1 <= count <= 64:
            raise ValueError(context+': native enum exceeds the fixed bound')
        address(data)
        raw = self.facts.fact(data, count*16)
        entries = [dict(name=old.resolve_name(self.session.read, self.base,
            raw[i:i+8]).display_text, value=struct.unpack_from('<q', raw, i+8)[0])
            for i in range(0, len(raw), 16)]
        if len({e['name'] for e in entries}) != count or self.identity(pointer, 'Enum') != before:
            raise ValueError(context+': enum identity or names changed')
        return dict(status='observed', identity=before, entries=entries,
            descriptor_enum_offset=0x90)


def read_field(row, name, operation):
    """Keep independent values; no final report is published without all rechecks."""
    try:
        row.setdefault('state', {})[name] = operation()
    except ValueError as error:
        row.setdefault('field_errors', []).append(dict(field=name, reason=str(error),
            error_type=type(error).__name__))
    row['status'] = 'partial' if row.get('field_errors') else 'observed'


def source_pins(game_root, profile_path):
    pins = old.source_pins(game_root, profile_path)
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600',
        old.MANIFEST_SHA256, game_root)
    for relative, expected in SOURCES.items():
        raw = (ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('The independent follow-up source changed: '+relative)
        pins = old.merge_source_pins(pins, {relative: expected})
        if relative.endswith('.json'):
            for function in json.loads(raw).get('functions', []):
                code = cache.read(int(function['span_start'], 16), function['span_bytes'])
                if hashlib.sha256(code).hexdigest() != function['code_sha256']:
                    raise ValueError('The follow-up cached native source changed: '+relative)
    pins['work/observe_weapon_initialization_followup.py'] = hashlib.sha256(
        Path(__file__).read_bytes()).hexdigest()
    return pins


def model_fields(record):
    """Use the already qualified Modular observation, including inherited fields."""
    from export_portable_modular_weapon_schema import CAPTURE, CAPTURE_SHA256
    raw = (ROOT/CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPTURE_SHA256:
        raise ValueError('The actual Modular field source changed')
    source = next(r for r in json.loads(raw)['loaded_named_classes']
        if r['class_path'] == old.MODULAR_CLASS)
    result = {}
    for name, offset, size in (('ModularReplicateInfo', 0x8f0, 232),
            ('CurrentModularWeaponDesc', 0xaa0, 8), ('bInitWeaponInner', 0xa99, 1)):
        expected = [dict({k: f[k] for k in old.FIELD_KEYS if k in f},
            declaring_class=d['class_name']) for d in source['declarations']
            for f in d['fields'] if f['name'] == name]
        actual = [dict(f, declaring_class=d['class_name']) for d in record['declarations']
            for f in d['fields'] if f['name'] == name]
        if (len(expected) != 1 or len(actual) != 1 or
                any(actual[0].get(k) != v for k, v in expected[0].items()) or
                (expected[0]['storage_offset'], expected[0]['element_bytes']) != (offset, size)):
            raise ValueError('The source-qualified model field changed: '+name)
        result[name] = actual[0]
    return result


def model_readiness(record, *, fields, facts, observation):
    selected = model_fields(record)
    pointer, klass = (address(record['identity'][key]) for key in ('address', 'class_address'))
    current = {name: fields.field(klass, field) for name, field in selected.items()}
    info_type = fields.struct_type(current['ModularReplicateInfo'], 'ReplicateModularWeaponInfo')
    nodes = fields.nested(info_type, 'WeaponPartNodes', 0, 16)
    if nodes['field_vtable_rva'] != 0x1ab5b730:
        raise ValueError('The model recipe node list is not the actual FArrayProperty')
    # Read only the typed list header, never unknown node payloads.
    header = facts.fact(pointer+0x8f0, 16)
    data, count, capacity = struct.unpack('<Qii', header)
    if not 0 <= count <= capacity <= 1000 or (capacity and not data):
        raise ValueError('The current full model recipe exceeds its source-qualified bound')
    if data:
        address(data)
        if data & 7 or data+count*296 >= 1 << 47:
            raise ValueError('The full model recipe header address is invalid')
    flags = {}
    for name, offset in (('initialized_internal', 0xa8d), ('activation_pending_internal', 0xa93)):
        raw = facts.fact(pointer+offset, 1)
        if raw[0] not in (0, 1):
            raise ValueError('The source-qualified native readiness byte is not bool: '+name)
        flags[name] = dict(native_member_offset=offset, value=bool(raw[0]),
            raw_hex=raw.hex(), reflected_property=False, net_property=False)
    return dict(**flags,
        bInitWeaponInner=fields.boolean(pointer, current['bInitWeaponInner']),
        modular_part_nodes=dict(count=count, capacity=capacity, element_bytes=296,
            header_raw_hex=header.hex(), payload_read=False),
        current_modular_description=observation.reference(pointer,
            selected['CurrentModularWeaponDesc'], expected_base='GPModularWeaponDesc'),
        gameplay_or_rendering_verified=False)


def read_actor(record, *, pawn_record, level, fields, facts, observation):
    identity = record['identity']
    if record['class_path'] == old.EMPTY_HAND_CLASS:
        old.qualify_weapon_actor(identity, record['class_path'], level)
        scope = 'actor'
    else:
        schema, _ = old.modular_actor_source()
        if (record['class_path'] != schema['actor']['class_path'] or
                identity.get('is_cdo') is not False or
                not identity.get('name', '').startswith('BP_WeaponModular_C_') or
                'WeaponBase' not in identity.get('class_ancestry', ()) or
                address(identity['outer_address']) != level):
            raise ValueError('The actual manager Actor is outside the qualified class/current Level')
        scope = 'modular_actor'
    row = dict(**record, scope='actual_manager_weapon_actor', state={},
        reference_origin='current_typed_WeaponManager.WeaponList')
    read_field(row, 'actor_fields', lambda: actor_values(record, scope=scope,
        pawn_record=pawn_record, observation=observation, fields=fields, facts=facts))
    actor_error = row['state'].get('actor_fields', {}).get('field_error')
    if actor_error:
        row.setdefault('field_errors', []).append(dict(field='actor_fields', **actor_error))
        row['status'] = 'partial'
    # The model fields are inherited WeaponBase declarations, including EmptyHand.
    read_field(row, 'model_readiness', lambda: model_readiness(record,
        fields=fields, facts=facts, observation=observation))
    return row


def actor_values(record, **kwargs):
    values = {}
    try:
        old.read_weapon_actor_state(record, state=values, **kwargs)
    except ValueError as error:
        values['field_error'] = dict(reason=str(error), error_type=type(error).__name__)
    return values


def observe_manager_actors(entries, *, pawn_record, level, observation, metadata, fields, facts):
    if type(entries) is not list or len(entries) > 32:
        raise ValueError('A bounded actual manager WeaponList is required')
    pointers = [address(x['address']) for x in entries if x is not None]
    if len(pointers) > 3 or len(set(pointers)) != len(pointers):
        raise ValueError('The actual manager weapon reference count/uniqueness changed')
    rows, counts = [], {}
    for index, before in enumerate(entries):
        if before is None:
            continue
        try:
            pointer = address(before['address'])
            if observation.identify(pointer, 'WeaponBase') != before:
                raise ValueError('The actual manager-bound weapon identity changed')
            record = metadata(pointer, 'WeaponBase')
            if record['identity'] != before:
                raise ValueError('The actual manager-bound metadata identity changed')
            path = record['class_path']
            counts[path] = counts.get(path, 0)+1
            if counts[path] > (2 if path == old.MODULAR_CLASS else 1):
                raise ValueError('The actual manager exceeds one EmptyHand and two Modular Actors')
            row = read_actor(record, pawn_record=pawn_record, level=level,
                fields=fields, facts=facts, observation=observation)
            row['manager_list_index'] = index
            rows.append(row)
        except ValueError as error:
            rows.append(dict(manager_list_index=index, identity=before,
                status='refused', reason=str(error)))
    return rows


def observe(game_root, trial_report):
    from portable_map_bootstrap import load_plan
    trial_raw = Path(trial_report).read_bytes()
    trial = json.loads(trial_raw)
    pid, created = owned_trial_identity(trial, game_root)
    profile_path = old._profile_path(trial)
    pins = source_pins(game_root, profile_path)
    plan = load_plan(ROOT, profile_path)
    if plan.sources != trial['portable_map_bootstrap']['source_pins']:
        raise ValueError('The follow-up plan differs from the exact original active trial')
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
            raise ValueError('The current primary Pawn binding is unavailable')
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
        fields = FollowupFields(session, base, observation.identify, facts)
        pawn_record = metadata(pawn, 'Pawn')
        if not pawn_record['class_path'].endswith('.BP_DFMCharacter_C'):
            raise ValueError('The current Pawn is outside the qualified DFM profile')
        level = address(pawn_record['identity']['outer_address'])
        observation.identify(level, 'Level')
        refs = [observation.reference(pawn, field)
            for field in old.select_fields(pawn_record['declarations'], 'pawn').values()]
        objects, actors, manager_entries = [], [], None
        for scope, property_name, name, expected_class, expected_path in old.COMPONENT_SCOPES:
            row = dict(scope=scope, state={}, status='reading')
            objects.append(row)
            try:
                link = next(r for r in refs if r['field_name'] == property_name)
                if link['status'] != 'typed_existing_reference':
                    row.update(status=link['status'])
                    continue
                pointer = address(link['identity']['address'])
                record = metadata(pointer, expected_class)
                if (record['identity']['name'] != name or record['class_path'] != expected_path or
                        address(record['identity']['outer_address']) != pawn):
                    raise ValueError('The current default component Name/class/Outer differs: '+name)
                row.update(record)
                selected = old.select_fields(record['declarations'], scope)
                klass = address(record['identity']['class_address'])

                def field(n):
                    return fields.field(klass, selected[n])

                read_field(row, 'character_owner', lambda: observation.reference(pointer,
                    selected['CharacterOwner'], expected_base='GPCharacterBase'))
                if scope == 'manager':
                    read_field(row, 'weapon_slot', lambda: dict(field=field('WeaponSlot'),
                        value=facts.fact(pointer+selected['WeaponSlot']['storage_offset'], 1)[0],
                        enum=fields.enum(field('WeaponSlot'))))
                    read_field(row, 'empty_hand_override', lambda: dict(field=field('EmptyHandOverrideID'),
                        value=struct.unpack('<q', facts.fact(pointer+selected['EmptyHandOverrideID']['storage_offset'], 8))[0]))
                    read_field(row, 'use_empty_hand_override', lambda: fields.boolean(pointer, field('bUseEmptyHandOverride')))
                    read_field(row, 'empty_hand_reference', lambda: observation.reference(pointer,
                        selected['EmptyHandWeapon'], expected_base='WeaponBase'))
                    for array_name, stride, kind in (('WeaponList', 8, 'object'),
                            ('WeaponIdentityList', 4, 'identity'), ('WeaponIDList', 8, 'int64')):
                        def array_value(n=array_name, s=stride, k=kind):
                            header, payload, _ = fields.array(pointer, field(n), s, kind=k)
                            if k == 'object':
                                entries = [None if not at else observation.identify(address(at), 'WeaponBase')
                                    for (at,) in struct.iter_unpack('<Q', payload)]
                            else:
                                entries = [at for (at,) in struct.iter_unpack('<'+('I' if k == 'identity' else 'q'), payload)]
                            return dict(**header, entries=entries)
                        read_field(row, array_name, array_value)
                    if 'WeaponList' in row['state']:
                        manager_entries = row['state']['WeaponList']['entries']
                else:
                    read_field(row, 'current_active', lambda: fields.pairs(pointer, field('CurrActiveWeapInfoArr')))
                    def weapon_info():
                        fast = field('WeapInfoArray')
                        fast_type = fields.struct_type(fast, 'GPWeaponRepInfoPairFastArray')
                        items = fields.nested(fast_type, 'Items', 0x108, 16)
                        return fields.pairs(pointer+fast['storage_offset'], items)
                    read_field(row, 'weapon_info', weapon_info)
            except ValueError as error:
                row.update(status='partial' if row['state'] else 'refused', reason=str(error))
        if manager_entries is not None:
            try:
                actors = observe_manager_actors(manager_entries, pawn_record=pawn_record,
                    level=level, observation=observation, metadata=metadata, fields=fields, facts=facts)
            except ValueError as error:
                actors.append(dict(status='refused', reason=str(error)))
        observation.finish()
        fields.finish()
        for klass, record in classes.items():
            if (callback(klass, 'Class') != record['class_identity'] or
                    typed_declarations(session, base, klass, callback) != record['declarations']):
                raise ValueError('The follow-up selected declarations changed before publication')
        facts.finish()
        sink['recheck_roots']()
        if observe_first_player_state(session, base, driver_address=driver,
                connection_address=connection, pc_address=pc_at, object_identity=callback) != binding:
            raise ValueError('The follow-up current PC/Pawn binding changed')
        reader.verify_identity()
        if reader.find_module() != base or source_pins(game_root, profile_path) != pins:
            raise ValueError('The follow-up pinned sources or module changed')
        partial = manager_entries is None or any(x.get('status') != 'observed' for x in objects+actors)
        return dict(kind='owned_weapon_initialization_readonly_followup_v1',
            status='partial' if partial else 'observed',
            pid=pid, created_at=created, observed_at_utc=datetime.now(timezone.utc).isoformat(),
            client_sha256=old.SHIPPING_SHA256, source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc, first_player_binding=binding,
            pawn_component_references=refs, objects=objects, actual_manager_weapon_actors=actors,
            identities_and_fields_rechecked=True, selected_roots_rechecked=True,
            process_identity_rechecked=True, read_calls=session.calls, read_bytes=session.bytes_read,
            process_memory_written=False, native_methods_invoked=False, native_layouts_constructed=False,
            packets_sent=False, code_sampled=False, historical_process_pointers_reused=False,
            snapshot_atomic=False, native_weapon_gameplay_verified=False)
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
