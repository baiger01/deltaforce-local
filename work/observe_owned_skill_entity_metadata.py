"""Observe actual primary skill entities in one already owned shadow trial.

No launch, native call, weak-serial assignment, process write, packet, code
sampling or layout construction. Current typed bindings and every read are
rechecked before publishing. A refused value scope preserves checked metadata.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from observe_owned_gameplay_metadata import (ROOT, SHIPPING_SHA256, address,
    owned_trial_identity, typed_declarations, label_existing, write_exclusive_report)
from observe_owned_vitals_metadata import (VitalsBindingObservation, object_metadata,
    enrich_existing_layout, source_pins as vitals_source_pins)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession,
    validate_source, discover_roots, observe_first_player_state, request_elevation,
    recheck_virtual_method)
from native_metadata_paths import object_path
from native_guid_object_metadata import _existing_weak, observe_connection_guid_mappings
from skill_entity_readonly_scope import (source_pins as entity_source_pins,
    qualified_skill_fields, read_map, read_contexts, read_replicated_states, FIELD_KEYS, CLIENT_SHA256,
    CAPTURE, CAPTURE_SHA256)

MAP_CAPTURE = 'work/native-client-tests/1792328560808149500/owned-map-marker-metadata.json'
MAP_CAPTURE_SHA256 = 'ff8b2c90f7a07aa5a74351c7ada8c389a8c85c6a708fe0cf78c7e456dceed1c9'
SUBSYSTEM_CAPTURE = 'work/native-client-tests/1792337436036819800/owned-skill-entity-metadata.json'
SUBSYSTEM_CAPTURE_SHA256 = '1fdfb2374d4c6fb4f18d1246736986b67813f878a5769eb21034f8b0d7945edb'


class Facts:
    def __init__(self, session):
        self.session, self.facts, self.bytes = session, {}, 0

    def fact(self, at, size):
        if (type(at) is not int or type(size) is not int or not 0 < size <= 65536 or
                not 0x10000 <= at < at+size <= 1 << 47 or
                len(self.facts) >= 16384 or self.bytes+size > 256*1024):
            raise ValueError('The skill entity readonly scope exceeded its fixed budget')
        raw = self.session.stable(at, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ValueError('The skill entity metadata read was incomplete')
        key = at, size
        if key in self.facts and self.facts[key] != raw:
            raise ValueError('The selected skill entity state changed')
        if key not in self.facts:
            self.bytes += size
        self.facts[key] = raw
        return raw

    def pointer(self, at):
        return address(struct.unpack('<Q', self.fact(at, 8))[0])

    def finish(self):
        if any(self.session.stable(at, size) != raw for (at, size), raw in self.facts.items()):
            raise ValueError('The selected skill entity state changed before publication')


def source_pins():
    pins = vitals_source_pins()
    pins.update(entity_source_pins())
    raw = (ROOT/MAP_CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != MAP_CAPTURE_SHA256:
        raise ValueError('The exact GS ability declaration source changed')
    pins[MAP_CAPTURE] = MAP_CAPTURE_SHA256
    if hashlib.sha256((ROOT/SUBSYSTEM_CAPTURE).read_bytes()).hexdigest() != SUBSYSTEM_CAPTURE_SHA256:
        raise ValueError('The exact existing subsystem declaration source changed')
    pins[SUBSYSTEM_CAPTURE] = SUBSYSTEM_CAPTURE_SHA256
    for path, digest in {
        'work/evidence/model-init-chain-20261018/native-map-marker-guid-lookup.json':
            '467917bcf328517641977770aa7351ae9a290b453166de5ca43b5bb4db7f6627',
        'work/evidence/model-init-chain-20261018/native-map-marker-guid-hash-lookup.json':
            'e704b5ccb521f7a2571b359b7ea881d5a410504f8dec43ab677fa3be6e27842d',
    }.items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest() != digest:
            raise ValueError('The current GUID metadata native source changed')
        pins[path] = digest
    for path in ('work/observe_owned_skill_entity_metadata.py', 'work/native_guid_object_metadata.py'):
        pins[path] = hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
    return pins


def exact_field(declarations, expected):
    rows = [dict(f, declaring_class=d['class_name']) for d in declarations
        for f in d['fields'] if f['name'] == expected['name']]
    if len(rows) != 1 or any(rows[0].get(k) != v for k, v in expected.items()):
        raise ValueError('The current entity binding declaration differs: '+expected['name'])
    return rows[0]


def captured_binding(which):
    path, digest = (CAPTURE, CAPTURE_SHA256) if which == 'skill' else (MAP_CAPTURE, MAP_CAPTURE_SHA256)
    raw = (ROOT/path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('The selected entity typed source changed')
    doc = json.loads(raw)
    if which == 'skill':
        obj, = [x for x in doc['objects'] if x['class_path'].endswith('.BP_DFMCharacter_C')]
        name = 'DFMSkillComponent'
    else:
        obj = doc['root_metadata']['game_state']
        name = 'GSAbilityComponent'
    row, = [dict({k: f[k] for k in FIELD_KEYS}, declaring_class=d['class_name'],
        declared_native_class=f['declared_native_class'],
        declared_native_class_path=f['declared_native_class_path'],
        native_property_type=f['native_property_type'])
        for d in obj['declarations'] for f in d['fields'] if f['name'] == name]
    return row


def static_subsystem_field(declarations, name):
    path = 'work/evidence/model-init-chain-20261018/native-skill-subsystem-class-declarations-v1.json'
    prop, = [p for p in json.loads((ROOT/path).read_bytes())['classes'][0]['declared_property_records']
        if p['name'] == name and int(p.get('native_member_offset', '0'), 16) > 0]
    signature = {
        'DataSystem': (0x370, 8, 0x15a86b80, '0x12', '0x18001040000200'),
        'AbilityEntityDataList': (0x378, 16, 0x1ab5b730, '0x16', '0x10008000000200'),
        'GameStateAbilityComponent': (0x400, 8, 0x1ab610f0, '0xe', '0x1c001040080208'),
    }.get(name)
    if signature is None or (int(prop['native_member_offset'], 16), prop['native_gen_flags']) != (signature[0], signature[3]):
        raise ValueError('The static subsystem native declaration differs: '+name)
    raw = (ROOT/SUBSYSTEM_CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SUBSYSTEM_CAPTURE_SHA256:
        raise ValueError('The exact current subsystem field source changed')
    source = json.loads(raw)
    if source.get('identities_and_fields_rechecked') is not True or source.get('client_sha256') != CLIENT_SHA256:
        raise ValueError('The current subsystem field source is not identity-qualified')
    obj, = [o for o in source['objects'] if o['class_path'] == '/Script/GPGameplay.SkillSubsystem']
    expected, = [dict({k: f[k] for k in FIELD_KEYS}, declaring_class=g['class_name'],
        **{k: f[k] for k in ('native_property_type', 'declared_native_class',
                             'declared_native_class_path') if k in f})
        for g in obj['declarations'] for f in g['fields'] if f['name'] == name]
    if (expected['storage_offset'], expected['element_bytes'], expected['field_vtable_rva'],
            expected['property_flags'], expected['array_dimension']) != (
                signature[0], signature[1], signature[2], signature[4], 1):
        raise ValueError('The pinned runtime subsystem variant differs: '+name)
    return exact_field(declarations, expected)


def read_subsystem_reference(facts, base, subsystem, field, observation):
    if field['name'] == 'DataSystem':
        return observation.reference(subsystem, field, expected_base='GPAbilityDataSystem')
    if (field['name'] != 'GameStateAbilityComponent' or field['field_vtable_rva'] != 0x1ab610f0
            or field['storage_offset'] != 0x400 or field['element_bytes'] != 8):
        raise ValueError('A qualified subsystem object/weak binding is required')
    # Native gen0x0e and current FWeakObjectProperty: these8 bytes are index/serial.
    key = facts.fact(subsystem+field['storage_offset'], 8)
    resolved = _existing_weak(facts, base, key)
    declared = captured_binding('gs')
    result = dict(field_name=field['name'], native_storage_offset=field['storage_offset'],
        declaring_class='SkillSubsystem', native_property_type='FWeakObjectProperty',
        declared_native_class=declared['declared_native_class'],
        declared_native_class_path=declared['declared_native_class_path'],
        property_flags=field['property_flags'], weak_reference_hex=key.hex(),
        native_weak_resolver_invoked=False, serial_created=False,
        weak_key_treated_as_object_pointer=False, **resolved)
    if resolved['status'] == 'existing_object_observed':
        before = observation.identify(address(resolved['object_address']), declared['declared_native_class'])
        result.update(status='typed_existing_reference', identity=before,
                      weak_identity_initialized=True, packed_native_callback_invoked=False)
    return result


def guarded_scope(output, name, declarations, operation):
    try:
        result = operation()
    except ValueError as error:
        result = dict(status='refused', reason=str(error), instance_value_published=False,
            actual_declarations=declarations)
    output[name] = result
    return result


def observe(game_root, trial_report):
    trial_raw = Path(trial_report).read_bytes()
    pid, created = owned_trial_identity(json.loads(trial_raw), game_root)
    pins = source_pins()
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True,
            first_player_state=True, _binding_identity_sink=sink, unpublished_batch_retry=True)
        identity = sink['callback']
        pc, = [x for x in roots['connection_binding_observations']['player_controllers']
            if x.get('status') == 'observed' and x.get('identity_and_fields_rechecked') is True
            and x.get('driver_primary_matches_original_connection') is True and x.get('local_player_index_field') == 0]
        pc_at, driver, connection = (address(pc[k]) for k in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_at, object_identity=identity)
        if binding.get('status') != 'observed' or binding['pc_pawn_reference'].get('status') != 'typed_existing_reference':
            raise ValueError('The current owning Pawn binding is unavailable')
        pawn = address(binding['pc_pawn_reference']['address'])
        facts, classes, records, hooks, reads = Facts(session), {}, {}, [], {}
        selected = [(at, kind, identity(at, kind)) for at, kind in
            ((pc_at, 'PlayerController'), (driver, 'NetDriver'), (connection, 'NetConnection'), (pawn, 'Pawn'))]

        def recheck_binding():
            sink['recheck_roots']()
            if any(identity(at, kind) != before for at, kind, before in selected):
                raise ValueError('The owning skill entity root identity changed')
            if observe_first_player_state(session, base, driver_address=driver,
                    connection_address=connection, pc_address=pc_at, object_identity=identity) != binding:
                raise ValueError('The owning skill entity PC/Pawn binding changed')

        def metadata(pointer, expected):
            before = observation.identify(pointer, expected)
            klass = address(before['class_address'])
            if klass not in classes:
                existing = label_existing(session, base, driver, klass)
                enrich_existing_layout(session, base, existing, hooks, reads)
                classes[klass] = dict(class_identity=identity(klass, 'Class'),
                    declarations=typed_declarations(session, base, klass, identity),
                    class_path=object_path(session.read, base, klass), existing_driver_class=existing)
            record = dict(classes[klass], identity=before,
                object_metadata=object_metadata(session, pointer, before, observation, reads))
            records[pointer] = record
            return record

        observation = VitalsBindingObservation(session, base, identity, metadata)
        pawn_record = metadata(pawn, 'Pawn')
        if pawn_record['class_path'] != '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C':
            raise ValueError('The current typed Pawn root class changed')
        link = observation.reference(pawn, exact_field(pawn_record['declarations'], captured_binding('skill')),
            expected_base='ActorComponent')
        scopes = {'current_skill_binding': link}
        skill, subsystem = None, None
        if link['status'] in ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized'):
            skill = address(link['identity']['address'])
            record = metadata(skill, 'DFMSkillComponent')
            if (record['class_path'] != '/Script/DFMGameplay.DFMSkillComponent' or
                    address(record['identity']['outer_address']) != pawn or record['identity']['is_cdo']):
                raise ValueError('The current DFMSkill is not the typed Pawn-owned instance')
            fields = qualified_skill_fields(record['declarations'])
            guarded_scope(scopes, 'replicated_skill_states', record['declarations'], lambda:
                dict(status='observed', **read_replicated_states(facts.fact, skill, record['declarations'])))
            for name, byte_key in (('SkillEntityMap', False), ('SkillEntitySlotMap', True)):
                guarded_scope(scopes, name, [fields[name]], lambda n=name, b=byte_key:
                    dict(status='observed', **read_map(facts.fact, skill+fields[n]['storage_offset'], byte_key=b)))
            key = facts.fact(skill+fields['SkillSystem']['storage_offset'], 8)
            resolved = _existing_weak(facts, base, key)
            scopes['SkillSystem'] = dict(resolved, weak_reference_hex=key.hex(),
                native_weak_resolver_invoked=False, serial_created=False)
            if resolved['status'] == 'existing_object_observed':
                subsystem = address(resolved['object_address'])
                sub = metadata(subsystem, 'SkillSubsystem')
                if sub['class_path'] != '/Script/GPGameplay.SkillSubsystem':
                    raise ValueError('The actual weak SkillSystem class differs from its native getter')
                def contexts():
                    static_subsystem_field(sub['declarations'], 'AbilityEntityDataList')
                    if scopes['SkillEntityMap']['status'] != 'observed':
                        raise ValueError('Primary entity map values were refused')
                    return dict(status='observed', **read_contexts(facts.fact, subsystem,
                        scopes['SkillEntityMap']['entries']))
                context = guarded_scope(scopes, 'primary_entity_contexts', sub['declarations'], contexts)
                for name, expected in (('DataSystem', 'GPAbilityDataSystem'),
                        ('GameStateAbilityComponent', 'GPAbilityGameStateComponent')):
                    guarded_scope(scopes, name, sub['declarations'], lambda n=name, e=expected:
                        read_subsystem_reference(facts, base, subsystem,
                            static_subsystem_field(sub['declarations'], n), observation))
                if context.get('status') == 'observed':
                    for entity in context['entries']:
                        for field, expected in (('ability_instance_weak_hex', 'GPAbilityInstance'),
                                ('ability_template_weak_hex', 'GPAbilityLogicTemplate')):
                            resolved = _existing_weak(facts, base, bytes.fromhex(entity[field]))
                            entity[field.removesuffix('_hex')+'_resolution'] = resolved
                            if resolved['status'] == 'existing_object_observed':
                                metadata(address(resolved['object_address']), expected)
        # The subsystem weak ref may still be uninitialized. The actual GS typed
        # link independently exposes its normal network component declarations.
        mapping = observe_connection_guid_mappings(session, base, driver_address=driver,
            connection_address=connection, recheck_binding=recheck_binding)
        gs_row, = [r for r in mapping['mappings'] if r['guid'] == 6]
        if gs_row['status'] == 'existing_object_observed':
            gs = address(gs_row['object_address'])
            gs_record = metadata(gs, 'GameStateBase')
            if gs_record['class_path'] != '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C':
                raise ValueError('The current typed GS ability root class changed')
            guarded_scope(scopes, 'GSAbilityComponent', gs_record['declarations'], lambda:
                observation.reference(gs, exact_field(gs_record['declarations'], captured_binding('gs')),
                    expected_base='GPAbilityGameStateComponent'))
        for name in ('DataSystem', 'GameStateAbilityComponent', 'GSAbilityComponent'):
            row = scopes.get(name, {})
            if row.get('status') in ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized'):
                metadata(address(row['identity']['address']), row['declared_native_class'])
        observation.finish()
        for klass, before in classes.items():
            if (identity(klass, 'Class') != before['class_identity'] or
                    typed_declarations(session, base, klass, identity) != before['declarations']):
                raise ValueError('The selected current skill class declarations changed')
        for descriptor, hook in hooks:
            recheck_virtual_method(session, base, descriptor, hook)
        if any(session.stable(at, size) != raw for (at, size), raw in reads.items()):
            raise ValueError('The selected skill object flags or descriptor bytes changed')
        facts.finish()
        recheck_binding()
        reader.verify_identity()
        if reader.find_module() != base or source_pins() != pins:
            raise ValueError('The skill source seal or client module changed')
        refused = any(s.get('status') == 'refused' for s in scopes.values())
        return dict(kind='owned_primary_skill_entity_metadata_v1', status='partial' if refused else 'observed',
            client_sha256=CLIENT_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(), primary_connection_binding=pc,
            first_player_binding=binding, objects=list(records.values()), scopes=scopes,
            identities_and_fields_rechecked=True, snapshot_atomic=False,
            native_methods_invoked=False, process_memory_written=False, code_sampled=False,
            packets_sent=False, native_layouts_constructed=False, historical_process_pointers_reused=False,
            skills_initialized_inferred=False)
    finally:
        reader.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work').resolve()):
        parser.error('Use an exclusive new project work output')
    owned_trial_identity(json.loads(args.trial_report.read_bytes()), args.game_root)
    source_pins()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(args.game_root.resolve()),
            '--trial-report', str(args.trial_report.resolve()), '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root, args.trial_report)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False,
                native_layouts_constructed=False, packets_sent=False, code_sampled=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))
