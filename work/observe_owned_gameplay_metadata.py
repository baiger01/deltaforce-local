"""Read existing gameplay metadata in a future, active project-owned shadow trial.

No game is started. No native method, layout producer, writer, injector, packet,
or code sampler is used. Missing driver caches stay missing. This diagnostic
does not authorize wire values or prove that a weapon/HUD has initialized.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

import export_native_replication_metadata as exporter
from observe_portable_map_runtime import (ROOT, SHIPPING_SHA256, Win32MetadataReader,
    MetadataSession, validate_source, discover_roots, observe_first_player_state,
    direct_root_reference, object_name, request_elevation)
from observe_map_component_sources import declared_fields
from native_metadata_names import resolve_name
from native_metadata_objects import validate_object_record
from native_metadata_paths import object_path
from native_replication_metadata_core import export_existing_driver_class

LOADED_CLASSES = frozenset(('MultiWeaponManagerComponent', 'WeaponManagerComponent',
    'WeaponReplicateComponent', 'SOLCharacterEquipComponent', 'InventoryManager',
    'DFMInteractorComponentBase', 'BP_DFMHUD_C', 'BP_SOLHudManager_C', 'WeaponInputHUDComponent',
    'WeaponBase', 'BP_EmptyHand_C', 'BP_WeaponModular_C'))
QUALIFIED_WEAPON_CLASS_PATHS = {
    'WeaponBase': '/Script/GPGameplay.WeaponBase',
    'BP_EmptyHand_C': '/Game/BluePrints/Weapons/WeaponBP/MeleeWeaponBP/BP_EmptyHand.BP_EmptyHand_C',
    'BP_WeaponModular_C': '/Game/BluePrints/Weapons/WeaponBP/BP_WeaponModular.BP_WeaponModular_C',
}
OBJECT_PROPERTY_TYPES = {0x15A86B80: 'FObjectProperty', 0x1AB613B0: 'FEncryptedObjectProperty'}
HUD_SCHEMA = 'outputs/df-local-server/protocol/portable-map-spawn/hud-schema.json'
HUD_CONTRACT_SHA = '3ef89f031dea37a1878f80acfef651fd1efc1f1d537bd69259b39666291c2d27'
SOURCE_REPORTS = {
    'outputs/df-local-server/protocol/weapon_preset_catalog.json':
        '66ed0bd86ecfc34be405b1e90f82b7ce2e7f23e3a2ac1dcf9cdeb649001a5626',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-manager-add-recid-source-v1.json':
        '5721081352a2d56c1460243b9f02c0e32b6fdb044ac34d668776096bf1f2e4af',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-receiver-config-class-resolver-v1.json':
        '59332d1f3c06c09f1b4279b4f7cf928d8d4d31a4b5a4c394f200597920b4b421',
    'work/evidence/map-system-audit-20261018/native-owning-gameplay-object-property-type-branches.json':
        '1981af3974d57daa4679f3c530f7f4408aaf5ddb875cc98c54cf98aed26733a4',
    'work/evidence/map-system-audit-20261018/native-owning-gameplay-object-property-class-storage.json':
        '79d21499bece260a93b14d40d10cb8942528b5205b4ded46cffda04539dd53ed',
    'work/evidence/map-system-audit-20261018/native-owning-gameplay-object-property-type-name.json':
        '9a164d313eeb1b3dfbb74b5871ff5f3b9f0cb19b42fc299c5ae18793bad3a4f1',
    'work/evidence/map-system-audit-20261018/native-owning-weapon-cooked-character-emptyhand-defaults.json':
        'e935d6eab000430da6933ce6578e2fea6a40e9897849c14597c734bf742dc543',
    'work/evidence/map-system-audit-20261018/native-owning-weapon-fastarray-header-and-baseclass.json':
        '6c494f4d5b9c2328bc6a0e05f5fae449f0e7d5f691b1420b7fa5e42323dbc9b0',
}
MAX_BOUND_OBJECTS = 24


def qualify_loaded_class(metadata):
    name = metadata['identity']['name']
    expected = QUALIFIED_WEAPON_CLASS_PATHS.get(name)
    if expected is not None and metadata['class_path'] != expected:
        raise ValueError('Loaded weapon source class path differs')
    return metadata


def address(value):
    if type(value) is str:
        value = int(value, 16)
    if type(value) is not int or not 0x10000 <= value < 1 << 47 or value & 7:
        raise ValueError('Invalid current metadata object address')
    return value


def owned_trial_identity(trial, game_root):
    if trial.get('record_complete') is True or trial.get('client_shadow_mode') is not True:
        raise ValueError('An active owned shadow trial is required')
    if Path(trial['test_game_root']).resolve() != Path(game_root).resolve():
        raise ValueError('The current owned shadow root differs')
    identities = {(r['pid'], r['created_at']) for r in trial['process_observations']
                  if r.get('name') == 'deltaforceclient-win64-shipping.exe'}
    if len(identities) != 1:
        raise ValueError('One owned Shipping process identity is required')
    pid, created = next(iter(identities))
    if type(pid) is not int or pid <= 0 or type(created) not in (int, float) or not created > 0:
        raise ValueError('The owned process identity is invalid')
    return pid, created


def source_pins():
    pins = {}
    for relative, expected in SOURCE_REPORTS.items():
        raw = (ROOT/relative).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError('Gameplay metadata source changed: '+relative)
        pins[relative] = digest
    raw = (ROOT/HUD_SCHEMA).read_bytes()
    schema = json.loads(raw)
    if (schema.get('client_sha256') != SHIPPING_SHA256 or
            schema.get('lifecycle', {}).get('pc_myhud_offset') != '0x400' or
            schema.get('native_contract_sha256') != HUD_CONTRACT_SHA):
        raise ValueError('The public HUD declaration is outside the qualified source')
    contract_path = (ROOT/schema['native_contract_relative_path']).resolve()
    if not contract_path.is_relative_to(ROOT.resolve()) or hashlib.sha256(
            contract_path.read_bytes()).hexdigest() != HUD_CONTRACT_SHA:
        raise ValueError('The HUD declaration contract changed')
    pins[HUD_SCHEMA] = hashlib.sha256(raw).hexdigest()
    pins[schema['native_contract_relative_path']] = HUD_CONTRACT_SHA
    for relative in ('work/observe_owned_gameplay_metadata.py', 'work/observe_map_component_sources.py',
            'work/observe_portable_map_runtime.py', 'work/export_native_replication_metadata.py',
            'work/native_replication_metadata_core.py', 'work/native_metadata_objects.py',
            'work/native_metadata_names.py', 'work/native_metadata_paths.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def typed_declarations(session, base, klass, identity):
    """Extend the existing declaration reader only for two sealed object types."""
    result = declared_fields(session, base, klass, identity)
    reads, cursor, classes, nodes = [], klass, set(), set()
    for declaration in result:
        if cursor in classes or len(classes) >= 32:
            raise ValueError('Typed declaration class cycle')
        classes.add(cursor)
        before = identity(cursor, 'Class')
        if before['name'] != declaration['class_name']:
            raise ValueError('Declared class changed between metadata walks')
        raw = session.stable(cursor+0x48, 8)
        reads.append((cursor+0x48, raw))
        parent = struct.unpack('<Q', raw)[0]
        raw = session.stable(cursor+0x70, 8)
        reads.append((cursor+0x70, raw))
        node = struct.unpack('<Q', raw)[0]
        matched = set()
        while node:
            if node in nodes or len(nodes) >= 1024:
                raise ValueError('Typed declaration field cycle or count bound')
            nodes.add(node)
            raw = session.stable(node, 0x60)
            reads.append((node, raw))
            table, owner = struct.unpack_from('<QQ', raw)
            following = struct.unpack_from('<Q', raw, 0x18)[0]
            kind = OBJECT_PROPERTY_TYPES.get(table-base)
            if kind:
                if owner != cursor or not raw[0x10]:
                    raise ValueError('Typed object property has a foreign owner')
                name = object_name(session.read, base, node, field_representation=0).display_text
                offset = struct.unpack_from('<i', raw, 0x54)[0]
                candidates = [r for r in declaration['fields'] if r['name'] == name and r['storage_offset'] == offset]
                if len(candidates) != 1 or name in matched:
                    raise ValueError('Typed object declaration is ambiguous')
                matched.add(name)
                pointer = session.stable(node+0x90, 8)
                reads.append((node+0x90, pointer))
                target = address(struct.unpack('<Q', pointer)[0])
                target_identity = identity(target, 'Class')
                candidates[0].update(native_property_type=kind,
                    declared_native_class=target_identity['name'],
                    declared_native_class_path=object_path(session.read, base, target))
            node = following
        if identity(cursor, 'Class') != before:
            raise ValueError('Typed declaring class identity changed')
        cursor = parent
    if cursor or any(session.stable(at, len(raw)) != raw for at, raw in reads):
        raise ValueError('Typed object declarations changed')
    return result


def named_field(name, scope, declared_class=''):
    low, target = name.lower(), declared_class.lower()
    if low.endswith('class') or low.endswith('classes'):
        return False
    tokens = ('weaponmanager', 'weaponreplicate', 'characterequip', 'inventory', 'interactor')
    if scope in ('pawn', 'player_state', 'component') and any(t in low or t in target for t in tokens):
        return True
    if scope in ('hud', 'hud_manager', 'hud_component'):
        return (any(t in low or t in target for t in ('hudmanager', 'hudcomponent')) or
                low in ('playerowner', 'owningplayer', 'owningpawn', 'pawn', 'playercontroller'))
    return False


class BindingObservation:
    def __init__(self, session, base, identity, metadata_reader):
        self.session, self.base, self.callback = session, base, identity
        self.metadata_reader = metadata_reader
        self.identities, self.reads = {}, {}

    def identify(self, pointer, base_class='Object'):
        pointer = address(pointer)
        value = self.callback(pointer, base_class)
        key = (pointer, base_class)
        if key in self.identities and self.identities[key] != value:
            raise ValueError('Bound gameplay object identity changed')
        self.identities[key] = value
        return value

    def reference(self, owner, field, *, expected_base='Object'):
        name, offset = field['name'], field['storage_offset']
        result = dict(field_name=name, native_storage_offset=offset,
            declaring_class=field.get('declaring_class'), native_property_type=field.get('native_property_type'),
            declared_native_class=field.get('declared_native_class'))
        if field.get('array_dimension') != 1 or field.get('element_bytes') != 8:
            return dict(result, status='unsupported_named_field_storage')
        if field.get('native_property_type') not in (*OBJECT_PROPERTY_TYPES.values(),
                'source_qualified_HUD_object_reference'):
            return dict(result, status='unqualified_named_property_type')
        raw = self.session.stable(owner+offset, 8)
        self.reads[(owner+offset, 8)] = raw
        try:
            pointer = direct_root_reference(struct.unpack('<Q', raw)[0])
            if not pointer:
                return dict(result, status='null_reference')
            value = self.identify(pointer, expected_base)
            declared = field.get('declared_native_class')
            if declared and declared not in value['class_ancestry']:
                raise ValueError('Bound object differs from its declared native class')
            return dict(result, status='typed_existing_reference', identity=value,
                outer_is_selected_owner=int(value['outer_address'], 16) == owner,
                packed_native_callback_invoked=False)
        except (ValueError, OSError) as error:
            return dict(result, status='refused', reason=str(error))

    def named_bindings(self, owner, base_class, *, scope):
        self.identify(owner, base_class)
        metadata = self.metadata_reader(owner, base_class)
        selected = []
        for cls in metadata['declarations']:
            for field in cls['fields']:
                if named_field(field['name'], scope, field.get('declared_native_class', '')):
                    selected.append({**field, 'declaring_class': cls['class_name']})
        if len(selected) > 32 or len({r['name'] for r in selected}) != len(selected):
            raise ValueError('Ambiguous or excessive named gameplay field declarations')
        return [self.reference(owner, field) for field in selected]

    def finish(self):
        for (pointer, base_class), before in self.identities.items():
            if self.callback(pointer, base_class) != before:
                raise ValueError('Bound gameplay object identity changed')
        for (pointer, size), before in self.reads.items():
            if self.session.stable(pointer, size) != before:
                raise ValueError('Bound gameplay reference changed')


def label_existing(session, base, driver, klass):
    record = validate_object_record(session.read, base, klass)
    if not record.serial:
        return dict(cache_status='missing', layout_status='missing',
            class_key_status='uninitialized_native_serial', native_getter_invoked=False)
    result = export_existing_driver_class(session, driver, struct.pack('<iI', record.index, record.serial))
    names = []
    for node in result.get('cache_nodes', []):
        for field in node['fields']:
            if not field['descriptor_address']:
                continue
            field['descriptor_name'] = object_name(session.read, base, field['descriptor_address'],
                field_representation=field['descriptor_representation']).display_text
            names.append((field['descriptor_address'], field['descriptor_representation'], field['descriptor_name']))
    for group in ('parents', 'commands'):
        for row in result.get('layout', {}).get(group, []):
            if not row['descriptor_address']:
                continue
            row['descriptor_name'] = object_name(session.read, base, row['descriptor_address'],
                                                 field_representation=0).display_text
            names.append((row['descriptor_address'], 0, row['descriptor_name']))
    if (validate_object_record(session.read, base, klass) != record or any(
            object_name(session.read, base, ptr, field_representation=representation).display_text != name
            for ptr, representation, name in names)):
        raise ValueError('Existing class cache metadata changed')
    return result


def observe(game_root, trial_report, *, maximum_seconds=120):
    trial_raw = Path(trial_report).read_bytes()
    pid, created = owned_trial_identity(json.loads(trial_raw), game_root)
    pins = source_pins()
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=maximum_seconds)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        previous_targets = exporter.TARGET_CLASSES
        try:
            # Only class/name/Outer registry metadata is added to discovery.
            exporter.TARGET_CLASSES = previous_targets | LOADED_CLASSES
            roots = discover_roots(session, base, connection_binding_only=True,
                first_player_state=True, _binding_identity_sink=sink, unpublished_batch_retry=True)
        finally:
            exporter.TARGET_CLASSES = previous_targets
        identity = sink['callback']
        candidates = [r for r in roots['connection_binding_observations']['player_controllers']
            if r.get('status') == 'observed' and r.get('identity_and_fields_rechecked') is True and
            r.get('driver_primary_matches_original_connection') is True and r.get('local_player_index_field') == 0]
        if len(candidates) != 1:
            raise ValueError('One current primary owned controller is required')
        pc = candidates[0]
        pc_address, driver, connection = (address(pc[k]) for k in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_address, object_identity=identity)
        if binding.get('status') != 'observed':
            raise ValueError('Current PC/Pawn binding could not be rechecked')
        pawn = binding['pc_pawn_reference']
        if pawn.get('status') != 'typed_existing_reference':
            raise ValueError('A current owned Pawn reference is required')
        classes, object_metadata = {}, {}

        def class_metadata(klass):
            if klass not in classes:
                before = identity(klass, 'Class')
                declarations = typed_declarations(session, base, klass, identity)
                classes[klass] = dict(identity=before, class_path=object_path(session.read, base, klass),
                    declarations=declarations, existing_driver_class=label_existing(session, base, driver, klass))
                if identity(klass, 'Class') != before:
                    raise ValueError('Selected gameplay class identity changed')
            return classes[klass]

        def metadata(pointer, base_class):
            before = identity(pointer, base_class)
            value = class_metadata(address(before['class_address']))
            object_metadata[pointer] = dict(identity=before, class_path=value['class_path'],
                declarations=value['declarations'], existing_driver_class=value['existing_driver_class'])
            return object_metadata[pointer]

        observation = BindingObservation(session, base, identity, metadata)
        roots_to_visit = [(pc_address, 'PlayerController', 'controller'), (pawn['address'], 'Pawn', 'pawn')]
        ps = binding['pc_player_state_reference']
        if ps.get('status') == 'typed_existing_reference':
            roots_to_visit.append((ps['address'], 'PlayerState', 'player_state'))
        metadata(pc_address, 'PlayerController')
        hud_ref = observation.reference(pc_address, dict(name='MyHUD', storage_offset=0x400,
            element_bytes=8, array_dimension=1, declaring_class='PlayerController',
            native_property_type='source_qualified_HUD_object_reference'), expected_base='HUD')
        if hud_ref['status'] == 'typed_existing_reference':
            roots_to_visit.append((address(hud_ref['identity']['address']), 'HUD', 'hud'))
        queue, seen, observations = [(p, b, scope, 0) for p, b, scope in roots_to_visit], set(), []
        while queue:
            pointer, base_class, scope, depth = queue.pop(0)
            if pointer in seen:
                continue
            if len(seen) >= MAX_BOUND_OBJECTS:
                raise ValueError('Bound gameplay object count exceeds local policy')
            seen.add(pointer)
            links = observation.named_bindings(pointer, base_class, scope=scope) if scope != 'controller' else []
            item = metadata(pointer, base_class)
            observations.append(dict(**item, scope=scope, named_bound_references=links))
            if depth < 2:
                for link in links:
                    if link['status'] != 'typed_existing_reference':
                        continue
                    child = link['identity']
                    # Owner references are recorded but do not expand the graph.
                    name = link['field_name'].lower()
                    if name in ('playerowner', 'owningplayer', 'owningpawn', 'pawn', 'playercontroller'):
                        continue
                    next_scope = ('hud_manager' if 'hudmanager' in name else 'hud_component') if scope.startswith('hud') else 'component'
                    queue.append((address(child['address']), 'Object', next_scope, depth+1))
        loaded = []
        for row in roots['classes']:
            if row['name'] in LOADED_CLASSES:
                loaded.append(qualify_loaded_class(class_metadata(row['address'])))
        observation.finish()
        for klass, before in classes.items():
            if (identity(klass, 'Class') != before['identity'] or
                    typed_declarations(session, base, klass, identity) != before['declarations']):
                raise ValueError('Gameplay class declarations changed before publishing')
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module() != base:
            raise ValueError('The qualified module changed')
        return dict(kind='owned_gameplay_existing_metadata_observation', status='observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc, first_player_binding=binding, controller_myhud=hud_ref,
            objects=observations, loaded_named_classes=loaded,
            missing_loaded_named_classes=sorted(LOADED_CLASSES-{r['identity']['name'] for r in loaded}),
            read_calls=session.calls, read_bytes=session.bytes_read,
            identities_and_fields_rechecked=True, selected_roots_rechecked=True,
            process_identity_rechecked=True, process_memory_written=False, native_methods_invoked=False,
            native_layouts_constructed=False, packets_sent=False, code_sampled=False,
            historical_process_pointers_reused=False, snapshot_atomic=False,
            gameplay_initialization_verified=False)
    finally:
        reader.close()


def write_exclusive_report(output, report):
    output.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(report, indent=2)+'\n').encode()
    with output.open('xb') as destination:
        destination.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    opts = parser.parse_args()
    output = opts.output.resolve()
    if not output.is_relative_to((ROOT/'work').resolve()) or output.exists():
        parser.error('Output must be an exclusive new project work file')
    owned_trial_identity(json.loads(opts.trial_report.read_bytes()), opts.game_root)
    source_pins()
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


if __name__ == '__main__':
    main()
