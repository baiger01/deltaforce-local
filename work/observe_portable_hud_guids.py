"""Observe only the owned PC's two HUD fields and its plan's two static GUIDs.

No client launch, resolver/getter call, layout creation, process write, packet,
or code sampling occurs. Code qualification reads the existing sealed cache.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from native_guid_object_metadata import _Read, _lookup, _existing_weak, LOOKUP_TARGET_RVA, IMAGE_BYTES
from native_metadata_names import resolve_name
from native_metadata_paths import object_path
import native_metadata_objects as registry
from observe_owned_gameplay_metadata import address, owned_trial_identity, write_exclusive_report
from observe_portable_map_runtime import (ROOT, SHIPPING_SHA256, Win32MetadataReader,
    MetadataSession, validate_source, discover_roots, request_elevation)
from portable_native_code_cache import CodeCache

PROFILE = 'outputs/df-local-server/protocol/portable-map-spawn/profile.json'
SCHEMA = 'outputs/df-local-server/protocol/portable-map-spawn/hud-schema.json'
SCHEMA_SHA256 = '767742c4ac03274433f43235af52f5e962b26dfd4557215659fd62dc35fb9049'
MANIFEST_SHA256 = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
GUIDS = (39, 41)
HUD_PACKAGE = '/Game/BluePrints/UIServer/BP_DFMHUD'
HUD_CLASS = HUD_PACKAGE + '.BP_DFMHUD_C'


def weak_slot_diagnostic(read, base, weak):
    """Inspect the two selected weak slots without following a reused object."""
    index, serial = struct.unpack('<iI', weak)
    result = dict(expected_object_index=index, expected_serial=serial)
    if index < 0 or not serial:
        return dict(result, status='weak_identity_uninitialized')
    snapshot = registry._snapshot(read.fact, base, registry.DEFAULT_MAX_OBJECTS)
    if index >= snapshot.count:
        return dict(result, status='index_outside_current_registry', registry_count=snapshot.count)
    pointer, flags, actual_serial = registry._entry(read.fact, snapshot, index)
    registry._check_snapshot(read.fact, base, registry.DEFAULT_MAX_OBJECTS, snapshot)
    return dict(result, status='registry_slot_observed', slot_pointer_non_null=bool(pointer),
        slot_flags=flags, slot_excluded=bool(flags & registry.EXCLUDED_FLAGS),
        slot_serial=actual_serial, serial_matches=serial == actual_serial,
        target_dereferenced=False)


def observer_source_pins():
    schema_raw, profile_raw = (ROOT / SCHEMA).read_bytes(), (ROOT / PROFILE).read_bytes()
    if hashlib.sha256(schema_raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The fixed HUD source schema changed')
    profile, schema = json.loads(profile_raw), json.loads(schema_raw)
    if (profile.get('kind') != 'portable_local_map_bootstrap_profile' or profile.get('map_id') != 2201 or
            profile.get('client_sha256') != SHIPPING_SHA256 or
            profile.get('controller_hud') != {'relative_path': SCHEMA, 'sha256': SCHEMA_SHA256} or
            schema.get('required_hud_class_path') != HUD_CLASS):
        raise ValueError('The current profile does not declare this fixed HUD scope')
    from portable_map_bootstrap import load_plan
    plan = load_plan(ROOT, ROOT / PROFILE)
    pc = plan.actors['PlayerController'].manifest
    definitions = {b.guid: b.full_path for b in pc.path_bindings}
    if plan.hud_class_guid != GUIDS[1] or any(definitions.get(g) != p
            for g, p in zip(GUIDS, (HUD_PACKAGE, HUD_CLASS))):
        raise ValueError('The current plan has different HUD package/class GUIDs')
    pins = {PROFILE: hashlib.sha256(profile_raw).hexdigest(), SCHEMA: SCHEMA_SHA256,
        'work/native-code-cache/1792259162856698600/manifest.json': MANIFEST_SHA256}
    for relative in ('work/observe_portable_hud_guids.py', 'work/native_guid_object_metadata.py',
            'work/observe_owned_gameplay_metadata.py', 'work/observe_portable_map_runtime.py',
            'work/portable_map_bootstrap.py', 'work/portable_map_hud.py',
            'work/native_metadata_objects.py', 'work/native_metadata_names.py',
            'work/native_metadata_paths.py', 'work/native_replication_metadata_core.py',
            'work/export_native_replication_metadata.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    contract_path = schema['native_contract_relative_path']
    raw = (ROOT / contract_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != schema['native_contract_sha256']:
        raise ValueError('The native HUD contract changed')
    pins[contract_path] = schema['native_contract_sha256']
    return pins


def source_pins(game_root):
    pins = observer_source_pins()
    cache = CodeCache(ROOT / 'work/native-code-cache/1792259162856698600', MANIFEST_SHA256, game_root)
    anchors = ((0x12bb8320, '488b8910030000e974f0ffff'),
               (0x4dc1665, '498985a0080000'))
    for rva, expected in anchors:
        if cache.read(rva, len(bytes.fromhex(expected))) != bytes.fromhex(expected):
            raise ValueError('The cached HUD field or GUID dispatch source changed')
    return pins


def observe_selected(session, base, *, pc, driver, connection, identity, recheck_binding):
    """Read a fixed current namespace; all pointers come from typed live roots."""
    read, objects = _Read(session), {}

    def typed(pointer, expected):
        value = identity(pointer, expected)
        key = (pointer, expected)
        if key in objects and objects[key] != value:
            raise ValueError('The selected HUD object identity changed')
        objects[key] = value
        return value

    def hud_class(pointer):
        represented = []
        cursor, seen = pointer, set()
        while cursor:
            if cursor in seen or len(seen) >= 32:
                raise ValueError('HUD UClass ancestry is cyclic or over bound')
            seen.add(cursor)
            value = typed(cursor, 'Class')
            represented.append(value['name'])
            cursor = struct.unpack('<Q', read.fact(cursor + 0x48, 8))[0]
        if 'HUD' not in represented:
            raise ValueError('The referenced UClass does not derive from HUD')
        return represented

    recheck_binding()
    typed(pc, 'PlayerController')
    typed(driver, 'NetDriver')
    typed(connection, 'NetConnection')
    if (read.pointer(driver + 0x98) != connection or read.pointer(connection + 0x58) != driver):
        raise ValueError('The current primary driver/connection binding changed')
    package_map = read.pointer(connection + 0x68)
    typed(package_map, 'PackageMapClient')
    if read.pointer(package_map + 0x130) != connection:
        raise ValueError('The current PackageMap backlink changed')
    table = read.pointer(package_map)
    if (not base <= table <= base + IMAGE_BYTES - 0x2d0 or
            read.pointer(table + 0x2c8) != base + LOOKUP_TARGET_RVA):
        raise ValueError('The current PackageMap GUID lookup is outside the cached source')
    cache = read.pointer(package_map + 0x310)
    if read.fact(cache + 0x152, 1) != b'\0' or read.fact(connection + 0xb4, 1)[0] & 1:
        raise ValueError('Only the ordinary non-export GUID reference state is supported')
    header = read.fact(cache, 0x50)
    rows = []
    for guid, expected_path in zip(GUIDS, (HUD_PACKAGE, HUD_CLASS)):
        found = _lookup(read, cache, header, guid)
        row = dict(guid=guid, expected_path=expected_path, status='mapping_missing')
        if found is not None:
            index, weak = found
            entry_at = struct.unpack_from('<Q', header)[0] + index * 56
            entry = read.fact(entry_at, 56)
            if struct.unpack_from('<I', entry)[0] != guid or entry[8:16] != weak:
                raise ValueError('The selected GUID record changed')
            token = entry[0x14:0x1c]
            name = resolve_name(read.fact, base, token).display_text
            flags = entry[0x28]
            row.update(status='path_entry_observed', map_slot_index=index,
                export_name=name, outer_guid=struct.unpack_from('<I', entry, 0x10)[0],
                network_checksum=struct.unpack_from('<I', entry, 0x1c)[0],
                native_flags_u8=flags, no_load=bool(flags & 1), broken=bool(flags & 8),
                resolution_skip_bit4=bool(flags & 4), weak_reference_hex=weak.hex())
            row['resolved_object'] = _existing_weak(read, base, weak)
            row['weak_slot_diagnostic'] = weak_slot_diagnostic(read, base, weak)
            resolved = row['resolved_object']
            if resolved['status'] == 'existing_object_observed':
                pointer = resolved['object_address']
                resolved['identity'] = typed(pointer, 'Package' if guid == GUIDS[0] else 'Class')
                resolved['object_path'] = object_path(read.fact, base, pointer)
                resolved['matches_expected_path'] = resolved['object_path'] == expected_path
                if guid == GUIDS[1]:
                    resolved['represented_class_ancestry'] = hud_class(pointer)
        rows.append(row)
    fields = []
    for name, offset, expected in (('MyHUD', 0x400, 'HUD'), ('DeferredSpawnHUDClass', 0x8a0, 'Class')):
        pointer = struct.unpack('<Q', read.fact(pc + offset, 8))[0]
        result = dict(field_name=name, native_storage_offset=offset, status='null_reference')
        if pointer:
            result.update(status='typed_existing_reference', identity=typed(address(pointer), expected),
                          object_path=object_path(read.fact, base, pointer))
            if expected == 'Class':
                result['represented_class_ancestry'] = hud_class(pointer)
        fields.append(result)
    recheck_binding()
    for (pointer, expected), before in objects.items():
        if identity(pointer, expected) != before:
            raise ValueError('The selected HUD identity changed before publishing')
    read.recheck()
    return dict(guid_cache_address=cache, package_map_address=package_map, guid_mappings=rows,
        controller_fields=fields, read_calls=read.calls, read_bytes=read.bytes,
        primary_connection_and_metadata_rechecked=True, native_getters_invoked=False,
        missing_references_resolved=False, native_objects_created=False)


def observe(game_root, trial_report):
    trial_raw = Path(trial_report).read_bytes()
    trial = json.loads(trial_raw)
    pid, created = owned_trial_identity(trial, game_root)
    pins = source_pins(game_root)
    served = trial.get('portable_map_bootstrap', {}).get('source_pins', {})
    if served.get(SCHEMA) != SCHEMA_SHA256:
        raise ValueError('The active trial did not install this HUD source schema')
    executable, image_size = validate_source(game_root)
    reader = Win32MetadataReader(executable, image_size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, image_size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True,
            _binding_identity_sink=sink, unpublished_batch_retry=True)
        pcs = [p for p in roots['connection_binding_observations']['player_controllers']
            if p.get('status') == 'observed' and p.get('identity_and_fields_rechecked') is True and
            p.get('driver_primary_matches_original_connection') is True and p.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One current owned primary controller is required')
        pc = pcs[0]
        result = observe_selected(session, base, pc=address(pc['address']), driver=address(pc['driver']),
            connection=address(pc['connection']), identity=sink['callback'], recheck_binding=sink['recheck_roots'])
        reader.verify_identity()
        if reader.find_module() != base:
            raise ValueError('The qualified module changed')
        if pins != source_pins(game_root):
            raise ValueError('The HUD observation sources changed while reading')
        return dict(kind='owned_portable_hud_guid_observation', status='observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(), primary_connection_binding=pc,
            **result, process_identity_rechecked=True, historical_process_pointers_reused=False,
            process_memory_written=False, native_methods_invoked=False, packets_sent=False,
            snapshot_atomic=False, hud_creation_verified=False)
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    opts = parser.parse_args()
    output = opts.output.resolve()
    if not output.is_relative_to((ROOT / 'work').resolve()) or output.exists():
        parser.error('Output must be a new project work file')
    owned_trial_identity(json.loads(opts.trial_report.read_bytes()), opts.game_root)
    source_pins(opts.game_root)
    if opts.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(opts.game_root.resolve()),
            '--trial-report', str(opts.trial_report.resolve()), '--output', str(output)], output)
        result = json.loads(output.read_bytes())
    else:
        try:
            result = observe(opts.game_root, opts.trial_report)
        except Exception as error:
            result = dict(status='refused', error_type=type(error).__name__, reason=str(error),
                process_memory_written=False, native_methods_invoked=False, packets_sent=False)
        write_exclusive_report(output, result)
    print(json.dumps(dict(status=result['status'], reason=result.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
