"""Readonly metadata for components of the current owned map Pawn.

Uses the same-build tracked object/field readers, not unavailable private
profiles. No setters, native calls, injections, GUID allocations or packets.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

from observe_portable_map_runtime import (ROOT, SHIPPING_SHA256, Win32MetadataReader,
    MetadataSession, validate_source, discover_roots, observe_first_player_state,
    direct_root_reference, object_name, observed_virtual_method, recheck_virtual_method,
    player_state_layout, read_declared_scalar_fields)
from native_metadata_objects import validate_object_record
from native_metadata_names import resolve_name
from export_native_replication_metadata import export_existing_driver_class


def declared_fields(session, base, klass, identity):
    """Walk bounded declared FProperties; record types without choosing values."""
    result, reads, classes, nodes = [], [], set(), set()

    def read(address, length):
        raw = session.stable(address, length)
        reads.append((address, raw))
        return raw

    while klass:
        if klass in classes or len(classes) >= 32:
            raise ValueError('Class cycle or depth bound')
        classes.add(klass)
        before = identity(klass, 'Class')
        parent = struct.unpack('<Q', read(klass + 0x48, 8))[0]
        node = struct.unpack('<Q', read(klass + 0x70, 8))[0]
        fields = []
        while node:
            if node in nodes or len(nodes) >= 1024:
                raise ValueError('Field cycle or count bound')
            nodes.add(node)
            raw = read(node, 0x60)
            table, owner = struct.unpack_from('<QQ', raw)
            following, field_class = struct.unpack_from('<QQ', raw, 0x18)
            mask = struct.unpack('<Q', read(field_class + 0x10, 8))[0]
            if mask & 1 and mask & 0x8000:
                if not raw[0x10] or owner != klass:
                    raise ValueError('Declared field owner differs from current class')
                dimension, size = struct.unpack_from('<ii', raw, 0x3c)
                offset = struct.unpack_from('<i', raw, 0x54)[0]
                if not 0 < dimension <= 1024 or not 0 < size <= 65536 or not 0 <= offset < 1 << 24:
                    raise ValueError('Declared field bounds changed')
                name = object_name(session.read, base, node, field_representation=0).display_text
                hooks = {}
                for slot in (0x88, 0x90):
                    hook = observed_virtual_method(session, base, node, slot)
                    recheck_virtual_method(session, base, node, hook)
                    hooks[hex(slot)] = {k: v for k, v in hook.items() if k not in ('vtable_address', 'target_address')}
                row = dict(name=name, storage_offset=offset, element_bytes=size,
                    array_dimension=dimension, property_flags=hex(struct.unpack_from('<Q', raw, 0x48)[0]),
                    declared_rep_index=struct.unpack_from('<H', raw, 0x50)[0], hooks=hooks,
                    field_vtable_rva=table-base if base <= table < base+0x1ff8f000 else None)
                if name == 'currentCharacterHeroID':
                    notify = read(node + 0x5c, 8)
                    row['repnotify_name'] = resolve_name(session.read, base, notify).display_text
                fields.append(row)
            node = following
        if identity(klass, 'Class') != before:
            raise ValueError('Declared class identity changed')
        result.append(dict(class_name=before['name'], fields=fields))
        klass = parent
    if any(session.stable(address, len(raw)) != raw for address, raw in reads):
        raise ValueError('Declared fields changed during observation')
    return result


def observe(trial_report, game_root):
    trial = json.loads(trial_report.read_bytes())
    if trial.get('record_complete') is True or trial.get('client_shadow_mode') is not True:
        raise ValueError('An active owned shadow trial is required')
    if Path(trial['test_game_root']).resolve() != game_root.resolve():
        raise ValueError('The owned shadow root changed')
    owned = {(r['pid'], r['created_at']) for r in trial['process_observations']
             if r.get('name') == 'deltaforceclient-win64-shipping.exe'}
    if len(owned) != 1:
        raise ValueError('One owned Shipping process is required')
    pid, created = next(iter(owned))
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True, first_player_state=True,
                               _binding_identity_sink=sink, unpublished_batch_retry=True)
        identity = sink['callback']
        candidates = [pc for pc in roots['connection_binding_observations']['player_controllers']
            if pc.get('status') == 'observed' and pc.get('driver_primary_matches_original_connection') is True
            and pc.get('identity_and_fields_rechecked') is True and pc.get('local_player_index_field') == 0]
        if len(candidates) != 1:
            raise ValueError('One current primary owned controller is required')
        pc = candidates[0]
        pc_address, driver, connection = (int(pc[k], 16) for k in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_address, object_identity=identity)
        pawn = binding['pc_pawn_reference']
        ps = binding['pc_player_state_reference']
        if pawn.get('status') != 'typed_existing_reference' or ps.get('status') != 'typed_existing_reference':
            raise ValueError('Current Pawn and PlayerState are required')
        result = dict(kind='owned_map_component_metadata_observation', client_sha256=SHIPPING_SHA256,
            pid=pid, source_qualification='tracked_same_build_readers_and_current_owned_typed_fields',
            process_memory_written=False, native_methods_invoked=False, packets_sent=False,
            unavailable_private_source_profiles_reconstructed=False)
        result['bounded_native_code'] = []
        for name, rva, length in (('actor_open_rotation_branch', 0x12bcce00, 192),
                ('player_state_avatar_notify', 0xb574b50, 4096),
                ('player_state_hero_notify', 0xb576330, 4096),
                ('fashion_component_avatar_consumer', 0xb04ebf0, 4096)):
            code = session.stable(base+rva, length)
            result['bounded_native_code'].append(dict(name=name, rva=rva, bytes=length,
                sha256=hashlib.sha256(code).hexdigest(), hex=code.hex(),
                source='tracked_same_build_static_analysis_anchor',
                complete_function_or_execution_verified=False))
        rotation = session.stable(pc_address+0x3d8, 12)
        result['controller_rotation'] = dict(stored_xyz=list(struct.unpack('<fff', rotation)),
            source='tracked_same_build_ControlRotation_declaration',
            native_getter_binding_verified=False, final_camera_rotation_verified=False)
        ps_schema = player_state_layout(session, base, roots, driver)
        result['player_state_uin'] = read_declared_scalar_fields(session, ps['address'], ps_schema, {'Uin': 20})['Uin']
        component_raw = session.stable(pawn['address'] + 0x26a8, 8)
        component = struct.unpack('<Q', component_raw)[0]
        fashion = identity(component, 'CharacterFashionComponent')
        owner = direct_root_reference(struct.unpack('<Q', session.stable(component + 0x100, 8))[0])
        receiver = direct_root_reference(struct.unpack('<Q', session.stable(component + 0x4d0, 8))[0])
        if owner != pawn['address'] or receiver != pawn['address']:
            raise ValueError('Fashion owner and receiver must be the current owned Pawn')
        try:
            klass = int(fashion['class_address'], 16)
            fields = declared_fields(session, base, klass, identity)
            record = validate_object_record(session.read, base, klass)
            existing = export_existing_driver_class(session, driver, struct.pack('<iI', record.index, record.serial))
            # Existing cache lookup never creates a layout. Missing is kept missing.
            result['fashion'] = dict(status='observed', class_name=fashion['class_ancestry'][0], declarations=fields,
                owner_and_receiver_match_current_pawn=True, existing_driver_class=existing,
                hero_id=struct.unpack('<Q', session.stable(component+0x508, 8))[0])
        except (ValueError, KeyError) as error:
            result['fashion'] = dict(status='refused', reason=str(error), error_type=type(error).__name__)
        if (identity(component, 'CharacterFashionComponent') != fashion or
                session.stable(pawn['address'] + 0x26a8, 8) != component_raw or
                read_declared_scalar_fields(session, ps['address'], ps_schema, {'Uin': 20})['Uin'] != result['player_state_uin']):
            raise ValueError('Selected component or player identity changed')
        sink['recheck_roots']()
        reader.verify_identity()
        result.update(status='observed', identities_and_fields_rechecked=True,
                      read_calls=session.calls, read_bytes=session.bytes_read)
        return result
    finally:
        reader.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output.exists():
        parser.error('Output must be a new project file')
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        command = subprocess.list2cmdline(['-B', str(Path(__file__).resolve()),
            '--trial-report', str(args.trial_report.resolve()), '--game-root', str(args.game_root.resolve()),
            '--output', str(output)])
        outcome = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, command, str(ROOT), 0)
        if outcome <= 32:
            raise OSError('Normal Windows elevation was not granted')
        print(json.dumps(dict(status='readonly_component_observation_requested', output=str(output))))
    else:
        try:
            report = observe(args.trial_report, args.game_root)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                          process_memory_written=False, native_methods_invoked=False)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
