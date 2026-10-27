"""Read typed binding facts from this project's currently owned shadow trial.

Uses the tracked reader's same-build offsets, independently of unavailable old
private source ledgers. The output records that provenance explicitly. No old
capture is relabelled as verified, no native getter is called, and nothing is
written into the client. Diagnostic observations do not authorize wire values.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from export_native_replication_metadata import (SHIPPING_SHA256, Win32MetadataReader,
    MetadataSession, validate_source, discover_roots, observed_virtual_method,
    recheck_virtual_method, ACTOR_CHANNEL_OPEN_SLOT, export_existing_driver_class,
    object_name, PROPERTY_SERIALIZER_SLOT, PROPERTY_SCALAR_LEAF_SLOT)
from native_gp_first_player_state import observe_first_player_state
from native_world_settings_context import observe_controller_world_settings
from native_metadata_paths import object_path
from native_metadata_objects import validate_object_record
from native_metadata_names import resolve_name


def direct_root_reference(raw):
    if type(raw) is not int or not 0 <= raw < 1 << 64:
        raise ValueError('Root reference must be uint64')
    stored = (raw >> 48) & 3
    mode = 1 if stored & 1 else stored
    active = mode == 1 or bool(raw >> 63)
    pointer = raw & 0xffffffffffff
    if pointer and not (mode == 0 or mode == 2 and not active):
        raise ValueError('Root reference requires an unimplemented native callback')
    if pointer and (not 0x10000 <= pointer < 1 << 47 or pointer & 7):
        raise ValueError('Root reference is outside aligned user objects')
    return pointer


def position_context(session, base, pawn, identity, *, actor_base_class='Pawn'):
    before = identity(pawn, actor_base_class)
    root_raw = session.stable(pawn + 0x180, 8)
    root = direct_root_reference(struct.unpack('<Q', root_raw)[0])
    if not root:
        return dict(status='root_unavailable')
    root_identity = identity(root, 'SceneComponent')
    tag = session.stable(root + 0x240, 4)
    if struct.unpack('<H', tag[:2])[0] != 0xffff:
        return dict(status='scene_translation_representation_unsupported')
    position = session.stable(root + 0x220, 16)
    xyz = struct.unpack('<fff', position[:12])
    if not all(math.isfinite(v) for v in xyz):
        raise ValueError('Scene translation is nonfinite')
    level = struct.unpack('<Q', session.stable(pawn + 0x10, 8))[0]
    level_identity = identity(level, 'Level')
    world = struct.unpack('<Q', session.stable(level + 0x10, 8))[0]
    world_identity = identity(world, 'World')
    origin_raw = session.stable(world + 0x640, 12)
    defaults = {}
    from native_spawn_default_state import FIELDS
    for name, rva, length, storage in FIELDS:
        raw = session.stable(base + rva, length)
        if raw != session.stable(base + rva, length):
            raise ValueError('Spawn global changed during observation')
        defaults[name] = list(struct.unpack('<' + ('f' if storage.startswith('float') else 'i') * (length // 4), raw))
    if (identity(pawn, actor_base_class) != before or identity(root, 'SceneComponent') != root_identity or
            identity(level, 'Level') != level_identity or identity(world, 'World') != world_identity or
            session.stable(pawn + 0x180, 8) != root_raw or
            session.stable(root + 0x240, 4) != tag or
            session.stable(root + 0x220, 16) != position or
            session.stable(world + 0x640, 12) != origin_raw):
        raise ValueError('Pawn position or owning world changed during observation')
    return dict(status='observed', root_world_translation_xyz=list(xyz),
        pawn_owning_world_path=object_path(session.read, base, world),
        pawn_owning_world_origin_xyz=list(struct.unpack('<iii', origin_raw)),
        spawn_global_defaults=defaults, identities_and_fields_rechecked=True,
        packed_runtime_callback_invoked=False, scene_translation_plain_tag_ffff=True,
        level_transform_verified=False)


def loaded_player_starts(session, base, identity, catalog, candidates):
    """Find only authored PlayerStart actors from the exact Dam catalog package."""
    group = catalog['spawn_groups'][0]
    wanted = {r['actor']: r for r in group['player_starts']}
    package = group['package']
    rows = []
    for record in candidates:
        address = record['address']
        path = object_path(session.read, base, address)
        if not path.startswith(package + '.') or path.rsplit('.', 1)[-1] not in wanted:
            continue
        row_identity = identity(address, 'PlayerStart')
        row = dict(asset_path=path, actor_name=path.rsplit('.', 1)[-1],
            object_index=record['object_index'], serial=record['serial'], group_id=group['group_id'],
            team_start_group_id=group['team_start_group_id'])
        try:
            row['position_context'] = position_context(session, base, address,
                                                       identity, actor_base_class='PlayerStart')
        except ValueError as error:
            row['position_context'] = dict(status='refused', reason=str(error))
        row['asset_transform'] = wanted[row['actor_name']]['transform']
        if identity(address, 'PlayerStart') != row_identity:
            raise ValueError('Selected PlayerStart identity changed')
        rows.append(row)
        if len(rows) > len(wanted):
            raise ValueError('Duplicate loaded PlayerStart path is ambiguous')
    return rows


def player_state_layout(session, base, roots, driver, class_name='BP_SOLPlayerState_C'):
    classes = [r for r in roots['classes'] if r['name'] == class_name]
    if len(classes) != 1 or classes[0].get('key') is None:
        return dict(status='player_state_class_key_unavailable')
    klass = classes[0]
    before = validate_object_record(session.read, base, klass['address'])
    result = export_existing_driver_class(session, driver, bytes.fromhex(klass['key']))
    result.update(class_name=klass['name'], class_asset_path=klass['asset_path'])
    for command in result.get('layout', {}).get('commands', []):
        if command.get('dispatch_opcode') == 1:
            if command['descriptor_address']:
                raise ValueError('Special layout return has a nonnull descriptor')
        elif command['descriptor_address']:
            address = command['descriptor_address']
            command['descriptor_name'] = object_name(session.read, base, address,
                                                     field_representation=0).display_text
            hook = observed_virtual_method(session, base, address, PROPERTY_SERIALIZER_SLOT)
            recheck_virtual_method(session, base, address, hook)
            command['property_serializer_hook'] = hook
            if hook.get('target_rva') == 0x10e5ce20:
                leaf = observed_virtual_method(session, base, address, PROPERTY_SCALAR_LEAF_SLOT)
                recheck_virtual_method(session, base, address, leaf)
                command['property_scalar_leaf_hook'] = leaf
    if validate_object_record(session.read, base, klass['address']) != before:
        raise ValueError('PlayerState class changed during schema observation')
    return result


def read_declared_scalar_fields(session, instance, metadata, requested):
    """Read a bounded set of scalar top-level properties from this live layout."""
    formats = {21: ('?', 1), 6: ('B', 1), 5: ('i', 4), 4: ('f', 4), 20: ('Q', 8)}
    if len(requested) > 16 or any(opcode not in formats for opcode in requested.values()):
        raise ValueError('Only bounded native scalar declarations are supported')
    layout = metadata.get('layout', {})
    parents, commands = layout.get('parents', []), layout.get('commands', [])
    result, reads = {}, []
    for name, opcode in requested.items():
        matches = [c for c in commands if c.get('descriptor_name') == name and
            type(c.get('parent_index')) is int and 0 <= c['parent_index'] < len(parents) and
            c.get('descriptor_address') and
            parents[c['parent_index']].get('descriptor_address') == c['descriptor_address']]
        if not matches:
            result[name] = dict(status='not_in_current_layout')
            continue
        if (len(matches) != 1 or matches[0].get('dispatch_opcode') != opcode or
                type(matches[0].get('data_offset')) is not int or
                not 0 < matches[0]['data_offset'] < 65536):
            raise ValueError('Current scalar field declaration is ambiguous or changed: ' + name)
        command = matches[0]
        fmt, size = formats[opcode]
        raw = session.stable(instance + command['data_offset'], size)
        if len(raw) != size or opcode == 21 and raw not in (b'\0', b'\1'):
            raise ValueError('Native scalar storage differs from its declared subset: ' + name)
        value = struct.unpack('<' + fmt, raw)[0]
        if type(value) is float and not math.isfinite(value):
            raise ValueError('Native scalar is not finite: ' + name)
        result[name] = dict(status='observed', value=value, raw_hex=raw.hex(),
                            native_data_offset=command['data_offset'])
        reads.append((instance + command['data_offset'], size, raw))
    if any(session.stable(address, size) != raw for address, size, raw in reads):
        raise ValueError('Selected scalar fields changed during observation')
    return result


def appearance_context(session, base, pawn, identity):
    """Observe the tracked same-build Fashion component without changing IDs."""
    before = identity(pawn, 'Pawn')
    component_raw = session.stable(pawn + 0x26a8, 8)
    component = struct.unpack('<Q', component_raw)[0]
    if not component:
        return dict(status='component_unavailable')
    component_identity = identity(component, 'CharacterFashionComponent')
    if component_identity.get('class_ancestry', [None])[0] != 'DFMCharacterFashionComponent':
        raise ValueError('The current Pawn Fashion class differs from its tracked declaration')
    receiver_raw = session.stable(component + 0x4d0, 8)
    receiver = direct_root_reference(struct.unpack('<Q', receiver_raw)[0])
    current_hero = session.stable(component + 0x508, 8)
    default_hero = session.stable(pawn + 0x26c0, 8)
    if (identity(pawn, 'Pawn') != before or
            identity(component, 'CharacterFashionComponent') != component_identity or
            session.stable(pawn + 0x26a8, 8) != component_raw or
            session.stable(component + 0x4d0, 8) != receiver_raw or
            session.stable(component + 0x508, 8) != current_hero or
            session.stable(pawn + 0x26c0, 8) != default_hero):
        raise ValueError('The current Pawn Fashion relationship or IDs changed')
    return dict(status='observed', component_class=component_identity['class_ancestry'][0],
        receiver_is_current_pawn=receiver == pawn,
        currentCharacterHeroID=struct.unpack('<Q', current_hero)[0],
        DefaultHeroID=struct.unpack('<Q', default_hero)[0],
        source='tracked_same_build_appearance_receiver_field_offsets',
        unavailable_original_private_ledgers_verified=False,
        identities_and_fields_rechecked=True, process_memory_written=False)


def role_layout_context(session, base, metadata, identity):
    """Observe the live byte enum and normal receiver's alternate Role parent."""
    layout = metadata['layout']
    address = layout['layout_address']
    header = session.stable(address + 0x40, 32)
    pp, pn, _, cp, cn, _ = struct.unpack('<QiiQii', header)
    if pn != len(layout['parents']) or cn != len(layout['commands']):
        raise ValueError('Role layout header changed')
    flag = session.stable(address + 0x30, 1)
    if not flag[0] & 2:
        raise ValueError('The normal receiver Role remapping flag is absent')
    if session.stable(base + 0xd968d0, 4) != bytes.fromhex('488b01c3'):
        raise ValueError('Enum array accessor is outside the supported direct subset')
    rows, reads = {}, []
    for name in ('Role', 'RemoteRole'):
        commands = [c for c in layout['commands'] if c.get('descriptor_name') == name]
        if len(commands) != 1:
            raise ValueError('One native Role byte declaration is required')
        c = commands[0]
        hook = c['property_serializer_hook']
        if (c['dispatch_opcode'] != 6 or hook.get('target_rva') != 0x10e8ec50 or
                hook.get('identity_rechecked') is not True):
            raise ValueError('The observed byte serializer is required for Role')
        parent = layout['parents'][c['parent_index']]
        parent_raw = session.stable(pp + c['parent_index'] * 64, 64)
        if hashlib.sha256(parent_raw).hexdigest() != parent['record_sha256']:
            raise ValueError('Role parent changed before remap observation')
        alternate = struct.unpack_from('<i', parent_raw, 0x28)[0]
        if not 0 <= alternate < pn:
            raise ValueError('The alternate Role parent is unavailable')
        other_raw = session.stable(pp + alternate * 64, 64)
        if hashlib.sha256(other_raw).hexdigest() != layout['parents'][alternate]['record_sha256']:
            raise ValueError('The alternate Role parent changed')
        destination = layout['commands'][struct.unpack_from('<H', other_raw, 0x24)[0]]
        if destination.get('descriptor_name') not in ('Role', 'RemoteRole') or destination['descriptor_name'] == name:
            raise ValueError('The native Role remap does not target its counterpart')
        enum_raw = session.stable(c['descriptor_address'] + 0x90, 8)
        enum = struct.unpack('<Q', enum_raw)[0]
        enum_identity = identity(enum, 'Enum')
        if enum_identity.get('name') != 'ENetRole':
            raise ValueError('The Role descriptor does not use typed ENetRole metadata')
        eh = session.stable(enum + 0x40, 12)
        data, count = struct.unpack('<Qi', eh)
        if not 1 <= count <= 64:
            raise ValueError('The native Role enum exceeds its read bound')
        values_raw = session.stable(data, count * 16)
        values = {resolve_name(session.read, base, values_raw[i:i+8]).display_text:
                  struct.unpack_from('<q', values_raw, i + 8)[0] for i in range(0, len(values_raw), 16)}
        if len(values) != count or not all(0 <= v <= 256 for v in values.values()):
            raise ValueError('The Role enum names or byte values are ambiguous')
        if identity(enum, 'Enum') != enum_identity:
            raise ValueError('The Role enum identity changed')
        maximum = max(values.values())
        rows[name] = dict(wire_handle=c['relative_handle'], enum_values=values,
            enum_maximum=maximum, wire_bit_count=0 if maximum <= 1 else (maximum - 1).bit_length(),
            source_offset=c['data_offset'], destination_field=destination['descriptor_name'],
            destination_offset=destination['data_offset'], serializer_target_rva=hook['target_rva'])
        reads += [(pp + c['parent_index'] * 64, parent_raw), (pp + alternate * 64, other_raw),
                  (c['descriptor_address'] + 0x90, enum_raw), (enum + 0x40, eh), (data, values_raw)]
    if (session.stable(address + 0x40, 32) != header or session.stable(address + 0x30, 1) != flag or
            any(session.stable(at, len(raw)) != raw for at, raw in reads)):
        raise ValueError('Role enum or destination metadata changed during observation')
    return dict(status='observed', fields=rows, normal_receiver_remap_enabled=True,
        identities_and_fields_rechecked=True, source='current_owned_pawn_existing_layout_and_typed_enum',
        unavailable_original_private_ledgers_verified=False, process_memory_written=False)


def observe(game_root, trial_report, *, maximum_seconds=120, include_player_starts=False):
    raw = Path(trial_report).read_bytes()
    trial = json.loads(raw)
    if trial.get('record_complete') is True or trial.get('client_shadow_mode') is not True:
        raise ValueError('A currently running owned shadow trial is required')
    if Path(trial['test_game_root']).resolve() != Path(game_root).resolve():
        raise ValueError('Game root does not match the owned trial')
    identities = {(r['pid'], r['created_at']) for r in trial['process_observations']
                  if r.get('name') == 'deltaforceclient-win64-shipping.exe'}
    if len(identities) != 1:
        raise ValueError('One owned Shipping identity is required')
    pid, created = next(iter(identities))
    executable, image_size = validate_source(game_root)
    result = dict(kind='portable_owned_map_runtime_observation',
        client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
        observed_at_utc=datetime.now(timezone.utc).isoformat(),
        source_qualification='tracked_same_build_readers_and_current_process_identity',
        unavailable_original_private_ledgers_verified=False,
        process_memory_written=False, native_methods_invoked=False,
        historical_process_pointers_reused=False, playable_map_verified=False)
    dependencies = ('work/observe_portable_map_runtime.py', 'work/export_native_replication_metadata.py',
        'work/native_connection_binding.py', 'work/native_gp_first_player_state.py',
        'work/native_world_settings_context.py', 'work/native_gp_bind_gate.py',
        'work/native_spawn_default_state.py', 'work/native_pawn_world_position.py',
        'work/native_packed_object_reference.py', 'work/native_world_origin_state.py',
        'work/native_metadata_names.py', 'work/native_metadata_objects.py', 'work/native_metadata_paths.py')
    result['reader_source_pins'] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                     for p in dependencies}
    reader = Win32MetadataReader(executable, image_size, pid, created,
                                 maximum_seconds=maximum_seconds)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, image_size
        sink, start_candidates = {}, []
        roots = discover_roots(session, reader.module_base, connection_binding_only=True,
            first_player_state=True, _binding_identity_sink=sink,
            unpublished_batch_retry=True,
            **({'_player_start_candidates': start_candidates} if include_player_starts else {}))
        result['connection_binding_observations'] = roots['connection_binding_observations']
        callback = sink['callback']
        if include_player_starts:
            catalog_path = ROOT / 'outputs/df-local-server/protocol/dam_gameplay_asset_catalog.json'
            catalog_raw = catalog_path.read_bytes()
            catalog = json.loads(catalog_raw)
            if catalog.get('source_client_sha256') != SHIPPING_SHA256 or catalog.get('map_id') != 2201:
                raise ValueError('PlayerStart catalog is for another map or build')
            result['player_start_catalog_sha256'] = hashlib.sha256(catalog_raw).hexdigest()
            result['loaded_player_start_metadata_candidates'] = len(start_candidates)
            result['loaded_player_starts'] = loaded_player_starts(session, reader.module_base,
                                                                  callback, catalog, start_candidates)
        views = []
        for pc in roots['connection_binding_observations']['player_controllers']:
            if not (pc.get('status') == 'observed' and pc.get('identity_and_fields_rechecked') is True
                    and pc.get('driver_primary_matches_original_connection') is True
                    and pc.get('local_player_index_field') == 0):
                continue
            address, driver, connection = (int(pc[k], 16) for k in ('address', 'driver', 'connection'))
            view = dict(first_player_state=observe_first_player_state(session, reader.module_base,
                driver_address=driver, connection_address=connection, pc_address=address,
                object_identity=callback))
            view['player_state_replication_metadata'] = player_state_layout(session,
                reader.module_base, roots, driver)
            pc_metadata = player_state_layout(session, reader.module_base, roots, driver,
                                              'BP_DFMPlayerController_C')
            view['controller_replication_metadata'] = pc_metadata
            view['controller_input_fields'] = read_declared_scalar_fields(session, address, pc_metadata,
                {'bServerEnableProcessPlayerInput': 21, 'bIsSpectatingAI': 21})
            state = view['first_player_state']
            pawn = state.get('pc_pawn_reference', {})
            if pawn.get('status') == 'typed_existing_reference':
                pawn_metadata = player_state_layout(session, reader.module_base, roots, driver,
                                                     'BP_DFMCharacter_C')
                view['pawn_replication_metadata'] = pawn_metadata
                pawn_identity = callback(pawn['address'], 'Pawn')
                view['pawn_movement_fields'] = read_declared_scalar_fields(session, pawn['address'], pawn_metadata,
                    {'Role': 6, 'RemoteRole': 6, 'ReplicatedMovementMode': 6,
                     'bIsDead': 21, 'MovementVelocityScaler': 4, 'bIsPlayerAI': 21})
                try:
                    view['pawn_role_metadata'] = role_layout_context(session, reader.module_base,
                                                                    pawn_metadata, callback)
                except ValueError as error:
                    view['pawn_role_metadata'] = dict(status='refused', reason=str(error))
                try:
                    view['pawn_appearance_context'] = appearance_context(session, reader.module_base,
                                                                        pawn['address'], callback)
                except ValueError as error:
                    view['pawn_appearance_context'] = dict(status='refused', reason=str(error))
                if callback(pawn['address'], 'Pawn') != pawn_identity:
                    raise ValueError('Current Pawn changed during movement state observation')
                try:
                    view['pawn_position_context'] = position_context(session, reader.module_base,
                        pawn['address'], callback)
                except ValueError as error:
                    view['pawn_position_context'] = dict(status='refused', reason=str(error))
            player_state = state.get('pc_player_state_reference', {})
            if player_state.get('status') == 'typed_existing_reference':
                ps = player_state['address']
                callback(ps, 'PlayerState')
                avatar_raw = session.stable(ps + 0x9f8, 0x20)
                if session.stable(ps + 0x9f8, 0x20) != avatar_raw:
                    raise ValueError('PlayerState avatar fields changed')
                view['player_state_avatar_fields'] = dict(HeroID=struct.unpack_from('<q', avatar_raw)[0],
                    CurrSameTeamAvatarId=struct.unpack_from('<Q', avatar_raw, 0x10)[0],
                    CurrDiffTeamAvatarId=struct.unpack_from('<Q', avatar_raw, 0x18)[0],
                    source='tracked_same_build_human_player_state_field_offsets',
                    identities_and_fields_rechecked=True)
            view['world_settings'] = observe_controller_world_settings(session, pc_address=address,
                                                                       object_identity=callback)
            level = struct.unpack('<Q', session.stable(address + 0x10, 8))[0]
            settings = struct.unpack('<Q', session.stable(level + 0x240, 8))[0]
            if settings:
                callback(settings, 'DFMWorldSettings')
                path = object_path(session.read, reader.module_base, settings)
                hook = observed_virtual_method(session, reader.module_base, settings, ACTOR_CHANNEL_OPEN_SLOT)
                recheck_virtual_method(session, reader.module_base, settings, hook)
                if hook.get('inside_pinned_image') is True:
                    prefix = session.stable(hook['target_address'], 3)
                    hook['code_prefix_hex'] = prefix.hex()
                    hook['empty_return_observed'] = prefix == bytes.fromhex('c20000')
                view['world_settings_actor'] = dict(asset_path=path, actor_channel_open_hook=hook)
            views.append(view)
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module() != reader.module_base:
            raise ValueError('Pinned module changed during observation')
        result.update(status='observed', primary_controller_views=views,
            read_calls=session.calls, read_bytes=session.bytes_read,
            process_identity_rechecked=True, selected_roots_rechecked=True)
        return result
    finally:
        reader.close()


def request_elevation(worker_args, output):
    """Keep the bounded read job alive until its normally elevated worker exits."""
    from ctypes import wintypes
    from export_native_replication_metadata import kernel

    class ShellInfo(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.DWORD), ('fMask', wintypes.ULONG),
            ('hwnd', wintypes.HWND), ('lpVerb', wintypes.LPCWSTR),
            ('lpFile', wintypes.LPCWSTR), ('lpParameters', wintypes.LPCWSTR),
            ('lpDirectory', wintypes.LPCWSTR), ('nShow', ctypes.c_int),
            ('hInstApp', wintypes.HINSTANCE), ('lpIDList', ctypes.c_void_p),
            ('lpClass', wintypes.LPCWSTR), ('hkeyClass', wintypes.HKEY),
            ('dwHotKey', wintypes.DWORD), ('hIcon', wintypes.HANDLE),
            ('hProcess', wintypes.HANDLE)]

    api = kernel()
    shell = ctypes.WinDLL('shell32', use_last_error=True).ShellExecuteExW
    shell.argtypes, shell.restype = [ctypes.POINTER(ShellInfo)], wintypes.BOOL
    info = ShellInfo()
    info.cbSize, info.fMask, info.lpVerb = ctypes.sizeof(info), 0x140, 'runas'
    info.lpFile, info.lpDirectory, info.nShow = sys.executable, str(ROOT), 0
    info.lpParameters = subprocess.list2cmdline(worker_args)
    if not shell(ctypes.byref(info)):
        raise OSError(ctypes.get_last_error(), 'Normal Windows elevation was not granted')
    try:
        if not info.hProcess:
            raise OSError('Windows returned no observer process identity handle')
        worker_pid = api.GetProcessId(info.hProcess)
        if not worker_pid:
            raise OSError('Windows observer process identity is unavailable')
        print(json.dumps(dict(status='readonly_observer_authorized', worker_pid=worker_pid,
                              output=str(output))), flush=True)
        deadline = time.monotonic() + 180
        while True:
            state = api.WaitForSingleObject(info.hProcess, 1000)
            if state == 0:
                code = wintypes.DWORD()
                if not api.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
                    raise OSError(ctypes.get_last_error(), 'Cannot read observer exit code')
                if code.value or not output.is_file():
                    raise RuntimeError('Observer exited without a result: ' + hex(code.value))
                return
            if state != 0x102:
                raise OSError(ctypes.get_last_error(), 'Cannot wait for observer process')
            if time.monotonic() >= deadline:
                raise TimeoutError('The bounded read-only observer did not complete')
    finally:
        if info.hProcess:
            api.CloseHandle(info.hProcess)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    parser.add_argument('--include-player-starts', action='store_true')
    opts = parser.parse_args()
    output = opts.output.resolve()
    if not output.is_relative_to(ROOT.resolve()) or output.exists():
        parser.error('Observation output must be a new project file')
    if opts.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        worker_args = ['-B', str(Path(__file__).resolve()),
            '--game-root', str(opts.game_root.resolve()), '--trial-report', str(opts.trial_report.resolve()),
            '--output', str(output)]
        if opts.include_player_starts:
            worker_args.append('--include-player-starts')
        request_elevation(worker_args, output)
        report = json.loads(output.read_bytes())
        print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))
        raise SystemExit(0)
    try:
        report = observe(opts.game_root, opts.trial_report, include_player_starts=opts.include_player_starts)
    except Exception as error:
        report = dict(status='refused', error_type=type(error).__name__,
                      reason=str(error), process_memory_written=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'),
        primary_controller_views=len(report.get('primary_controller_views', [])), output=str(output))))
