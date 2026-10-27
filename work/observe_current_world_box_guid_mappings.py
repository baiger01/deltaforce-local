"""Read existing SafeBox GUID associations in one already owned shadow trial.

The explicit frozen profile selects three static GUIDs, not historical process
addresses. Exact PackageMap weak associations and ordinary current World level
membership are reported separately. No resolver, native method, lock inference,
memory write, packet, client launch or gameplay readiness assertion is made.
"""
import argparse
from copy import deepcopy
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import threading
from types import MappingProxyType

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'outputs/df-local-server'))

from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest
from native_guid_object_metadata import _Read, _lookup, _existing_weak, LOOKUP_TARGET_RVA
from native_metadata_paths import object_path as native_object_path
from native_replication_metadata_core import MetadataSession
from observe_owned_gameplay_metadata import address, owned_trial_identity, write_exclusive_report
from observe_portable_map_runtime import (Win32MetadataReader, validate_source, discover_roots,
    observe_first_player_state, request_elevation)
import observe_current_world_actor_membership as membership
from native_static_box_guid_sources import qualify_installed_sources as qualify_guid_sources
import native_static_box_guid_sources as sources
import current_world_box_position_readonly_scope as positions


SHIPPING_SHA256, IMAGE_SIZE = sources.SHIPPING_SHA256, membership.IMAGE_SIZE
ACCESSOR_CELL, ACCESSOR_TARGET = 0x1d59de58, 0xd968d0
MAX_PROFILE_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_SOURCE_BYTES = 512 * 1024 * 1024
_LOCK = threading.Lock()


@dataclass(frozen=True)
class BoxGuid:
    actor_path: str
    class_path: str
    guid: int


@dataclass(frozen=True)
class ProfileSelection:
    bindings: tuple
    source_pins: object
    profile_sha256: str
    recheck: object


def source_pins():
    result = sources.source_pins()
    result.update(membership.source_pins())
    result.update(positions.source_pins())
    for relative in ('work/observe_current_world_box_guid_mappings.py',
                     'work/portable_map_bootstrap.py', 'work/portable_map_level_actors.py',
                     'outputs/df-local-server/dfserver/legacy_ds_static_actor_manifest.py',
                     'work/native_replication_metadata_core.py'):
        result[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    if Path(__file__).resolve() != ROOT / 'work/observe_current_world_box_guid_mappings.py':
        raise ValueError('The SafeBox GUID observer was imported from another checkout')
    return result


def qualify_installed_sources(game_root):
    pins = qualify_guid_sources(game_root)
    pins.update(positions.sources.qualify_installed_sources(game_root))
    return pins


def _box_schema():
    return tuple(row for row in membership.sealed_scope.qualified_actor_paths()
                 if row['class_path'].endswith('BP_Interactor_Container_SafeBox_C'))


def _bindings(values):
    expected = {row['actor_path']: row['class_path'] for row in _box_schema()}
    if (type(values) is not tuple or len(values) != 3 or len(expected) != 3
            or any(type(row) is not BoxGuid or type(row.guid) is not int
                   or not 3 <= row.guid <= 0xffffffff or not row.guid & 1
                   or expected.get(row.actor_path) != row.class_path for row in values)
            or len({row.guid for row in values}) != 3
            or {row.actor_path for row in values} != set(expected)):
        raise ValueError('The three exact manifest SafeBoxes and unique static GUIDs are required')
    by_path = {row.actor_path: row for row in values}
    return tuple(by_path[row['actor_path']] for row in _box_schema())


def _read_trial(trial_report):
    path = Path(trial_report).resolve(strict=True)
    allowed = ((ROOT / 'work/native-client-tests').resolve(),
               (ROOT / 'outputs/native-account-provider').resolve())
    if not any(path.is_relative_to(parent) for parent in allowed):
        raise ValueError('Use the existing owned project trial report')
    if not 0 < path.stat().st_size <= 8 * 1024 * 1024:
        raise ValueError('The owned trial report exceeds its fixed bound')
    raw = path.read_bytes()
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('The owned trial report grew beyond its fixed bound')
    return path, raw, json.loads(raw)


def qualified_profile(profile_path, trial):
    """Select GUIDs from the exact profile and source set served in this trial."""
    from portable_map_bootstrap import load_plan
    profile_path = Path(profile_path).resolve(strict=True)
    if not profile_path.is_relative_to(ROOT) or not 0 < profile_path.stat().st_size <= 65536:
        raise ValueError('A bounded explicit frozen project profile is required')
    raw = profile_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    relative = profile_path.relative_to(ROOT).as_posix()
    served = trial.get('portable_map_bootstrap', {}).get('source_pins', {})
    if type(served) is not dict or served.get(relative) != digest:
        raise ValueError('The actual owned trial did not freeze this profile')
    plan = load_plan(ROOT, profile_path)
    if any(served.get(key) != value for key, value in plan.sources.items()):
        raise ValueError('The current profile source set differs from the actual trial freeze')
    selected = []
    expected = {row['actor_path']: row['class_path'] for row in _box_schema()}
    for manifest in plan.additional_manifests:
        if type(manifest) is StaticActorManifest and manifest.actor_path in expected:
            selected.append(BoxGuid(manifest.actor_path, manifest.class_path, manifest.actor_guid))
    bindings = _bindings(tuple(selected))
    pins = MappingProxyType(dict(plan.sources))

    def recheck():
        total = 0
        for source, expected_sha in pins.items():
            path = (ROOT / source).resolve(strict=True)
            if not path.is_relative_to(ROOT) or not path.is_file() or path.stat().st_size > MAX_PROFILE_SOURCE_FILE_BYTES:
                raise ValueError('The actual trial source escaped its bounded project scope')
            current = path.read_bytes()
            total += len(current)
            if len(current) > MAX_PROFILE_SOURCE_FILE_BYTES or total > MAX_PROFILE_SOURCE_BYTES:
                raise ValueError('The actual trial source set exceeds its fixed byte bound')
            if hashlib.sha256(current).hexdigest() != expected_sha:
                raise ValueError('The actual trial frozen profile source changed')
        return True

    recheck()
    return ProfileSelection(bindings, pins, digest, recheck)


def observe_scope(*, session, module_base, driver_address, connection_address, pc_address,
                  pawn_address, bindings, object_identity, object_path, final_recheck, source_pins,
                  actor_candidates=()):
    """Bounded callback scope; callers own process, primary binding and source seals."""
    bindings = _bindings(bindings)
    pins = globals()['source_pins']()
    if (not isinstance(session, MetadataSession) or type(source_pins) is not dict
            or any(source_pins.get(key) != value for key, value in pins.items())
            or any(not callable(cb) for cb in (object_identity, object_path, final_recheck))):
        raise ValueError('An exact source-sealed metadata session and root rechecks are required')
    result = dict(kind='owned_current_world_box_guid_mappings_v1', status='refused', mappings=[],
        source_pins=pins, native_actor_binding_verified=False, interaction_ready_verified=False,
        ack_or_export_acceptance_inferred=False, native_getter_result_reproduced=False,
        missing_references_resolved=False, native_objects_created=False,
        native_methods_invoked=False, process_memory_written=False, packets_sent=False,
        historical_process_pointers_reused=False, code_sampled=False, snapshot_is_atomic=False,
        guid_cache_lifetime_proved=False, native_layouts_constructed=False,
        package_map_weak_identity_initialized=None, package_map_registry_identity_rechecked=False,
        identity_fields_roots_and_process_rechecked=False)
    read, identities, paths = _Read(session), {}, {}
    before_calls, before_bytes = session.calls, session.bytes_read

    def typed(pointer, base, *, weak_required=True):
        pointer = address(pointer)
        row = object_identity(pointer, base)
        if (type(row) is not dict or address(row['address']) != pointer
                or base not in row['class_ancestry'] or row['is_cdo'] is not False
                or type(row['serial']) is not int or row['serial'] < (1 if weak_required else 0)
                or type(row['object_index']) is not int or row['object_index'] < 0
                or identities.setdefault((pointer, base), deepcopy(row)) != row):
            raise ValueError('An initialized unchanged typed GUID object is required')
        return deepcopy(row)

    def path_of(pointer):
        path = object_path(pointer)
        if type(path) is not str or not 0 < len(path) <= 4096 or paths.setdefault(pointer, path) != path:
            raise ValueError('The current GUID object path is unavailable or changed')
        return path

    try:
        if (getattr(session, 'module_sha256', None) != SHIPPING_SHA256
                or getattr(session, 'module_size', None) != IMAGE_SIZE or final_recheck() is not True):
            raise ValueError('The current owned process, image or root binding is not qualified')
        base, driver, connection = map(address, (module_base, driver_address, connection_address))
        typed(driver, 'NetDriver')
        typed(connection, 'NetConnection')
        if read.pointer(driver + 0x98) != connection or read.pointer(connection + 0x58) != driver:
            raise ValueError('The current primary driver/connection binding changed')
        package_map = read.pointer(connection + 0x68)
        package_map_identity = typed(package_map, 'PackageMapClient', weak_required=False)
        if read.pointer(package_map + 0x130) != connection:
            raise ValueError('The current PackageMap connection backlink changed')
        table = read.pointer(package_map)
        if (not base <= table <= base + IMAGE_SIZE - 0x2d0
                or read.pointer(table + 0x2c8) != base + LOOKUP_TARGET_RVA):
            raise ValueError('The actual PackageMap lookup target is outside the qualified source')
        if read.pointer(base + ACCESSOR_CELL) != base + ACCESSOR_TARGET:
            raise ValueError('The actual native GUID array accessor differs')
        cache = read.pointer(package_map + 0x310)
        if read.fact(cache + 0x152, 1) != b'\0' or read.fact(connection + 0xb4, 1)[0] & 1:
            raise ValueError('The current GUID reference mode is unsupported')
        header = read.fact(cache, 0x50)
        allowed_paths = {row['actor_path'] for row in membership.sealed_scope.qualified_actor_paths()}
        if (type(actor_candidates) is not tuple or len(actor_candidates) > 4
                or any(type(row) is not membership.ActorCandidate or row.actor_path not in allowed_paths
                       for row in actor_candidates)
                or len({row.actor_path for row in actor_candidates}) != len(actor_candidates)
                or len({row.address for row in actor_candidates}) != len(actor_candidates)):
            raise ValueError('Only fresh bounded exact manifest Actor candidates are accepted')
        rows, candidates = [], {row.actor_path: row for row in actor_candidates}
        for binding in bindings:
            found = _lookup(read, cache, header, binding.guid)
            resolved = (dict(status='mapping_missing', object_address=None) if found is None else
                        _existing_weak(read, base, found[1]))
            row = dict(guid=binding.guid, expected_actor_path=binding.actor_path,
                expected_class_path=binding.class_path, map_slot_index=None if found is None else found[0],
                current_package_map_actor_association_observed=False,
                current_loaded_visible_level_membership_observed=False, **resolved)
            if resolved['status'] == 'existing_object_observed':
                try:
                    pointer = address(resolved['object_address'])
                    actor = typed(pointer, 'Actor')
                    actual_path, class_path = path_of(pointer), path_of(address(actor['class_address']))
                    row.update(actual_actor_path=actual_path, actual_class_path=class_path, actual_actor_identity=actor)
                    exact = (actual_path == binding.actor_path and class_path == binding.class_path
                             and actor['object_index'] == resolved['object_index'] and actor['serial'] == resolved['serial'])
                    row['current_package_map_actor_association_observed'] = exact
                    if not exact:
                        row['qualification_refusal'] = 'mapped_actor_path_class_or_weak_generation_differs'
                except (ValueError, OSError, KeyError, TypeError) as error:
                    row['qualification_refusal'] = str(error)
                if row['current_package_map_actor_association_observed']:
                    candidate = membership.ActorCandidate(pointer, binding.actor_path)
                    if binding.actor_path in candidates and candidates[binding.actor_path] != candidate:
                        raise ValueError('The current manifest path has ambiguous Actor candidates')
                    candidates[binding.actor_path] = candidate
            rows.append(row)
        world = membership.observe_scope(session=session, pc_address=pc_address, pawn_address=pawn_address,
            actor_candidates=tuple(candidates.values()), object_identity=typed, object_path=object_path,
            final_recheck=final_recheck, source_pins=pins)
        if world['status'] == 'refused':
            raise ValueError('The current-world dependency scope refused: ' + str(world.get('reason')))
        members = {row['actor_path']: row for row in world['actors']}
        for row in rows:
            member = members[row['expected_actor_path']]
            row['current_loaded_visible_level_membership_observed'] = (
                row['current_package_map_actor_association_observed']
                and member['current_loaded_visible_level_membership_observed'])
        position_observation = positions.observe_scope(session=session, module_base=base,
            pc_address=pc_address, pawn_address=pawn_address,
            targets=tuple(positions.PositionTarget(
                candidates[binding.actor_path].address if binding.actor_path in candidates else None,
                binding.actor_path, binding.class_path, binding.guid) for binding in bindings),
            membership_observation=world, object_identity=typed, object_path=object_path,
            final_recheck=final_recheck, source_pins=pins)
        if final_recheck() is not True:
            raise ValueError('The final owned process and primary binding check refused')
        for (pointer, expected), old in identities.items():
            if object_identity(pointer, expected) != old:
                raise ValueError('The current mapped object identity changed before publication')
        if any(object_path(pointer) != old for pointer, old in paths.items()):
            raise ValueError('The current mapped Actor or Class path changed before publication')
        read.recheck()
        if globals()['source_pins']() != pins:
            raise ValueError('The current GUID observation source seal changed')
        complete = world['status'] == 'observed' and all(
            row['current_loaded_visible_level_membership_observed'] for row in rows)
        result.update(status='observed' if complete else 'partial', mappings=rows, world_membership=world,
            position_observation=position_observation,
            package_map_address=hex(package_map), guid_cache_address=hex(cache),
            package_map_weak_identity_initialized=package_map_identity['serial'] > 0,
            package_map_registry_identity_rechecked=True,
            driver_address=hex(driver), connection_address=hex(connection),
            identity_fields_roots_and_process_rechecked=True)
    except (ValueError, OSError, KeyError, TypeError) as error:
        result.update(status='refused', mappings=[], reason=str(error))
    result.update(guid_read_bytes=read.bytes, guid_read_calls=read.calls,
                  read_calls=session.calls - before_calls, read_bytes=session.bytes_read - before_bytes)
    return result


def observe(game_root, trial_report, *, profile_path):
    path, raw, trial = _read_trial(trial_report)
    pid, created = owned_trial_identity(trial, game_root)
    selected = qualified_profile(profile_path, trial)
    pins = source_pins()
    qualify_installed_sources(game_root)
    executable, size = validate_source(game_root)
    if size != IMAGE_SIZE or not _LOCK.acquire(blocking=False):
        raise ValueError('One isolated current-build SafeBox GUID observer is required')
    reader = None
    try:
        reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=180)
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        roots, records = membership._discover_roots_and_manifest_records(session, base, sink)
        identity = sink['callback']
        candidates = membership._discover_manifest_candidates(session, base, records, identity)
        pcs = [row for row in roots['connection_binding_observations']['player_controllers']
               if row.get('status') == 'observed' and row.get('identity_and_fields_rechecked') is True
               and row.get('driver_primary_matches_original_connection') is True
               and row.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One current owned primary controller is required')
        pc = pcs[0]
        arguments = dict(driver_address=address(pc['driver']), connection_address=address(pc['connection']),
                         pc_address=address(pc['address']), object_identity=identity)
        binding = observe_first_player_state(session, base, **arguments)
        pawn = binding.get('pc_pawn_reference', {})
        if binding.get('status') != 'observed' or pawn.get('status') != 'typed_existing_reference':
            raise ValueError('A current owned primary PC/Pawn binding is required')

        def recheck():
            sink['recheck_roots']()
            if observe_first_player_state(session, base, **arguments) != binding:
                raise ValueError('The current owned primary PC/Pawn binding changed')
            reader.verify_identity()
            if (reader.find_module() != base or _read_trial(path)[1] != raw
                    or selected.recheck() is not True or source_pins() != pins):
                raise ValueError('The owned image, trial, profile or source seal changed')
            return True

        result = observe_scope(session=session, module_base=base, driver_address=arguments['driver_address'],
            connection_address=arguments['connection_address'], pc_address=arguments['pc_address'],
            pawn_address=address(pawn['address']), bindings=selected.bindings, object_identity=identity,
            object_path=lambda pointer: native_object_path(session.read, base, pointer),
            final_recheck=recheck, source_pins=pins, actor_candidates=candidates)
        recheck()
        result.update(client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), trial_report_sha256=hashlib.sha256(raw).hexdigest(),
            profile_sha256=selected.profile_sha256, profile_source_pins=dict(selected.source_pins),
            primary_connection_binding=pc, first_player_binding=binding, registry_scan=roots.get('registry_scan'),
            process_identity_rechecked=True, selected_roots_rechecked=True,
            read_calls=session.calls, read_bytes=session.bytes_read)
        return result
    finally:
        if reader is not None:
            reader.close()
        _LOCK.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT / 'work').resolve()):
        parser.error('Use an exclusive new project work output')
    _, _, trial = _read_trial(args.trial_report)
    owned_trial_identity(trial, args.game_root)
    source_pins()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(args.game_root.resolve()),
            '--trial-report', str(args.trial_report.resolve()), '--profile', str(args.profile.resolve()),
            '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root, args.trial_report, profile_path=args.profile)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__, mappings=[],
                native_actor_binding_verified=False, interaction_ready_verified=False,
                process_memory_written=False, native_methods_invoked=False, packets_sent=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
