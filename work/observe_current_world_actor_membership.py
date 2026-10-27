"""Observe four fixed manifest Actors in an already owned shadow trial.

Only the current trial's PID/creation time/executable may be opened read-only.
Ordinary World.Levels and StreamingLevels prove their own relationships; the
encrypted PersistentLevel field is a separate, explicitly refused scope when
its raw bytes are not a plain canonical object reference. No coordinates,
native getter, write, packet, launch or historical address is used.
"""
import argparse
from copy import deepcopy
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import threading

import export_native_replication_metadata as exporter
from observe_owned_gameplay_metadata import owned_trial_identity, address, write_exclusive_report
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession,
    validate_source, discover_roots, observe_first_player_state, request_elevation, object_name)
from native_metadata_objects import validate_object_record, ObjectMetadataError, ABSOLUTE_MAX_OBJECTS
from native_metadata_paths import object_path
from native_replication_metadata_core import (
    MAX_READ_BYTES as MAX_METADATA_READ_BYTES, MAX_READ_CALLS as MAX_METADATA_READ_CALLS)
import observe_current_world_actor_membership_scope as sealed_scope


ROOT = Path(__file__).resolve().parent.parent
SHIPPING_SHA256, IMAGE_SIZE = sealed_scope.SHIPPING_SHA256, sealed_scope.IMAGE_SIZE
MAX_ARRAY_COUNT, MAX_ARRAY_CAPACITY = sealed_scope.MAX_ARRAY_COUNT, sealed_scope.MAX_ARRAY_CAPACITY
# Trial 1792548525430131600 rechecked StreamingLevels count1622/capacity2046.
# These are diagnostic budgets, separate from the unchanged World.Levels bound.
MAX_STREAMING_COUNT, MAX_STREAMING_CAPACITY = 2048, 4096
MAX_READ_BYTES, MAX_READ_CALLS = 256 * 1024, 16384
ActorCandidate = sealed_scope.ActorCandidate
MAX_CLASSES, MAX_FAMILY_NAMES, MAX_NAME_CANDIDATES = 25000, 4096, 32
MAX_OBSERVATION_ATTEMPTS = 3
RETRYABLE_REGISTRY_ERRORS = frozenset(('object_slot_changed_during_metadata_read',
                                     'object_slot_not_live_or_identity_mismatch'))
BUDGET_REFUSALS = {'Metadata session read budget exhausted': 'shared_metadata_budget_exhausted',
                   'Metadata collection time budget exhausted': 'shared_metadata_time_budget_exhausted'}
_LOCK = threading.Lock()


def source_pins():
    pins = sealed_scope.source_pins()
    for relative in ('work/observe_current_world_actor_membership.py',
            'work/observe_owned_gameplay_metadata.py', 'work/observe_portable_map_runtime.py',
            'work/export_native_replication_metadata.py', 'work/native_metadata_objects.py',
            'work/native_metadata_paths.py', 'work/native_metadata_names.py',
            'work/native_gp_first_player_state.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    if Path(__file__).resolve() != ROOT / 'work/observe_current_world_actor_membership.py':
        raise ValueError('The current-world observer was imported from another checkout')
    return pins


def _read_trial(trial_report):
    path = Path(trial_report).resolve(strict=True)
    public = ROOT.resolve() / 'outputs/native-account-provider/client-observation.json'
    if not path.is_relative_to((ROOT / 'work/native-client-tests').resolve()) and path != public:
        raise ValueError('Use an existing owned project native trial report')
    if not 0 < path.stat().st_size <= 8 * 1024 * 1024:
        raise ValueError('The owned trial report exceeds its read bound')
    with path.open('rb') as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('The owned trial report grew beyond its bound')
    return path, raw, json.loads(raw)


def _metadata_failure_context(error):
    raw = getattr(error, 'metadata_failure_context', None)
    if type(raw) is not dict:
        return None
    fields = frozenset(('object_pointer', 'flags', 'serial', 'auxiliary_words'))
    def entry(value):
        if type(value) is not dict:
            return {}
        result = {}
        for key in ('object_index', 'first_changed_object_index', 'changed_slot_count'):
            if type(value.get(key)) is int and 0 <= value[key] <= ABSOLUTE_MAX_OBJECTS:
                result[key] = value[key]
        if type(value.get('changed_fields')) is list:
            result['changed_fields'] = [name for name in value['changed_fields'][:4]
                                        if type(name) is str and name in fields]
        for key in ('before', 'after'):
            state = value.get(key)
            if type(state) is dict:
                result[key] = {name: state[name] for name, choices in (
                    ('pointer_state', ('null', 'non_null')),
                    ('flag_state', ('excluded', 'not_excluded')),
                    ('serial_state', ('initialized', 'uninitialized')))
                    if state.get(name) in choices}
        return result
    result = entry(raw)
    if raw.get('phase') in ('registry_batch_recheck', 'single_object_identity_recheck'):
        result['phase'] = raw['phase']
    span = raw.get('index_range')
    if (type(span) is list and len(span) == 2 and
            all(type(value) is int and 0 <= value <= ABSOLUTE_MAX_OBJECTS for value in span)):
        result['index_range'] = list(span)
    for key in ('batch_records_yielded', 'changes_truncated'):
        if type(raw.get(key)) is bool:
            result[key] = raw[key]
    if type(raw.get('changes')) is list:
        result['changes'] = [entry(value) for value in raw['changes'][:8] if type(value) is dict]
    return result or None


def _discover_roots_and_manifest_records(session, base, sink):
    manifest = sealed_scope.qualified_actor_paths()
    class_paths = {row['class_path'].rsplit('.', 1)[1]: row['class_path'] for row in manifest}
    own_names = {row['actor_path'].rsplit('.', 1)[1] for row in manifest}
    classes, candidates, family_names = {}, [], 0
    original = exporter.iter_object_records

    def registry(read, module_base, **options):
        nonlocal family_names
        for record in original(read, module_base, **options):
            klass = address(record.class_address)
            if klass not in classes:
                if len(classes) >= MAX_CLASSES:
                    raise ValueError('The fixed class-name selection exceeds its bound')
                before = validate_object_record(session.read, base, klass)
                name = object_name(session.read, base, klass).display_text
                classes[klass] = (name in class_paths and
                    object_path(session.read, base, klass) == class_paths[name])
                if validate_object_record(session.read, base, klass) != before:
                    raise ValueError('A class identity changed during exact manifest selection')
            if classes[klass]:
                family_names += 1
                if family_names > MAX_FAMILY_NAMES:
                    raise ValueError('The fixed manifest class-family name scope exceeds its bound')
                if object_name(session.read, base, record.object_address).display_text in own_names:
                    if len(candidates) >= MAX_NAME_CANDIDATES:
                        raise ValueError('The exact manifest instance-name candidates exceed their bound')
                    candidates.append(record)
            yield record

    try:
        exporter.iter_object_records = registry
        roots = discover_roots(session, base, connection_binding_only=True, first_player_state=True,
            _binding_identity_sink=sink, unpublished_batch_retry=True)
    finally:
        exporter.iter_object_records = original
    return roots, candidates


def _discover_manifest_candidates(session, base, records, identity):
    manifest = {row['actor_path']: row for row in sealed_scope.qualified_actor_paths()}
    selected = {}
    for record in records:
        before = identity(record.object_address, 'Actor')
        path = object_path(session.read, base, record.object_address)
        if path not in manifest:
            continue
        if (record.index != before['object_index'] or record.serial != before['serial']
                or object_path(session.read, base, address(before['class_address'])) != manifest[path]['class_path']
                or identity(record.object_address, 'Actor') != before):
            raise ValueError('An exact manifest Actor registry/class identity changed')
        if path in selected:
            raise ValueError('An exact manifest Actor path has multiple current instances')
        selected[path] = ActorCandidate(record.object_address, path)
    return tuple(selected[row['actor_path']] for row in sealed_scope.qualified_actor_paths()
                 if row['actor_path'] in selected)


def observe_scope(*, session, pc_address, pawn_address, actor_candidates, object_identity,
                  object_path, final_recheck, source_pins):
    """Callback-only ordinary-level membership, separately qualified from f8."""
    pins = globals()['source_pins']()
    manifest = sealed_scope.qualified_actor_paths()
    bindings = {row['actor_path']: row for row in manifest}
    if (not isinstance(session, MetadataSession) or type(source_pins) is not dict
            or any(source_pins.get(key) != value for key, value in pins.items())
            or type(actor_candidates) is not tuple or len(actor_candidates) > 4
            or any(type(row) is not ActorCandidate or row.actor_path not in bindings for row in actor_candidates)
            or len({row.address for row in actor_candidates}) != len(actor_candidates)
            or len({row.actor_path for row in actor_candidates}) != len(actor_candidates)
            or any(not callable(cb) for cb in (object_identity, object_path, final_recheck))):
        raise ValueError('An exact source-sealed current Actor scope and root rechecks are required')
    report = dict(kind='owned_current_world_actor_membership_v1', status='refused', actors=[], manifest_levels=[],
        source_pins=pins, native_actor_binding_verified=False, interaction_ready_verified=False,
        process_memory_written=False, native_methods_invoked=False, packets_sent=False, code_sampled=False,
        native_layouts_constructed=False, coordinates_read=False, historical_process_pointers_reused=False,
        reported_visibility_or_ack_used_as_scene_proof=False, persistent_level_relation_verified=False)
    start_calls, start_bytes = session.calls, session.bytes_read
    facts, identities, paths = {}, {}, {}
    scoped_bytes, scoped_calls = 0, 0
    partial = False

    def stable(at, size):
        nonlocal scoped_bytes, scoped_calls
        calls = 2 * ((size + 8191) // 8192)
        if scoped_bytes + size * 2 > MAX_READ_BYTES or scoped_calls + calls > MAX_READ_CALLS:
            raise ValueError('The exact world member read scope exceeds its budget')
        scoped_bytes += size * 2
        scoped_calls += calls
        return session.stable(at, size)

    def fact(at, size):
        raw = stable(at, size)
        if facts.setdefault((at, size), raw) != raw:
            raise ValueError('A current-world source field changed')
        return raw

    def path_of(pointer):
        value = object_path(pointer)
        if type(value) is not str or not value or len(value) > 4096 or paths.setdefault(pointer, value) != value:
            raise ValueError('A current typed object path is unavailable or changed')
        return value

    def identify(pointer, base_class):
        pointer = address(pointer)
        value = object_identity(pointer, base_class)
        # Streaming arrays hold raw UObject references; a live stream may not
        # have had a weak serial allocated. Keep its actual zero and recheck it.
        minimum_serial = 0 if base_class == 'LevelStreaming' else 1
        if (type(value) is not dict or base_class not in value['class_ancestry']
                or type(value['serial']) is not int or value['serial'] < minimum_serial
                or value['is_cdo'] is not False or address(value['address']) != pointer
                or identities.setdefault((pointer, base_class), value) != value):
            raise ValueError('An initialized unchanged current typed object is required')
        path_of(pointer)
        return value

    def reference(at, *, null=False):
        value = struct.unpack('<Q', fact(at, 8))[0]
        return 0 if null and value == 0 else address(value)

    def array(owner, offset, base_class, *, diagnostic=None,
              maximum_count=MAX_ARRAY_COUNT, maximum_capacity=MAX_ARRAY_CAPACITY):
        def phase(name, reason):
            if diagnostic is not None:
                diagnostic.update(refusal_phase=name, refusal_reason=reason)
        phase('header_read', 'header_read_refused')
        data, count, capacity = struct.unpack('<Qii', fact(owner + offset, 16))
        if diagnostic is not None:
            diagnostic.update(count=count, capacity=capacity)
        phase('header_validation', 'invalid_array_bound')
        if not 0 <= count <= capacity <= maximum_capacity or count > maximum_count:
            raise ValueError('The ordinary current-world reference array exceeds its fixed bound')
        phase('header_validation', 'invalid_array_pointer')
        if capacity and not data:
            raise ValueError('The ordinary current-world reference array has no storage')
        if data:
            address(data)
        phase('element_read', 'element_read_refused')
        raw = fact(data, count * 8) if count else b''
        phase('element_validation', 'invalid_element_pointer')
        values = tuple(address(value) for value, in struct.iter_unpack('<Q', raw) if value)
        phase('element_validation', 'duplicate_array_entries')
        if len(values) != len(set(values)):
            raise ValueError('The current-world reference array contains duplicates')
        phase('stream_identity', 'stream_identity_refused')
        for pointer in values:
            identify(pointer, base_class)
        return values, dict(count=count, capacity=capacity, elements_read=True, field_offset=offset)

    try:
        if (getattr(session, 'module_sha256', None) != SHIPPING_SHA256
                or getattr(session, 'module_size', None) != IMAGE_SIZE or final_recheck() is not True):
            raise ValueError('The current owned image, primary roots or process cannot be rechecked')
        pc, pawn = address(pc_address), address(pawn_address)
        pc_identity, pawn_identity = identify(pc, 'PlayerController'), identify(pawn, 'Pawn')
        root_level = address(pc_identity['outer_address'])
        if address(pawn_identity['outer_address']) != root_level:
            raise ValueError('The current primary PC and Pawn do not share a qualified Level')
        world = address(identify(root_level, 'Level')['outer_address'])
        identify(world, 'World')
        if reference(root_level + 0xa8) != world:
            raise ValueError('The primary PC/Pawn Level does not belong to the selected World')
        levels, report['world_levels'] = array(world, 0x158, 'Level')
        if root_level not in levels:
            raise ValueError('The primary PC/Pawn Level is absent from the ordinary World.Levels array')
        level_rows = {}
        manifest_level_paths = {row['level_path'] for row in manifest}
        for level in levels:
            row = dict(level_path=paths[level], level_in_current_world_levels=True,
                       manifest_level_state_read=False)
            if paths[level] in manifest_level_paths:
                row.update(manifest_level_state_read=True,
                    level_owning_world_matches_current=reference(level + 0xa8) == world,
                    level_visible_bit=bool(fact(level + 0x1e4, 1)[0] & 0x20))
            level_rows[level] = row
        report['world_levels']['entries'] = tuple(level_rows.values())
        try:
            persistent = reference(world + 0xf8)
            identify(persistent, 'Level')
            qualified = persistent == root_level and persistent in levels and reference(persistent + 0xa8) == world
            report['persistent_level'] = dict(status='observed' if qualified else 'relationship_refused',
                raw_plain_reference_accepted=True, actual_level_path=paths[persistent])
            report['persistent_level_relation_verified'] = qualified
            if qualified:
                report['actual_persistent_level_path'] = paths[persistent]
            else:
                partial = True
        except (ValueError, OSError, KeyError) as error:
            if isinstance(error, ObjectMetadataError):
                raise
            partial = True
            report['persistent_level'] = dict(status='unsupported_raw_reference', raw_plain_reference_accepted=False,
                encrypted_property_decoded=False, guessed_or_masked_reference_used=False)
        loaded = {}
        streaming_diagnostic = dict(header_fields_rechecked=False)
        try:
            streams, report['streaming_levels'] = array(world, 0x90, 'LevelStreaming',
                diagnostic=streaming_diagnostic, maximum_count=MAX_STREAMING_COUNT,
                maximum_capacity=MAX_STREAMING_CAPACITY)
            stream_rows = []
            for stream in streams:
                streaming_diagnostic.update(refusal_phase='stream_identity', refusal_reason='stream_identity_refused')
                stream_identity = identify(stream, 'LevelStreaming')
                same_world = address(stream_identity['outer_address']) == world
                entry = dict(streaming_path=paths[stream], outer_is_current_world=same_world,
                             loaded_level_reference_read=False,
                             weak_identity_serial_initialized=stream_identity['serial'] > 0)
                if same_world:
                    streaming_diagnostic.update(refusal_phase='loaded_level_read', refusal_reason='loaded_level_read_refused')
                    level = reference(stream + 0x128, null=True)
                    entry['loaded_level_reference_read'] = True
                    entry['loaded_level_path'] = None
                    if level:
                        streaming_diagnostic.update(refusal_phase='loaded_level_identity', refusal_reason='loaded_level_identity_refused')
                        identify(level, 'Level')
                        entry['loaded_level_path'] = paths[level]
                        loaded.setdefault(level, []).append(paths[stream])
                stream_rows.append(entry)
            report['streaming_levels']['entries'] = tuple(stream_rows)
            report['streaming_levels']['zero_serial_metadata_count'] = sum(
                not row['weak_identity_serial_initialized'] for row in stream_rows)
        except (ValueError, OSError, KeyError) as error:
            report['streaming_levels'] = dict(elements_read=False, reason='streaming_scope_refused',
                maximum_count=MAX_STREAMING_COUNT, maximum_capacity=MAX_STREAMING_CAPACITY,
                **streaming_diagnostic)
            if isinstance(error, ObjectMetadataError):
                raise
            partial, loaded = True, {}
        by_path = {}
        for pointer, row in level_rows.items():
            by_path.setdefault(row['level_path'], []).append(pointer)
        manifest_levels = {}
        for binding in manifest:
            path = binding['level_path']
            matches = by_path.get(path, [])
            row = dict(level_path=path, current_world_match_count=len(matches),
                level_in_current_world_levels=len(matches) == 1,
                level_owning_world_matches_current=False, loaded_by_current_world_streaming=False,
                level_visible_bit=False, current_loaded_visible_level_membership_observed=False)
            if len(matches) == 1:
                level = matches[0]
                row.update(level_rows[level], loaded_by_current_world_streaming=level in loaded,
                           matching_streaming_paths=tuple(loaded.get(level, ())))
                row['current_loaded_visible_level_membership_observed'] = all(row[key] is True for key in (
                    'level_in_current_world_levels', 'level_owning_world_matches_current',
                    'loaded_by_current_world_streaming', 'level_visible_bit'))
            manifest_levels[path] = row
        candidates = {row.actor_path: row for row in actor_candidates}
        actors = []
        for binding in manifest:
            row = dict(actor_path=binding['actor_path'], class_path=binding['class_path'],
                manifest_level_path=binding['level_path'], actor_discovery_status='not_found',
                actor_identity_verified=False, actor_outer_matches_manifest_level=False,
                current_world_level_membership_observed=False,
                current_loaded_visible_level_membership_observed=False)
            candidate = candidates.get(binding['actor_path'])
            if candidate is not None:
                try:
                    actor = identify(candidate.address, 'Actor')
                    if (paths[candidate.address] != candidate.actor_path
                            or path_of(address(actor['class_address'])) != binding['class_path']):
                        raise ValueError('The selected actual Actor path or class differs from the manifest')
                    outer = address(actor['outer_address'])
                    identify(outer, 'Level')
                    level_scope = manifest_levels[binding['level_path']]
                    exact_outer = paths[outer] == binding['level_path'] and by_path.get(binding['level_path']) == [outer]
                    row.update(actor_discovery_status='exact_current_instance', actor_identity_verified=True,
                        actual_level_path=paths[outer], actor_outer_matches_manifest_level=exact_outer)
                    row['current_world_level_membership_observed'] = exact_outer and level_scope['level_owning_world_matches_current']
                    row['current_loaded_visible_level_membership_observed'] = (row['current_world_level_membership_observed']
                        and level_scope['current_loaded_visible_level_membership_observed'])
                except (ValueError, OSError, KeyError) as error:
                    if isinstance(error, ObjectMetadataError):
                        raise
                    partial = True
                    row['actor_discovery_status'] = 'selected_actor_context_refused'
            actors.append(row)
        if final_recheck() is not True:
            raise ValueError('The final owned process and primary root check refused')
        for (at, size), before in facts.items():
            if stable(at, size) != before:
                raise ValueError('A current-world source field changed before publication')
        for (pointer, base_class), before in identities.items():
            if object_identity(pointer, base_class) != before or object_path(pointer) != paths[pointer]:
                raise ValueError('A current-world typed identity changed before publication')
        if (any(object_path(pointer) != before for pointer, before in paths.items())
                or globals()['source_pins']() != pins
                or getattr(session, 'module_sha256', None) != SHIPPING_SHA256
                or getattr(session, 'module_size', None) != IMAGE_SIZE):
            raise ValueError('A current-world object path or source seal changed before publication')
        if 'count' in report['streaming_levels']:
            report['streaming_levels']['header_fields_rechecked'] = True
        report.update(status='partial' if partial else 'observed', actors=actors,
            manifest_levels=tuple(manifest_levels.values()), current_world_path=paths[world],
            primary_pc_pawn_level_path=paths[root_level], identity_fields_roots_and_process_rechecked=True,
            snapshot_is_atomic=False)
    except (ValueError, OSError, KeyError, TypeError) as error:
        report.update(status='refused', actors=[], manifest_levels=[], reason=str(error),
                      error_type=type(error).__name__, metadata_failure_context=_metadata_failure_context(error),
                      identity_fields_roots_and_process_rechecked=False, persistent_level_relation_verified=False)
        report.pop('actual_persistent_level_path', None)
        if 'persistent_level' in report:
            report['persistent_level'] = dict(status='final_scope_refused', raw_plain_reference_accepted=False)
        for key in ('world_levels', 'streaming_levels'):
            if key in report:
                report[key].pop('entries', None)
                report[key]['elements_read'] = False
                report[key]['final_scope_rechecked'] = False
                if key == 'streaming_levels':
                    report[key]['header_fields_rechecked'] = False
    report.update(scoped_field_read_bytes=scoped_bytes, scoped_field_read_calls=scoped_calls,
                  read_calls=session.calls - start_calls, read_bytes=session.bytes_read - start_bytes)
    return report


def _observe_once(session, reader, path, trial_raw, pins):
    base, sink = reader.module_base, {}
    roots, records = _discover_roots_and_manifest_records(session, base, sink)
    identity = sink['callback']
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
    candidates = _discover_manifest_candidates(session, base, records, identity)

    def recheck():
        sink['recheck_roots']()
        if observe_first_player_state(session, base, **arguments) != binding:
            raise ValueError('The current owned primary PC/Pawn binding changed')
        reader.verify_identity()
        if reader.find_module() != base or _read_trial(path)[1] != trial_raw or source_pins() != pins:
            raise ValueError('The owned module, active trial or source seals changed')
        return True

    result = observe_scope(session=session, pc_address=arguments['pc_address'], pawn_address=address(pawn['address']),
        actor_candidates=candidates, object_identity=identity,
        object_path=lambda pointer: object_path(session.read, base, pointer), final_recheck=recheck, source_pins=pins)
    failed_context = deepcopy(result.get('metadata_failure_context'))
    try:
        recheck()
    except (ValueError, OSError, KeyError, TypeError) as error:
        if result['status'] != 'refused' or result.get('error_type') != 'ObjectMetadataError':
            raise
        reason = str(error)
        safe_reason = (reason if reason in BUDGET_REFUSALS or reason in RETRYABLE_REGISTRY_ERRORS else
                       'owned_process_roots_or_sources_recheck_refused')
        error_type = type(error).__name__
        if error_type not in ('ValueError', 'ObjectMetadataError', 'OSError', 'KeyError', 'TypeError'):
            error_type = 'recheck_error'
        result.update(actors=[], manifest_levels=[], metadata_failure_context=failed_context,
            secondary_refusal=dict(phase='post_scope_final_recheck', reason=safe_reason,
                error_type=error_type, metadata_failure_context=_metadata_failure_context(error)),
            retry_refusal=BUDGET_REFUSALS.get(reason, 'post_scope_final_recheck_refused'),
            process_identity_rechecked=False, selected_roots_rechecked=False,
            identity_fields_roots_and_process_rechecked=False, persistent_level_relation_verified=False)
        return result
    result.update(primary_connection_binding=pc, first_player_binding=binding, registry_scan=roots.get('registry_scan'),
        exact_manifest_actor_candidates=len(candidates), process_identity_rechecked=True, selected_roots_rechecked=True)
    return result


def observe(game_root, trial_report):
    path, trial_raw, trial = _read_trial(trial_report)
    pid, created = owned_trial_identity(trial, game_root)
    pins = source_pins()
    executable, size = validate_source(game_root)
    if size != IMAGE_SIZE:
        raise ValueError('The exact current-world client image size is required')
    if not _LOCK.acquire(blocking=False):
        raise ValueError('One isolated exact manifest observer is required')
    reader = None
    try:
        reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=180)
        attempts, total_bytes, total_calls = [], 0, 0
        result = None
        for attempt in range(MAX_OBSERVATION_ATTEMPTS):
            reader.verify_identity()
            if (reader.find_module() != reader.module_base or _read_trial(path)[1] != trial_raw or
                    source_pins() != pins):
                raise ValueError('The owned module, active trial or source seals changed')
            if total_bytes >= MAX_METADATA_READ_BYTES or total_calls >= MAX_METADATA_READ_CALLS:
                result['retry_refusal'] = 'shared_metadata_budget_exhausted'
                break
            session = MetadataSession(reader.read_exact, max_bytes=MAX_METADATA_READ_BYTES-total_bytes,
                                      max_calls=MAX_METADATA_READ_CALLS-total_calls)
            session.module_sha256, session.module_size = SHIPPING_SHA256, size
            try:
                result = _observe_once(session, reader, path, trial_raw, pins)
            except ValueError as error:
                budget_error = str(error) in BUDGET_REFUSALS
                if not isinstance(error, ObjectMetadataError) and not budget_error:
                    raise
                result = dict(kind='owned_current_world_actor_membership_v1', status='refused',
                    actors=[], manifest_levels=[], reason=str(error), error_type=type(error).__name__,
                    metadata_failure_context=_metadata_failure_context(error),
                    source_pins=pins, identity_fields_roots_and_process_rechecked=False,
                    process_memory_written=False, native_methods_invoked=False, packets_sent=False,
                    code_sampled=False, native_layouts_constructed=False, coordinates_read=False,
                    historical_process_pointers_reused=False, native_actor_binding_verified=False,
                    interaction_ready_verified=False, persistent_level_relation_verified=False)
                if budget_error:
                    result['retry_refusal'] = BUDGET_REFUSALS[str(error)]
            finally:
                total_bytes += session.bytes_read
                total_calls += session.calls
            attempts.append(dict(attempt=attempt+1, status=result['status'], reason=result.get('reason'),
                metadata_failure_context=result.get('metadata_failure_context'),
                secondary_refusal=result.get('secondary_refusal'),
                read_bytes=session.bytes_read, read_calls=session.calls))
            if not (result['status'] == 'refused' and not result.get('secondary_refusal') and
                    result.get('error_type') == 'ObjectMetadataError' and
                    result.get('reason') in RETRYABLE_REGISTRY_ERRORS):
                break
        result.update(client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            observation_attempts=attempts, observation_attempt_count=len(attempts),
            maximum_observation_attempts=MAX_OBSERVATION_ATTEMPTS, discarded_attempt_records_merged=False,
            shared_metadata_max_bytes=MAX_METADATA_READ_BYTES, shared_metadata_max_calls=MAX_METADATA_READ_CALLS,
            maximum_seconds=180, read_calls=total_calls, read_bytes=total_bytes)
        return result
    finally:
        if reader is not None:
            reader.close()
        _LOCK.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
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
            '--trial-report', str(args.trial_report.resolve()), '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root, args.trial_report)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__, actors=[],
                metadata_failure_context=_metadata_failure_context(error),
                manifest_levels=[], process_memory_written=False, native_methods_invoked=False,
                native_layouts_constructed=False, packets_sent=False, code_sampled=False,
                historical_process_pointers_reused=False, native_actor_binding_verified=False,
                interaction_ready_verified=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
