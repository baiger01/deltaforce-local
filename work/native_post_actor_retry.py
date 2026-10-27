"""One fresh post-Actor observation retry after a registry batch changes.

No partial roots or tables are merged. The same owned PID/creation time and
source-qualified options are passed to a new collector within one shared budget.
"""
from pathlib import Path
import time


def _first_guid_slot_identity_retry(result, pid, options):
    """One discarded observation may be rebuilt; this does not prove transience."""
    if (type(result) is not dict or result.get('status') != 'metadata_export_refused' or
            result.get('error_type') != 'ObjectMetadataError' or
            result.get('reason') != 'object_slot_not_live_or_identity_mismatch' or
            result.get('kind') != 'existing_native_replication_metadata_export' or
            result.get('client_sha256') != '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0' or
            type(result.get('requested_pid')) is not int or result['requested_pid'] != pid or
            any(result.get(k) is not False for k in ('game_modified','process_memory_written','native_getter_invoked')) or
            any(options.get(k) is not True for k in ('connection_binding_only','connection_class_net_cache',
                'connection_rpc_layouts','connection_guid_mappings','reference_conditions',
                'connection_first_player_state','connection_world_context'))):
        return False
    phases = result.get('collection_phase_diagnostics')
    progress = result.get('registry_discovery_progress')
    if (type(phases) is not dict or phases.get('last_phase') != 'guid_mapping_first' or
            type(progress) is not dict or progress.get('status') != 'selected_roots_rechecked' or
            progress.get('range_exhausted') is not True):
        return False
    completed = phases.get('completed_phases')
    expected = ['source_preflight','binding_root_discovery','subworld_context_observation',
        'controller_world_settings_observation','first_player_state_observation','pawn_world_settings_observation']
    return (type(completed) is list and len(completed) == len(expected) and
        all(type(row) is dict for row in completed) and [row.get('phase') for row in completed] == expected)


def collect_post_actor_metadata(collector, game_root, folder, *, pid, created_at,
                                options, maximum_seconds=180, clock=time.monotonic, source_recheck=None):
    if (not callable(collector) or not callable(clock) or type(options) is not dict or
            'pid' in options or 'created_at' in options or 'maximum_seconds' in options or
            type(maximum_seconds) is not int or not 10 <= maximum_seconds <= 600 or
            source_recheck is not None and not callable(source_recheck)):
        raise ValueError('A bounded owned post-Actor collector invocation is required')
    started = clock()
    folder = Path(folder)
    result = collector(game_root, folder, pid=pid, created_at=created_at,
                       maximum_seconds=maximum_seconds, **options)
    attempts = [{'directory': folder.name, 'status': result.get('status'), 'reason': result.get('reason')}]
    if (result.get('status') == 'metadata_export_refused' and
            result.get('reason') == 'object_slot_changed_during_metadata_read' or
            callable(source_recheck) and _first_guid_slot_identity_retry(result, pid, options)):
        remaining = int(maximum_seconds - (clock() - started))
        if remaining >= 10 and source_recheck is not None:
            source_recheck()
            remaining = int(maximum_seconds - (clock() - started))
        if remaining >= 10:
            second = folder.with_name(folder.name + '-retry-2')
            second.mkdir(exist_ok=False)
            result = collector(game_root, second, pid=pid, created_at=created_at,
                               maximum_seconds=remaining, **options)
            folder = second
            attempts.append({'directory': folder.name, 'status': result.get('status'), 'reason': result.get('reason')})
    return result, folder, {'maximum_attempts': 2, 'attempts': attempts,
                           'partial_metadata_merged': False, 'shared_maximum_seconds': maximum_seconds}
