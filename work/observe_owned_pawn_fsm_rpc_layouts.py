"""Observe the current Pawn startup RPC's already-built FunctionRepLayout."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from observe_owned_gameplay_metadata import (ROOT, SHIPPING_SHA256, owned_trial_identity,
    address, label_existing, write_exclusive_report)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, request_elevation)
from native_metadata_paths import object_path
from observe_owned_skill_rpc_layouts_v2 import select_trial_report
from pawn_fsm_rpc_readonly_scope import (PAWN_CLASS, source_pins, qualify_pawn_owner,
    export_existing_pawn_fsm_rpc_layouts)


def observe(game_root, trial_report=None, *, active_trial_snapshot=None):
    selected = select_trial_report(trial_report, active_trial_snapshot=active_trial_snapshot)
    trial_raw = selected.read_bytes()
    pid, created = owned_trial_identity(json.loads(trial_raw), game_root)
    pins = source_pins()
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True, first_player_state=True,
            _binding_identity_sink=sink, unpublished_batch_retry=True)
        identity = sink['callback']
        pcs = [pc for pc in roots['connection_binding_observations']['player_controllers']
            if pc.get('status') == 'observed' and pc.get('identity_and_fields_rechecked') is True and
            pc.get('driver_primary_matches_original_connection') is True and pc.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One actual current owned primary PC is required')
        pc = pcs[0]
        pc_at, driver, connection = (address(pc[key]) for key in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_at, object_identity=identity)
        pawn_ref = binding.get('pc_pawn_reference', {})
        if binding.get('status') != 'observed' or pawn_ref.get('status') != 'typed_existing_reference':
            raise ValueError('The actual current PC/Pawn binding is unavailable')
        pawn = address(pawn_ref['address'])
        selected_identities = [(at, kind, identity(at, kind)) for at, kind in
            ((pc_at, 'PlayerController'), (driver, 'NetDriver'), (connection, 'NetConnection'), (pawn, 'Pawn'))]
        pawn_identity = selected_identities[-1][2]
        klass = address(pawn_identity['class_address'])
        klass_identity = identity(klass, 'Class')
        class_path = object_path(session.read, base, klass)
        qualify_pawn_owner(pawn_identity, class_path)
        cache = label_existing(session, base, driver, klass)
        final_checks = []
        functions = export_existing_pawn_fsm_rpc_layouts(session, base, driver, cache,
            object_identity=identity, object_path=lambda pointer: object_path(session.read, base, pointer),
            _final_recheck_sink=final_checks)
        if (identity(klass, 'Class') != klass_identity or object_path(session.read, base, klass) != class_path or
                label_existing(session, base, driver, klass) != cache):
            raise ValueError('The original Pawn class or existing ClassNetCache changed')
        for check in final_checks:
            check()
        sink['recheck_roots']()
        if (any(identity(at, kind) != before for at, kind, before in selected_identities) or
                observe_first_player_state(session, base, driver_address=driver,
                    connection_address=connection, pc_address=pc_at, object_identity=identity) != binding):
            raise ValueError('The original primary PC/Pawn/driver binding changed')
        reader.verify_identity()
        if reader.find_module() != base or source_pins() != pins:
            raise ValueError('The current client module or observer sources changed')
        return dict(kind='owned_current_pawn_fsm_existing_rpc_layouts_v1', status='observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(), primary_connection_binding=pc,
            first_player_binding=binding, current_pawn_identity=pawn_identity, owner_class_path=class_path,
            existing_driver_class={k: v for k, v in cache.items() if k != 'layout'}, rpc_functions=functions,
            class_property_layout_omitted_from_output=True, identities_and_fields_rechecked=True,
            read_calls=session.calls, read_bytes=session.bytes_read, maximum_seconds=120, snapshot_atomic=False,
            native_methods_invoked=False, process_memory_written=False, code_sampled=False, packets_sent=False,
            native_layouts_constructed=False, historical_process_pointers_reused=False,
            function_layout_key_kind='weak_object_index_and_serial', serial_zero_proves_layout_absence=False,
            pointer_key_lookup_supported=False, rpc_parameter_codec_recovered=False,
            startup_transition_execution_inferred=False)
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--trial-report', type=Path)
    inputs.add_argument('--active-trial-snapshot', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    selected = select_trial_report(args.trial_report, active_trial_snapshot=args.active_trial_snapshot)
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work').resolve()):
        parser.error('Use an exclusive new project work output')
    owned_trial_identity(json.loads(selected.read_bytes()), args.game_root)
    source_pins()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        option = '--active-trial-snapshot' if args.active_trial_snapshot is not None else '--trial-report'
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(args.game_root.resolve()),
            option, str(selected.resolve()), '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root, args.trial_report, active_trial_snapshot=args.active_trial_snapshot)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                native_methods_invoked=False, process_memory_written=False, code_sampled=False, packets_sent=False,
                native_layouts_constructed=False, pointer_key_substituted=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
