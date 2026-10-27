"""Bounded current-owner DFMSkill RPC layouts; no getter, native call or write."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from observe_owned_gameplay_metadata import (ROOT, SHIPPING_SHA256, owned_trial_identity, address,
    typed_declarations, label_existing, BindingObservation, write_exclusive_report)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, request_elevation)
from native_metadata_paths import object_path
from skill_rpc_layout_readonly_scope import (source_pins, qualified_skill_field, qualify_skill_owner,
    export_existing_skill_rpc_layouts, SKILL_CLASS, PAWN_CLASS)


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
        cache = {}

        def metadata(pointer, expected):
            current = observation.identify(pointer, expected)
            klass = address(current['class_address'])
            if klass not in cache:
                cache[klass] = dict(identity=identity(klass, 'Class'),
                    class_path=object_path(session.read, base, klass),
                    declarations=typed_declarations(session, base, klass, identity),
                    existing_driver_class=label_existing(session, base, driver, klass))
            return cache[klass]

        observation = BindingObservation(session, base, identity, metadata)
        selected = [(at, kind, observation.identify(at, kind)) for at, kind in
            ((pc_at, 'PlayerController'), (driver, 'NetDriver'), (connection, 'NetConnection'), (pawn, 'Pawn'))]
        pawn_metadata = metadata(pawn, 'Pawn')
        if pawn_metadata['class_path'] != PAWN_CLASS:
            raise ValueError('The current owning Pawn class differs from the native source')
        link = observation.reference(pawn, qualified_skill_field(pawn_metadata['declarations']),
            expected_base='DFMSkillComponent')
        if link.get('status') != 'typed_existing_reference':
            raise ValueError('The current typed DFMSkill reference is unavailable: '+link.get('status', 'missing'))
        skill = address(link['identity']['address'])
        current = metadata(skill, 'DFMSkillComponent')
        qualify_skill_owner(link['identity'], current['class_path'], pawn)
        final_checks = []
        functions = export_existing_skill_rpc_layouts(session, base, driver,
            current['existing_driver_class'], object_identity=observation.identify,
            _final_recheck_sink=final_checks)
        for klass, before in cache.items():
            if (identity(klass, 'Class') != before['identity'] or
                    object_path(session.read, base, klass) != before['class_path'] or
                    typed_declarations(session, base, klass, identity) != before['declarations'] or
                    label_existing(session, base, driver, klass) != before['existing_driver_class']):
                raise ValueError('The original owning class cache or declarations changed before publication')
        for check in final_checks:
            check()
        observation.finish()
        sink['recheck_roots']()
        if (any(identity(at, kind) != before for at, kind, before in selected) or
                observe_first_player_state(session, base, driver_address=driver,
                    connection_address=connection, pc_address=pc_at, object_identity=identity) != binding):
            raise ValueError('The original primary PC/Pawn/driver binding changed')
        reader.verify_identity()
        if reader.find_module() != base or source_pins() != pins:
            raise ValueError('The current client module or frozen observer source changed')
        return dict(kind='owned_current_dfm_skill_existing_rpc_layouts_v1', status='observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(), primary_connection_binding=pc,
            first_player_binding=binding, current_skill_binding=link, owner_class_path=SKILL_CLASS,
            existing_driver_class=current['existing_driver_class'], rpc_functions=functions,
            identities_and_fields_rechecked=True, read_calls=session.calls, read_bytes=session.bytes_read,
            maximum_seconds=120, snapshot_atomic=False, native_methods_invoked=False,
            process_memory_written=False, code_sampled=False, packets_sent=False,
            native_layouts_constructed=False, historical_process_pointers_reused=False,
            rpc_parameter_codec_recovered=False, skill_activation_inferred=False)
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
                native_methods_invoked=False, process_memory_written=False, code_sampled=False,
                packets_sent=False, native_layouts_constructed=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
