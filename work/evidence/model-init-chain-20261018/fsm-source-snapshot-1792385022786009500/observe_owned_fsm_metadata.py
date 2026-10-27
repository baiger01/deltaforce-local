"""Observe one current owned Pawn's FSM, using bounded read-only metadata.

No launch, process write, native method, serial allocation, or packet API.
Only current typed references are followed. Unknown values fail per field.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from observe_owned_gameplay_metadata import (address, owned_trial_identity, typed_declarations,
    label_existing, write_exclusive_report)
from observe_owned_vitals_metadata import (VitalsBindingObservation, object_metadata,
    enrich_existing_layout)
from observe_owned_skill_entity_metadata import Facts
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, recheck_virtual_method, request_elevation)
from native_metadata_paths import object_path
from fsm_readonly_scope import (ROOT, CLIENT, PATHS, source_pins, contract, qualified_field,
    array_header, started_value, read_field, capture_record, named, SIGNATURE)
from fsm_generated_class_scope import observe_class_metadata
from observe_owned_emptyhand_class_metadata import ClassObservation
from sprint_transient_input_guard import read_current_guard

REFERENCE_STATUSES = ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized')


def lifecycle(session, pointer, record, pawn, observation, reads):
    expected = named(capture_record('blackboard'), 'CreationMethod')
    current = named(record, 'CreationMethod')
    if any(current.get(k) != expected.get(k) for k in SIGNATURE):
        raise ValueError('The current FSM ActorComponent lifecycle declaration changed')
    def stable(at, size):
        raw = session.stable(at, size)
        if (at, size) in reads and reads[(at, size)] != raw:
            raise ValueError('The current FSM ActorComponent lifecycle changed')
        reads[(at, size)] = raw
        return raw
    registered = stable(pointer+0xc8, 1)[0]
    flags = stable(pointer+0xcc, 1)[0]
    creation = stable(pointer+0xce, 1)[0]
    owner_at, = struct.unpack('<Q', stable(pointer+0xe8, 8))
    owner = dict(status='null_reference')
    if owner_at:
        identity = observation.identify(address(owner_at), 'Actor')
        owner = dict(status='typed_existing_reference' if identity['serial'] else
            'typed_reference_weak_identity_uninitialized', identity=identity,
            is_current_pawn=owner_at == pawn)
    return dict(status='observed', raw_registered_byte=hex(registered),
        registered_byte_offset=0xc8, registered=bool(registered & 1),
        replication_bit_set=bool(registered & 8), raw_lifecycle_byte=hex(flags),
        lifecycle_byte_offset=0xcc, wants_initialize_component=bool(flags & 2),
        native_created_flag_set=bool(flags & 8), native_initialize_flag_set=bool(flags & 0x10),
        native_beginplay_flag_set=bool(flags & 0x20),
        creation_method=dict(field=current, raw=hex(creation)), owner_private=owner,
        derived_initialization_success_inferred=False, native_methods_invoked=False,
        snapshot_atomic=False)


def byte_value(facts, pointer, offset, *, native_consumer=None):
    raw = facts.fact(pointer+offset, 1)
    if raw[0] not in (0, 1):
        raise ValueError('The source-qualified FSM boolean is not canonical')
    return dict(status='observed', value=bool(raw[0]), raw_hex=raw.hex(),
        storage_offset=offset, native_consumer_rva=native_consumer)


def observe(game_root, trial_report):
    trial_raw = Path(trial_report).read_bytes()
    pid, created = owned_trial_identity(json.loads(trial_raw), game_root)
    pins = source_pins()
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = CLIENT, size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True,
            first_player_state=True, _binding_identity_sink=sink, unpublished_batch_retry=True)
        callback = sink['callback']
        pcs = [p for p in roots['connection_binding_observations']['player_controllers']
            if p.get('status') == 'observed' and p.get('identity_and_fields_rechecked') is True
            and p.get('driver_primary_matches_original_connection') is True
            and p.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One current primary owning controller is required')
        pc = pcs[0]
        pc_at, driver, connection = (address(pc[k]) for k in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_at, object_identity=callback)
        if binding.get('status') != 'observed' or binding['pc_pawn_reference'].get('status') != 'typed_existing_reference':
            raise ValueError('The current primary owning Pawn binding is unavailable')
        pawn = address(binding['pc_pawn_reference']['address'])
        classes, records, hooks, reads = {}, {}, [], {}
        generated_class_observations = []
        facts = Facts(session)

        def metadata(pointer, expected):
            identity = observation.identify(pointer, expected)
            klass = address(identity['class_address'])
            if klass not in classes:
                existing = label_existing(session, base, driver, klass)
                enrich_existing_layout(session, base, existing, hooks, reads)
                classes[klass] = dict(class_identity=callback(klass, 'Class'),
                    class_path=object_path(session.read, base, klass),
                    declarations=typed_declarations(session, base, klass, callback),
                    existing_driver_class=existing)
            result = dict(classes[klass], identity=identity,
                object_metadata=object_metadata(session, pointer, identity, observation, reads))
            records[pointer] = result
            return result

        observation = VitalsBindingObservation(session, base, callback, metadata)
        scopes = {'pawn': {}, 'blackboard': {}, 'component': {}, 'instance': {}}
        pawn_record = metadata(pawn, 'Pawn')
        if pawn_record['class_path'] != PATHS['pawn']:
            raise ValueError('The current owning Pawn class differs from the cooked FSM source')

        def ref(pointer, record, scope, name, expected):
            return observation.reference(pointer, qualified_field(record, scope, name), expected_base=expected)

        component_link = read_field(scopes['pawn'], 'FSMComponent', lambda:
            ref(pawn, pawn_record, 'pawn', 'FSMComponent', 'GPFSMStateMachineComponent'))
        blackboard_link = read_field(scopes['pawn'], 'Blackboard', lambda:
            ref(pawn, pawn_record, 'pawn', 'Blackboard', 'GPBlackboardComponent'))
        if blackboard_link['status'] in REFERENCE_STATUSES:
            board = address(blackboard_link['identity']['address'])
            board_record = metadata(board, 'GPBlackboardComponent')
            read_field(scopes['blackboard'], 'transient_sprint_input_guard', lambda:
                read_current_guard(session.stable, base, board, board_record))
            def checking():
                field = qualified_field(board_record, 'blackboard', 'bIsCheckingSkill')
                return dict(byte_value(facts, board, field['storage_offset'], native_consumer='0x3234fa6'), field=field)
            read_field(scopes['blackboard'], 'bIsCheckingSkill', checking)
            board_fsm = read_field(scopes['blackboard'], 'FSMComponent', lambda:
                ref(board, board_record, 'blackboard', 'FSMComponent', 'GPFSMStateMachineComponent'))
            if board_fsm['status'] in REFERENCE_STATUSES and component_link['status'] in REFERENCE_STATUSES:
                scopes['blackboard']['same_fsm_as_current_pawn'] = (
                    board_fsm['identity'] == component_link['identity'])
        else:
            scopes['blackboard'].update(status='partial', reason='Current Pawn Blackboard is unavailable')

        instance_link = None
        if component_link['status'] in REFERENCE_STATUSES:
            component = address(component_link['identity']['address'])
            record = metadata(component, 'GPFSMStateMachineComponent')
            if (record['class_path'] != PATHS['component'] or record['identity']['is_cdo'] is not False
                    or record['identity']['name'] != 'GPFSMStateMachine'
                    or address(record['identity']['outer_address']) != pawn):
                raise ValueError('The current FSM component lacks its exact typed Pawn/default-name binding')
            read_field(scopes['component'], 'lifecycle', lambda:
                lifecycle(session, component, record, pawn, observation, reads))
            for name in ('GPOwner', 'GPActor', 'InstanceTemplate', 'R_Instance'):
                expected = 'SMInstance' if name in ('InstanceTemplate', 'R_Instance') else 'Actor'
                value = read_field(scopes['component'], name, lambda n=name, e=expected:
                    ref(component, record, 'component', n, e))
                if name == 'R_Instance':
                    instance_link = value
                if name in ('GPOwner', 'GPActor') and value['status'] in REFERENCE_STATUSES:
                    value['is_current_pawn'] = value['identity']['address'] == pawn_record['identity']['address']
            def machine_class():
                field = qualified_field(record, 'component', 'StateMachineClass')
                raw = facts.fact(component+field['storage_offset'], 8)
                pointer, = struct.unpack('<Q', raw)
                if not pointer:
                    return dict(status='null_reference', field=field)
                identity = observation.identify(address(pointer), 'Class')
                path = object_path(session.read, base, pointer)
                class_ob = ClassObservation(session, base)
                generated = read_field({}, 'class_metadata', lambda:
                    observe_class_metadata(class_ob, pointer, image_size=size))
                if generated.get('status') == 'observed':
                    generated_class_observations.append((class_ob, generated))
                return dict(status='observed', identity=identity, class_path=path,
                    is_cooked_main_fsm_class=path == PATHS['instance'], field=field,
                    generated_class_metadata=generated)
            read_field(scopes['component'], 'StateMachineClass', machine_class)
            for name in ('bInitializeOnBeginPlay', 'bStartOnBeginPlay', 'bReplicateStatesOnLoad',
                    'bDiscardTransitionsBeforeInitialize', 'R_bShuttingDown'):
                def boolean(n=name):
                    field = qualified_field(record, 'component', n)
                    return dict(byte_value(facts, component, field['storage_offset']), field=field)
                read_field(scopes['component'], name, boolean)
            def transactions():
                field = qualified_field(record, 'component', 'R_NetworkedTransactions')
                return dict(status='observed', field=field,
                    **array_header(facts.fact(component+field['storage_offset'], 16)))
            read_field(scopes['component'], 'R_NetworkedTransactions', transactions)
        else:
            scopes['component'].update(status='partial', reason='Current Pawn FSM component is unavailable')

        if instance_link and instance_link['status'] in REFERENCE_STATUSES:
            instance = address(instance_link['identity']['address'])
            record = metadata(instance, 'SMInstance')
            if record['class_path'] != PATHS['instance'] or record['identity']['is_cdo'] is not False:
                scopes['instance'].update(status='partial', reason='The current R_Instance class differs from the cooked main FSM')
            else:
                read_field(scopes['instance'], 'R_StateMachineContext', lambda:
                    ref(instance, record, 'instance', 'R_StateMachineContext', 'Object'))
                read_field(scopes['instance'], 'IsInitialized', lambda:
                    byte_value(facts, instance, 0x6d4, native_consumer='0x1072f35'))
                def started():
                    field = qualified_field(record, 'instance', 'R_bHasStarted')
                    return dict(status='observed', field=field, **started_value(facts.fact(instance+0x664, 4)))
                read_field(scopes['instance'], 'R_bHasStarted', started)
                for name in ('R_ActiveStates', 'RootStatePathGuidArray', 'PackedActiveStateNumInfos'):
                    def header(n=name):
                        field = qualified_field(record, 'instance', n)
                        return dict(status='observed', field=field,
                            **array_header(facts.fact(instance+field['storage_offset'], 16)))
                    read_field(scopes['instance'], name, header)
        else:
            scopes['instance'].update(status='partial', reason='No current qualified R_Instance reference was observed')
        observation.finish()
        for class_ob, generated in generated_class_observations:
            class_ob.finish()
            generated.update(metadata_recheck_required=False, identities_and_fields_rechecked=True)
        for klass, record in classes.items():
            if (callback(klass, 'Class') != record['class_identity'] or
                    typed_declarations(session, base, klass, callback) != record['declarations']):
                raise ValueError('The current FSM class/declarations changed before publication')
        for descriptor, hook in hooks:
            recheck_virtual_method(session, base, descriptor, hook)
        if any(session.stable(at, size) != raw for (at, size), raw in reads.items()):
            raise ValueError('The selected FSM metadata/lifecycle changed before publication')
        facts.finish()
        sink['recheck_roots']()
        if observe_first_player_state(session, base, driver_address=driver, connection_address=connection,
                pc_address=pc_at, object_identity=callback) != binding:
            raise ValueError('The current FSM owning Pawn binding changed before publication')
        reader.verify_identity()
        if reader.find_module() != base or source_pins() != pins:
            raise ValueError('The FSM source seal or native module changed')
        return dict(kind='owned_main_fsm_readonly_metadata_v1',
            status='partial' if any(s.get('status') != 'observed' for s in scopes.values()) else 'observed',
            client_sha256=CLIENT, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc, first_player_binding=binding,
            objects=list(records.values()), scopes=scopes,
            identities_and_fields_rechecked=True, selected_roots_rechecked=True,
            process_identity_rechecked=True, snapshot_atomic=False,
            read_calls=session.calls, read_bytes=session.bytes_read,
            process_memory_written=False, native_methods_invoked=False, packets_sent=False,
            code_sampled=False, native_layouts_constructed=False, historical_process_pointers_reused=False,
            gameplay_initialization_verified=False)
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
                process_memory_written=False, native_methods_invoked=False, packets_sent=False,
                code_sampled=False, native_layouts_constructed=False, historical_process_pointers_reused=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
