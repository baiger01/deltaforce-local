"""Exclusive read-only followup for the active owned FSM diagnostic trial."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from fsm_readonly_scope import ROOT, CLIENT, PATHS, qualified_field, source_pins
from fsm_generated_class_scope import observe_class_metadata
from observe_owned_emptyhand_class_metadata import ClassObservation
from observe_owned_gameplay_metadata import (address, owned_trial_identity, typed_declarations,
    label_existing, write_exclusive_report)
from observe_owned_vitals_metadata import VitalsBindingObservation, enrich_existing_layout
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, recheck_virtual_method, request_elevation)
from native_metadata_paths import object_path

CAPTURE = 'work/native-client-tests/1792385022786009500/owned-fsm-metadata.json'
CAPTURE_SHA = '1aa920e4db727a55e0c75cffc2bae533d83e27a9cd0d0ecb368489cebfa8f628'
PID, CREATED = 11500, 1792385029.5729253


def observe(game_root, trial_report):
    original = (ROOT/CAPTURE).read_bytes()
    if hashlib.sha256(original).hexdigest() != CAPTURE_SHA:
        raise ValueError('The exact first FSM capture changed')
    trial_raw = Path(trial_report).read_bytes()
    if owned_trial_identity(json.loads(trial_raw), game_root) != (PID, CREATED):
        raise ValueError('This exclusive followup belongs to the active diagnostic only')
    pins = source_pins()
    if pins != json.loads(original)['source_pins']:
        raise ValueError('The frozen first FSM observation imports changed')
    pins = dict(pins, **{CAPTURE: CAPTURE_SHA, Path(__file__).relative_to(ROOT).as_posix():
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, PID, CREATED, maximum_seconds=120)
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
            raise ValueError('One current primary owning connection is required')
        pc = pcs[0]
        pc_at, driver, connection = (address(pc[k]) for k in ('address','driver','connection'))
        binding = observe_first_player_state(session,base,driver_address=driver,
            connection_address=connection,pc_address=pc_at,object_identity=callback)
        if binding.get('status') != 'observed' or binding['pc_pawn_reference'].get('status') != 'typed_existing_reference':
            raise ValueError('The current owned Pawn binding is unavailable')
        pawn = address(binding['pc_pawn_reference']['address'])
        records, hooks, reads, chains = {}, [], {}, {}
        def metadata(pointer, expected):
            identity = observation.identify(pointer,expected)
            klass = address(identity['class_address'])
            existing = label_existing(session,base,driver,klass)
            enrich_existing_layout(session,base,existing,hooks,reads)
            row = dict(identity=identity,class_identity=callback(klass,'Class'),
                class_path=object_path(session.read,base,klass),
                declarations=typed_declarations(session,base,klass,callback),existing_driver_class=existing)
            records[pointer] = row
            return row
        observation = VitalsBindingObservation(session,base,callback,metadata)
        pawn_record = metadata(pawn,'Pawn')
        link = observation.reference(pawn,qualified_field(pawn_record,'pawn','FSMComponent'),
            expected_base='GPFSMStateMachineComponent')
        if link.get('status') != 'typed_existing_reference':
            raise ValueError('The current Pawn FSM reference is unavailable')
        component = address(link['identity']['address'])
        record = metadata(component,'GPFSMStateMachineComponent')
        if (record['class_path'] != PATHS['component'] or record['identity']['name'] != 'GPFSMStateMachine' or
                address(record['identity']['outer_address']) != pawn):
            raise ValueError('The current Pawn default FSM identity differs')
        instance = observation.reference(component,qualified_field(record,'component','R_Instance'),
            expected_base='SMInstance')
        class_field = qualified_field(record,'component','StateMachineClass')
        class_at = component+class_field['storage_offset']
        class_raw = session.stable(class_at,8)
        reads[class_at,8] = class_raw
        klass = address(struct.unpack('<Q',class_raw)[0])
        generated_identity = observation.identify(klass,'Class')
        if object_path(session.read,base,klass) != PATHS['instance']:
            raise ValueError('The current StateMachineClass is not the source main FSM')
        declarations = typed_declarations(session,base,klass,callback)
        generated_layout = label_existing(session,base,driver,klass)
        enrich_existing_layout(session,base,generated_layout,hooks,reads)
        class_ob = ClassObservation(session,base)
        generated_metadata = observe_class_metadata(class_ob,klass,image_size=size)
        for role, first in (('component',address(record['identity']['class_address'])),('generated_instance',klass)):
            rows, cursor, seen = [], first, set()
            while cursor:
                if cursor in seen or len(seen) >= 32:
                    raise ValueError('The selected FSM ancestor chain exceeds its scope')
                seen.add(cursor)
                identity = observation.identify(cursor,'Class')
                raw = session.stable(cursor+0x48,8)
                reads[cursor+0x48,8] = raw
                layout = label_existing(session,base,driver,cursor)
                enrich_existing_layout(session,base,layout,hooks,reads)
                rows.append(dict(identity=identity,class_path=object_path(session.read,base,cursor),
                    existing_driver_class=layout))
                cursor = struct.unpack('<Q',raw)[0]
            chains[role] = rows
        observation.finish()
        class_ob.finish()
        generated_metadata.update(metadata_recheck_required=False,identities_and_fields_rechecked=True)
        if typed_declarations(session,base,klass,callback) != declarations:
            raise ValueError('The generated FSM declarations changed before publication')
        for pointer, row in records.items():
            current = address(row['identity']['class_address'])
            if typed_declarations(session,base,current,callback) != row['declarations']:
                raise ValueError('The current FSM root declarations changed')
        for descriptor, hook in hooks:
            recheck_virtual_method(session,base,descriptor,hook)
        if any(session.stable(at,size) != raw for (at,size),raw in reads.items()):
            raise ValueError('The current FSM metadata changed before publication')
        sink['recheck_roots']()
        if observe_first_player_state(session,base,driver_address=driver,connection_address=connection,
                pc_address=pc_at,object_identity=callback) != binding:
            raise ValueError('The current owning Pawn binding changed')
        reader.verify_identity()
        if reader.find_module() != base or source_pins() != json.loads(original)['source_pins']:
            raise ValueError('The frozen current source/module changed')
        return dict(kind='owned_fsm_current_class_layout_followup_v1',status='observed',
            client_sha256=CLIENT,pid=PID,created_at=CREATED,source_pins=pins,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc,first_player_binding=binding,objects=list(records.values()),
            current_R_Instance=instance,generated_instance_class=dict(identity=generated_identity,
                class_path=PATHS['instance'],declarations=declarations,
                existing_driver_class=generated_layout,generated_class_metadata=generated_metadata),
            ancestor_driver_metadata=chains,identities_and_fields_rechecked=True,
            selected_roots_rechecked=True,process_identity_rechecked=True,snapshot_atomic=False,
            process_memory_written=False,native_methods_invoked=False,packets_sent=False,
            native_layouts_constructed=False,code_sampled=False,historical_process_pointers_reused=False,
            wire_handles_inferred_from_class_net_cache_indices=False,
            read_calls=session.calls,read_bytes=session.bytes_read)
    finally:
        reader.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root',type=Path,required=True)
    parser.add_argument('--trial-report',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--request-uac',action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work').resolve()):
        parser.error('Use an exclusive new project work output')
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B',str(Path(__file__).resolve()),'--game-root',str(args.game_root.resolve()),
            '--trial-report',str(args.trial_report.resolve()),'--output',str(output)],output)
        result = json.loads(output.read_bytes())
    else:
        try:
            result = observe(args.game_root,args.trial_report)
        except Exception as error:
            result = dict(status='refused',reason=str(error),error_type=type(error).__name__,
                process_memory_written=False,native_methods_invoked=False,packets_sent=False)
        write_exclusive_report(output,result)
    print(json.dumps(dict(status=result['status'],reason=result.get('reason'),output=str(output))))
