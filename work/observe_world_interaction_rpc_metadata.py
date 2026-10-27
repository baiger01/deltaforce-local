"""Read existing interaction RPC layouts and reflected parameters; no RPC calls."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import export_native_replication_metadata as exporter
from observe_owned_gameplay_metadata import (address,owned_trial_identity,typed_declarations,
    BindingObservation,write_exclusive_report,label_existing,OBJECT_PROPERTY_TYPES)
from observe_portable_map_runtime import (ROOT,SHIPPING_SHA256,Win32MetadataReader,
    MetadataSession,validate_source,discover_roots,observe_first_player_state,request_elevation)
from native_metadata_paths import object_path
from observe_world_interaction_lifecycle import Facts,Fields,sources as world_sources

LOOKUP_SOURCE = 'work/evidence/map-system-audit-20261018/native-economy-interaction-existing-rpc-layout-lookup-v1.json'
LOOKUP_SHA = '6a1e96b58549324868c549adbe57f024aa5a13447ff4a517725f53b04704cd6f'
REQUESTS = {
    'controller': ('ServerOpenPickupBox',),
    'InventoryManager': ('ServerProcessItemMoveCmd',),
    'InteractorComponent': ('ServerInteractAction', 'ServerExecuteInteractByTag',
                           'ServerExecuteInteractableCompByTag'),
}


def targets(cache_nodes,names):
    fields = [f for node in cache_nodes for f in node['fields']]
    selected = {}
    for name in names:
        rows = [f for f in fields if f.get('descriptor_name')==name]
        if not rows:
            continue
        if (len(rows)!=1 or rows[0].get('descriptor_representation')!=1 or
                rows[0].get('incompatible') or not rows[0].get('descriptor_address')):
            raise ValueError('An exact compatible native Function mapping is required: '+name)
        index = rows[0]['rep_index']
        if type(index) is not int or not 0<=index<65536 or index in selected:
            raise ValueError('A current native Function cache index is invalid or aliased')
        selected[index] = name
    return selected


def sources():
    pins = world_sources()
    raw = (ROOT/LOOKUP_SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=LOOKUP_SHA:
        raise ValueError('The existing Function RepLayout source changed')
    source = json.loads(raw)
    operands = [row['operands'] for f in source['functions'] for row in f['instructions']]
    if (source.get('client_sha256')!=SHIPPING_SHA256 or source.get('process_access') is not False or
            not any('0x430' in value for value in operands)):
        raise ValueError('The source does not qualify the actual driver Function layout table')
    pins[LOOKUP_SOURCE] = LOOKUP_SHA
    relative = 'work/observe_world_interaction_rpc_metadata.py'
    pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def observe(game_root,trial_report):
    trial_raw = Path(trial_report).read_bytes()
    pid,created = owned_trial_identity(json.loads(trial_raw),game_root)
    pins = sources()
    executable,size = validate_source(game_root)
    reader = Win32MetadataReader(executable,size,pid,created,maximum_seconds=150)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256,session.module_size = SHIPPING_SHA256,size
        base,sink = reader.module_base,{}
        roots = discover_roots(session,base,connection_binding_only=True,first_player_state=True,
            _binding_identity_sink=sink,unpublished_batch_retry=True)
        identity = sink['callback']
        pcs = [r for r in roots['connection_binding_observations']['player_controllers']
            if r.get('status')=='observed' and r.get('identity_and_fields_rechecked') is True
            and r.get('driver_primary_matches_original_connection') is True and r.get('local_player_index_field')==0]
        if len(pcs)!=1:
            raise ValueError('One current owned primary controller is required')
        pc = pcs[0]
        driver = address(pc['driver'])
        binding = observe_first_player_state(session,base,driver_address=driver,
            connection_address=address(pc['connection']),pc_address=address(pc['address']),object_identity=identity)
        pawn = binding.get('pc_pawn_reference',{})
        if binding.get('status')!='observed' or pawn.get('status')!='typed_existing_reference':
            raise ValueError('One current owned Pawn is required')
        facts,cache,final_rpc_checks = Facts(session),{},[]

        def metadata(pointer,expected):
            value = identity(pointer,expected)
            klass = address(value['class_address'])
            if klass not in cache:
                cache[klass] = dict(declarations=typed_declarations(session,base,klass,identity),
                    existing_driver_class=label_existing(session,base,driver,klass))
            return cache[klass]

        observation = BindingObservation(session,base,identity,metadata)
        fields = Fields(session,base,observation.identify,facts)
        pawn_pointer = address(pawn['address'])
        observation.identify(pawn_pointer,'Pawn')
        owners = [('controller',address(pc['address']),'PlayerController')]
        missing_owners = []
        for name in ('InventoryManager','InteractorComponent'):
            rows = [dict(f,declaring_class=c['class_name'])
                for c in metadata(pawn_pointer,'Pawn')['declarations'] for f in c['fields'] if f['name']==name]
            if len(rows)!=1:
                raise ValueError('One current default-subobject declaration is required: '+name)
            link = observation.reference(pawn_pointer,rows[0],expected_base='ActorComponent')
            if link.get('status')!='typed_existing_reference':
                missing_owners.append(dict(name=name,binding=link))
                continue
            value = link['identity']
            if value['name']!=name or address(value['outer_address'])!=pawn_pointer:
                raise ValueError('The current interaction RPC owner Name or Outer differs')
            owners.append((name,address(value['address']),'ActorComponent'))

        def parameter(field,depth=0):
            if depth>3:
                return dict(field=field,status='nested_metadata_depth_bound')
            result = dict(field=field,serializer_hook=fields.hook(field))
            descriptor = field['descriptor_address']
            kind = field['field_vtable_rva']
            if kind in OBJECT_PROPERTY_TYPES:
                target = address(struct.unpack('<Q',facts.keep(descriptor+0x90,8))[0])
                result.update(declared_native_class=observation.identify(target,'Class'),
                    declared_native_class_path=object_path(session.read,base,target))
            elif kind==0x15a86f40:
                target = address(struct.unpack('<Q',facts.keep(descriptor+0x90,8))[0])
                result.update(declared_struct=observation.identify(target,'ScriptStruct'),
                    declared_struct_path=object_path(session.read,base,target))
                nested = fields.properties(target)
                if len(nested)>64:
                    raise ValueError('Nested interaction parameter fields exceed the metadata bound')
                result['fields'] = [parameter(row,depth+1) for row in nested]
            elif kind==0x1ab5b730:
                inner = address(struct.unpack('<Q',facts.keep(descriptor+0x90,8))[0])
                raw = facts.keep(inner,0x60)
                result['inner'] = parameter(dict(name=field['name']+'[]',descriptor_address=inner,
                    declaring_class=field['declaring_class'],storage_offset=struct.unpack_from('<i',raw,0x54)[0],
                    element_bytes=struct.unpack_from('<i',raw,0x40)[0],array_dimension=struct.unpack_from('<i',raw,0x3c)[0],
                    field_vtable_rva=struct.unpack_from('<Q',raw)[0]-base,
                    property_flags=hex(struct.unpack_from('<Q',raw,0x48)[0])),depth+1)
            elif kind==0x15a868a0:
                result['bool_masks_hex'] = facts.keep(descriptor+0x8a,3).hex()
            return result

        results = []
        for scope,pointer,expected in owners:
            before = observation.identify(pointer,expected)
            current = metadata(pointer,expected)['existing_driver_class']
            nodes = current.get('cache_nodes',[])
            selected = targets(nodes,REQUESTS[scope])
            original = exporter.CONNECTION_RPC_LAYOUT_TARGETS
            try:
                exporter.CONNECTION_RPC_LAYOUT_TARGETS = selected
                rpc = exporter.export_existing_pc_rpc_layouts(session,base,driver,nodes,
                    object_identity=observation.identify,_final_recheck_sink=final_rpc_checks)
            finally:
                exporter.CONNECTION_RPC_LAYOUT_TARGETS = original
            for row in rpc:
                function = row.get('descriptor_address')
                if function:
                    row['parameter_declarations'] = [parameter(field) for field in fields.properties(function)]
            results.append(dict(scope=scope,identity=before,object_path=object_path(session.read,base,pointer),
                class_path=object_path(session.read,base,address(before['class_address'])),
                existing_driver_class=current,rpc_functions=rpc,
                missing_current_function_names=sorted(set(REQUESTS[scope])-set(selected.values()))))
        facts.finish()
        for recheck in final_rpc_checks:
            recheck()
        observation.finish()
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module()!=base or sources()!=pins:
            raise ValueError('The interaction RPC source/module identity changed')
        return dict(kind='owned_current_interaction_rpc_parameter_metadata_observation',status='observed',
            client_sha256=SHIPPING_SHA256,pid=pid,created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),primary_connection_binding=pc,
            first_player_binding=binding,owners=results,missing_owners=missing_owners,
            identities_and_fields_rechecked=True,read_calls=session.calls,read_bytes=session.bytes_read,
            process_memory_written=False,native_methods_invoked=False,native_layouts_constructed=False,
            packets_sent=False,code_sampled=False,historical_process_pointers_reused=False)
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root',type=Path,required=True)
    parser.add_argument('--trial-report',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--request-uac',action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/'work'):
        parser.error('Use an exclusive new project work output')
    owned_trial_identity(json.loads(args.trial_report.read_bytes()),args.game_root)
    sources()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B',str(Path(__file__).resolve()),'--game-root',str(args.game_root.resolve()),
            '--trial-report',str(args.trial_report.resolve()),'--output',str(output)],output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root,args.trial_report)
        except Exception as error:
            report = dict(status='refused',reason=str(error),error_type=type(error).__name__,
                process_memory_written=False,native_methods_invoked=False,native_layouts_constructed=False,
                packets_sent=False,code_sampled=False,historical_process_pointers_reused=False)
        write_exclusive_report(output,report)
    print(json.dumps(dict(status=report['status'],reason=report.get('reason'),output=str(output))))


if __name__=='__main__':
    main()
