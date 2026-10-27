"""Current twelve startup RPC declarations and complete nested parameter inputs."""
import argparse
import json
from pathlib import Path
import struct

from research_updated_metadata_roots import ROOT,sha
from research_updated_native_registration import Archive,CLIENT_SHA
from research_updated_minimum_leaf_bindings import concrete_vtable,complete_method,enum_registration
from research_updated_enum_widths import width_candidates

INPUTS={
    'work/research_updated_native_registration_79fb7b10_v4.json':'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_source_map_schema_79fb7b10_v1.json':'ed591569846bb22602dbbe6571de72720b87e93f2ebb12da5dfff412696f4d27',
    'work/research_updated_deferred_struct_ops_79fb7b10_v1.json':'60426a191620a7149ffd50e34e43d858295f690ced63125f7446317363fc621e',
    'work/research_updated_ename_bindings_79fb7b10_v3.json':'4b4fc6de5a4722034517cafa60b1186f2b1d859a0aab086d3c8751126c2e73d1'}
NAMES=('ServerShortTimeout','Server_RcvACWorldTime','ServerFieldOfView','NotifySeamlessLoginReady',
    'ClientAckSeamlessLoginReady','ServerBouncePing','ClientReturnPing','ClientRestart',
    'ServerAcknowledgePossession','ClientSetViewTarget','ServerVerifyViewTarget','ClientSetRotation')


def derive():
    docs={}
    for path,expected in INPUTS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Current minimum RPC declaration input changed: '+path)
        docs[path]=json.loads(raw)
    native=docs[next(p for p in INPUTS if 'native_registration_' in p)]
    schema=docs[next(p for p in INPUTS if 'source_map_schema_' in p)]
    cache=next(r['cache'] for r in schema['selected_classes'] if r['path'].endswith('.BP_DFMPlayerController_C'))
    by_path={c['package']+'.'+c['name']:c for c in native['classes']+native['supporting_native_ancestors']}
    a=Archive(); functions=[]; pending=[]; structures={}; references=[]; byte_enums={}
    for name in NAMES:
        fields=[f for f in cache['fields'] if f['kind']=='function' and f['name']==name]
        if len(fields)!=1:
            raise ValueError('Exact source-bound current startup RPC absent or ambiguous: '+name)
        field=fields[0]
        candidates=[f for f in by_path[field['owner']]['functions'] if f['name']==name]
        if len(candidates)!=1 or candidates[0]['super_function_factory_rva'] is not None:
            raise ValueError('Exact current RPC registration owner/super identity differs')
        fn=candidates[0]
        functions.append(dict(name=name,declaring_class=field['owner'],class_cache_index=field['cache_index'],
            exclusive_cache_index_maximum=cache['exclusive_cache_index_maximum'],declaration=fn))
        pending.extend(fn['parameters']['fields'])
    families=set()
    while pending:
        prop=pending.pop(0); kind=prop['kind']; families.add(kind)
        if kind=='FStructProperty':
            callback=next(c for c in prop['callbacks'] if c['parameter_offset']=='0x28')
            key=callback['function_rva']
            if key is None:
                raise ValueError('Current RPC struct parameter lacks exact source callback')
            references.append(dict(property_name=prop['name'],property_parameter_rva=prop['parameter_record_rva'],factory_rva=key))
            if key not in structures:
                if len(structures)>=32:
                    raise ValueError('Startup RPC nested graph exceeds local bound')
                node=a.structure(int(key,16)); structures[key]=node
                pending.extend(node['fields']['fields'])
        elif kind=='FByteProperty':
            callback=next(c for c in prop['callbacks'] if c['parameter_offset']=='0x28')
            key=callback['function_rva']
            if key:
                enum=enum_registration(a,int(key,16))
                widths=width_candidates(enum['name'],enum['cpp_form'],[(e['name'],e['value']) for e in enum['enumerators']])
                byte_enums[key]=dict(declaration=enum,width_candidates=widths)
        elif kind not in ('FFloatProperty','FDoubleProperty','FBoolProperty','FObjectProperty'):
            raise ValueError('Startup RPC scalar family outside explicitly supported source graph: '+kind)
        pending.extend(prop['children'])
    grammar={r['kind']:r for r in a.property_grammar().values()}; bindings={}
    for kind in sorted(families):
        callback,vtable=concrete_vtable(a,grammar[kind]); methods=[]
        for slot in (0x88,0x90):
            pointer,=struct.unpack('<Q',a.read(vtable+slot,8)); target=pointer-a.base
            complete_method(a,target)
            methods.append(dict(slot=hex(slot),target_rva=hex(target),native_function_called=False))
        bindings[kind]=dict(field_class_construct_callback_rva=hex(callback),vtable_rva=hex(vtable),methods=methods)
    a.instructions(0x12db3000); a.instructions(0x12d9b530); a.instructions(0x12da27b0)
    deferred=docs[next(p for p in INPUTS if 'deferred_struct_ops_' in p)]
    rotator=next(r for r in deferred['registrations'] if r['name']=='Rotator')
    enames=docs[next(p for p in INPUTS if 'ename_bindings_' in p)]
    if next(r for r in enames['hardcoded_names'] if r['ename_index']==0x3c)['literal_name']!='Rotator':
        raise ValueError('Current Rotator special command name identity unqualified')
    helpers=[Path(__file__),ROOT/'work/research_updated_native_registration.py',ROOT/'work/research_updated_minimum_leaf_bindings.py',
        ROOT/'work/research_updated_enum_widths.py']
    return dict(kind='current_minimum_startup_rpc_declarations',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        functions=functions,struct_reference_edges=references,structures=list(structures.values()),
        property_families=bindings,byte_enums=list(byte_enums.values()),rotator_net_serializer_source=rotator,
        native_functions=[p for _,p in a.functions.values()],immutable_reads=list(a.data.values()),code_source=a.code.source_evidence(),
        current_parameter_declaration_trees_complete=True,rpc_wire_serializer_reimplemented=False,
        pure_sender_recipe_compatibility_checked=False,profile_activation_authorized=False,
        process_opened=False,native_engine_function_called=False,runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),functions=len(report['functions']),structs=len(report['structures']))))
