"""Current declaration-derived RepLayout shape candidates, without leaf opcodes."""
import argparse
import json
from pathlib import Path
from capstone.x86 import X86_OP_IMM

from research_updated_metadata_roots import ROOT,sha
from research_updated_native_registration import Archive,CLIENT_SHA
from research_updated_source_map_schema import ascii_key

INPUTS={
    'work/research_updated_nested_registration_79fb7b10_v1.json':'418679e96c04c60e790f3633e41cccbeca8159266b21cbb46e1495ae987abf62',
    'work/research_updated_deferred_struct_ops_79fb7b10_v1.json':'60426a191620a7149ffd50e34e43d858295f690ced63125f7446317363fc621e',
    'work/research_updated_native_registration_79fb7b10_v4.json':'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_source_map_schema_79fb7b10_v1.json':'ed591569846bb22602dbbe6571de72720b87e93f2ebb12da5dfff412696f4d27'}


def command_shapes(properties,structures):
    commands=[]
    def emit(field,base,handle,parent,scope,depth):
        if depth>32 or len(commands)>=8192:
            raise ValueError('Command recursion/count exceeds local bound')
        if field['array_dim']!=1:
            raise ValueError('This source prefix reconstruction accepts ArrayDim=1 only')
        if type(field['offset']) is not int or not 0<=field['offset']<=1048576:
            raise ValueError('Exact bounded constructor storage offset required')
        current=base+field['offset']; kind=field['kind']
        if kind=='FArrayProperty':
            if len(field['children'])!=1:
                raise ValueError('Current array needs exactly one qualified inner declaration')
            handle+=1
            index=len(commands)
            commands.append(dict(kind='array',name=field['name'],relative_handle=handle,scope=scope,
                parent_index=parent,constructor_offset_sum=current,dispatch_opcode=0))
            emit(field['children'][0],0,0,parent,scope+[field['name']],depth+1)
            commands.append(dict(kind='return',name=None,relative_handle=0,scope=scope+[field['name']],
                parent_index=0,constructor_offset_sum=0,dispatch_opcode=1))
            commands[index]['end_command_exclusive']=len(commands)
            return handle
        if kind=='FStructProperty':
            key=field['struct']
            if key not in structures or structures[key]['net_serializer'] is None:
                raise ValueError('Current effective struct NetSerialize flag is unqualified: '+key)
            structure=structures[key]
            if not structure['net_serializer']:
                chain=[]; seen=set(); at=key
                while at is not None:
                    if at in seen or at not in structures or len(seen)>=32:
                        raise ValueError('Complete acyclic struct inheritance required')
                    seen.add(at); chain.extend(structures[at]['fields']); at=structures[at]['parent']
                children=[p for p in chain if not p['flags']&0x80000000]
                keys=[(p['offset'],ascii_key(p['name'])) for p in children]
                if len(keys)!=len(set(keys)):
                    raise ValueError('Exact native sort required for equal nested comparator keys')
                for child in sorted(children,key=lambda p:(p['offset'],ascii_key(p['name']))):
                    handle=emit(child,current,handle,parent,scope,depth+1)
                return handle
        elif kind not in ('FByteProperty','FBoolProperty','FFloatProperty','FDoubleProperty',
                'FInt8Property','FInt16Property','FIntProperty','FInt64Property','FUInt16Property',
                'FUInt32Property','FUInt64Property','FEnumProperty','FNameProperty','FObjectProperty',
                'FStrProperty','FTextProperty','FClassProperty','FMapProperty','FSetProperty'):
            raise ValueError('Current leaf family is outside qualified prefix subset: '+kind)
        handle+=1
        if handle>65535:
            raise ValueError('Relative handle exceeds bounded no-wrap subset')
        commands.append(dict(kind='leaf',name=field['name'],field_family=kind,relative_handle=handle,
            scope=scope,parent_index=parent,constructor_offset_sum=current,dispatch_opcode_recovered=False))
        return handle
    handle=0
    for parent,field in enumerate(properties):
        handle=emit(field,0,handle,parent,[],0)
    for index,command in enumerate(commands):
        command['command_index']=index
    return dict(commands=commands,outer_handle_maximum=handle,
        relative_handle_basis='qualified current recursive/leaf command allocation and complete selected declarations',
        constructor_offset_sums_are_not_qualified_native_command_offsets=True,
        auxiliary_property_remapping_not_applied=True,lifetime_conditions_reconstructed=False,
        leaf_dispatch_opcodes_recovered=False,current_runtime_rep_layout_observed=False)


def derive():
    docs={}
    for path,expected in INPUTS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Current command shape input changed: '+path)
        docs[path]=json.loads(raw)
    graph=docs[next(p for p in INPUTS if 'nested_registration_' in p)]
    deferred=docs[next(p for p in INPUTS if 'deferred_struct_ops_' in p)]
    native=docs[next(p for p in INPUTS if 'native_registration_' in p)]
    schema=docs[next(p for p in INPUTS if 'source_map_schema_' in p)]
    a=Archive(); family_flags={}
    for case in a.property_grammar().values():
        if case['kind'] in family_flags:
            continue
        ins=a.instructions(int(case['field_class_binding_rva'],16))
        calls=[j for j,i in enumerate(ins) if i.mnemonic=='call' and i.op_str=='0x10e09140']
        if len(calls)!=1:
            raise ValueError('Current FieldClass named constructor binding is ambiguous')
        writes=[i for i in ins[:calls[0]] if i.mnemonic in ('mov','movabs') and
            i.op_str.startswith(('r9,','r9d,')) and i.operands[1].type==X86_OP_IMM]
        if not writes:
            raise ValueError('Current literal FieldClass cast flags absent')
        family_flags[case['kind']]=dict(cast_flags64=hex(writes[-1].operands[1].imm),
            setter_rva=hex(writes[-1].address),field_class_constructor_rva='0x10e09140')
    ctor={i.address:i for i in a.instructions(0x10e09140)}
    if ctor[0x10e09172].op_str!='qword ptr [rcx + 0x10], r9':
        raise ValueError('Current FieldClass cast-flag storage changed')
    recursive={i.address:i for i in a.instructions(0x12d9b530)}
    leaf={i.address:i for i in a.instructions(0x12da27b0)}
    a.instructions(0x12db2210); a.instructions(0x4a24a60)
    expected={0x12d9b570:'rdx, 0x15',0x12d9b589:'r12d',0x12d9b601:'dword ptr [rsp + 0x38], r13d',
        0x12d9b606:'r9d, r9d',0x12d9b662:'byte ptr [rax + rcx + 0x1c], 1',
        0x12d9b696:'rcx, 0x14',0x12d9b6b2:'eax, 0xa',0x12d9b766:'rax, 0x1f',
        0x12d9b7cc:'0x4a24a60',0x12d9b899:'0x12d9b530',0x12d9b924:'0x12da27b0'}
    expected[0x12d9b89c]=expected.pop(0x12d9b899)
    for at,value in expected.items():
        if at not in recursive or recursive[at].op_str!=value:
            raise ValueError('Current recursive shape witness changed: '+hex(at))
    if leaf[0x12da2839].op_str!='word ptr [rdi + 0x14], bp':
        raise ValueError('Current leaf relative-handle assignment changed')
    def normalize(p):
        flags=int(family_flags[p['kind']]['cast_flags64'],16)
        if bool(flags&(1<<21))!=(p['kind']=='FArrayProperty') or bool(flags&(1<<20))!=(p['kind']=='FStructProperty'):
            raise ValueError('Current selected family has an unimplemented array/struct branch: '+p['kind'])
        offset=p.get('constructor_offset_argument')
        if p['kind']=='FBoolProperty':
            offset=p['source_derived_bool_storage'].get('storage_offset')
        row=dict(name=p['name'],kind=p['kind'],offset=offset,array_dim=p['array_dim'],
            flags=int(p['property_flags64_before_factory'],16),children=[normalize(c) for c in p['children']])
        if p['kind']=='FStructProperty':
            matches=[c['function_rva'] for c in p['callbacks'] if c['parameter_offset']=='0x28']
            if len(matches)!=1 or matches[0] is None:
                raise ValueError('Exact selected struct callback absent')
            row['struct']=matches[0]
        return row
    patched={r['name']:r['struct_flag_0x400_after_prepare'] for r in deferred['registrations']}
    structures={}
    for s in graph['structures']:
        binding=s['cpp_struct_ops_source_binding']
        flag=binding['struct_flag_0x400_after_prepare'] if binding else patched.get(s['name'])
        if int(s['declared_struct_flags'],16)&0x400:
            flag=True
        structures[s['factory_rva']]=dict(name=s['name'],parent=s['super_struct_factory_rva'],
            net_serializer=flag,fields=[normalize(p) for p in s['fields']['fields']])
    classes=native['classes']+native['supporting_native_ancestors']+schema['additional_native_classes']
    fields={p['parameter_record_rva']:p for c in classes for p in c['fields']['fields']}
    candidates=[]
    for prefix in graph['property_prefixes']:
        properties=[normalize(fields[p['parameter_rva']]) for p in prefix['own_and_inherited_net_property_prefix']]
        candidates.append(dict(receiver_class=prefix['receiver_class'],stop_property=prefix['stop_property'],
            **command_shapes(properties,structures)))
    helpers=[Path(__file__),ROOT/'work/research_updated_command_shapes_test.py',
        ROOT/'work/research_updated_native_registration.py',ROOT/'work/research_updated_source_map_schema.py']
    return dict(kind='current_source_derived_minimum_map_command_shapes',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        selected_classes=candidates,current_field_class_flags=family_flags,
        native_functions=[p for _,p in a.functions.values()],
        code_source=a.code.source_evidence(),source_derived_relative_handles_are_not_runtime_observation=True,
        profile_guards_relaxed=False,process_opened=False,native_engine_function_called=False,
        runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),classes=len(report['selected_classes']))))
