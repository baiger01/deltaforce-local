"""Current minimum-field opcode and concrete property method source bindings."""
import argparse
import json
from pathlib import Path
import struct

from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_OP_REG,X86_REG_RIP
from research_updated_metadata_roots import ROOT,disasm,instruction_row,sha
from research_updated_native_registration import Archive,CLIENT_SHA,text

INPUTS={
    'work/research_updated_command_shapes_79fb7b10_v1.json':'68471964b153ab566619c123fe03b53f5ac1e7221f4f74697ad3b2aaf9476989',
    'work/research_updated_native_registration_79fb7b10_v4.json':'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_source_map_schema_79fb7b10_v1.json':'ed591569846bb22602dbbe6571de72720b87e93f2ebb12da5dfff412696f4d27',
    'work/research_updated_nested_registration_79fb7b10_v1.json':'418679e96c04c60e790f3633e41cccbeca8159266b21cbb46e1495ae987abf62'}
FIELDS={
    'BP_DFMPlayerController_C':('Pawn','PlayerState'),
    'BP_DFMCharacter_C':('Controller','PlayerState','Role','RemoteRole'),
    'BP_GameState_PVPVE_C':('bReplicatedHasBegunPlay','bStartMathWithAllPlayerReady','bCanSwitchToAbseil',
        'MapId','RoomId','bMatchRealStart','DFMGamePlayerMode'),
    'BP_SOLPlayerState_C':('Uin','HeroID','CurrSameTeamAvatarId','CurrDiffTeamAvatarId')}
OPCODES={'FBoolProperty':21,'FIntProperty':5,'FInt64Property':2,'FByteProperty':6,
    'FEnumProperty':6,'FObjectProperty':8,'FUInt64Property':20}


def minimal_opcode(flags,ids,native_bool):
    if flags&ids['Struct']:
        raise ValueError('Special struct name classifier is outside the minimum scalar subset')
    if flags&ids['Bool']:
        if type(native_bool) is not bool:
            raise ValueError('Current Boolean FieldMask/native branch is required')
        return 21 if native_bool else 3
    for name,opcode in (('Float',4),('Int',5),('Byte',6)):
        if flags&ids[name]:
            return opcode
    if flags&ids['ObjectBase']:
        return 22 if flags&ids['SoftObject'] else 23 if flags&ids['WeakObject'] else 8
    for name,opcode in (('Name',7),('UInt32',9),('UInt64',20),('Str',19)):
        if flags&ids[name]:
            return opcode
    return 2


def class_id(a,rva):
    ins=a.instructions(rva)
    calls=[j for j,i in enumerate(ins) if i.mnemonic=='call' and i.op_str=='0x10e09140']
    if len(calls)!=1:
        raise ValueError('Unique current FieldClass construction absent for leaf type test')
    writes=[i for i in ins[:calls[0]] if i.mnemonic in ('mov','movabs') and
        i.op_str.startswith(('r8,','r8d,')) and i.operands[1].type==X86_OP_IMM]
    if not writes:
        raise ValueError('Current FieldClass type-test ID is not an immutable argument')
    return dict(getter_rva=hex(rva),setter_rva=hex(writes[-1].address),class_id64=hex(writes[-1].operands[1].imm))


def concrete_vtable(a,case):
    getter=a.instructions(int(case['field_class_binding_rva'],16))
    calls=[j for j,i in enumerate(getter) if i.mnemonic=='call' and i.op_str=='0x10e09140']
    if len(calls)!=1:
        raise ValueError('Unique named FFieldClass construction absent')
    pointers=[a.rip(i) for i in getter[:calls[0]] if i.mnemonic=='lea' and i.op_str.startswith('rdx, [rip')]
    if len(pointers)<2:
        raise ValueError('Current FieldClass construct callback binding absent')
    callback=pointers[-2]; ins=a.instructions(callback); values={}; vtables=[]
    for item in ins:
        if item.mnemonic=='call':
            for name in ('rax','rcx','rdx','r8','r9','r10','r11'):
                values.pop(name,None)
        if len(item.operands)!=2:
            continue
        dst,src=item.operands
        if dst.type==X86_OP_REG and dst.reg in item.regs_access()[1]:
            values.pop(item.reg_name(dst.reg),None)
            if item.mnemonic=='lea' and src.type==X86_OP_MEM and src.mem.base==X86_REG_RIP:
                values[item.reg_name(dst.reg)]=a.rip(item)
        elif (item.mnemonic=='mov' and dst.type==X86_OP_MEM and dst.size==8 and
                dst.mem.disp==0 and not dst.mem.index and item.reg_name(dst.mem.base) not in ('rsp','rbp') and
                src.type==X86_OP_REG and item.reg_name(src.reg) in values):
            vtables.append(values[item.reg_name(src.reg)])
    if len(set(vtables))!=1:
        raise ValueError('Current concrete property constructor vtable is ambiguous: '+case['kind'])
    return callback,vtables[0]


def complete_method(a,rva):
    if rva not in (0x286bc30,0x286bcc0):
        return a.instructions(rva)
    size={0x286bc30:0x4b,0x286bcc0:0x4c}[rva]
    ins=list(disasm(a.code,rva,size)); boundaries={i.address for i in ins}
    if sum(i.size for i in ins)!=size or a.code.read(rva+size,1)!=b'\xcc':
        raise ValueError('Explicit current numeric scalar method boundary changed')
    for item in ins:
        if item.mnemonic=='call':
            raise ValueError('Numeric scalar method unexpectedly calls a function')
        if item.mnemonic.startswith('j'):
            internal=item.operands[0].type==X86_OP_IMM and item.operands[0].imm in boundaries
            delegate={0x286bc30:0x10b4af10,0x286bcc0:0x10b4af70}[rva]
            tail=item.mnemonic=='jmp' and (item.op_str=='qword ptr [rax + 0x60]' or
                item.address==ins[-1].address and item.operands[0].type==X86_OP_IMM and item.operands[0].imm==delegate)
            if not internal and not tail:
                raise ValueError('Numeric scalar method has unqualified external control flow')
    if ins[-1].mnemonic not in ('ret','jmp'):
        raise ValueError('Numeric scalar method terminal differs')
    a.instructions(delegate)
    a.functions[rva]=(ins,dict(entry_rva=hex(rva),bytes=size,sha256=sha(a.code.read(rva,size)),
        complete_control_flow=True,explicit_archive_virtual_tail='0x60',instructions=[instruction_row(i) for i in ins]))
    return ins


def enum_registration(a,rva):
    factory=a.factory(rva)
    if factory['kind']!='enum':
        raise ValueError('Exact current enum registration required')
    raw=a.read(int(factory['parameter_rva'],16),56)
    outer,display,name,cpp,array,count=struct.unpack_from('<5Qi',raw)
    if not 1<=count<=1024:
        raise ValueError('Bounded exact current enumerator table required')
    entries=[]
    for index in range(count):
        pointer,value=struct.unpack('<Qq',a.read(array-a.base+index*16,16))
        entries.append(dict(name=text(a.read,pointer-a.base),value=value))
    if len({e['name'] for e in entries})!=count:
        raise ValueError('Duplicate current enum names')
    return dict(**factory,name=text(a.read,name-a.base),cpp_type_name=text(a.read,cpp-a.base),
        enumerators=entries,declared_maximum=max(e['value'] for e in entries),
        native_set_enums_flag_input=struct.unpack_from('<I',raw,48)[0],cpp_form=raw[52],
        enum_object_observed=False,post_set_enums_maximum_reconstructed=False)


def derive():
    docs={}
    for path,expected in INPUTS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Current minimum property source changed: '+path)
        docs[path]=json.loads(raw)
    shapes=docs[next(p for p in INPUTS if 'command_shapes_' in p)]
    native=docs[next(p for p in INPUTS if 'native_registration_' in p)]
    schema=docs[next(p for p in INPUTS if 'source_map_schema_' in p)]
    graph=docs[next(p for p in INPUTS if 'nested_registration_' in p)]
    classes=native['classes']+native['supporting_native_ancestors']+schema['additional_native_classes']
    by_path={c['package']+'.'+c['name']:c for c in classes}; a=Archive(); grammar=a.property_grammar()
    by_kind={case['kind']:case for case in grammar.values()}; families={}
    leaf=a.instructions(0x12da27b0); leaf_rows={i.address:i for i in leaf}
    witnesses={0x12da2858:'rbx, qword ptr [rbx + 0x88]',0x12da2a5f:'byte ptr [rbx + 0x8c], 0xff',
        0x12da2a6b:'ecx, 0x15',0x12da2aaa:'byte ptr [rdi + 0x1c], 5',
        0x12da2ac6:'byte ptr [rdi + 0x1c], 6',0x12da2b07:'r9d, 8',
        0x12da2b72:'byte ptr [rdi + 0x1c], 0x14'}
    for at,expected in witnesses.items():
        if leaf_rows[at].op_str!=expected:
            raise ValueError('Current minimal leaf opcode witness changed: '+hex(at))
    test_getters={name:class_id(a,rva) for name,rva in (
        ('Struct',0x10e98490),('Bool',0x10e972b0),('Float',0x10e976d0),('Int',0x10e97990),
        ('Byte',0x10e97360),('ObjectBase',0x10e98070),('SoftObject',0x10e98330),
        ('WeakObject',0x10e98800),('Name',0x10e97e60),('UInt32',0x10e986a0),
        ('UInt64',0x10e98750),('Str',0x10e983e0))}
    ids={name:int(row['class_id64'],16) for name,row in test_getters.items()}
    for kind,opcode in OPCODES.items():
        callback,vtable=concrete_vtable(a,by_kind[kind]); methods=[]
        for slot in (0x60,0x88,0x90):
            pointer,=struct.unpack('<Q',a.read(vtable+slot,8)); target=pointer-a.base
            complete_method(a,target)
            methods.append(dict(slot=hex(slot),target_rva=hex(target),native_function_called=False))
        families[kind]=dict(field_class_construct_callback_rva=hex(callback),concrete_vtable_rva=hex(vtable),
            dispatch_opcode=opcode,methods=methods,get_cpp_type_output_reconstructed=False)
    selected=[]; enums={}
    for receiver in shapes['selected_classes']:
        cache=next(r['cache'] for r in schema['selected_classes'] if r['path'].endswith('.'+receiver['receiver_class']))
        for name in FIELDS[receiver['receiver_class']]:
            commands=[c for c in receiver['commands'] if c['kind']=='leaf' and not c['scope'] and c['name']==name]
            if len(commands)!=1:
                raise ValueError('Exact minimum current leaf command identity absent: '+name)
            command=commands[0]; parent=cache['fields']
            if name in ('MapId','RoomId'):
                owner=next(s for s in graph['structures'] if s['name']=='MatchInfo')
                candidates=[p for p in owner['fields']['fields'] if p['name']==name]
                owner_name='MatchInfo'
            else:
                owners=[by_path[r['path']] for r in cache['classes'][:-1]]
                candidates=[p for c in owners for p in c['fields']['fields'] if p['name']==name]
                owner_name=next(c['name'] for c in owners if any(p['name']==name for p in c['fields']['fields']))
            if len(candidates)!=1:
                raise ValueError('Exact minimum native field source identity ambiguous: '+name)
            field=candidates[0]; kind=field['kind']; binding=families[kind]
            if kind=='FBoolProperty' and field['source_derived_bool_storage'].get('native_bool') is not True:
                raise ValueError('Minimum Boolean uses unqualified bitfield branch')
            type_field=field
            cast_flags=int(shapes['current_field_class_flags'][kind]['cast_flags64'],16)
            if cast_flags&(1<<48):
                if len(field['children'])!=1:
                    raise ValueError('Current enum underlying property binding is ambiguous')
                type_field=field['children'][0]
                cast_flags=int(shapes['current_field_class_flags'][type_field['kind']]['cast_flags64'],16)
            opcode=minimal_opcode(cast_flags,ids,field.get('source_derived_bool_storage',{}).get('native_bool'))
            if opcode!=binding['dispatch_opcode']:
                raise ValueError('Current literal FieldClass bits disagree with minimum leaf branch: '+name)
            enum=None
            if kind in ('FByteProperty','FEnumProperty'):
                callbacks=[c for c in field['callbacks'] if c['parameter_offset']=='0x28']
                if len(callbacks)!=1 or callbacks[0]['function_rva'] is None:
                    raise ValueError('Minimum enum-backed field lacks current enum source binding')
                key=callbacks[0]['function_rva']
                if key not in enums:
                    enums[key]=enum_registration(a,int(key,16))
                enum=key
            selected.append(dict(receiver_class=receiver['receiver_class'],field=name,declaring_owner=owner_name,
                parameter_record_rva=field['parameter_record_rva'],family=kind,
                relative_handle=command['relative_handle'],command_index=command['command_index'],
                dispatch_opcode=binding['dispatch_opcode'],property_method_binding=binding,
                enum_factory_rva=enum,runtime_descriptor_or_command_observed=False))
    for rva in (0x10e1dc70,0x10e37950,0x10e09ed0,0x10e1a3a0,0x10e1cf00,0x10e70240):
        a.instructions(rva)
    ctor={i.address:i for i in a.instructions(0x10e09ed0)}
    vtable=a.rip(ctor[0x10e09ede]); pointer,=struct.unpack('<Q',a.read(vtable+0x288,8))
    if pointer-a.base!=0x10e37950:
        raise ValueError('Current UEnum SetEnums source vtable binding differs')
    helpers=[Path(__file__),ROOT/'work/research_updated_minimum_leaf_bindings_test.py',ROOT/'work/research_updated_native_registration.py']
    return dict(kind='current_minimum_map_leaf_opcode_method_bindings',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        minimum_fields=selected,property_families=families,leaf_type_test_getters=test_getters,
        enum_registrations=list(enums.values()),
        enum_width_semantics=dict(byte_property='ceil_log2(UEnum current maximum), or 8 without enum',
            enum_property='archive EngineNetVer+0x54 <12: ceil_log2(maximum); >=12: ceil_log2(maximum+1)',
            current_post_set_enums_maximum_reconstructed=False,current_archive_engine_net_version_observed=False),
        native_functions=[p for _,p in a.functions.values()],immutable_reads=list(a.data.values()),
        code_source=a.code.source_evidence(),current_cpp_type_outputs_reconstructed=False,
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
    print(json.dumps(dict(output=str(target),sha256=sha(raw),minimum_fields=len(report['minimum_fields']))))
