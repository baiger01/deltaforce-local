"""Current compiled constructor assignments, never cached-CDO observations."""
import argparse
import bisect
import json
import mmap
from pathlib import Path
import struct

from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_OP_REG,X86_REG_RIP
from research_updated_metadata_roots import CLIENT,ROOT,disasm,instruction_row,sha
from research_updated_native_registration import Archive,CLIENT_SHA,text
from research_updated_source_map_schema import private_class_arguments

INPUTS={
    'work/research_updated_native_registration_79fb7b10_v4.json':'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_source_map_schema_79fb7b10_v1.json':'ed591569846bb22602dbbe6571de72720b87e93f2ebb12da5dfff412696f4d27',
    'work/research_updated_cooked_declarations_79fb7b10_v5.json':'b29f6cda96c690351596f5e96879d96267610adbfd86b36cd253661af7ec3037'}


def constructor_assignments(instructions,*,from_initializer=False):
    values={'rcx':('initializer' if from_initializer else 'object',0)}; rows=[]
    for ins in instructions:
        ops=ins.operands
        if ins.mnemonic=='call':
            for name in ('rax','rcx','rdx','r8','r9','r10','r11'):
                values.pop(name,None)
            continue
        if len(ops)!=2:
            continue
        dst,src=ops
        value=None
        if ins.mnemonic=='lea' and src.type==X86_OP_MEM:
            if src.mem.base==X86_REG_RIP:
                value=('rva',ins.address+ins.size+src.mem.disp)
            elif not src.mem.index:
                base=values.get(ins.reg_name(src.mem.base))
                if base and base[0]=='object':
                    value=('object',base[1]+src.mem.disp)
        elif ins.mnemonic in ('mov','movabs'):
            if src.type==X86_OP_REG:
                value=values.get(ins.reg_name(src.reg))
            elif src.type==X86_OP_MEM and not src.mem.index and src.mem.disp==0:
                base=values.get(ins.reg_name(src.mem.base))
                if base and base[0]=='initializer':
                    value=('object',0)
        if dst.type==X86_OP_REG and dst.reg in ins.regs_access()[1]:
            values.pop(ins.reg_name(dst.reg),None)
            if value:
                values[ins.reg_name(dst.reg)]=value
        elif ins.mnemonic=='mov' and dst.type==X86_OP_MEM and dst.size==8 and not dst.mem.index:
            base=values.get(ins.reg_name(dst.mem.base))
            if base and base[0]=='object' and value and value[0]=='rva':
                rows.append(dict(object_offset=base[1]+dst.mem.disp,source_rva=value[1],
                    assignment_rva=hex(ins.address),instruction=ins.mnemonic+' '+ins.op_str))
    return rows


def constructor(a,rva):
    if a.image.fragments(rva):
        return a.instructions(rva),True
    ins=list(disasm(a.code,rva,20))
    shape=[(i.mnemonic,i.op_str) for i in ins]
    if (len(ins)!=7 or sum(i.size for i in ins)!=20 or
            shape[:2]!=[('mov','rax, qword ptr [rcx]'),('test','rax, rax')] or
            ins[2].mnemonic!='je' or ins[2].operands[0].imm!=rva+19 or
            shape[3:5]!=[('mov','rdx, rcx'),('mov','rcx, rax')] or
            ins[5].mnemonic!='jmp' or ins[5].operands[0].type!=X86_OP_IMM or ins[6].mnemonic!='ret'):
        raise ValueError('Only the complete current nullable initializer tail wrapper is qualified: '+hex(rva))
    target=ins[5].operands[0].imm
    a.instructions(target)
    a.functions[rva]=(ins,dict(entry_rva=hex(rva),bytes=20,sha256=sha(a.code.read(rva,20)),
        complete_control_flow=True,null_initializer_returns=True,all_other_paths_tail_to=hex(target),
        instructions=[instruction_row(i) for i in ins],function_called=False))
    return a.instructions(target),False


def find_class(a,name,prefix='U'):
    needle=(prefix+name+'\0').encode('utf-16le'); targets=[]
    with CLIENT.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as view:
        at=view.find(needle)
        while at>=0:
            for first,size,raw in a.image.sections:
                if raw<=at<raw+size:
                    targets.append(first+at-raw)
            if len(targets)>64:
                raise ValueError('Class C++ literal search exceeds local bound')
            at=view.find(needle,at+1)
    candidates=[]
    for first,_,_ in a.code.blocks:
        a.code.read(first,1); raw=a.code.loaded[first]; at=raw.find(b'\x4c\x8d\x05')
        while at>=0 and at+7<=len(raw):
            if first+at+7+struct.unpack_from('<i',raw,at+3)[0] in targets:
                source=first+at; index=bisect.bisect_right(a.image.starts,source)-1
                if index>=0:
                    entry=a.image.entries[index]
                    if entry[0]<=source<entry[1]:
                        ins=a.instructions(entry[0])
                        if len(ins)==12 and ins[-3].op_str=='0x10ec0a90':
                            args={i.reg_name(i.operands[0].reg):a.rip(i) for i in ins if i.mnemonic=='lea' and i.operands[0].type==X86_OP_REG}
                            if text(a.read,args['r8'],wide=True)==prefix+name:
                                factory=a.factory(args['rcx'])
                                params=a.read(int(factory['parameter_rva'],16),88)
                                no_register,=struct.unpack_from('<Q',params)
                                row=dict(**factory,**a.class_identity(no_register-a.base),
                                    native_no_register_getter_rva=hex(no_register-a.base),
                                    parameter_sha256=sha(params),class_fields_not_extracted=True)
                                if row['name']!=name or row['native_no_register_getter_rva']!=hex(args['rdx']):
                                    raise ValueError('Named current class registration identity disagrees')
                                candidates.append(dict(registration_initializer_rva=hex(entry[0]),**row))
            at=raw.find(b'\x4c\x8d\x05',at+1)
    unique={r['factory_rva']:r for r in candidates}
    if len(unique)!=1:
        raise ValueError('Named current class registration not unique: '+name)
    return next(iter(unique.values()))


def method(a,vtable,slot):
    pointer,=struct.unpack('<Q',a.read(vtable+slot,8)); target=pointer-a.base
    if not 0<target<a.image.image_size:
        raise ValueError('Constructor-assigned method target outside exact current image')
    proof=a.instructions(target)
    return dict(vtable_rva=hex(vtable),slot=hex(slot),target_rva=hex(target),
        full_current_body_available=True,runtime_target_observed=False,native_function_called=False)


def derive():
    docs={}
    for path,expected in INPUTS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Sealed source constructor input changed: '+path)
        docs[path]=json.loads(raw)
    schema=docs[next(p for p in INPUTS if 'source_map_schema_' in p)]
    for path,expected in schema['source_pins'].items():
        if sha((ROOT/path).read_bytes())!=expected:
            raise ValueError('Source schema producer changed: '+path)
    native=docs[next(p for p in INPUTS if 'native_registration_' in p)]
    classes=native['classes']+native['supporting_native_ancestors']+schema['additional_native_classes']
    natives={c['package']+'.'+c['name']:c for c in classes}
    bindings={r['path']:r for r in schema['native_constructor_arguments']}
    a=Archive(); results=[]
    for selected in schema['selected_classes']:
        cache=selected['cache']; parent=cache['classes'][-2]['path']; args=bindings[parent]['source_arguments']
        wrapper=args['class_constructor_wrapper_rva']; ins,from_initializer=constructor(a,wrapper)
        assignments=constructor_assignments(ins,from_initializer=from_initializer)
        primary=[r for r in assignments if r['object_offset']==0]
        if len(primary)!=1:
            raise ValueError('Unique current constructor primary assignment absent: '+parent)
        vtable=primary[0]['source_rva']; open_hook=method(a,vtable,0x3d8)
        interfaces=[]
        for owner in cache['classes'][:-1]:
            for record in natives[owner['path']]['own_interfaces']:
                ident=a.class_identity(int(record['class_getter_rva'],16))
                interfaces.append(dict(owner=owner['path'],interface_path=ident['package']+'.'+ident['name'],**record))
        net=[r for r in interfaces if r['interface_path']=='/Script/GPGameplay.NetRepActorInterface']
        if len(net)>1:
            raise ValueError('Ambiguous inherited native NetRepActorInterface entries')
        net_binding=None
        if net:
            record=net[0]
            if record['implemented_by_script'] or not 0<=record['pointer_adjustment']<args['instance_size']:
                raise ValueError('Current native NetRepActorInterface has unqualified adjustment/script branch')
            slots=[r for r in assignments if r['object_offset']==record['pointer_adjustment']]
            if len(slots)!=1:
                raise ValueError('Unique current secondary-vtable assignment absent')
            net_binding=dict(interface=record,constructor_assignment=slots[0],method=method(a,slots[0]['source_rva'],0x10))
        results.append(dict(class_path=selected['path'],nearest_native_parent=parent,
            native_constructor_wrapper_rva=hex(wrapper),instance_constructor_entry_rva=hex(ins[0].address),
            constructor_primary_assignment=primary[0],actor_open_hook=open_hook,
            inherited_native_interfaces=interfaces,net_rep_actor_interface=net_binding,
            cached_cdo_identity_observed=False,source_assignment_is_not_runtime_observation=True))
    generated=find_class(a,'BlueprintGeneratedClass')
    generated_args=private_class_arguments(a.instructions(int(generated['private_class_getter_rva'],16)))
    gi,initializer=constructor(a,generated_args['class_constructor_wrapper_rva'])
    generated_assignments=constructor_assignments(gi,from_initializer=initializer)
    primary=[r for r in generated_assignments if r['object_offset']==0]
    if len(primary)!=1:
        raise ValueError('Generated-class native metaclass vtable assignment ambiguous')
    bind=method(a,primary[0]['source_rva'],0x260)
    helpers=[Path(__file__),ROOT/'work/research_updated_source_template_bindings_test.py',
        ROOT/'work/research_updated_source_map_schema.py',ROOT/'work/research_updated_native_registration.py']
    return dict(kind='current_source_constructor_template_binding_candidates',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        selected_classes=results,generated_class_metaclass_registration=generated,
        generated_class_constructor_arguments=generated_args,generated_class_constructor_assignments=generated_assignments,
        generated_class_bind_slot=bind,native_functions=[p for _,p in a.functions.values()],
        immutable_reads=list(a.data.values()),code_source=a.code.source_evidence(),
        generated_class_constructor_inheritance_qualified=False,
        cached_cdo_or_instance_vtable_observed=False,profile_guards_relaxed=False,
        process_opened=False,native_engine_function_called=False,runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True); args=parser.parse_args(); target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),classes=len(report['selected_classes']))))
