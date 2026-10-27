"""Current declaration-derived cache candidates, distinct from observed native caches.

No historical index is read or used. This report does not activate a profile.
"""
import argparse
import bisect
import json
import mmap
from pathlib import Path
import struct

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from research_updated_metadata_roots import CLIENT, ROOT, instruction_row, sha
from research_updated_native_registration import Archive, CLIENT_SHA
from research_updated_cooked_field_stream import parse_class_stream

INPUTS={
    'work/research_updated_native_registration_79fb7b10_v4.json':'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_cooked_functions_79fb7b10_v1.json':'3e930ca5569d133bdb01121bfa6bd0169229144fff847e01dd36a50e459d9b62',
    'work/research_updated_cooked_declarations_79fb7b10_v5.json':'b29f6cda96c690351596f5e96879d96267610adbfd86b36cd253661af7ec3037',
    'work/research_updated_cache_initialization_79fb7b10.json':'9f27a79bd5686c0d90dd3b30d983a3b9af86516de550b0936607c061dc00b6ac',
    'work/native-client-tests/1792803423602487700/updated-class-metadata.json':'ae58fa8354c4a777e32ae4dac05481dfe0bd1662f263269f6a77b2c3e93fc64f'}
ROOTS=('BP_DFMPlayerController_C','BP_DFMCharacter_C','BP_GameState_PVPVE_C','BP_SOLPlayerState_C')


def ascii_key(name):
    if not isinstance(name,str) or not name or any(ord(c)>127 for c in name):
        raise ValueError('This source reconstruction accepts exact nonempty ASCII names only')
    return tuple(ord(c)+32 if 'A'<=c<='Z' else ord(c) for c in name)


def source_cache(nodes,root):
    chain,seen=[],set()
    at=root
    while at is not None:
        if at in seen or len(seen)>=64 or at not in nodes or nodes[at]['path']!=at:
            raise ValueError('Complete acyclic exact class ancestry required')
        seen.add(at); chain.append(nodes[at]); at=nodes[at]['parent']
    fields,classes,reps=[],[],0
    for klass in reversed(chain):
        own=[p for p in klass['properties'] if p['net']]
        for p in own:
            if (type(p['offset']) is not int or not 0<=p['offset']<=1048576 or
                    type(p['array_dim']) is not int or not 1<=p['array_dim']<=4096):
                raise ValueError('Exact bounded source offset and ArrayDim required')
        keys=[(p['offset'],ascii_key(p['name'])) for p in own]
        if len(set(keys))!=len(keys):
            raise ValueError('Native property comparator ties require unimplemented exact sort emulation')
        own=sorted(own,key=lambda p:(p['offset'],ascii_key(p['name'])))
        functions=[f for f in klass['functions'] if f['flags']&0x40 and not f['super_present']]
        names=[ascii_key(f['name']) for f in functions]
        if len(set(names))!=len(names):
            raise ValueError('Native Function comparator ties require unimplemented exact sort emulation')
        functions=sorted(functions,key=lambda f:ascii_key(f['name']))
        start=len(fields)
        for p in own:
            fields.append(dict(owner=klass['path'],name=p['name'],kind='property',cache_index=len(fields),
                property_rep_index=reps,array_dim=p['array_dim'],source_offset=p['offset']))
            reps+=p['array_dim']
            if reps>65535:
                raise ValueError('Source ClassReps exceeds the explicitly bounded no-wrap subset')
        for f in functions:
            fields.append(dict(owner=klass['path'],name=f['name'],kind='function',cache_index=len(fields),
                function_flags=hex(f['flags'])))
        classes.append(dict(path=klass['path'],own_cache_start=start,own_cache_count=len(fields)-start,
            own_net_property_count=len(own),own_net_function_count=len(functions)))
    return dict(root=root,classes=classes,fields=fields,exclusive_cache_index_maximum=len(fields),
        class_reps_count=reps,basis='current declarations and qualified current setup/cache ordering',
        runtime_native_cache_observed=False,checksum_reconstructed=False,profile_activation_authorized=False)


def private_class_arguments(instructions):
    regs={'rsp':('stack',0)}; memory={}
    def register(ins,op):
        name=ins.reg_name(op.reg)
        return {'eax':'rax','ecx':'rcx','edx':'rdx','r8d':'r8','r9d':'r9','r10d':'r10','r11d':'r11'}.get(name,name)
    def address(ins,op):
        if op.mem.index:
            return None
        base=regs.get(ins.reg_name(op.mem.base))
        return base[1]+op.mem.disp if base and base[0]=='stack' else None
    for ins in instructions:
        ops=ins.operands
        if ins.mnemonic=='call' and ins.op_str=='0x10cff980':
            frame=regs['rsp'][1]
            slots={label:memory.get(frame+offset) for label,offset in (
                ('instance_size',0x20),('alignment',0x28),('class_flags',0x30),('cast_flags',0x38),
                ('config_name_rva',0x40),('class_constructor_wrapper_rva',0x48),
                ('vtable_helper_constructor_rva',0x50),('add_referenced_objects_rva',0x58),('super_class_getter_rva',0x60))}
            if any(type(v) is not int for v in slots.values()):
                raise ValueError('Private class getter has unresolved constructor arguments')
            return dict(**slots,argument_call_rva=hex(ins.address),native_function_called=False)
        if ins.mnemonic in ('sub','add') and ops and ops[0].type==X86_OP_REG and ins.reg_name(ops[0].reg)=='rsp':
            if ops[1].type!=X86_OP_IMM:
                raise ValueError('Dynamic native class getter frame')
            regs['rsp']=('stack',regs['rsp'][1]+ops[1].imm*(1 if ins.mnemonic=='add' else -1))
        elif ins.mnemonic=='push':
            regs['rsp']=('stack',regs['rsp'][1]-8)
        elif ins.mnemonic=='xor' and len(ops)==2 and ops[0].type==X86_OP_REG and ops[1].type==X86_OP_REG and ops[0].reg==ops[1].reg:
            regs[register(ins,ops[0])]=('constant',0)
        elif ins.mnemonic=='lea' and ops[0].type==X86_OP_REG:
            target=ops[1]
            value=(ins.address+ins.size+target.mem.disp) if target.mem.base==X86_REG_RIP else None
            regs[register(ins,ops[0])]=('constant',value) if value is not None else ('unknown',None)
        elif ins.mnemonic in ('mov','movabs') and len(ops)==2:
            dst,src=ops
            value=('constant',src.imm) if src.type==X86_OP_IMM else regs.get(register(ins,src),('unknown',None)) if src.type==X86_OP_REG else ('unknown',None)
            if dst.type==X86_OP_REG:
                regs[register(ins,dst)]=value
            elif dst.type==X86_OP_MEM:
                slot=address(ins,dst)
                if slot is not None:
                    memory[slot]=value[1] if value[0]=='constant' else None
    raise ValueError('Current named GetPrivateStaticClassBody call absent')


def named_initializer(a,name):
    literal=('A'+name+'\0').encode('utf-16le'); targets=[]
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as view:
        at=view.find(literal)
        while at>=0:
            for first,size,raw in a.image.sections:
                if raw<=at<raw+size:
                    targets.append(first+at-raw)
            at=view.find(literal,at+1)
            if len(targets)>64:
                raise ValueError('Native C++ name literal search is ambiguous')
    hits=[]
    for first,_,_ in a.code.blocks:
        a.code.read(first,1); raw=a.code.loaded[first]; at=raw.find(b'\x4c\x8d\x05')
        while at>=0 and at+7<=len(raw):
            target=first+at+7+struct.unpack_from('<i',raw,at+3)[0]
            if target in targets:
                source=first+at; index=bisect.bisect_right(a.image.starts,source)-1
                if index>=0:
                    entry=a.image.entries[index]
                    if entry[0]<=source<entry[1]:
                        try:
                            row=a.registered_class(name,entry[0]); hits.append(row)
                        except ValueError:
                            pass
            at=raw.find(b'\x4c\x8d\x05',at+1)
    unique={r['factory_rva']:r for r in hits}
    if len(unique)!=1:
        raise ValueError('Exact named current static initializer is missing or ambiguous: '+name)
    return next(iter(unique.values()))


def derive():
    docs={}
    for path,expected in INPUTS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Source schema input changed: '+path)
        docs[path]=json.loads(raw)
    native=docs[next(p for p in INPUTS if 'native_registration_' in p)]
    for path,expected in native['source_pins'].items():
        if sha((ROOT/path).read_bytes())!=expected:
            raise ValueError('Native registration producer changed: '+path)
    capture=docs[next(p for p in INPUTS if 'updated-class-metadata' in p)]
    a=Archive(); natives=native['classes']+native['supporting_native_ancestors']
    by_factory={r['factory_rva']:r for r in natives}
    pawn=named_initializer(a,'SOLCharacter')
    queue=[pawn]
    while queue:
        row=queue.pop(0)
        if row['factory_rva'] in by_factory:
            continue
        if len(by_factory)>=64:
            raise ValueError('Native source ancestry budget exceeded')
        by_factory[row['factory_rva']]=row
        for d in row['dependency_factories']:
            if d['kind']=='class' and d['factory_rva'] not in by_factory:
                queue.append(a.class_record(d))
    observed={ascii_key(c['path']):c for c in capture['selected_classes']}
    if len(observed)!=len(capture['selected_classes']):
        raise ValueError('Current class paths collide under the qualified ASCII comparator')
    nodes={}; ctor_bindings=[]; checks=[]
    for row in by_factory.values():
        path=row['package']+'.'+row['name']
        dependencies=[d for d in row['dependency_factories'] if d['kind']=='class']
        if len(dependencies)>1:
            raise ValueError('Source ancestry is not a unique compiled superclass dependency')
        parent=by_factory[dependencies[0]['factory_rva']] if dependencies else None
        args=private_class_arguments(a.instructions(int(row['private_class_getter_rva'],16)))
        if parent:
            identity=a.class_identity(args['super_class_getter_rva'])
            if (identity['name'],identity['package'])!=(parent['name'],parent['package']):
                raise ValueError('Dependency and native private getter superclass identity disagree')
        ctor_bindings.append(dict(path=path,source_arguments=args,
            own_interfaces=row['own_interfaces'],cached_cdo_observed=False,final_instance_vtable_qualified=False))
        properties=[]
        for p in row['fields']['fields']:
            offset=p.get('constructor_offset_argument')
            if p['kind']=='FBoolProperty':
                offset=p['source_derived_bool_storage'].get('storage_offset')
            if p['net_flag'] and offset is None:
                raise ValueError('Net Boolean has unresolved source storage offset: '+path+'.'+p['name'])
            properties.append(dict(name=p['name'],offset=offset,array_dim=p['array_dim'],net=p['net_flag']))
        functions=[dict(name=f['name'],flags=int(f['function_flags'],16),super_present=f['super_function_factory_rva'] is not None)
            for f in row['functions']]
        node=dict(path=path,parent=parent['package']+'.'+parent['name'] if parent else None,
            properties=properties,functions=functions)
        if ascii_key(path) in observed:
            live=observed[ascii_key(path)]; fields={ascii_key(p['name']):p for p in live['own_properties']}
            parent_matches=(live['superclass_path'] is None and node['parent'] is None) or (
                live['superclass_path'] is not None and node['parent'] is not None and
                ascii_key(live['superclass_path'])==ascii_key(node['parent']))
            if len(fields)!=len(properties) or set(fields)!={ascii_key(p['name']) for p in properties} or not parent_matches:
                raise ValueError('Current observed native declaration identities disagree with immutable source: '+path)
            variants=[]
            for p in properties:
                fresh=fields[ascii_key(p['name'])]
                if (p['offset'],p['array_dim'],p['net'])!=(fresh['storage_offset'],fresh['array_dim'],bool(fresh['flags_low32']&0x20)):
                    raise ValueError('Current observed property geometry disagrees with source: '+path+'.'+p['name'])
                if p['name']!=fresh['name']:
                    variants.append(dict(native_literal=p['name'],observed_display_name=fresh['name'],
                        qualified_sort_keys_equal=True,metadata_name_rewritten=False))
            expected={(ascii_key(f['name']),f['flags'],f['super_present']) for f in functions if f['flags']&0x40}
            actual={(ascii_key(f['name']),f['function_flags'],f['super_function_present']) for f in live['own_net_functions']}
            if expected!=actual:
                raise ValueError('Current observed NetFunction declarations disagree with immutable source: '+path)
            checks.append(dict(path=path,own_properties=len(properties),net_functions=len(expected),
                observed_class_display_path=live['path'],observed_superclass_display_path=live['superclass_path'],
                source_comparator_geometry_matches_current_observation=True,display_case_variants=variants))
        nodes[path]=node
    packages=docs[next(p for p in INPUTS if 'cooked_declarations_' in p)]['packages']
    pc_functions=docs[next(p for p in INPUTS if 'cooked_functions_' in p)]['functions']
    selected=[]
    for package in packages:
        row=package['class_export']; name=row['name']; path=package['package_path']+'.'+name
        if name not in ROOTS:
            raise ValueError('Unexpected selected Blueprint class')
        parent_ref=row['super_reference']
        if len(parent_ref)!=2:
            raise ValueError('Exact native script parent reference required')
        parent=parent_ref[0]+'.'+parent_ref[1]
        if name=='BP_DFMCharacter_C':
            live=observed[ascii_key(path)]
            own=[dict(name=p['name'],offset=p['storage_offset'],array_dim=p['array_dim'],net=bool(p['flags_low32']&0x20)) for p in live['own_properties']]
            funcs=[dict(name=f['name'],flags=f['function_flags'],super_present=f['super_function_present']) for f in live['own_net_functions']]
            source='current complete bounded metadata observation; cooked field stream not fully parsed'
        else:
            parsed=parse_class_stream(package)
            if parsed['complete'] is not True or any(p['property_net_flag'] for p in parsed['fields']):
                raise ValueError('Only completely parsed no-own-Net-property generated class streams are qualified')
            own=[]
            if name=='BP_DFMPlayerController_C':
                funcs=[dict(name=f['name'],flags=int(f['function_flags'],16),super_present=f['super_package_index']!=0) for f in pc_functions]
            else:
                if package['function_exports']:
                    raise ValueError('Unexpected own Function exports in selected GS/PS package')
                funcs=[]
            source='current independently hashed cooked class and Function streams'
        nodes[path]=dict(path=path,parent=parent,properties=own,functions=funcs)
        selected.append(dict(path=path,declaration_source=source,cache=source_cache(nodes,path)))
    helpers=[Path(__file__),ROOT/'work/research_updated_source_map_schema_test.py',ROOT/'work/research_updated_native_registration.py']
    return dict(kind='current_source_derived_minimal_map_cache_candidates',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        selected_classes=selected,native_constructor_arguments=ctor_bindings,source_observation_crosschecks=checks,
        additional_native_classes=[r for key,r in by_factory.items() if key not in {c['factory_rva'] for c in natives}],
        additional_complete_native_functions=[p for _,p in a.functions.values()],code_source=a.code.source_evidence(),
        immutable_reads=list(a.data.values()),
        source_derived_indices_are_not_runtime_observed_native_caches=True,
        rep_layout_commands_reconstructed=False,checksums_reconstructed=False,
        cached_cdo_or_instance_vtable_observed=False,profile_guards_relaxed=False,
        process_opened=False,native_engine_function_called=False,runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True); args=parser.parse_args()
    target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),classes=len(report['selected_classes']))))
