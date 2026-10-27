"""Current deferred core struct operation registrations, without engine calls."""
import argparse
import json
import mmap
from pathlib import Path
import struct

from research_updated_metadata_roots import CLIENT,ROOT,sha
from research_updated_native_registration import Archive,CLIENT_SHA,literal_bool,text
from research_updated_replication_core import call_xrefs

INPUT='work/research_updated_nested_registration_79fb7b10_v1.json'
INPUT_SHA='418679e96c04c60e790f3633e41cccbeca8159266b21cbb46e1495ae987abf62'


def derive():
    raw=(ROOT/INPUT).read_bytes()
    if sha(raw)!=INPUT_SHA:
        raise ValueError('Current nested struct graph changed')
    graph=json.loads(raw); missing={s['name']:s for s in graph['structures'] if s['cpp_struct_ops_source_binding'] is None}
    a=Archive(); targets={}
    with CLIENT.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as view:
        for name in missing:
            needle=(name+'\0').encode('utf-16le'); at=view.find(needle)
            while at>=0:
                for first,size,raw_at in a.image.sections:
                    if raw_at<=at<raw_at+size:
                        targets[first+at-raw_at]=name
                at=view.find(needle,at+1)
    a.instructions(0x10cfa400); a.instructions(0x10cfe070); a.instructions(0x10d03650)
    xrefs=call_xrefs(a.code,a.image,{0x10cfa400}); found=[]
    for root in sorted({int(x['root'],16) for x in xrefs}):
        ranges=a.image.fragments(root); size=ranges[-1][1]-root
        if size>2048:
            continue
        raw=a.code.read(root,size); at=raw.find(b'\x48\x8d\x15'); hits=[]
        while at>=0 and at+7<=len(raw):
            target=root+at+7+struct.unpack_from('<i',raw,at+3)[0]
            if target in targets:
                hits.append((target,targets[target]))
            at=raw.find(b'\x48\x8d\x15',at+1)
        if not hits:
            continue
        ins=a.instructions(root)
        if (len(ins)!=27 or len(hits)!=1 or ins[5].op_str!='0x10b55a40' or
                ins[8].op_str!='0x17179a0' or ins[17].op_str!='0x10cfa400' or ins[23].op_str!='0x10cfa400' or
                ins[13].op_str!='qword ptr [rax], rcx' or
                ins[12].op_str.split(',')[0]!='dword ptr [rax + 8]' or
                ins[16].op_str.split(',')[0]!='dword ptr [rax + 0xc]' or
                ins[10].mnemonic!='je' or ins[10].operands[0].imm!=ins[21].address or
                ins[20].mnemonic!='ret' or ins[-1].mnemonic!='ret'):
            raise ValueError('Selected deferred core registration has unqualified complete source grammar: '+hex(root))
        name=hits[0][1]
        if a.rip(ins[3])!=hits[0][0] or text(a.read,hits[0][0],wide=True)!=name:
            raise ValueError('Selected core FName construction argument changed')
        size,alignment=ins[12].operands[1].imm,ins[16].operands[1].imm
        if (size,alignment)!=(missing[name]['native_size'],missing[name]['native_alignment']):
            raise ValueError('Deferred CppStructOps size/alignment differs from current reflected registration')
        vtable=a.rip(ins[11]); traits=[]
        for slot in (0x60,0x68):
            pointer,=struct.unpack('<Q',a.read(vtable+slot,8))
            value=literal_bool(a.instructions(pointer-a.base))
            traits.append(dict(slot=hex(slot),target_rva=hex(pointer-a.base),value=value))
        net=traits[0]['value']; pointer,=struct.unpack('<Q',a.read(vtable+0x70,8))
        if net:
            a.instructions(pointer-a.base)
        found.append(dict(name=name,initializer_rva=hex(root),cpp_ops_vtable_rva=hex(vtable),
            native_size=size,native_alignment=alignment,traits=traits,
            struct_flag_0x400_after_prepare=net,
            struct_flag_0x400000_after_prepare=net and traits[1]['value'],
            net_serialize_target_rva=hex(pointer-a.base) if net else None,
            registrar_key='FName constructed from exact current UTF16 literal',
            successful_allocator_branch_qualified=True,cpp_ops_pointer_observed=False,native_function_called=False))
    grouped={name:[r for r in found if r['name']==name] for name in missing}
    if any(len(grouped[name])!=1 for name in ('Vector','Rotator','EncVector','EncHandler')):
        raise ValueError('Required deferred core registrations are absent or ambiguous')
    unresolved=[dict(name=name,reason='No accepted exact named deferred registration found; no absence-of-registration claim',
        required_for_command_expansion=False if name=='UniqueNetIdWrapper' else None)
        for name,rows in grouped.items() if not rows]
    helpers=[Path(__file__),ROOT/'work/research_updated_native_registration.py',ROOT/'work/research_updated_replication_core.py']
    return dict(kind='current_deferred_core_struct_operations',client_sha256=CLIENT_SHA,
        source_inputs={INPUT:INPUT_SHA},source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        registrations=found,unresolved=unresolved,registrar_callsite_search=dict(qualified_direct_calls=len(xrefs),
            exact_utf16_name_rip_lea_prefilter=True,accepted_candidates_revalidated_as_complete_functions=True),
        native_functions=[p for _,p in a.functions.values()],immutable_reads=list(a.data.values()),
        code_source=a.code.source_evidence(),runtime_registry_observed=False,profile_activation_authorized=False,
        process_opened=False,native_engine_function_called=False,runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),registrations=len(report['registrations']))))
