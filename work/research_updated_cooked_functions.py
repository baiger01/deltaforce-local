"""Source-qualified current cooked PC Function declarations; no engine execution."""
import argparse
import json
from pathlib import Path
import struct

from research_updated_cooked_declarations import CLIENT_SHA, SHADOW, parse_package
from research_updated_cooked_field_stream import Cursor, RELEASE_GUID, FIELD_GUID, native_proof
from research_updated_metadata_roots import ROOT, sha
from research_updated_native_registration import Archive

PACKAGE_REPORT='work/research_updated_cooked_declarations_79fb7b10_v5.json'
PACKAGE_SHA='b29f6cda96c690351596f5e96879d96267610adbfd86b36cd253661af7ec3037'


def parse_function(raw,pkg,function):
    versions={r['guid_bytes_hex']:r['value'] for r in pkg['custom_versions']}
    if (len(versions)!=len(pkg['custom_versions']) or versions.get(RELEASE_GUID)!=36 or
            versions.get(FIELD_GUID)!=4):
        raise ValueError('Only exact release36 / FField4 Function streams are qualified')
    c=Cursor(raw,pkg['serialized_names'],pkg['imports'],pkg['exports'])
    if c.number('i')!=0:
        raise ValueError('Only absent serialized UObject GUID branch is qualified')
    superclass=c.reference()
    if superclass!=function['super_index']:
        raise ValueError('Function SuperStruct differs from its exact export binding')
    children=[c.reference() for _ in range(c.count(256))]
    if children:
        raise ValueError('Only observed empty legacy child-object array is qualified')
    fields=[]
    for _ in range(c.count(256)):
        start,kind,name=c.at,c.name(),c.name()
        flags,dimension,size,pflags=c.number('I'),c.number('i'),c.number('i'),c.number('Q')
        rep,notify,condition=c.number('H'),c.name(),c.number('B')
        if not 1<=dimension<=1024 or not 1<=size<=1048576:
            raise ValueError('Unbounded serialized Function property dimension/size')
        field=dict(name=name,serialized_kind=kind,object_flags=hex(flags),array_dim=dimension,
            serialized_element_size=size,serialized_property_flags64=hex(pflags),
            serialized_rep_index=rep,rep_notify=notify,blueprint_replication_condition=condition,
            parameter_flag=bool(pflags&0x80),out_parameter_flag=bool(pflags&0x100),
            return_parameter_flag=bool(pflags&0x400),reference_parameter_flag=bool(pflags&0x8000000))
        if kind in ('ObjectProperty','StructProperty','DelegateProperty'):
            field['type_object_package_index']=c.reference()
        elif kind=='BoolProperty':
            field['serialized_bool_bytes']=[c.number('B') for _ in range(6)]
        elif kind!='IntProperty':
            raise ValueError('Current Function field family lacks qualified suffix grammar: '+kind+' '+name)
        field.update(serialized_offset=start,serialized_bytes=c.at-start)
        fields.append(field)
    if len({f['name'] for f in fields})!=len(fields):
        raise ValueError('Ambiguous own Function field names')
    bytecode_size,stored_size=c.number('i'),c.number('i')
    if not 0<=bytecode_size<=1048576 or not 0<=stored_size<=4096 or c.at+stored_size>len(raw):
        raise ValueError('Stored Function bytecode extent outside bounded export')
    script=raw[c.at:c.at+stored_size]; c.at+=stored_size
    flags=c.number('I')
    rpc=c.number('H') if flags&0x40 else None
    graph,offset=c.reference(),c.number('i')
    if c.at!=len(raw):
        raise ValueError('Complete Function export extent required; runtime parameter-metadata branch is unqualified')
    return dict(name=function['name'],export_index=function['index'],super_package_index=superclass,
        function_flags=hex(flags),net_flag=bool(flags&0x40),legacy_rpc_id=rpc,
        fields=fields,bytecode_memory_bytes=bytecode_size,stored_bytecode_bytes=stored_size,
        stored_bytecode_sha256=sha(script),event_graph_package_index=graph,event_graph_call_offset=offset,
        complete_serialized_function_extent=True,serialized_sha256=sha(raw),
        runtime_u_function_observed=False,current_wire_index_recovered=False)


def load_current_pc():
    from recover_economy_pak_access import pak_footer,validate_index,directory_index,decode_entry
    from research_updated_content_resources import access
    from scan_weapon_tables import parse_entry
    import oodle_payload_reader
    raw=(ROOT/PACKAGE_REPORT).read_bytes()
    if sha(raw)!=PACKAGE_SHA:
        raise ValueError('Sealed current PAK search report changed')
    prior=json.loads(raw)
    for source,expected in prior['source_pins'].items():
        if sha((ROOT/source).read_bytes())!=expected:
            raise ValueError('Current PAK research helper source changed: '+source)
    candidates=[p for p in prior['packages'] if p['package_path'].endswith('/BP_DFMPlayerController')]
    if len(candidates)!=1:
        raise ValueError('Unique exact current PC package required')
    package=candidates[0]
    rows=[r for r in prior['archives'] if r['archive']==package['archive']]
    if len(rows)!=1:
        raise ValueError('Unique current archive source record required')
    source=rows[0]; path=SHADOW/'DeltaForce/Content/Paks'/source['archive']
    if path.stat().st_size!=source['archive_bytes']:
        raise ValueError('Current source archive extent changed')
    footer=pak_footer(path); keys,_=access(); clear=key=None
    for candidate in keys:
        valid,clear,key=validate_index(path,footer,{footer['guid']:candidate})
        if clear is not None:
            break
    if (clear is None or valid.get('index_sha1_valid') is not True or
            any(valid[k]!=source[k] for k in ('footer_sha256','decoded_index_sha256'))):
        raise ValueError('Current source index no longer matches its independently verified identity')
    details,_,_=directory_index(path,footer,clear,key)
    if details.get('secondary_indices',[])!=source['secondary_indices']:
        raise ValueError('Current secondary index evidence changed')
    oodle_payload_reader.PATH=SHADOW/'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    decoded={}
    with path.open('rb') as stream:
        for name in (package['archive_uasset'],package['archive_uexp']):
            matches=[r for r in source['matches'] if r['asset']==name]
            if len(matches)!=1:
                raise ValueError('Exact current entry binding absent')
            match=matches[0]; pos=match['entry_offset']
            entry=parse_entry(stream,pos,footer['offset'],variant='observed_permutation')
            if not 0<entry['uncompressed']<=16*1024*1024:
                raise ValueError('Bounded current cooked entry required')
            payload,verified=decode_entry(stream,pos,entry,footer['methods'],key)
            if not verified or sha(payload)!=match['decoded_sha256']:
                raise ValueError('Current decoded payload identity/hash mismatch')
            decoded[name]=payload
    header,payload=decoded[package['archive_uasset']],decoded[package['archive_uexp']]
    current=parse_package(header,payload,'BP_DFMPlayerController')
    if any(current[k]!=package[k] for k in ('uasset_sha256','uexp_sha256','exports','imports','serialized_names')):
        raise ValueError('Current parsed package bindings differ from sealed current directory extraction')
    return current,payload,dict(path=PACKAGE_REPORT,sha256=PACKAGE_SHA,archive=source['archive'],
        footer_sha256=source['footer_sha256'],index_sha1_valid=True,payload_sha1_valid=True)


def derive():
    a=Archive()
    proof=native_proof(a.image,a.code)
    grammar=a.property_grammar()
    if grammar[26]['field_class_name']!='DelegateProperty':
        raise ValueError('Current DelegateProperty construction type differs')
    ctor={i.address:i for i in a.instructions(0x10ea3190)}
    if ctor[0x10ea4c90].op_str!='qword ptr [rbx], rsi':
        raise ValueError('Current delegate concrete-vtable assignment changed')
    vtable=a.rip(ctor[0x10ea4c85])
    target,=struct.unpack('<Q',a.read(vtable+8,8))
    delegate=a.instructions(target-a.base)
    if ([(i.address,i.op_str) for i in delegate if i.mnemonic=='call'][:2]!=
            [(0x10e92915,'0x10e61980'),(0x10e92927,'qword ptr [rax + 0x40]')]):
        raise ValueError('Current DelegateProperty serializer does not have the qualified base/reference prefix')
    function=a.instructions(0x10e00050)
    expected={0x10e000ba:'byte ptr [rdi + 0xc0], 0x40',0x10e0010a:'dword ptr [rbx + 0x40], 0x1c3',
        0x10e00120:'qword ptr [rax + 0x40]',0x10e00166:'dword ptr [rbx + 0x30], 0x1000'}
    for item in function:
        if item.address in expected and item.op_str!=expected.pop(item.address):
            raise ValueError('Current Function serialized-branch witness changed')
    if expected:
        raise ValueError('Current Function branch witnesses absent')
    package,payload,source=load_current_pc()
    rows=[]
    for row in package['function_exports']:
        start=row['property_terminator_end']; end=row['serialized_uexp_offset']+row['serialized_bytes']
        if not row['tagged_property_prefix_decoded'] or row['tagged_properties']:
            raise ValueError('Only the observed exact empty tagged Function prefix is qualified')
        rows.append(parse_function(payload[start:end],package,row))
    helpers=[Path(__file__),ROOT/'work/research_updated_cooked_functions_test.py',
        ROOT/'work/research_updated_native_registration.py',ROOT/'work/research_updated_cooked_field_stream.py',
        ROOT/'work/research_updated_cooked_declarations.py']
    return dict(kind='current_cooked_pc_function_declarations',client_sha256=CLIENT_SHA,
        source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        package_source=source,functions=rows,own_function_count=len(rows),own_net_function_count=sum(r['net_flag'] for r in rows),
        native_stream_proof=proof,native_function_serialize_proof=a.functions[0x10e00050][1],
        additional_native_proof=[p for _,p in a.functions.values()],
        delegate_serializer_binding=dict(vtable_rva=hex(vtable),slot='0x8',target_rva=hex(target-a.base),
            serialized_suffix='one package object reference after common FProperty data'),
        native_engine_function_called=False,process_opened=False,runtime_files_changed=False,
        current_wire_handles_recovered=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True); args=parser.parse_args()
    target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report path required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),functions=report['own_function_count'],
        net_functions=report['own_net_function_count'])))
