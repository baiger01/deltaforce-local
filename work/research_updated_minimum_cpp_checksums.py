"""Minimum current GetCPPType lowercase inputs and nonrecursive property CRCs."""
import argparse
import json
from pathlib import Path
import re
import struct

from research_updated_metadata_roots import ROOT,sha
from research_updated_native_registration import Archive,CLIENT_SHA,text

INPUTS={
    'work/research_updated_minimum_leaf_bindings_79fb7b10_v2.json':'21d89e42a08a38e827e7ee227e3ab1f00900b2e84b0f96a55f8dbd1a358500d6',
    'work/research_updated_native_registration_79fb7b10_v4.json':'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/research_updated_source_map_schema_79fb7b10_v1.json':'ed591569846bb22602dbbe6571de72720b87e93f2ebb12da5dfff412696f4d27',
    'work/research_updated_nested_registration_79fb7b10_v1.json':'418679e96c04c60e790f3633e41cccbeca8159266b21cbb46e1495ae987abf62',
    'work/research_updated_ename_bindings_79fb7b10_v3.json':'4b4fc6de5a4722034517cafa60b1186f2b1d859a0aab086d3c8751126c2e73d1',
    'work/research_updated_cache_initialization_79fb7b10.json':'9f27a79bd5686c0d90dd3b30d983a3b9af86516de550b0936607c061dc00b6ac'}


def fold(seed,value):
    if type(seed) is not int or not 0<=seed<=0xffffffff or not isinstance(value,str) or any(not 0<ord(c)<128 for c in value):
        raise ValueError('Exact ASCII no-NUL string and unsigned CRC seed required')
    crc=seed^0xffffffff
    for char in value:
        code=ord(char)+32 if 'A'<=char<='Z' else ord(char)
        for byte in (code,0,0,0):
            crc^=byte
            for _ in range(8):
                crc=(crc>>1)^(0xedb88320 if crc&1 else 0)
    return crc^0xffffffff


def property_checksum(name,cpp_type,dimension):
    if type(dimension) is not int or not 1<=dimension<=4096:
        raise ValueError('Exact bounded ArrayDim required')
    return fold(fold(fold(0,name),cpp_type),str(dimension))


def derive():
    docs={}
    for path,expected in INPUTS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Current minimum CPP/checksum input changed: '+path)
        docs[path]=json.loads(raw)
    leaves=docs[next(p for p in INPUTS if 'minimum_leaf_bindings_' in p)]
    native=docs[next(p for p in INPUTS if 'native_registration_' in p)]
    schema=docs[next(p for p in INPUTS if 'source_map_schema_' in p)]
    graph=docs[next(p for p in INPUTS if 'nested_registration_' in p)]
    enames=docs[next(p for p in INPUTS if 'ename_bindings_' in p)]
    if next(r for r in enames['hardcoded_names'] if r['ename_index']==0x66)['literal_name']!='Actor':
        raise ValueError('Current class-prefix Actor identity is unqualified')
    classes=native['classes']+native['supporting_native_ancestors']+schema['additional_native_classes']
    by_path={c['package']+'.'+c['name']:c for c in classes}; by_factory={c['factory_rva']:c for c in classes}
    fields={p['parameter_record_rva']:p for c in classes+graph['structures'] for p in c['fields']['fields']}
    enums={e['factory_rva']:e for e in leaves['enum_registrations']}
    a=Archive(); current={}
    for kind,binding in leaves['property_families'].items():
        target=int(next(m['target_rva'] for m in binding['methods'] if m['slot']=='0x60'),16)
        current[kind]={i.address:i for i in a.instructions(target)}
    additional={rva:{i.address:i for i in a.instructions(rva)} for rva in (
        0x10e84900,0x10cfe940,0x10cffc80,0x109fbe20,0x12db14a0,0x10ea59b0,0x10e70240)}
    cache=docs[next(p for p in INPUTS if 'cache_initialization_' in p)]
    crc=next(f for f in cache['functions'] if f['new_rva']=='0xe56960')
    if crc['bytes']!=0x6e or sha(a.code.read(0xe56960,0x6e))!=crc['new_code_sha256']:
        raise ValueError('Current complete CRC leaf differs from its sealed full-body proof')
    literals=[]
    for root,at,expected in ((0x10e827b0,0x10e827f4,'uint64'),(0x25a2fb0,0x25a2ff8,'int64'),
            (0x25a2d80,0x25a2dc8,'int32'),(0x10e82830,0x10e82a63,'bool'),
            (0x10e82a80,0x10e82c29,'TEnumAsByte<%s>'),(0x10e84900,0x10e84926,'%s*'),
            (0x25a2ca0,0x25a2d14,'%s%s'),(0x10cfe940,0x10cfe9a8,'A')):
        method=additional.get(root) or next(rows for rows in current.values() if at in rows)
        rva=a.rip(method[at]); value=text(a.read,rva,wide=True)
        if value!=expected:
            raise ValueError('Current GetCPPType output literal changed: '+hex(at))
        literals.append(dict(rva=hex(rva),value=value,source_instruction_rva=hex(at)))
    checks=((0x10cffc80,0x10cffeb0,'r9d, r9d'),(0x10cffc80,0x10cffeb3,'r8d, r8d'),
        (0x10e82830,0x10e82847,'0x10e82a28'),(0x10e82a80,0x10e82bf6,'r12d, 2'),
        (0x10e1ad60,0x10e1ad8c,'dword ptr [rax + 0x38], 1'),
        (0x10e1ad60,0x10e1ad9d,'0xd61f40'),(0x10ea59b0,0x10ea5bc1,'rdx, qword ptr [r14 + 0x18]'),
        (0x10ea59b0,0x10ea5bcf,'rcx, [r15 + 0x30]'))
    for root,at,expected in checks:
        method=additional.get(root) or next(rows for rows in current.values() if at in rows)
        if method[at].op_str!=expected:
            raise ValueError('Current minimum GetCPPType branch witness changed')
    generic_vtable=0x1ab3a1d8
    pointer,=struct.unpack('<Q',a.read(generic_vtable+0x2b8,8))
    if pointer-a.base!=0x10cfe940:
        raise ValueError('Current native UClass prefix method binding changed')
    rows=[]
    for item in leaves['minimum_fields']:
        field=fields[item['parameter_record_rva']]; kind=field['kind']; object_binding=None
        if kind in ('FIntProperty','FInt64Property','FUInt64Property'):
            cpp={'FIntProperty':'int32','FInt64Property':'int64','FUInt64Property':'uint64'}[kind]
        elif kind=='FBoolProperty':
            if field['source_derived_bool_storage']['native_bool'] is not True:
                raise ValueError('Current minimum Boolean requires an unqualified CPP bitfield branch')
            cpp='bool'
        elif kind in ('FByteProperty','FEnumProperty'):
            enum=enums[item['enum_factory_rva']]
            if len(enum['cpp_type_name'])<=1:
                raise ValueError('Current enum lacks a complete explicit CPP type string')
            if kind=='FByteProperty' and enum['cpp_form']!=0:
                raise ValueError('Current byte enum requires an unqualified scoped-enum branch')
            cpp='TEnumAsByte<'+enum['cpp_type_name']+'>' if kind=='FByteProperty' else enum['cpp_type_name']
        elif kind=='FObjectProperty':
            callback=next(c for c in field['callbacks'] if c['parameter_offset']=='0x28')
            identity=a.class_identity(int(callback['function_rva'],16)); path=identity['package']+'.'+identity['name']
            if path not in by_path or re.search(r'_\d+$',identity['name']):
                raise ValueError('Current object CPP class has unqualified identity/number formatting')
            chain=[]; at=by_path[path]
            for _ in range(64):
                if int(at['native_class_flags_input'],16)&0x2000000:
                    raise ValueError('Current minimum object CPP type takes the interface-prefix branch')
                chain.append(at['package']+'.'+at['name'])
                deps=[d for d in at['dependency_factories'] if d['kind']=='class']
                if not deps:
                    break
                if len(deps)!=1:
                    raise ValueError('Current object CPP ancestry is ambiguous')
                at=by_factory[deps[0]['factory_rva']]
            else:
                raise ValueError('Current object CPP ancestry exceeds local bound')
            if '/Script/Engine.Actor' not in chain:
                raise ValueError('Current minimum object CPP type is outside proved Actor-prefix branch')
            cpp='A'+identity['name']+'*'; object_binding=dict(class_path=path,ancestry=chain,prefix='A')
        else:
            raise ValueError('Current minimum CPP family unsupported')
        rows.append(dict(receiver_class=item['receiver_class'],field=item['field'],declaring_owner=item['declaring_owner'],
            cpp_type_recipe=cpp,cpp_type_for_checksum_lower=cpp.lower(),cpp_export_flags=0,
            object_type_source=object_binding,array_dim=field['array_dim'],
            nonrecursive_property_checksum_seed0=hex(property_checksum(field['name'],cpp,field['array_dim'])),
            checksum_domain='FProperty checksum(seed=0,recurse=false); not aggregate class or RepLayout command CRC',
            runtime_get_cpp_type_invoked=False))
    helpers=[Path(__file__),ROOT/'work/research_updated_minimum_cpp_checksums_test.py',ROOT/'work/research_updated_native_registration.py']
    return dict(kind='current_minimum_cpp_type_checksum_inputs',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        minimum_fields=rows,source_literals=literals,native_functions=[p for _,p in a.functions.values()],
        sealed_current_crc_leaf_proof=crc,
        immutable_reads=list(a.data.values()),code_source=a.code.source_evidence(),
        aggregate_class_checksums_reconstructed=False,rep_layout_command_checksums_reconstructed=False,
        command_checksum_context_gate=dict(function_rva='0x12db14a0',
            zero_result_condition='nonnull context and (context byte+0xb4 &1)==0',
            compute_condition='null context or (context byte+0xb4 &1)!=0',
            other_branch='nonnull context dword+0x1528<4 folds decimal static-array index; otherwise CRC of its four raw bytes',
            actual_context_or_flags_observed=False),
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
    print(json.dumps(dict(output=str(target),sha256=sha(raw),fields=len(report['minimum_fields']))))
