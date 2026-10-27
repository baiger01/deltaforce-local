"""Ordinary current generated-class constructor inheritance, without a CDO read.

The certificate covers fresh/ordinary cooked non-nativized class construction.
It does not claim to observe a live class constructor, cache or CDO identity.
"""
import argparse
import json
from pathlib import Path
import struct

from research_updated_metadata_roots import ROOT,sha
from research_updated_native_registration import Archive,CLIENT_SHA
from research_updated_cooked_field_stream import parse_class_stream

INPUTS={
    'work/research_updated_source_template_bindings_79fb7b10_v1.json':'bca9a315624f5e58506387f001a719f9d8a13c629d405da0bbad9503e193512b',
    'work/research_updated_cooked_declarations_79fb7b10_v5.json':'b29f6cda96c690351596f5e96879d96267610adbfd86b36cd253661af7ec3037',
    'work/native-client-tests/1792803423602487700/updated-class-metadata.json':'ae58fa8354c4a777e32ae4dac05481dfe0bd1662f263269f6a77b2c3e93fc64f'}


def derive():
    docs={}
    for path,expected in INPUTS.items():
        raw=(ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Current ordinary constructor source input changed: '+path)
        docs[path]=json.loads(raw)
    templates=docs[next(p for p in INPUTS if 'source_template_' in p)]
    packages=docs[next(p for p in INPUTS if 'cooked_declarations_' in p)]['packages']
    capture=docs[next(p for p in INPUTS if 'updated-class-metadata' in p)]
    a=Archive(); methods={}
    roots=(0x10ebc130,0x10cf5810,0x126959e0,0x10eb0060,0x10e9cf50,0x10eb2fc0,
        0x10e060a0,0x10e065c0,0x10e06310,0x10e17180,0x10e17170,
        0x126999e0,0x10cf8630,0x126ada60,0x10dff770,0x1269c500,0x10cf9c00)
    for root in roots:
        methods[root]={i.address:i for i in a.instructions(root)}
    expected=((0x10ebc130,0x10ebc45a,'bl, bl'),(0x10ebc130,0x10ebc47f,'0x10ebc3ed'),
        (0x10ebc130,0x10ebc478,'dword ptr [rbp - 0x71], r13d'),
        (0x10ebc130,0x10ebc5e8,'r8, dword ptr [rbp - 0x71]'),
        (0x10ebc130,0x10ebc5ec,'edx, edx'),(0x10ebc130,0x10ebc5ee,'rcx, rdi'),
        (0x10ebc130,0x10ebc5f1,'0x1497fd92'),
        (0x126959e0,0x126959f2,'0x10cf5810'),(0x126959e0,0x12695aa8,'byte ptr [rdi + 0x26c], 0xf8'),
        (0x10eb0060,0x10eb008b,'r10d, 0x10000080'),(0x10eb0060,0x10eb0092,'r15b'),
        (0x10eb0060,0x10eb02a0,'r15b, r15b'),(0x10eb0060,0x10eb02a3,'0x10eb02be'),
        (0x10cf8630,0x10cf8759,'rsi, qword ptr [rbx + 0xb8]'),
        (0x10cf8630,0x10cf8760,'qword ptr [rdi + 0xb8], rsi'),
        (0x126999e0,0x126999e9,'0x10cf8630'),
        (0x126ada60,0x126ada70,'0x10dff770'),(0x10cf9c00,0x10cf9f41,'qword ptr [rbx + 0xb8]'))
    for root,at,value in expected:
        if at not in methods[root] or methods[root][at].op_str!=value:
            raise ValueError('Current ordinary metadata construction witness changed: '+hex(at))
    # Core manual reflection builders specify their exact native property offsets.
    core=[]
    for root,required in ((0x10e06310,[0x28]),(0x10e065c0,[0x48,0x58,0x98]),
            (0x10e060a0,[0x140,0xe8,0xf0,0x120])):
        ins=list(methods[root].values())
        offsets=[i.operands[1].imm for i in ins if i.mnemonic=='mov' and i.op_str.startswith('edx,')
            and i.operands[1].type==2]
        if offsets!=required:
            raise ValueError('Current core metadata reflection registration offsets changed')
        for offset in offsets:
            if offset<0xc0 and offset+16>0xb8:
                raise ValueError('Core reflected metadata property might overlap ClassConstructor')
        core.append(dict(registration_rva=hex(root),reflected_property_offsets=[hex(v) for v in offsets]))
    generated=templates['generated_class_metaclass_registration']
    raw=a.read(int(generated['parameter_rva'],16),88)
    props,=struct.unpack_from('<Q',raw,40); count,=struct.unpack_from('<I',raw,64)
    fields=a.tree(props,count)
    for p in fields['fields']:
        offset=p.get('constructor_offset_argument')
        if p['kind']=='FBoolProperty':
            offset=p['source_derived_bool_storage'].get('storage_offset')
        if offset is None or offset<0x268:
            raise ValueError('Generated-class reflected initialization range is unqualified')
    # The native metadata-class constructor never writes the constructor pointer.
    for root in (0x10cf5810,0x126959e0,0x126999e0,0x126ada60):
        for ins in methods[root].values():
            if ins.operands and ins.operands[0].type==3 and ins.operands[0].mem.disp==0xb8:
                raise ValueError('Current metaclass constructor/override directly modifies ClassConstructor')
    rows=[]
    for package in packages:
        name=package['class_export']['name']
        tags=package['class_export']['tagged_properties']
        nativized=[tag for tag in tags if tag['name']=='bHasNativizedParent']
        if nativized and (len(nativized)!=1 or nativized[0]['value'] is not False):
            raise ValueError('Selected cooked class takes a nativized-parent construction branch')
        if name=='BP_DFMCharacter_C':
            observed=next(c for c in capture['selected_classes'] if c['name']==name)
            flags=observed['setup_metadata']['class_flags']
            flags_source='existing current bounded declaration observation'
        else:
            parsed=parse_class_stream(package)
            if not parsed['complete']:
                raise ValueError('Selected cooked class flags stream incomplete')
            flags=int(parsed['serialized_class_flags'],16); flags_source='complete current cooked class stream'
        if flags&0x80:
            raise ValueError('Selected generated class unexpectedly declares Native class flag')
        binding=next(c for c in templates['selected_classes'] if c['class_path'].endswith('.'+name))
        rows.append(dict(class_path=binding['class_path'],serialized_class_flags=hex(flags),class_flags_source=flags_source,
            nativized_parent=False,nativized_parent_basis='explicit false tag' if nativized else 'native metaclass default bit cleared and no serialized override',
            inherited_constructor_wrapper_rva=binding['native_constructor_wrapper_rva'],
            expected_primary_vtable_assignment=binding['constructor_primary_assignment'],
            expected_actor_open_hook=binding['actor_open_hook'],expected_net_rep_actor_interface=binding['net_rep_actor_interface']))
    helpers=[Path(__file__),ROOT/'work/research_updated_native_registration.py',ROOT/'work/research_updated_cooked_field_stream.py']
    return dict(kind='current_ordinary_generated_class_constructor_source_certificate',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        selected_classes=rows,core_reflected_metadata=core,generated_metaclass_own_fields=fields,
        source_model=dict(scope='ordinary cooked non-nativized metadata class loading from current assets',
            fresh_metadata_zero_path='allocator no-existing-object branch clears BL then zeroes complete instance at0x10ebc5f1',
            native_metadata_initialization='native ClassFlags&0x10000080 selects reflected-property copying; unreflected constructor pointer+b8 is not copied',
            constructor_inheritance='Bind initializes null ClassConstructor+b8 from actual superclass, recursively; BP override does not replace+b8',
            cdo_creation='UClass CreateDefaultObject calls selected ClassConstructor+b8 at0x10cf9f41',
            qualified_expected_constructor_targets_for_ordinary_source_model=True),
        native_functions=[p for _,p in a.functions.values()],immutable_reads=list(a.data.values()),code_source=a.code.source_evidence(),
        actual_runtime_class_constructor_pointer_observed=False,cached_cdo_or_instance_vtable_observed=False,
        arbitrary_runtime_class_replacement_or_reinstancing_qualified=False,
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
