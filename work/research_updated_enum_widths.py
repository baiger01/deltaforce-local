"""Current minimum enum widths, retaining MAX-registration failure branches."""
import argparse
import json
from pathlib import Path
import struct

from research_updated_metadata_roots import ROOT,sha
from research_updated_native_registration import Archive,CLIENT_SHA,text

INPUT='work/research_updated_minimum_leaf_bindings_79fb7b10_v2.json'
INPUT_SHA='21d89e42a08a38e827e7ee227e3ab1f00900b2e84b0f96a55f8dbd1a358500d6'


def width_candidates(name,form,enumerators):
    if (form not in (0,2) or not 1<=len(enumerators)<=1024 or
            len({n for n,_ in enumerators})!=len(enumerators) or
            any(not n or any(ord(c)>127 for c in n) or not 0<=v<=255 for n,v in enumerators)):
        raise ValueError('Exact bounded current ASCII enum-class/regular byte-valued branch required')
    names=[n for n,_ in enumerators]
    def full(value):
        return name+'::'+value if form and '::' not in value else value
    common=names[0]
    for other in names[1:]:
        count=0
        while count<min(len(common),len(other)) and common[count]==other[count]:
            count+=1
        common=common[:count]
    split=common.rfind('_')
    prefix=common[:split] if split>0 else name
    checked=[full('MAX'),full(prefix+'_MAX')]
    existing=any(candidate in names for candidate in checked)
    maximum=max(v for _,v in enumerators)
    maxima=[maximum] if existing else [maximum,maximum+1]
    log2=lambda value:0 if value<=1 else (value-1).bit_length()
    return dict(checked_existing_max_names=checked,existing_generated_max_name_present=existing,
        possible_maxima=sorted(set(maxima)),
        byte_property_bit_widths=sorted({log2(v) for v in maxima}),
        enum_property_pre_version12_bit_widths=sorted({log2(v) for v in maxima}),
        enum_property_version12_and_later_bit_widths=sorted({log2(v+1) for v in maxima}),
        enum_property_all_version_bit_widths=sorted({log2(v+delta) for v in maxima for delta in (0,1)}),
        absent_max_name_keeps_registration_collision_failure_branch=True)


def derive():
    raw=(ROOT/INPUT).read_bytes()
    if sha(raw)!=INPUT_SHA:
        raise ValueError('Current minimum enum source changed')
    prior=json.loads(raw)
    for source,expected in prior['source_pins'].items():
        if sha((ROOT/source).read_bytes())!=expected:
            raise ValueError('Current minimum enum producer changed: '+source)
    a=Archive(); methods={}
    for rva in (0x10e37950,0x10e1a3a0,0x10e1a710,0x10e1cf00,0x10e1dc70,0x10e27cd0,
            0x109f08c0,0x10e8e5f0,0x10e29940):
        methods[rva]={i.address:i for i in a.instructions(rva)}
    checks=((0x10e37950,0x10e37a5f,'0x10e37ce0'),(0x10e37950,0x10e37b78,'0x10e37ce0'),
        (0x10e37950,0x10e37ca9,'r14, [rax + 1]'),(0x10e1a3a0,0x10e1a478,'ecx, word ptr [rsi + rax]'),
        (0x10e1a3a0,0x10e1a5c2,'r9d, 1'),(0x10e1a3a0,0x10e1a6e8,'0x10b779d0'),
        (0x10e1a710,0x10e1a71f,'dword ptr [rcx + 0x50], 0'),
        (0x10e29940,0x10e2994a,'dword ptr [rdx + 0x54], 0xc'),(0x10e29940,0x10e29982,'rax'))
    for root,at,expected in checks:
        if methods[root][at].op_str!=expected:
            raise ValueError('Current enum MAX/width witness changed: '+hex(at))
    literals=[]
    for root,at,expected in ((0x10e37950,0x10e37a02,'MAX'),(0x10e37950,0x10e37a8f,'_MAX'),
            (0x10e1a3a0,0x10e1a5d3,'_'),(0x10e1a710,0x10e1a72e,'::'),
            (0x10e1a710,0x10e1a778,'%s::%s')):
        rva=a.rip(methods[root][at]); value=text(a.read,rva,wide=True)
        if value!=expected:
            raise ValueError('Current enum string-construction literal changed')
        literals.append(dict(rva=hex(rva),value=value))
    rows=[]
    for enum in prior['enum_registrations']:
        if enum['native_set_enums_flag_input']!=0:
            raise ValueError('Only current AddMax=true registration branch is qualified')
        result=width_candidates(enum['name'],enum['cpp_form'],[(e['name'],e['value']) for e in enum['enumerators']])
        rows.append(dict(enum_name=enum['name'],factory_rva=enum['factory_rva'],**result))
    helpers=[Path(__file__),ROOT/'work/research_updated_enum_widths_test.py',ROOT/'work/research_updated_native_registration.py']
    return dict(kind='current_minimum_enum_network_widths',client_sha256=CLIENT_SHA,
        source_inputs={INPUT:INPUT_SHA},source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        enums=rows,source_literals=literals,native_functions=[p for _,p in a.functions.values()],
        immutable_reads=list(a.data.values()),code_source=a.code.source_evidence(),
        current_role_byte_width=next(r['byte_property_bit_widths'] for r in rows if r['enum_name']=='ENetRole'),
        current_game_mode_enum_width_all_archive_versions=next(r['enum_property_all_version_bit_widths'] for r in rows if r['enum_name']=='EDFMGamePlayMode'),
        runtime_enum_or_archive_version_observed=False,profile_activation_authorized=False,
        process_opened=False,native_engine_function_called=False,runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),role_bits=report['current_role_byte_width'],
        mode_bits=report['current_game_mode_enum_width_all_archive_versions'])))
