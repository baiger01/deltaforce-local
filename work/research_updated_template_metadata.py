"""Offline qualification of existing CDO/interface metadata for build79fb7b10.

This is a source contract for bounded read-only observations. It never opens a
process, invokes a getter, initializes a CDO or changes an existing producer.
"""
import argparse
import json
import struct

from research_updated_metadata_roots import (
    ROOT, PINS, ForensicObservation, NewImage, sha,
)
from research_updated_replication_core import compare_full
from research_updated_cache_initialization import unwind_inventory


MAP_PROOF = 'work/evidence/updated-map-profile-closure-79fb7b10.json'
TEMPLATES = 'outputs/df-local-server/protocol/portable-map-spawn/templates.json'
PINS_INPUT = {
    'work/research_updated_metadata_roots.py': 'ea107a5bc475bea3ec262dd26ea91283b6fdfa5ad564e29fec3763b737c32cf6',
    'work/research_updated_replication_core.py': '3f9938b62167eba78650c869261f9e6e76f2e8582e058134d9f2739ca5af7c83',
    'work/research_updated_cache_initialization.py': '88e2502c09aeef23013c77ec3877e587ed4e10ee8785afb7a9a90ac3282fa9dd',
    MAP_PROOF: 'd3b5e2b63959859080b250ebe6badff831dd9ad4e993f2f14993367a0ab673ab',
    TEMPLATES: 'add5d53b212843dd146581b77b61e7077a6dd49fb31288d3e675d5f7c4e4d01c',
}
PAIRS = [
    ('object_archetype_or_cdo_selection', 0x10eabab0, 0x10eab450),
    ('class_create_default_object', 0x10cfa260, 0x10cf9c00),
    ('class_constructor', 0x10cf5e70, 0x10cf5810),
    ('class_native_constructor', 0x10cf6020, 0x10cf59c0),
    ('native_interface_address', 0x10eacb60, 0x10eac500),
    ('net_rep_actor_interface_class_getter', 0x603f7a0, 0x603f320),
    ('array_data_accessor', 0xd968d0, 0xd968f0, 4),
    ('empty_actor_channel_open', 0xd5f350, 0xd5f3d0, 3),
]


def qualify():
    docs, sources = {}, []
    for path,expected in PINS_INPUT.items():
        raw = (ROOT/path).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Template metadata source changed: '+path)
        sources.append(dict(path=path,sha256=expected))
        if path.endswith('.json'):
            docs[path] = json.loads(raw)
    if (docs[MAP_PROOF]['client_sha256'] != PINS['new'][2]
            or docs[MAP_PROOF]['native_called'] is not False
            or docs[TEMPLATES]['client_sha256'] != PINS['old'][2]):
        raise ValueError('Template source identity changed')
    old,new,image = ForensicObservation('old'),ForensicObservation('new'),NewImage()
    functions = [compare_full(old,new,image,*row) for row in PAIRS]
    unwind = unwind_inventory(image,functions,[])
    instructions = {int(i['rva'],16):i for f in functions for i in f['decoded_new_instructions']}
    checks = [
        ('Class constructor clears existing CDO pointer',0x10cf58c8,'mov qword ptr [rdi + 0x140], rsi'),
        ('Native Class constructor clears existing CDO pointer',0x10cf5a9f,'mov qword ptr [rdi + 0x140], rsi'),
        ('Native CDO creation initial existing-pointer test',0x10cf9c24,'cmp qword ptr [rcx + 0x140], 0'),
        ('Native CDO construction explicit flags include0x10',0x10cf9e27,'mov r9d, 0x31'),
        ('Native CDO creation stores result at Class+140',0x10cf9e5b,'mov qword ptr [rbx + 0x140], rax'),
        ('Generic selected class CDO null test',0x10eaba60,'cmp qword ptr [r15 + 0x140], 0'),
        ('Generic selected class may create CDO if absent',0x10eaba70,'call qword ptr [rax + 0x388]'),
        ('Generic selected class reads existing CDO cell',0x10eaba76,'mov rsi, qword ptr [r15 + 0x140]'),
        ('InterfaceClass flags field',0x10eac521,'mov eax, dword ptr [rdx + 0xd4]'),
        ('InterfaceClass native bit7 field',0x10eac540,'mov eax, dword ptr [r15 + 0xd4]'),
        ('UObject class pointer',0x10eac54f,'mov r14, qword ptr [r13 + 8]'),
        ('Implemented interface count',0x10eac59c,'cmp ebx, dword ptr [r14 + 0x208]'),
        ('Implemented interface array',0x10eac5a8,'lea rcx, [r14 + 0x200]'),
        ('Implemented interface stride factor2 before8-byte indexing',0x10eac5af,'add rdi, rdi'),
        ('Implemented interface script flag byte',0x10eac5b8,'cmp byte ptr [rax + rdi*8 + 0xc], r12b'),
        ('Implemented interface Class pointer',0x10eac5bf,'mov rax, qword ptr [rax + rdi*8]'),
        ('Requested interface base-chain record',0x10eac5c3,'lea rdx, [r15 + 0x30]'),
        ('Requested interface base-chain depth',0x10eac5c7,'movsxd rcx, dword ptr [rdx + 8]'),
        ('Implemented interface base-chain depth',0x10eac5cb,'cmp ecx, dword ptr [rax + 0x38]'),
        ('Implemented interface base-chain pointer',0x10eac5d0,'mov rax, qword ptr [rax + 0x30]'),
        ('Interface native inheritance identity comparison',0x10eac5d4,'cmp qword ptr [rax + rcx*8], rdx'),
        ('Interface pointer adjustment is signed32',0x10eac5eb,'movsxd rbp, dword ptr [rax + rdi*8 + 8]'),
        ('Interface address is UObject plus pointer adjustment',0x10eac5f0,'add rbp, r13'),
        ('Class superclass traversal',0x10eac5f3,'mov r14, qword ptr [r14 + 0x48]'),
    ]
    witnesses = []
    for meaning,at,expected in checks:
        row = instructions[at]
        if row['instruction'] != expected:
            raise ValueError('Template metadata witness changed: '+meaning)
        witnesses.append(dict(meaning=meaning,**row))
    rip_checks = [
        ('UClass static native vtable',0x10cf5830,0x1ab3a1d8),
        ('UClass native-constructor same vtable',0x10cf59ee,0x1ab3a1d8),
        ('Interface array accessor global cell',0x10eac5b2,0x1d59de88),
        ('Interface adjustment accessor global cell',0x10eac5e5,0x1d59de88),
        ('NetRepActorInterface existing singleton read',0x603f32a,0x1de5c888),
        ('NetRepActorInterface existing singleton return',0x603f3c3,0x1de5c888),
        ('NetRepActorInterface literal binding',0x603f35d,0x1671645a),
        ('NetRepActorInterface package binding',0x603f39f,0x165824a8),
    ]
    for meaning,at,target in rip_checks:
        row = instructions[at]
        if row.get('rip_targets') != [hex(target)]:
            raise ValueError('Template metadata binding changed: '+meaning)
        witnesses.append(dict(meaning=meaning,**row))
    data = []
    for meaning,rva,target in [
        ('UClass static vtable+388 CDO creator',0x1ab3a1d8+0x388,0x10cf9c00),
        ('Implemented-interface TArray data accessor',0x1d59de88,0xd968f0),
    ]:
        raw = image.read(rva,8)
        if struct.unpack('<Q',raw)[0] != image.image_base+target:
            raise ValueError('Current immutable pointer mismatch: '+meaning)
        data.append(dict(meaning=meaning,rva=hex(rva),bytes_hex=raw.hex(),
                         sha256=sha(raw),target_rva=hex(target),runtime_cell_observed=False))
    literals = []
    for rva,expected in [(0x1671645a,'NetRepActorInterface'),(0x165824a8,'/Script/GPGameplay')]:
        raw = image.read(rva,(len(expected)+1)*2)
        if raw.decode('utf-16le') != expected+'\0':
            raise ValueError('Current interface literal mismatch')
        literals.append(dict(rva=hex(rva),text=expected,bytes_hex=raw.hex(),sha256=sha(raw)))
    old_pawn = next(c for c in docs[TEMPLATES]['roots']['named_template_candidates']
                    if c['class_name'] == 'BP_DFMCharacter_C')
    if old_pawn['actor_channel_open_hook']['target_rva'] != 0xd5f350:
        raise ValueError('Historical Pawn empty hook input changed')
    map_functions = {f['name']:f for f in docs[MAP_PROOF]['functions']}
    expected_hooks = []
    for name,slot,expected in [
        ('pc_on_actor_channel_open',0x3d8,0x12d4e100),
        ('pawn_net_rep_writer',0x10,0x4e19500),
    ]:
        f = map_functions[name]
        if int(f['new_rva'],16) != expected:
            raise ValueError('Previously qualified selected hook changed')
        expected_hooks.append(dict(name=name,slot=hex(slot),expected_new_rva=hex(expected),
            current_selected_cdo_binding_observed=False,
            proof=dict(path=MAP_PROOF,sha256=PINS_INPUT[MAP_PROOF],
                       function=name,code_sha256=f['new_code_sha256'],bytes=f['bytes'])))
    expected_hooks.append(dict(name='pawn_actor_channel_open',slot='0x3d8',
        expected_new_rva='0xd5f3d0',body='ret 0',
        qualification='Historical Pawn selected this empty hook; new complete3-byte body is qualified here. Current CDO must independently resolve to it.',
        current_selected_cdo_binding_observed=False))
    return dict(kind='offline_updated_existing_template_metadata_qualification',
        client_sha256=PINS['new'][2],historical_client_sha256=PINS['old'][2],
        process_access=False,client_launched=False,native_called=False,
        process_memory_written=False,production_sources_changed=False,
        current_cdo_observed=False,current_interface_bindings_observed=False,
        native_protocol_compatibility_verified=False,
        source_inputs=sources,functions=functions,unwind_inventory=unwind,
        exact_instruction_witnesses=witnesses,immutable_data=data,immutable_literals=literals,
        cdo_contract=dict(class_existing_cdo_pointer_offset='0x140',pointer_bytes=8,
            class_cdo_creator_vslot='0x388',qualified_base_creator_rva='0x10cf9c00',
            qualified_base_uclass_vtable_rva='0x1ab3a1d8',
            selected_derived_metaclass_creator_target_not_assumed=True,
            raw_uobject=dict(vtable=0,class_pointer=8,outer_pointer='0x10',flags32='0x18',
                fname_token='0x1c',registry_index='0x24'),
            creation_flags_witness='Creator passes0x31; record raw CDO flags and require the observed candidate Class/name/path/registry binding. Flags alone are not identity.',
            no_call_rule='Read Class+140 only. Null means unavailable. Do not call v388, GetDefaultObject, a class constructor or a singleton getter.',
            expected_name='Default__'+ '<selected exact class name>',
            outer_path_rule='Read actual UObject Outer and actual full path through the already qualified current name/path reader. Do not manufacture package/class Outer relation.',
            candidate_rule='A same-name registry candidate is separate diagnostic metadata. It cannot replace an absent Class+140 pointer or claim CDO flags verified.'),
        interface_contract=dict(array_class_offset='0x200',array_data_pointer_offset=0,
            array_count_offset=8,array_count_signed=True,entry_bytes=16,
            entry_interface_class_pointer_offset=0,entry_signed_pointer_adjustment_offset=8,
            entry_implemented_by_script_u8_offset=12,entry_native_branch_script_byte=0,
            superclass_offset='0x48',class_flags32_offset='0xd4',
            requested_interface_required_class_flag_bits=[14,7],
            interface_base_chain_pointer_offset='0x30',interface_base_chain_depth_i32_offset='0x38',
            native_comparison='requestedDepth <= entryInterface.depth AND entryInterface.baseChain[requestedDepth] == requestedInterface+0x30',
            current_data_accessor_cell_rva='0x1d59de88',current_data_accessor_rva='0xd968f0',
            accessor_complete_body='mov rax, qword ptr [rcx]; ret',
            native_match_order='Derived-to-base Class traversal and first eligible interface entry. A bounded observer can reject multiple matches as stricter local policy.',
            selected_adjustment_rule='Observe actual signed adjustment; old0xa60 is not an updated observation.',
            interface_method_rule='For the eligible selected CDO interface: read secondary vtable pointer at CDO+actual_adjustment, then read method slot0x10. No invocation.'),
        net_rep_actor_interface=dict(getter_rva='0x603f320',existing_singleton_cell_rva='0x1de5c888',
            class_name='NetRepActorInterface',class_path='/Script/GPGameplay.NetRepActorInterface',
            getter_called=False,existing_cell_value_observed=False,
            fallback='If singleton is null, report unavailable. A separately registry-validated exact class can be recorded diagnostically; never initialize the singleton.'),
        expected_selected_actor_hooks=expected_hooks,
        bounded_observation_recipe=[
            'Use the current-build qualified object/name/path reader with fresh Class and registry identities. Confirm selected metaclass ancestry contains Class; preserve superclass identity/path records.',
            'Snapshot Class+140. If nonzero, validate current registry identity, actual Class pointer equals selected Class, exact Default__ name, actual Outer and actual path. Read CDO main vtable and v3d8 target from qualified image ranges.',
            'Read and recheck the actual runtime accessor cell1d59de88; require module_base+d968f0 before claiming the native array-storage interpretation. Read its pointer only; do not invoke it.',
            'Snapshot every selected Class and ancestor interface array header+200/208. For positive count require a non-null readable data pointer and bounded16-byte records; resolve each entry InterfaceClass through the current registry reader.',
            'Read the already-existing NetRepActorInterface singleton at explicit new cell1de5c888; validate exact class identity/name/path, bit14+bit7 flags and base-chain depth. Match native entries with scriptbyte0 using the proved chain identity comparison.',
            'Only after one qualified native interface match, validate CDO+signed_adjustment address and secondary vtable, then record slot10 target. Require4e19500 before qualifying the known Pawn spawn byte algorithm.',
            'Re-read all Class/CDO/interface headers, object identities, vtable cells and method pointers before publishing. Enforce caps for classes, ancestry, interfaces, calls, bytes and elapsed time. Caps are observer policy, not native limits.',
            'Read current image singleton/vtable cells through explicit newly qualified backend ranges. UpdatedMetadata._read intentionally rejects unqualified image globals; do not broaden that filter or spoof an old image identity.'],
        fail_closed_cases=[
            dict(input='Class+140 null',status='missing_existing_cdo_pointer',action='No object dereference, constructor/getter call, invented named-default substitute or Actor manifest qualification.'),
            dict(input='Class absent or ambiguous',status='missing_or_ambiguous_current_class',action='Do not use archived addresses/weak serials.'),
            dict(input='CDO registry/Class/name/Outer/path changes',status='inconsistent_existing_cdo_metadata',action='Discard this observation; no binding qualification.'),
            dict(input='Interface array count<0, exceeds local cap or positive count with null data',status='unavailable_or_invalid_interface_array',action='Do not treat it as an empty list or use a null entry.'),
            dict(input='Runtime interface-array accessor cell null/different/changed',status='unqualified_interface_array_accessor',action='Do not assume the immutable on-disk pointer is its current value; no callback invocation.'),
            dict(input='NetRepActorInterface singleton null',status='missing_existing_interface_class_pointer',action='Do not invoke singleton getter; interface eligibility remains unqualified.'),
            dict(input='Interface entry Class null, chain null with referenced depth, invalid depth/cycle or unreadable descriptor',status='unavailable_or_invalid_interface_entry',action='No guessed interface identity, base-chain membership or adjustment.'),
            dict(input='No native match or several matches under strict observer policy',status='missing_or_ambiguous_native_interface',action='No extension-byte binding.'),
            dict(input='CDO/main/secondary vtable or selected method pointer null/outside image/changed',status='unavailable_or_unqualified_current_method_binding',action='No call and no old target/table substitution.'),
            dict(input='Selected method differs from qualified expected target',status='observed_different_method_requires_source_qualification',action='Record observation but keep corresponding native sender feature disabled.'),
        ],
        limits=['Whole selected function bodies match outside recorded references; external callees, live global cells and derived selected CDO bindings are not recursively certified by that fact.',
            'Class+140 and interface array reads recover metadata only. They do not initialize ClassNetCache/RepLayout, assign wire handles, resolve network GUIDs or prove gameplay acceptance.',
            'No current process metadata is present in this report. All current runtime fields above are requirements for a later bounded read-only capture.'],
        source_observations=[old.source_evidence(),new.source_evidence()],
        research_script=dict(path='work/research_updated_template_metadata.py',
            sha256=sha((ROOT/'work/research_updated_template_metadata.py').read_bytes())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualify',action='store_true',required=True)
    parser.parse_args()
    result = qualify()
    output = ROOT/'work/evidence/updated-template-metadata-79fb7b10.json'
    raw = (json.dumps(result,indent=2)+'\n').encode('utf-8')
    output.write_bytes(raw)
    print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(),sha256=sha(raw),
        functions=len(result['functions']),witnesses=len(result['exact_instruction_witnesses']),
        cdo_offset='0x140',interface_array_offset='0x200',native_called=False)))


if __name__ == '__main__':
    main()
