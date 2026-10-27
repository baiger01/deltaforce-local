"""Qualify exact observed updated property method bindings offline.

No process access, native call, old-build reader import, activation or runtime
mutation. Historical bindings remain attached to their original client identity.
"""
import argparse
import collections
import json

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from research_updated_metadata_roots import (
    ROOT, PINS, ForensicObservation, NewImage, disasm, instruction_row, sha,
)
from research_updated_replication_core import compare_full
from research_updated_cache_initialization import unwind_inventory
import research_updated_schema_comparison as historical


CAPTURE = 'work/native-client-tests/1792803423602487700/updated-class-metadata.json'
INPUT_PINS = {
    CAPTURE: 'ae58fa8354c4a777e32ae4dac05481dfe0bd1662f263269f6a77b2c3e93fc64f',
    'work/research_updated_metadata_roots.py': 'ea107a5bc475bea3ec262dd26ea91283b6fdfa5ad564e29fec3763b737c32cf6',
    'work/research_updated_replication_core.py': '3f9938b62167eba78650c869261f9e6e76f2e8582e058134d9f2739ca5af7c83',
    'work/research_updated_cache_initialization.py': '88e2502c09aeef23013c77ec3877e587ed4e10ee8785afb7a9a90ac3282fa9dd',
    'work/research_updated_schema_comparison.py': '28ac4bb8eef6eaa115b2a22c5deac31e6c314cfa2381070e055dde0575f20620',
    'work/research_updated_cache_initialization_79fb7b10.json': '9f27a79bd5686c0d90dd3b30d983a3b9af86516de550b0936607c061dc00b6ac',
    'work/research_updated_transport_79fb7b10.json': 'd127c9b551192ba1a126f3b5f5e2c90f9a9a6a0e6d4ff806b6d037941fb73e92',
    'work/research_updated_transport_profile_79fb7b10.json': '2e55c4989ddb28f7ae75a6ddfd62e92f50d77bc523a99aebbf84ffd65ccd43c8',
    **{path:historical.PINS[path] for path in historical.OLD_CAPTURES+historical.SCHEMAS[:3]},
}

# These are bounded code extents, not a rule for moving arbitrary RVAs.
LEAVES = {
    (0x286bf70, 0x286bc30): ('numeric_scalar_archive32', 0x4b, None),
    (0x286bfc0, 0x286bc80): ('archive_tail_vslot50', 0x14, 'jmp qword ptr [rax + 0x50]'),
    (0x286bfe0, 0x286bca0): ('archive_tail_scalar', 0x12, 'jmp 0x109e9da0'),
    (0x286c000, 0x286bcc0): ('numeric_scalar_archive64', 0x4c, None),
    (0x10e93c60, 0x10e93600): ('archive_scalar16', 0x4d, 'jmp 0x10b4aeb0'),
    (0x10e95350, 0x10e94cf0): ('property_archive_tail_vslot160', 0x14, 'jmp qword ptr [r10 + 0x160]'),
    (0x10ebaec0, 0x10eba860): ('archive_tail_vslot48', 0x14, 'jmp qword ptr [rax + 0x48]'),
    (0xd5c5d0, 0xd5c650): ('constant_success', 3, None),
    (0xd5f3a0, 0xd5f420): ('constant_failure', 3, None),
}
DELEGATES = [
    ('archive_read16_tail', 0x10b4b4e0, 0x10b4aeb0),
    ('archive_read32_tail', 0x10b4b540, 0x10b4af10),
    ('archive_read64_tail', 0x10b4b5a0, 0x10b4af70),
    ('archive_scalar_tail', 0x109ea340, 0x109e9da0),
]
TYPE_TARGETS = (0x25a2ca0, 0x10e840d0, 0x10e826f0, 0x10e827b0, 0x10e82a80)


def read_inputs():
    documents, pins = {}, []
    for path, expected in INPUT_PINS.items():
        raw = (ROOT/path).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Serializer qualification input changed: '+path)
        pins.append(dict(path=path, sha256=expected))
        if path.endswith('.json'):
            documents[path] = json.loads(raw)
    return documents, pins


def explicit_tail_leaf(old, new, image, name, old_rva, new_rva, length, final_tail):
    if image.fragments(new_rva):
        raise ValueError('Explicit leaf unexpectedly has unwind metadata')
    oi, ni = disasm(old, old_rva, length), disasm(new, new_rva, length)
    if len(oi) != len(ni) or sum(x.size for x in ni) != length or sum(x.size for x in oi) != length:
        raise ValueError('Leaf linear decode changed')
    if instruction_row(ni[-1])['instruction'] != final_tail:
        raise ValueError('Explicit final tail target changed')
    for observation, rva in ((old, old_rva), (new, new_rva)):
        if observation.read(rva+length, 1) != b'\xcc':
            raise ValueError('Explicit leaf final padding boundary changed')
    boundaries = {x.address for x in ni}
    refs = []
    for a,b in zip(oi,ni):
        if (a.address-old_rva,a.size,a.id) != (b.address-new_rva,b.size,b.id):
            raise ValueError('Leaf instruction shape changed')
        if b.mnemonic == 'call':
            raise ValueError('Explicit tail leaf contains call')
        if b.mnemonic.startswith('j'):
            operand = b.operands[0]
            internal = operand.type == X86_OP_IMM and operand.imm in boundaries
            vslot_tail = b.mnemonic == 'jmp' and b.op_str == 'qword ptr [rax + 0x60]' and name == 'archive_scalar16'
            if not internal and b.address != ni[-1].address and not vslot_tail:
                raise ValueError('Unqualified non-final leaf exit')
        aa,bb = bytearray(a.bytes),bytearray(b.bytes)
        for x,y in zip(a.operands,b.operands):
            if x.type != y.type:
                raise ValueError('Leaf operand type changed')
            if x.type == X86_OP_MEM and x.mem.base == X86_REG_RIP:
                aa[a.disp_offset:a.disp_offset+4] = bb[b.disp_offset:b.disp_offset+4] = bytes(4)
                refs.append(dict(kind='rip_reference', old_instruction=hex(a.address), new_instruction=hex(b.address),
                    old_target=hex(a.address+a.size+x.mem.disp),new_target=hex(b.address+b.size+y.mem.disp)))
            elif x.type == X86_OP_IMM and a.mnemonic.startswith('j'):
                if old_rva <= x.imm < old_rva+length and x.imm-old_rva != y.imm-new_rva:
                    raise ValueError('Internal leaf control flow changed')
                aa[a.imm_offset:a.imm_offset+a.imm_size] = bytes(a.imm_size)
                bb[b.imm_offset:b.imm_offset+b.imm_size] = bytes(b.imm_size)
                refs.append(dict(kind='direct_control_flow',old_instruction=hex(a.address),new_instruction=hex(b.address),
                    old_target=hex(x.imm),new_target=hex(y.imm)))
        if aa != bb:
            raise ValueError('Non-reference leaf bytes changed')
    return dict(name=name,old_rva=hex(old_rva),new_rva=hex(new_rva),bytes=length,
        old_code_sha256=sha(old.read(old_rva,length)),new_code_sha256=sha(new.read(new_rva,length)),
        instruction_count=len(ni),full_linear_decode=True,
        all_non_reference_instruction_bytes_identical=True,internal_direct_control_flow_preserved=True,
        structure_displacements_and_nonaddress_immediates_are_not_masked=True,
        boundary_basis='Explicit complete leaf through specified final tail followed by int3; every other exit is internal or the specified archive vslot60 tail.',
        new_fragments=[],references=refs,decoded_new_instructions=[instruction_row(x) for x in ni],
        dynamic_virtual_tail_targets_observed=False)


def qualify():
    docs, pins = read_inputs()
    fresh = docs[CAPTURE]
    if (fresh['client_sha256'] != PINS['new'][2] or fresh['complete'] is not True
            or any(fresh[x] is not False for x in ('native_protocol_compatibility_verified',
                'process_memory_written','native_function_called','account_data_read'))):
        raise ValueError('Fresh serializer observation scope changed')
    producer_path = 'work/updated_client_metadata.py'
    if sha((ROOT/producer_path).read_bytes()) != fresh['source_pins'][producer_path]:
        raise ValueError('Actual captured enriched metadata producer changed')
    pins.append(dict(path=producer_path,sha256=fresh['source_pins'][producer_path]))
    classes = fresh['selected_classes']
    current = {c['name']:c for c in classes}
    if len(current) != len(classes) or len(classes) != 45:
        raise ValueError('Current class match labels are ambiguous')
    fields = {(c['name'],p['name']):(ci,pi,p) for ci,c in enumerate(classes)
              for pi,p in enumerate(c['own_properties'])}
    previous, pairs = {}, {}
    for path in historical.OLD_CAPTURES:
        document = docs[path]
        if document['client_sha256'] != PINS['old'][2] or not document['identities_and_fields_rechecked']:
            raise ValueError('Historical declaration scope changed')
        for collection in ('objects','loaded_named_classes'):
            for oi,obj in enumerate(document.get(collection,[])):
                for di,decl in enumerate(obj['declarations']):
                    for pi,field in enumerate(decl['fields']):
                        key = decl['class_name'],field['name']
                        if key not in fields:
                            continue
                        ci,ni,now = fields[key]
                        source = dict(path=path,json_pointer=f'/{collection}/{oi}/declarations/{di}/fields/{pi}')
                        facts = historical.historical_field(field)
                        for fact in historical.FACT_KEYS:
                            if facts[fact] != now[fact]:
                                raise ValueError('Required current property geometry changed: '+repr(key))
                        item = previous.setdefault(key,dict(old_facts=facts,
                            old_vtable=field['field_vtable_rva'],old_hooks={},historical_sources=[]))
                        if item['old_vtable'] != field['field_vtable_rva']:
                            raise ValueError('Historical property vtable disagreement')
                        item['historical_sources'].append(source)
                        for slot,hook in field['hooks'].items():
                            if not hook['inside_pinned_image'] or not hook['identity_rechecked']:
                                raise ValueError('Historical binding identity unqualified')
                            old_rva = hook['target_rva']
                            if slot in item['old_hooks'] and item['old_hooks'][slot] != old_rva:
                                raise ValueError('Historical method binding disagreement')
                            item['old_hooks'][slot] = old_rva
                            new_rva = now['virtual_methods'][slot]['target_rva']
                            pair = pairs.setdefault((slot,old_rva,new_rva),dict(affected_properties=set(),sources=[]))
                            pair['affected_properties'].add(key)
                            pair['sources'].append(dict(**source,slot=slot))
    if len(previous) != 1646 or len(pairs) != 32:
        raise ValueError('Exact historical/current binding coverage changed')
    old,new,image = ForensicObservation('old'),ForensicObservation('new'),NewImage()
    functions, binding_pairs = [], []
    for (slot,o,n),coverage in sorted(pairs.items()):
        if (o,n) in LEAVES:
            name,length,tail = LEAVES[o,n]
            proof = (explicit_tail_leaf(old,new,image,name,o,n,length,tail) if tail
                     else compare_full(old,new,image,name,o,n,length))
        else:
            proof = compare_full(old,new,image,'observed_'+slot+'_'+hex(o),o,n)
        functions.append(proof)
        binding_pairs.append(dict(slot=slot,old_target_rva=hex(o),observed_new_target_rva=hex(n),
            whole_function_proof=proof['name'],affected_properties=[a+'.'+b for a,b in sorted(coverage['affected_properties'])],
            property_count=len(coverage['affected_properties']),historical_bindings=coverage['sources']))
    functions.extend(compare_full(old,new,image,*row) for row in DELEGATES)
    type_methods, type_fragments = [], []
    for target in TYPE_TARGETS:
        fragments = image.fragments(target)
        length = fragments[-1][1]-target
        decoded = disasm(new,target,length)
        if sum(x.size for x in decoded) != length:
            raise ValueError('Observed type method full decode incomplete')
        type_fragments.extend(fragments)
        type_methods.append(dict(observed_new_target_rva=hex(target),bytes=length,
            code_sha256=sha(new.read(target,length)),new_fragments=[dict(begin=hex(a),end_exclusive=hex(b),unwind_rva=hex(c)) for a,b,c in fragments],
            decoded_new_instructions=[instruction_row(i) for i in decoded],
            historical_vslot60_binding_observed=False,
            type_output_invoked_or_emulated=False))
    inventory = unwind_inventory(image,functions,type_fragments)
    inventory.pop('leaf_crc_boundary')
    inventory['explicit_leaf_boundaries'] = [dict(old_rva=hex(o),new_rva=hex(n),
        name=name,bytes=length,final_tail=tail,
        basis='Full bounded decode, closed internal branches and explicit return/tail; no native call or emulation.')
        for (o,n),(name,length,tail) in LEAVES.items()]
    instruction_rows = {int(x['rva'],16):x for f in functions for x in f['decoded_new_instructions']}
    witnesses = []
    for rule,address,text in [
        ('Observed numeric net serializer delegates to property slot88',0x10e5c815,'call qword ptr [rax + 0x88]'),
        ('Byte serializer enum pointer property+90',0x10e8e5fa,'mov rcx, qword ptr [rcx + 0x90]'),
        ('Byte serializer without enum width8',0x10e8e651,'mov ecx, 8'),
        ('Byte serializer delegates archive bits slot68',0x10e8e662,'call qword ptr [rax + 0x68]'),
        ('Object property declared class pointer+90',0x10e8e6ea,'mov r8, qword ptr [rbx + 0x90]'),
        ('Object serializer delegates PackageMap slot260',0x10e8e716,'call qword ptr [rax + 0x260]'),
        ('Struct serializer reads current struct descriptor+90',0x10e8e7f9,'mov rcx, qword ptr [rcx + 0x90]'),
        ('Struct serializer requires native net flag400',0x10e8e800,'test dword ptr [rcx + 0xb8], 0x400'),
        ('Struct serializer reads current CppStructOps+c0',0x10e8e810,'mov rcx, qword ptr [rcx + 0xc0]'),
        ('Struct serializer delegates CppStructOps slot70',0x10e8e831,'call qword ptr [rax + 0x70]'),
    ]:
        actual = instruction_rows.get(address)
        if actual is None or actual['instruction'] != text:
            raise ValueError('Serializer semantic witness changed: '+rule)
        witnesses.append(dict(rule=rule,**actual))
    setups = []
    for ci,c in enumerate(classes):
        setup = c['setup_metadata']
        arrays = setup['arrays']
        setups.append(dict(name=c['name'],path=c['path'],superclass_path=c['superclass_path'],
            class_flags=hex(setup['class_flags']),setup_flag0x800=bool(setup['class_flags']&0x800),
            guard_nonzero=bool(int.from_bytes(bytes.fromhex(setup['setup_guard_raw']),'little')),
            observed_arrays=arrays,declared_net_functions=len(c['own_net_functions']),
            declared_root_net_functions=sum(not f['super_function_present'] for f in c['own_net_functions']),
            source_json_pointer=f'/selected_classes/{ci}/setup_metadata'))
    if any(s['setup_flag0x800'] or any(a['count'] or a['capacity'] or a['storage_present']
            for a in s['observed_arrays'].values()) for s in setups):
        raise ValueError('Expected uninitialized fresh setup snapshot changed')
    property_rows = []
    for key,before in sorted(previous.items()):
        ci,pi,field = fields[key]
        property_rows.append(dict(class_name=key[0],property=key[1],class_path=current[key[0]]['path'],
            old_facts=before['old_facts'],observed_new_facts=field,
            old_vtable_rva=hex(before['old_vtable']),observed_new_vtable_rva=hex(field['field_vtable_rva']),
            old_hook_rvas={k:hex(v) for k,v in before['old_hooks'].items()},
            all_compared_geometry_equal=True,old_sources=before['historical_sources'],
            current_source=dict(path=CAPTURE,json_pointer=f'/selected_classes/{ci}/own_properties/{pi}'),
            current_slot88_slot90_body_bindings_qualified=True,
            current_slot60_binding_observed=True,
            slot60_historical_binding_equivalence_qualified=False,
            current_wire_handle_qualified=False))
    property_index={(r['class_name'],r['property']):r for r in property_rows}
    subset = []
    schema_path=historical.SCHEMAS[2]
    for name,field in docs[schema_path]['actor']['fields'].items():
        actual=property_index[field['declaring_class'],name]
        subset.append(dict(name=name,declaring_class=field['declaring_class'],current=actual,
            historical_schema_source=dict(path=schema_path,json_pointer='/actor/fields/'+name),
            historical_ordinary_or_inner_handle=field.get('ordinary_handle',field.get('inner_handle')),
            current_handle_qualified=False,
            remaining_wire_dependencies=('current RepLayout/handle plus nested struct/CppStructOps and inner field' if name=='ServerWeaponIdentity'
                else 'current RepLayout/handle plus actual enum pointer/values and width' if name=='WeaponSlot'
                else 'current RepLayout/handle plus PackageMap subtype/class dispatch' if name in ('Owner','CharacterOwner')
                else 'current RepLayout/handle; fixed-width scalar binding/code is qualified')))
    role_rows=[property_index['Actor',name] for name in ('RemoteRole','Role')]
    literals=[]
    for label,rva,value in [('WeaponEquipPosition native CPP type',0x14f19fe0,'uint32'),
                            ('WeaponID/Guid native CPP type',0x14f19ff0,'uint64'),
                            ('Byte no-enum native CPP type',0x14f19fc0,'uint8')]:
        raw=image.read(rva,(len(value)+1)*2)
        if raw!=(value+'\0').encode('utf-16-le'):
            raise ValueError('Current GetCPPType literal changed')
        literals.append(dict(label=label,rva=hex(rva),value=value,bytes_hex=raw.hex(),sha256=sha(raw),
            old_literal_table_available=False))
    assessment_sources=[]
    for path in ['outputs/df-local-server/dfserver/replication/legacy_ds_actor_bunch.py',
                 'outputs/df-local-server/dfserver/replication/legacy_ds_actor_open.py',
                 'outputs/df-local-server/dfserver/transport/native/legacy_ds_wire_codec.py',
                 'outputs/df-local-server/protocol/native_ds_wire_profile.json',
                 'work/native_role_byte_metadata.py']:
        assessment_sources.append(dict(path=path,sha256=sha((ROOT/path).read_bytes())))
    return dict(kind='updated_observed_serializer_bindings_offline_qualification',
        client_sha256=PINS['new'][2],historical_client_sha256=PINS['old'][2],
        process_access=False,native_called=False,native_emulated=False,
        production_sources_changed=False,protocol_acceptance=False,input_sources=pins,
        observed_classes=len(classes),observed_properties=len(fields),
        matched_historical_properties=len(property_rows),exact_observed_serializer_pairs=len(binding_pairs),
        pair_scope='The three examined historical declaration captures produce32 exact matched slot88/90 pairs. Additional requested pairs have no binding source in these inputs; no synthetic pairs are added.',
        functions=functions,binding_pairs=binding_pairs,property_comparisons=property_rows,
        current_weapon_actor_subset=subset,actor_role_remote_role_bindings=role_rows,
        historical_weapon_component_coverage=[dict(class_name=name,
            actual_current_class_captured=name in current,
            current_schema_or_binding_qualified=False) for name in (
                'WeaponManagerComponent','MultiWeaponManagerComponent',
                'GPWeaponReplicateComponent','WeaponReplicateComponent')],
        current_type_methods=type_methods,current_type_literals=literals,
        historical_slot60_binding_claimed=False,exact_instruction_witnesses=witnesses,
        unwind_inventory=inventory,setup_observations=setups,
        setup_summary=dict(all45_class_flags_0x800_clear=True,all_replication_arrays_empty=True,
            all_rep_index_zero=all(f['rep_index']==0 for _,_,f in fields.values()),
            nonzero_setup_guard_classes=sum(s['guard_nonzero'] for s in setups),
            declared_net_functions=sum(s['declared_net_functions'] for s in setups),
            declared_root_net_functions=sum(s['declared_root_net_functions'] for s in setups),
            setup_invoked_false_is_reader_provenance_not_a_native_state_bit=True,
            no_current_class_net_cache_or_rep_layout_observed=True),
        now_certified=[
            'All matched1646 property name/geometry/ArrayDim/ElementSize/low32 flags facts equal historical declarations, plus actual new property vtable and slot88/90 target observations attached to full-body old/new code comparisons.',
            'WeaponID and WeaponGuid current slot88 binds the64-bit scalar leaf and slot90 binds generic numeric; WeaponEquipPosition binds32-bit scalar/generic numeric. Current type methods use updated PE uint64/uint32 literals.',
            'Actor Owner and WeaponBase CharacterOwner actual slot90 binds current object-property serializer; ServerWeaponIdentity binds current struct net serializer; WeaponSlot, Actor Role/RemoteRole bind current byte serializer.',
            'Current native setup arrays are actually empty, initialized bit0x800 clear. Own declared net UFunctions can exist while native NetFunctions arrays remain empty.',
        ],
        remaining_requirements=[
            'Current stable NetDriver class cache and class RepLayout (parents/commands/handles) after ordinary native initialization, or independently qualified full reconstruction. Nonzero prior handles are not inherited from unchanged bindings.',
            'Actual byte-property Enum+90 identity/entries/max values for WeaponSlot and Role/RemoteRole. A current byte serializer binding does not establish8bits or2bits.',
            'ServerWeaponIdentity current UScriptStruct+90, flags+b8, CppStructOps+c0/vslot70 binding and actual nested UniqueId descriptor/type/command. Struct net body equality does not certify the historical inner handle40.',
            'Object reference declared class+90 and current PackageMap virtual slot260/268 bindings/profile; full serializer output closure is not claimed for dynamic callees.',
            'Current UFunction parameter fields/flags/directions and actual ClassNetCache indices before any RPC body; fresh own_net_functions names/flags/super presence do not provide parameter schemas or wire indices.',
            'FName::ToString table relocation/formatting and all dynamic GetCPPType dependencies remain unqualified for independent checksum reconstruction; slot60 addresses are observations, not native outputs.',
        ],
        minimal_ordinary_probe_assessment=dict(
            possible_without_old_memory_reader=True,
            control_route='Use explicit new-build identity and source-pinned pure ordinary wire codecs at the service boundary. Observe new Hello/version/handler envelope and current connection cap/versions; then an independently qualified control exchange. Pure codecs do not need a fabricated old-image memory session.',
            control_requirements=['Current Hello checksum and packet-handler envelope observation; old1077088301 is not requalified.',
                'Actor102/Control255 and packet/bunch framing are code-qualified by transport/profile reports, while live archive versions/cap and actual control state transitions still require current connection evidence.',
                'Keep historical image gates intact; current process metadata reads must use the separately qualified updated session/global-cell bindings. Never assign the old module SHA to the new process.'],
            actor_route='A header-only ordinary Actor-open, with no property content/RPC/Role payload, avoids needing historical RepLayout handles. A static existing Actor is the smallest candidate, conditional on a current resolvable in-world Actor reference/export graph and qualified no-extra-fields OnActorChannelOpen hook.',
            actor_requirements=['Fully qualify updated ReceiveNetGUIDBunch/SerializeObject/SerializeNewActor/Actor channel InitActor and chosen OnActorChannelOpen bodies/profile; current transport proof does not certify these downstream Actor-open functions.',
                'Observe the actual current existing Actor identity/Outer/path, GUID mapping, PackageMap subtype and no-extra-fields hook. The45-class snapshot contains class descriptors, not a qualified in-world Actor instance or GUID mapping.',
                'If a dynamic Actor is needed, additionally qualify current archetype/CDO and Level references, spawn serialization and any game interface/derived class header tails. A class path alone cannot supply those contracts.',
                'Construct a single unpartial reliable bunch below the actual measured connection cap; packet ACK proves transport only. Confirm native object/channel state separately before property or RPC probes.'],
            executable_probe_ready=False,
            reason='This evidence closes serializer bindings and observes empty setup arrays; current connection envelope/Actor-open reference and hook prerequisites are not supplied by this capture.',
            assessment_sources=assessment_sources),
        limits=[
            'New target RVAs come from exact observed property slots, never a uniform RVA delta or wildcard substitution.',
            'Current vtable RVAs may differ independently of function RVAs. Property binding equality is paired per declaration/name and geometry, not by matching old vtable addresses.',
            'The code cache and binding snapshot are different saved observations of the same exact EXE identity. Current target pages were not reread for contemporaneous executable bytes by the enriched metadata producer.',
            'Whole function matching masks only direct branch/call and RIP reference fields. Struct offsets, vslot offsets and all nonaddress constants are compared exactly; dynamic external target semantics are separate requirements.',
            'All proof remains isolated research. No old schema identity, old reader guard, production wire profile or runtime dependency was changed.',
        ],source_observations=[old.source_evidence(),new.source_evidence()],
        research_script=dict(path='work/research_updated_serializer_bindings.py',
            sha256=sha((ROOT/'work/research_updated_serializer_bindings.py').read_bytes())))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualify',action='store_true',required=True)
    parser.parse_args()
    result=qualify()
    output=ROOT/'work/research_updated_serializer_bindings_79fb7b10.json'
    raw=(json.dumps(result,indent=2)+'\n').encode('utf-8')
    output.write_bytes(raw)
    print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(),sha256=sha(raw),
        matched_properties=result['matched_historical_properties'],pairs=result['exact_observed_serializer_pairs'],
        functions=len(result['functions']),class_setup_empty=result['setup_summary']['all_replication_arrays_empty'],
        protocol_acceptance=False)))


if __name__=='__main__':
    main()
