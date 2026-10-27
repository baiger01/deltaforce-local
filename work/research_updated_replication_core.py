"""Offline full-code qualification of updated reflection/replication metadata.

Read-only research from explicitly hash-pinned observations and the updated
shadow PE. No process/native calls and no production metadata-reader changes.
"""
import argparse
import bisect
import json
import struct

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from research_updated_metadata_roots import (
    ROOT, PINS, ForensicObservation, NewImage, decoder, disasm, sha,
    compare_pair, instruction_row,
)


def masked_prefix(code, rva):
    result = bytearray(code)
    instructions = list(decoder().disasm(code, rva))
    length = sum(x.size for x in instructions)
    for ins in instructions:
        offset = ins.address-rva
        if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP for op in ins.operands):
            # RIP-relative x64 operands always encode disp32. Capstone5 reports
            # disp_size=2 for some 66-prefixed SIMD instructions despite disp32.
            result[offset+ins.disp_offset:offset+ins.disp_offset+4] = b'\0'*4
        if ins.mnemonic.startswith(('j', 'call')) and any(op.type == X86_OP_IMM for op in ins.operands):
            result[offset+ins.imm_offset:offset+ins.imm_offset+ins.imm_size] = b'\0'*ins.imm_size
    return bytes(result[:length]), length


def locate(old, new, old_rva, radius=0x5000, prefix=96):
    code = old.read(old_rva, prefix)
    masked, length = masked_prefix(code, old_rva)
    # Leading instruction bytes are retained; prefix equality is only a search
    # aid and never a certificate of a complete function or field offset.
    first = max(0x1000, old_rva-radius)
    raw = new.read(first, radius*2+prefix)
    marker = code[:3]
    hits, at = [], raw.find(marker)
    while at >= 0:
        candidate = raw[at:at+prefix]
        other, used = masked_prefix(candidate, first+at)
        if used == length and other == masked:
            hits.append(first+at)
        at = raw.find(marker, at+1)
    return hits


def compare_full(old, new, image, name, old_rva, new_rva, fixed_length=None):
    fragments = image.fragments(new_rva)
    if not fragments and fixed_length is None:
        raise ValueError('Exact current unwind root required')
    length = fixed_length if fixed_length is not None else fragments[-1][1]-new_rva
    old_code, new_code = old.read(old_rva, length), new.read(new_rva, length)
    oi, ni = disasm(old, old_rva, length), disasm(new, new_rva, length)
    if len(oi) != len(ni) or sum(i.size for i in oi) != length or sum(i.size for i in ni) != length:
        raise ValueError('Full function decode/size changed: '+name)
    if not fragments:
        boundaries = {i.address for i in ni}
        numeric_leaf = name in ('numeric_scalar_archive32', 'numeric_scalar_archive64')
        bad = False
        for i in ni:
            if i.mnemonic == 'call':
                bad = True
            if i.mnemonic.startswith('j'):
                op = i.operands[0]
                internal = op.type == X86_OP_IMM and op.imm in boundaries
                explicit_tail = numeric_leaf and i.mnemonic == 'jmp' and (
                    i.address == ni[-1].address or op.type == X86_OP_MEM and i.op_str == 'qword ptr [rax + 0x60]')
                if not internal and not explicit_tail:
                    bad = True
        if ni[-1].mnemonic not in ('ret', 'jmp') or bad:
            raise ValueError('Fixed leaf is not closed control flow')
    refs = []
    for a, b in zip(oi, ni):
        if (a.address-old_rva, a.size, a.id) != (b.address-new_rva, b.size, b.id):
            raise ValueError(f'Instruction shape changed: {name}/{a.address:x}/{b.address:x}')
        aa, bb = bytearray(a.bytes), bytearray(b.bytes)
        for x, y in zip(a.operands, b.operands):
            if x.type != y.type:
                raise ValueError('Operand type changed')
            if x.type == X86_OP_MEM and x.mem.base == X86_REG_RIP:
                if y.mem.base != X86_REG_RIP or (x.mem.index, x.mem.scale) != (y.mem.index, y.mem.scale):
                    raise ValueError('RIP addressing mode changed')
                start, size = a.disp_offset, 4
                aa[start:start+size] = bb[start:start+size] = bytes(size)
                refs.append(dict(kind='rip_reference', old_instruction=hex(a.address),
                    new_instruction=hex(b.address), old_target=hex(a.address+a.size+x.mem.disp),
                    new_target=hex(b.address+b.size+y.mem.disp)))
            elif x.type == X86_OP_IMM and a.mnemonic.startswith(('j', 'call')):
                if old_rva <= x.imm < old_rva+length and x.imm-old_rva != y.imm-new_rva:
                    raise ValueError('Internal direct control flow changed')
                start, size = a.imm_offset, a.imm_size
                aa[start:start+size] = bb[start:start+size] = bytes(size)
                refs.append(dict(kind='direct_control_flow', old_instruction=hex(a.address),
                    new_instruction=hex(b.address), old_target=hex(x.imm), new_target=hex(y.imm)))
        if aa != bb:
            raise ValueError(f'Non-reference instruction bytes changed: {name}/{a.address:x}/{b.address:x}')
    return dict(name=name, old_rva=hex(old_rva), new_rva=hex(new_rva), bytes=length,
        old_code_sha256=sha(old_code), new_code_sha256=sha(new_code),
        instruction_count=len(ni), full_linear_decode=True,
        all_non_reference_instruction_bytes_identical=True, internal_direct_control_flow_preserved=True,
        structure_displacements_and_nonaddress_immediates_are_not_masked=True,
        boundary_basis=('explicit leaf through final ret or tail delegate' if not fragments
                        else 'full contiguous chained unwind ranges'),
        new_fragments=[dict(begin=hex(a), end_exclusive=hex(b), unwind_rva=hex(c)) for a,b,c in fragments],
        references=refs, decoded_new_instructions=[instruction_row(i) for i in ni])


def containing_primary(image, rva):
    i = bisect.bisect_right(image.starts, rva)-1
    if i < 0 or not image.entries[i][0] <= rva < image.entries[i][1]:
        return None
    row = image.entries[i]
    for _ in range(64):
        head = image.read(row[2], 4)
        if head[0] >> 3 != 4:
            return row[0]
        row = struct.unpack('<III', image.read(row[2]+4+((head[2]+1)&~1)*2, 12))
    raise ValueError('Chained unwind root depth exceeded')


def call_xrefs(observation, image, targets):
    results = []
    for first, end, block in observation.blocks:
        observation.read(first, 1)
        raw = observation.loaded[first]
        at = raw.find(b'\xe8')
        while at >= 0 and at+5 <= len(raw):
            target = first+at+5+struct.unpack_from('<i', raw, at+1)[0]
            if target in targets:
                source = first+at
                root = containing_primary(image, source)
                if root:
                    fragments = image.fragments(root)
                    amount = fragments[-1][1]-root
                    if amount <= 65536:
                        instructions = disasm(observation, root, amount)
                        hits = [i for i in instructions if i.address == source and i.mnemonic == 'call']
                        if hits:
                            results.append(dict(call=hex(source), target=hex(target), root=hex(root)))
            at = raw.find(b'\xe8', at+1)
    return results


PAIRS = [
    ('weak_key_lookup_cache24', 0xd8cbc0, 0xd8cbe0),
    ('weak_key_lookup_layout32', 0xd8caf0, 0xd8cb10),
    ('weak_key_equality', 0xd86840, 0xd86860),
    ('sparse_array_allocate_slot', 0xd64a50, 0xd64a70),
    ('class_cache_get_or_build', 0x10cfdad0, 0x10cfd470),
    ('class_replication_descriptor_setup', 0x10e055a0, 0x10e04f40),
    ('property_checksum', 0x10d002e0, 0x10cffc80),
    ('property_iterator', 0x10d02210, 0x10d01bb0),
    ('ufield_iterator', 0x10cd27e0, 0x10cd2180),
    ('driver_cache_binding_consumer', 0x1289bb70, 0x1289bec0),
    ('get_class_rep_layout', 0x12b90c70, 0x12b90fc0),
    ('get_function_rep_layout', 0x12b90940, 0x12b90c90),
    ('class_layout_factory', 0x12daa010, 0x12daa360),
    ('function_layout_factory', 0x12daa150, 0x12daa4a0),
    ('layout_constructor', 0x12d9d6f0, 0x12d9da40),
    ('class_layout_initialize', 0x12db1ec0, 0x12db2210),
    ('function_layout_initialize', 0x12db2cb0, 0x12db3000),
    ('recursive_command_builder', 0x12d9b1e0, 0x12d9b530),
    ('leaf_command_builder', 0x12da2460, 0x12da27b0),
    ('shadow_offsets_assign', 0x12d985c0, 0x12d98910),
    ('command_property_serializer_consumer', 0x12dbb3a0, 0x12dbb6f0),
    ('generic_numeric_net_serializer', 0x10e5ce20, 0x10e5c7c0),
    ('numeric_scalar_archive32', 0x286bf70, 0x286bc30, 0x4b),
    ('numeric_scalar_archive64', 0x286c000, 0x286bcc0, 0x4c),
    ('field_owner_name_path', 0x10e1f740, 0x10e1f0e0),
    ('field_owner_variant_isa', 0x10e26ea0, 0x10e26840, 0x2f),
    ('array_data_accessor', 0xd968d0, 0xd968f0, 4),
]


def qualify():
    old, new, image = ForensicObservation('old'), ForensicObservation('new'), NewImage()
    functions = [compare_full(old, new, image, *row) for row in PAIRS]
    all_ins = {int(i['rva'], 16):i for row in functions for i in row['decoded_new_instructions']}
    witnesses = []
    checks = [
        ('NetDriver cache manager at +0x170', 0x1289bee2, 'mov rcx, qword ptr [rcx + 0x170]'),
        ('cache manager map at +8', 0x10cfd49f, 'lea rcx, [r15 + 8]'),
        ('NetDriver layout map at +0x430', 0x12b90ff8, 'lea rcx, [r15 + 0x430]'),
        ('map allocated slot count at +8', 0xd8cbf2, 'mov eax, dword ptr [rcx + 8]'),
        ('map backing slot capacity at +0xc', 0xd64ace, 'cmp eax, dword ptr [rcx + 0xc]'),
        ('map free slot count at +0x34', 0xd8cbfe, 'cmp eax, dword ptr [rcx + 0x34]'),
        ('map inline bucket storage at +0x38', 0xd8cc07, 'lea rsi, [rcx + 0x38]'),
        ('map external buckets pointer at +0x40', 0xd8cc0b, 'lea rcx, [rsi + 8]'),
        ('map bucket count at +0x48', 0xd8cc15, 'movsxd rcx, dword ptr [rbp + 0x48]'),
        ('map hash low XOR high', 0xd8cc29, 'xor rbx, rdx'),
        ('map bucket index mask', 0xd8cc2c, 'and rbx, rcx'),
        ('cache map entry stride part1 =3*index', 0xd8cc46, 'lea rsi, [rax + rax*2]'),
        ('cache map next index at +0x10', 0xd8cc7a, 'mov ebx, dword ptr [rax + rsi*8 + 0x10]'),
        ('layout map stride32', 0xd8cb76, 'shl rsi, 5'),
        ('layout map next index at +0x18', 0xd8cbaa, 'mov ebx, dword ptr [rsi + rax + 0x18]'),
        ('class cache weak key at +0x10', 0x10cfd507, 'lea rcx, [rax + 0x10]'),
        ('class cache parent at +8', 0x10cfd613, 'mov qword ptr [r12 + 8], rax'),
        ('class cache inherited count', 0x10cfd618, 'mov ecx, dword ptr [rax + 0x28]'),
        ('class cache inherited start', 0x10cfd61b, 'add ecx, dword ptr [rax]'),
        ('class cache own start at +0', 0x10cfd61d, 'mov dword ptr [r12], ecx'),
        ('class cache checksum at +0x18', 0x10cfd624, 'mov dword ptr [r12 + 0x18], eax'),
        ('class cache fields array at +0x20', 0x10cfd632, 'lea rcx, [r12 + 0x20]'),
        ('class cache fields count at +0x28', 0x10cfd6f5, 'mov dword ptr [r12 + 0x28], eax'),
        ('class cache fields capacity at +0x2c', 0x10cfd6fa, 'cmp eax, dword ptr [r12 + 0x2c]'),
        ('class cache field record stride32', 0x10cfd722, 'shl rcx, 5'),
        ('class SuperStruct pointer at +0x48', 0x10e04fa6, 'mov rdi, qword ptr [r13 + 0x48]'),
        ('UStruct FProperty chain at +0x70', 0x10e050ce, 'mov rax, qword ptr [r13 + 0x70]'),
        ('UStruct UObject Children at +0x58', 0x10e05187, 'mov rax, qword ptr [r13 + 0x58]'),
        ('FProperty Next at +0x18', 0x10e05166, 'mov rax, qword ptr [rbx + 0x18]'),
        ('UField Next at +0x28', 0x10e0521d, 'mov rax, qword ptr [rbx + 0x28]'),
        ('FProperty class at +0x20', 0x10e05101, 'mov rax, qword ptr [rbx + 0x20]'),
        ('FFieldClass flags low32 at +0x10', 0x10e05105, 'mov ecx, dword ptr [rax + 0x10]'),
        ('FFieldClass flags read as u64 at +0x10', 0x10cfff47, 'mov rcx, qword ptr [rax + 0x10]'),
        ('FProperty property flag Net bit at +0x48', 0x10e05116, 'test byte ptr [rbx + 0x48], 0x20'),
        ('UFunction flags at +0xc0', 0x10e051e2, 'test byte ptr [rbx + 0xc0], 0x40'),
        ('FProperty RepIndex u16 at +0x50', 0x10e05297, 'mov word ptr [rcx + 0x50], ax'),
        ('FProperty ArrayDim i32 at +0x3c', 0x10e052a8, 'cmp dword ptr [rcx + 0x3c], esi'),
        ('class replicated-property records at +0x110', 0x10e052d3, 'call 0xd84d60'),
        ('class replicated-property record stride16', 0x10e052e5, 'shl rdi, 4'),
        ('class replicated-property record descriptor at +0', 0x10e052fb, 'mov qword ptr [rdi], rcx'),
        ('class replicated-property record array index at +8', 0x10e052fe, 'mov dword ptr [rdi + 8], esi'),
        ('FProperty owner variant passed at field+8', 0x10e05124, 'lea rcx, [rbx + 8]'),
        ('owner variant UObject tag byte at variant+8 / field+0x10', 0x10e26840, 'cmp byte ptr [rcx + 8], 0'),
        ('owner variant owner pointer at variant+0 / field+8', 0x10e26846, 'mov rax, qword ptr [rcx]'),
        ('FProperty name token at +0x28', 0x10e1f146, 'lea rcx, [rsi + 0x28]'),
        ('FProperty ElementSize i32 at +0x40', 0x12db24a8, 'imul r13d, dword ptr [rsi + 0x40]'),
        ('FProperty OffsetInternal i32 at +0x54', 0x12db25e0, 'mov edx, dword ptr [rbx + 0x54]'),
        ('RepLayout parents TArray at +0x40', 0x12db2310, 'lea r14, [rsi + 0x40]'),
        ('RepLayout commands TArray at +0x50', 0x12db23f5, 'lea rax, [rsi + 0x50]'),
        ('RepLayout parent stride64', 0x12db2457, 'shl rdx, 6'),
        ('RepLayout parent descriptor at +0', 0x12db245e, 'mov qword ptr [rdx], rsi'),
        ('RepLayout parent name token at +8', 0x12db2483, 'mov qword ptr [rdx + 8], rax'),
        ('RepLayout command stride32', 0x12da2810, 'shl rdi, 5'),
        ('RepLayout command descriptor at +0', 0x12da2823, 'mov qword ptr [rdi], rbx'),
        ('RepLayout command data_offset i32 at +0xc', 0x12da282a, 'mov dword ptr [rdi + 0xc], r14d'),
        ('RepLayout command shadow_offset i32 at +0x10', 0x12d98b92, 'mov dword ptr [rcx + rsi + 0x10], edx'),
        ('RepLayout command relative_handle u16 at +0x14', 0x12da2839, 'mov word ptr [rdi + 0x14], bp'),
        ('RepLayout command parent_index u16 at +0x16', 0x12da283d, 'mov word ptr [rdi + 0x16], ax'),
        ('RepLayout command dispatch byte at +0x1c', 0x12da2826, 'mov byte ptr [rdi + 0x1c], 2'),
        ('RepLayout empty special command has descriptor0 and opcode1', 0x12d9b662, 'mov byte ptr [rax + rcx + 0x1c], 1'),
        ('Cmd descriptor drives property vtable selection', 0x12dbb884, 'mov rcx, qword ptr [r12]'),
        ('property descriptor vtable pointer at +0', 0x12dbb89e, 'mov rax, qword ptr [rcx]'),
        ('property Net serializer vslot0x90', 0x12dbb8a1, 'call qword ptr [rax + 0x90]'),
        ('generic numeric serializer delegates scalar vslot0x88', 0x10e5c815, 'call qword ptr [rax + 0x88]'),
        ('GetClassLayout calls class factory', 0x12b9106b, 'call 0x12daa360'),
        ('class factory calls class layout initialize', 0x12daa472, 'call 0x12db2210'),
        ('GetFunctionLayout calls function factory', 0x12b90d3b, 'call 0x12daa4a0'),
        ('function factory calls function layout initialize', 0x12daa5b2, 'call 0x12db3000'),
    ]
    for meaning, at, expected in checks:
        witness = all_ins[at]
        if witness['instruction'] != expected:
            raise ValueError('Exact offset witness changed: '+meaning)
        witnesses.append(dict(meaning=meaning, **witness))
    callback_data = image.read(0x1d59de88, 8)
    if struct.unpack('<Q', callback_data)[0] != image.image_base+0xd968f0:
        raise ValueError('On-disk array data accessor pointer changed')
    indirect_jumps = [(row['name'], i['instruction']) for row in functions
                      for i in row['decoded_new_instructions']
                      if i['instruction'].startswith('jmp ') and not i['instruction'].startswith('jmp 0x')]
    if indirect_jumps != [('numeric_scalar_archive32', 'jmp qword ptr [rax + 0x60]'),
                          ('numeric_scalar_archive64', 'jmp qword ptr [rax + 0x60]')]:
        raise ValueError('Unexpected indexed dispatch/jump table requires separate qualification')
    return dict(kind='offline_updated_reflection_replication_core_qualification',
        client_sha256=PINS['new'][2], historical_client_sha256=PINS['old'][2],
        script_sha256=sha(__import__('pathlib').Path(__file__).read_bytes()),
        process_accessed=False, native_getter_called=False, process_memory_written=False,
        runtime_class_schema_recovered=False, native_protocol_compatibility_verified=False,
        production_reader_changed=False, function_comparisons=functions,
        exact_offset_witnesses=witnesses,
        indexed_jump_tables_present=False,
        indirect_jumps=[dict(function=name, instruction=ins) for name,ins in indirect_jumps],
        qualification_summary=dict(all_qualified_structure_offsets_unchanged=True,
            rvas_require_explicit_new_bindings=True,
            class_vs_function_entry_disambiguation='full factory/initializer call chain and class-specific replication array traversal',
            no_prefix_match_is_used_as_a_native_binding=True,
            class_cache=dict(header_bytes=48, entry_bytes=32, index_start=0, parent=8,
                weak_key='0x10', checksum='0x18', fields='0x20', count='0x28', capacity='0x2c',
                entry=dict(descriptor=0, representation=8, rep_index='0x10', checksum='0x14', incompatible='0x18')),
            reflection=dict(super_struct='0x48', uobject_children='0x58', ufield_next='0x28',
                fproperty_children='0x70', ffield_next='0x18', ffield_class='0x20',
                ffieldclass_flags_u64='0x10', ffield_owner_pointer=8, ffield_owner_uobject_tag='0x10',
                ffield_name='0x28', array_dimension_i32='0x3c', element_size_i32='0x40',
                property_flag_low_bits='0x48', rep_index_u16='0x50', offset_internal_i32='0x54',
                function_flags_u32='0xc0', class_replicated_records='0x110',
                class_replicated_count='0x118', class_replicated_capacity='0x11c',
                class_replicated_record_bytes=16),
            rep_layout=dict(parents='0x40', commands='0x50', parent_record_bytes=64,
                command_record_bytes=32, parent_descriptor=0, parent_name=8,
                command_descriptor=0, command_data_offset_i32='0xc', command_shadow_offset_i32='0x10',
                command_handle_u16='0x14', command_parent_index_u16='0x16', dispatch_opcode_u8='0x1c'),
            driver=dict(class_cache_manager='0x170', manager_cache_map=8, layout_map='0x430'),
            methods=dict(property_net_serializer_vslot='0x90', numeric_scalar_vslot='0x88',
                generic_numeric_new_rva='0x10e5c7c0', archive32_new_rva='0x286bc30',
                archive64_new_rva='0x286bcc0')),
        limitations=[
            'No updated game process, selected class, current ClassNetCache, RepLayout, runtime descriptor vtable, schema names/indices/handles or native protocol behavior has been observed.',
            'Offset equality proves the selected read layouts only; old captured schemas and concrete game object/property storage offsets must not be reused automatically.',
            'FProperty flags low-bit tests and field offset0x48 are proved; upper32 property-flag meanings are not separately recovered in this scope. FFieldClass cast flags are explicitly loaded as u64 at class+0x10.',
            'Native weak-key comparison also equates two invalid references; the existing pure lookup deliberately accepts only the exact selected nonzero weak key branch.',
            'On-disk array accessor pointer1d59de88 resolves to simple d968f0; its current runtime cell value was not observed. The process reader must preserve source/identity and stable-read checks.',
            'Generic numeric serializer and the fixed archive32/64 leaf bodies are qualified, including their tail delegates. Tail delegate internals, all other per-type serializers, type classifiers/constants and serializer wire compatibility are outside this qualification.',
            'Actor channel vslot0x3d8, diagnostic CVar1cba32f0, connection/player/world pointers and optional exporter scopes are not qualified here.',
            'The historical helpers/old cache identities remain untouched. New bindings must be selected explicitly under the updated Shipping SHA.',
        ],
        verification_command='python work/research_updated_replication_core.py --qualify',
        array_data_accessor_cell=dict(on_disk_rva='0x1d59de88', bytes_hex=callback_data.hex(),
            sha256=sha(callback_data), target_rva='0xd968f0',
            native_body='mov rax,qword ptr [rcx]; ret', runtime_cell_value_observed=False),
        sources=[old.source_evidence(), new.source_evidence()],
        bindings={name:hex(new_rva) for name, old_rva, new_rva, *rest in PAIRS},
        reader_source_pins={p:sha((ROOT/p).read_bytes()) for p in [
            'work/native_replication_metadata_core.py', 'work/export_native_replication_metadata.py',
            'outputs/df-local-server/dfserver/replication/legacy_ds_class_net_cache.py']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--locate', nargs='+', type=lambda x:int(x, 0))
    parser.add_argument('--calls', nargs='+', type=lambda x:int(x, 0))
    parser.add_argument('--qualify', action='store_true')
    args = parser.parse_args()
    old, new = ForensicObservation('old'), ForensicObservation('new')
    if args.locate:
        print(json.dumps({hex(rva):[hex(x) for x in locate(old, new, rva)] for rva in args.locate}, indent=2))
    if args.calls:
        print(json.dumps(call_xrefs(new, NewImage(), set(args.calls)), indent=2))
    if args.qualify:
        result = qualify()
        output = ROOT/'work/evidence/updated-replication-core-79fb7b10.json'
        output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(), sha256=sha(output.read_bytes()),
            full_functions=len(result['function_comparisons']), witnesses=len(result['exact_offset_witnesses']))))


if __name__ == '__main__':
    main()
