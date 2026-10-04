"""Seal precise name-resolver code evidence from existing disk artifacts only."""
import hashlib
import json
import mmap
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha
from offline_metadata_name_trace import CACHE, MANIFEST
import offline_native_code_cache as cache

SOURCES = {
    'native-class-cache-layout-direct-helpers.json': [0x10e1c980],
    'native-class-replication-descriptor-setup.json': [0x10e1c900],
    'native-metadata-name-roots.json': [0x10b78000, 0x10eac970],
    'native-metadata-name-entry-helpers.json': [0x10e1f740, 0x10b638b0, 0x10b68690, 0x10b5bde0, 0x10b5bec0],
    'native-metadata-name-number-helper.json': [0x109ed950],
    'native-metadata-name-narrow-widen.json': [0xd60360],
}
ANCHORS = {
    0x10e1c98c: 'cmp byte ptr [rcx + 8], 0', 0x10e1c99b: 'call 0x10eac970',
    0x10e1c9a9: 'call 0x10e1c900', 0x10e1c910: 'mov rcx, qword ptr [rcx + 0x20]',
    0x10e1c914: 'call 0x10b78000', 0x10e1c939: 'call 0x10e1f740',
    0x10e1f7a6: 'lea rcx, [rsi + 0x28]', 0x10e1f7ae: 'call 0x10b78000',
    0x10e1faa4: 'lea rcx, [r15 + 0x28]', 0x10e1faac: 'call 0x10b78000',
    0x10eacb19: 'mov rax, qword ptr [rsi + 0x1c]', 0x10eacb2a: 'call 0x10b5bec0',
    0x10b638ba: 'shr ebx, 0x12', 0x10b638bd: 'and eax, 0x3ffff',
    0x10b638fb: 'add eax, eax', 0x10b638fd: 'add rax, qword ptr [rdx + rbx*8 + 8]',
    0x10b686b4: 'movzx eax, word ptr [rcx]', 0x10b686bd: 'lea rdx, [rcx + 2]',
    0x10b686c7: 'shr edi, 6', 0x10b686cf: 'test al, 1',
    0x10b686e2: 'call 0x10b5ff10', 0x10b68750: 'call 0x10b5fd00',
    0x10b68798: 'mov word ptr [rsp + 0x20], 0x3f', 0x10b687a9: 'call 0xd60360',
    0xd603a0: 'movsx ecx, byte ptr [r8 + rdx]', 0xd603c4: 'cmp byte ptr [rcx + r8], 0',
    0xd603c9: 'jge 0xd603d0', 0xd603cb: 'mov word ptr [rdi + rcx*2], r9w',
    0x10b5be73: 'movsx edx, byte ptr [rsp + rax + 0x20]',
    0x10b5be78: 'mov word ptr [rsp + rax*2 + 0x20], dx',
    0x10b781ac: 'mov edx, dword ptr [rsi + 4]', 0x10b781af: 'dec edx',
    0x10b781b1: 'call 0x109ed950', 0x109ed979: 'shr r11d, 0x1f',
    0x109ed99f: 'sar edx, 2', 0x109ed9d5: 'mov word ptr [rsp + rax*2 + 0x20], cx',
}

def main():
    folder, _, pin = cache.validate_manifest(CACHE, MANIFEST)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    verified, source_pins, instructions = [], [], {}
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Shipping identity mismatch')
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = ImmutableImage(raw)
        for filename, needed in SOURCES.items():
            path = ROOT / 'work/evidence' / filename
            report = json.loads(path.read_bytes())
            source_pins.append({'relative_path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path.read_bytes())})
            if report['client_sha256'] != SOURCE_SHA:
                raise ValueError('Saved source build mismatch')
            for row in report['roots']:
                begin = int(row['begin'], 16)
                if begin not in needed:
                    continue
                binary = (ROOT / row['code_relative_path']).read_bytes()
                code = binary[32:]
                if struct.unpack('<4sIQQQ', binary[:32]) != (b'DCDE', 1, begin, row['bytes'], image.image_base):
                    raise ValueError('Saved dfcode header mismatch')
                if sha(binary) != row['file_sha256'] or sha(code) != row['code_sha256'] or len(code) != row['bytes']:
                    raise ValueError('Saved dfcode SHA/length mismatch')
                if code != validated_range(folder, begin, len(code), pin):
                    raise ValueError('Saved source differs from pinned cache')
                fragments = row.get('fragments', [row])
                for fragment in fragments:
                    pdata = image.containing(int(fragment['begin'], 16))
                    metadata = image.unwind(pdata)
                    for key in ('begin', 'end_exclusive', 'unwind_rva', 'unwind_flags', 'metadata_bytes', 'metadata_sha256'):
                        if metadata[key] != fragment[key]:
                            raise ValueError('Immutable pdata/unwind fragment mismatch')
                decoded = list(decoder.disasm(code, begin))
                if sum(i.size for i in decoded) != len(code):
                    raise ValueError('Saved complete name helper is not full decode')
                asm = ('\n'.join(f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in decoded) + '\n').encode()
                if sha(asm) != row['asm_sha256'] or (ROOT / row['asm_relative_path']).read_bytes() != asm:
                    raise ValueError('Saved ASM mismatch')
                instructions.update({i.address: i for i in decoded})
                verified.append({'rva': hex(begin), 'bytes': len(code), 'file_sha256': sha(binary),
                    'code_sha256': sha(code), 'asm_sha256': sha(asm), 'source': row['code_relative_path'],
                    'full_decode': True, 'complete_fragments': len(fragments)})
        anchors = []
        for rva, expected in ANCHORS.items():
            ins = instructions[rva]
            if f'{ins.mnemonic} {ins.op_str}' != expected:
                raise ValueError(f'Exact instruction evidence changed at {rva:x}')
            anchors.append({'rva': hex(rva), 'instruction': expected, 'bytes_hex': bytes(ins.bytes).hex()})
        globals_out = []
        for rva, expected in [(0x10b638c2, 0x1e3267ac), (0x10b638d3, 0x1e326a80)]:
            ins = instructions[rva]
            if not any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and
                ins.address + ins.size + op.mem.disp == expected for op in ins.operands):
                raise ValueError('Exact pool global RIP reference mismatch')
            globals_out.append({'instruction_rva': hex(rva), 'target_rva': hex(expected),
                'instruction': f'{ins.mnemonic} {ins.op_str}', 'bytes_hex': bytes(ins.bytes).hex()})
        leaves = []
        for begin, end, table in [(0x10b5fd00, 0x10b5feec, 0x10b5feec),
                                  (0x10b5ff10, 0x10b6016e, 0x10b60170)]:
            code = validated_range(folder, begin, end - begin, pin)
            decoded = list(decoder.disasm(code, begin))
            boundaries = {ins.address for ins in decoded}
            if sum(i.size for i in decoded) != len(code) or decoded[-1].mnemonic != 'ret':
                raise ValueError('Leaf code/table division is not complete decode')
            raw_table = validated_range(folder, table, 36, pin)
            targets = struct.unpack('<9I', raw_table)
            if not all(target in boundaries for target in targets):
                raise ValueError('Fixed nine-way table target is not a leaf instruction')
            for ins in decoded:
                if ins.mnemonic == 'call' or (ins.mnemonic.startswith('j') and ins.operands and
                        ins.operands[0].type == X86_OP_IMM and ins.operands[0].imm not in boundaries):
                    raise ValueError('Name transform leaf escapes the fixed code range')
            filename = ROOT / 'work/evidence' / ('native-metadata-name-transform-complete.' + hex(begin)[2:])
            binary = struct.pack('<4sIQQQ', b'DCDE', 1, begin, len(code), image.image_base) + code
            asm = ('\n'.join(f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in decoded) + '\n').encode()
            Path(str(filename) + '.dfcode').write_bytes(binary)
            Path(str(filename) + '.asm.txt').write_bytes(asm)
            leaves.append({'begin': hex(begin), 'end_exclusive': hex(end), 'code_bytes': len(code),
                'code_sha256': sha(code), 'file_sha256': sha(binary), 'asm_sha256': sha(asm),
                'code_relative_path': Path(str(filename) + '.dfcode').relative_to(ROOT).as_posix(),
                'table_rva': hex(table), 'table_bytes': 36, 'table_sha256': sha(raw_table),
                'table_raw_hex': raw_table.hex(), 'table_case_targets': [hex(x) for x in targets],
                'pdata_present': False, 'code_ranges_exclude_inline_table': True,
                'all_direct_branches_internal': True, 'table_targets_are_valid_instruction_boundaries': True,
                'wide_loop_unit_step': 2 if begin == 0x10b5ff10 else 1})
        prefix = validated_range(folder, 0x10b562d0, 768, pin)
        prefix_ins = {i.address: i for i in decoder.disasm(prefix, 0x10b562d0)}
        ctor_anchors = []
        for rva, expected in [(0x10b56313, 'lea rcx, [rbx + 8]'), (0x10b56317, 'mov r8d, 0x10000'),
                              (0x10b5634e, 'mov ecx, 0x80000'), (0x10b5635b, 'mov qword ptr [rbx + 8], rax')]:
            ins = prefix_ins[rva]
            if f'{ins.mnemonic} {ins.op_str}' != expected:
                raise ValueError('Name-pool constructor prefix changed')
            ctor_anchors.append({'rva': hex(rva), 'instruction': expected, 'bytes_hex': bytes(ins.bytes).hex()})
        digits = image.read(0x1aad7c58, 40)
        if digits.decode('utf-16-le') != '9876543210123456789\0':
            raise ValueError('Signed decimal digit table mismatch')
    cache.validate_manifest(folder, pin)
    result = {'kind': 'pinned_native_metadata_name_resolver', 'shipping_sha256': SOURCE_SHA,
        'cache_manifest_sha256': pin, 'process_accessed': False, 'native_called': False,
        'actual_runtime_names_recovered': False, 'source_pins': source_pins, 'complete_sources': verified,
        'exact_instruction_anchors': anchors, 'pool_global_references': globals_out,
        'transform_leaf_code_and_tables': leaves, 'constructor_prefix_scope': {
            'begin': '0x10b562d0', 'bytes': 768, 'code_sha256': sha(prefix),
            'complete_function': False, 'exact_anchors': ctor_anchors},
        'name_descriptor': {'rep0_fname_offset': '0x28', 'rep1_uobject_fname_offset': '0x1c',
            'fname_bytes': 8, 'entry_id_u32_offset': 0, 'number_u32_offset': 4,
            'entry_id_block': 'id >> 18', 'entry_offset_bytes': '(id & 0x3ffff) * 2'},
        'name_pool': {'root_rva': '0x1e326a80', 'initialized_byte_rva': '0x1e3267ac',
            'block_pointer_array_offset': 8, 'block_pointer_slots': 8192, 'block_bytes': 0x80000,
            'entry_header_u16_offset': 0, 'entry_payload_offset': 2, 'length_units': 'header >> 6',
            'is_wide': '(header & 1) != 0', 'max_header_length_units': 1023,
            'other_low_header_bits': 'unknown; native string helper does not branch on them',
            'current_block_and_cursor_offsets': None},
        'characters': {'narrow': 'len%9 key, XOR all copied bytes only when first raw byte !=0',
            'wide': 'len%9 16bit key, XOR unit indexes 0,2,4,... only when first raw unit !=0',
            'case5_difference': 'narrow: 3*(len-0x29); wide: 3*len+0x85; then mask and OR0x7f',
            'zero_number_narrow_high_bytes': 'replaced with U+003F by d60360; caller explicit replacement0x3f',
            'nonzero_number_narrow_high_bytes': 'sign-extended byte to UTF16 unit by 10b5bde0',
            'number_suffix': "if number!=0, '_' plus signed-int32 decimal of number-1",
            'digits_rva': '0x1aad7c58', 'digits_bytes_sha256': sha(digits)},
        'module': {'relative_path': 'work/native_metadata_names.py',
            'sha256': sha((ROOT / 'work/native_metadata_names.py').read_bytes()),
            'api': ['resolve_name(read_exact,module_base,token8,*,with_number=True)',
                    'object_name(read_exact,module_base,address,*,field_representation=None)'],
            'returns': 'ResolvedName(base_text,entry_id,number,is_wide,display_text)',
            'max_callback_reads_resolve': 6, 'max_callback_reads_object_name': 7,
            'strict_local_policies': ['init must be exact1', 'empty/NUL/malformedUTF16 rejected',
                'block index<8192 and entire payload within0x80000', 'pointer/header post-read stability'],
            'full_object_path': 'not implemented; no outer traversal or property schema inferred'},
        'test': {'relative_path': 'work/test_native_metadata_names.py',
            'sha256': sha((ROOT / 'work/test_native_metadata_names.py').read_bytes()),
            'passed': 14, 'fixture_policy': 'explicit independent byte literals; no encoder roundtrips'}}
    out = ROOT / 'work/evidence/native-metadata-name-resolver.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'evidence': out.name, 'sha256': sha(out.read_bytes()),
                     'complete_sources': len(verified), 'anchors': len(anchors),
                     'module_sha256': result['module']['sha256']}))

if __name__ == '__main__':
    main()
