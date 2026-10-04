"""Seal exact saved-code Outer/path evidence; disk-only, no native calls."""
import hashlib
import json
import mmap
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
from offline_metadata_name_trace import CACHE, MANIFEST
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha
import offline_native_code_cache as cache

SOURCES = {
    'native-metadata-object-path-helpers.json': '2142d92663366b2c2078ab6f3311af00a80bd9a57d922d1b07dfdfc3de176222',
    'native-metadata-object-path-package-class.json': '8892c878449afc96a22db480dec99313d9875b345677840ffdb64772fdcc27f3',
    'native-metadata-name-roots.json': '7d70b4fab5afacaf7dad154cdd5a220e95c841a8c9e5f1f7a6bf89cfe3a7886f',
}
WANTED = {0x10ead090, 0x10ead1e0, 0x10e564e0, 0x10eac970}
ANCHORS = {
    0x10ead0c8: ('mov', 'rbx, qword ptr [rcx + 0x10]', 'Outer field'),
    0x10ead0e1: ('mov', 'rcx, rbx', 'Outer is recursive receiver'),
    0x10ead0e7: ('call', '0x10ead1e0', 'Outer path recursion'),
    0x10ead0f1: ('cmp', 'qword ptr [rbx + 8], rax', 'Outer Class compared with Package singleton'),
    0x10ead0fc: ('mov', 'rcx, qword ptr [rbx + 0x10]', 'Outer.Outer field'),
    0x10ead100: ('cmp', 'qword ptr [rcx + 8], rax', 'Outer.Outer Class compared with Package singleton'),
    0x10ead136: ('mov', 'word ptr [rax + rbx*2], 0x3a', 'colon separator branch'),
    0x10ead16e: ('mov', 'word ptr [rax + rbx*2], 0x2e', 'dot separator branch'),
    0x10ead182: ('mov', 'rax, qword ptr [rsi + 0x1c]', 'object Name token'),
    0x10ead193: ('call', '0x10b5bec0', 'append Name token'),
    0x10ead207: ('mov', 'rbx, qword ptr [rcx + 0x10]', 'recursive Outer field'),
    0x10ead21d: ('mov', 'rcx, rbx', 'Outer receiver'),
    0x10ead225: ('call', '0x10ead1e0', 'self recursion'),
    0x10ead22f: ('cmp', 'qword ptr [rbx + 8], rax', 'recursive Outer Class test'),
    0x10ead23a: ('mov', 'rcx, qword ptr [rbx + 0x10]', 'recursive Outer.Outer field'),
    0x10ead23e: ('cmp', 'qword ptr [rcx + 8], rax', 'recursive Outer.Outer Class test'),
    0x10ead276: ('mov', 'word ptr [rax + rbx*2], 0x3a', 'recursive colon branch'),
    0x10ead2b0: ('mov', 'word ptr [rax + rbx*2], 0x2e', 'recursive dot branch'),
    0x10ead2c9: ('mov', 'rax, qword ptr [rsi + 0x1c]', 'recursive object Name token'),
    0x10ead2da: ('call', '0x10b5bec0', 'recursive append Name token'),
    0x10eac9ae: ('mov', 'rax, qword ptr [rsi + 8]', 'class pointer in full-name formatter'),
    0x10eaca5a: ('mov', 'rbx, qword ptr [rsi + 0x10]', 'same Outer field in full-name formatter'),
    0x10eaca76: ('mov', 'rcx, rbx', 'full-name Outer receiver'),
    0x10eaca79: ('call', '0x10ead1e0', 'full-name formatter calls same path helper'),
    0x10eacb19: ('mov', 'rax, qword ptr [rsi + 0x1c]', 'same object Name token in full-name formatter'),
}
RIP_TARGETS = {0x10e564ea: 0x1e34ca90, 0x10e56509: 0x1e34ca90,
               0x10e5651b: 0x1ab59122, 0x10e56526: 0x15a850a8,
               0x10e56584: 0x1e34ca90, 0x10ead1b6: 0x14ec37c8,
               0x10ead2f5: 0x14ec37c8}
LITERALS = {
    0x1ab59122: (16, 'f9428836a110a71b8894d663394a83c134781c3485109e26f32e4a8f31ea9edf', 'Package'),
    0x15a850a8: (40, '6b715e6bf695b36f81749550308ae98794be898c5ff686da58e47d4bf237a185', '/Script/CoreUObject'),
    0x14ec37c8: (10, '89762610bdb9fd53bd5c3bedb0a98ffa83bce46d94bb3f50a40d0cce7addb291', 'None'),
}


def main():
    folder, manifest, pin = cache.validate_manifest(CACHE, MANIFEST)
    if not manifest['complete']:
        raise ValueError('Saved code cache must be complete')
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Immutable Shipping SHA changed')
    result = dict(kind='source_proven_metadata_outer_paths', client_sha256=SOURCE_SHA,
        cache_manifest_sha256=pin, process_accessed=False, game_launched=False,
        native_called=False, runtime_class_paths_recovered=False, sources=[],
        roots=[], instructions=[], immutable_literals=[], rip_references=[])
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    all_instructions = {}
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = ImmutableImage(raw)
        for filename, expected in SOURCES.items():
            path = ROOT / 'work/evidence' / filename
            content = path.read_bytes()
            if sha(content) != expected:
                raise ValueError('Source report SHA changed: ' + filename)
            report = json.loads(content)
            if report['client_sha256'] != SOURCE_SHA:
                raise ValueError('Source Shipping qualification changed')
            result['sources'].append(dict(relative_path=path.relative_to(ROOT).as_posix(), sha256=expected))
            for row in report['roots']:
                begin = int(row['begin'], 16)
                if begin not in WANTED:
                    continue
                amount = row['bytes']
                binary = (ROOT / row['code_relative_path']).read_bytes()
                code = binary[32:]
                if len(code) != amount or sha(binary) != row['file_sha256'] or sha(code) != row['code_sha256']:
                    raise ValueError('Source code SHA/length changed')
                if struct.unpack('<4sIQQQ', binary[:32]) != (b'DCDE', 1, begin, amount, image.image_base):
                    raise ValueError('Saved code header changed')
                asm = (ROOT / row['asm_relative_path']).read_bytes()
                if sha(asm) != row['asm_sha256'] or validated_range(folder, begin, amount, pin) != code:
                    raise ValueError('Source asm/cache changed')
                fragments = row.get('fragments', [row])
                cursor = begin
                for fragment in fragments:
                    actual = image.containing(int(fragment['begin'], 16))
                    if actual is None or actual[0] != cursor:
                        raise ValueError('Fragment is not exact contiguous pdata')
                    metadata = image.unwind(actual)
                    if any(metadata[key] != fragment[key] for key in metadata):
                        raise ValueError('Immutable unwind metadata changed')
                    cursor = actual[1]
                if cursor != begin + amount:
                    raise ValueError('Incomplete root fragment coverage')
                instructions = list(decoder.disasm(code, begin))
                if sum(item.size for item in instructions) != amount:
                    raise ValueError('Source root did not fully decode')
                regenerated_asm = ('\n'.join(f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in instructions) + '\n').encode()
                if asm != regenerated_asm:
                    raise ValueError('Asm source does not match current decoder')
                all_instructions.update({item.address: item for item in instructions})
                result['roots'].append(dict(begin=row['begin'], bytes=amount, fragments=fragments,
                    code_relative_path=row['code_relative_path'], code_sha256=row['code_sha256'],
                    file_sha256=row['file_sha256'], asm_sha256=row['asm_sha256'], full_decode=True))
        if {int(row['begin'], 16) for row in result['roots']} != WANTED:
            raise ValueError('Missing fixed root')
        for address, (mnemonic, operands, meaning) in ANCHORS.items():
            ins = all_instructions[address]
            if (ins.mnemonic, ins.op_str) != (mnemonic, operands):
                raise ValueError('Exact instruction anchor changed')
            result['instructions'].append(dict(rva=hex(address), bytes_hex=bytes(ins.bytes).hex(),
                instruction=f'{ins.mnemonic} {ins.op_str}', meaning=meaning))
        for address, target in RIP_TARGETS.items():
            ins = all_instructions[address]
            found = [ins.address + ins.size + op.mem.disp for op in ins.operands
                     if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
            if found != [target]:
                raise ValueError('Exact RIP target changed')
            result['rip_references'].append(dict(instruction_rva=hex(address), target_rva=hex(target),
                bytes_hex=bytes(ins.bytes).hex(), instruction=f'{ins.mnemonic} {ins.op_str}'))
        for rva, (size, expected, label) in LITERALS.items():
            data = image.read(rva, size)
            if sha(data) != expected or data.decode('utf-16-le') != label + '\0':
                raise ValueError('Immutable path-role literal changed')
            result['immutable_literals'].append(dict(rva=hex(rva), bytes=size, sha256=expected, utf16=label))
    result['layout'] = dict(outer_offset='0x10', class_offset='0x8', name_token_offset='0x1c',
        package_class_global_rva='0x1e34ca90', null_receiver_literal='None',
        separator='colon only when Outer.Class!=PackageClass and Outer.Outer.Class==PackageClass; otherwise dot',
        root_order='outermost name first, then separators and descendant names',
        name_resolver_source='work/evidence/native-metadata-name-resolver.json')
    result['local_reader_restrictions'] = dict(caller_selected_class_metadata_only=True,
        max_nodes=32, registry_identity_each_node=True, package_name_exact='Package',
        serial_zero_allowed=True, native_call=False, end_identity_and_fields_rechecked=True,
        cycle_or_changed_or_unavailable_rejected=True,
        nonpackage_outer_missing_its_parent_rejected=True,
        no_actual_class_path_or_netguid_is_invented=True)
    cache.validate_manifest(folder, pin)
    output = ROOT / 'work/evidence/native-metadata-object-path-resolver.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(evidence=output.name, sha256=sha(output.read_bytes()),
        fixed_roots=len(result['roots']), instructions=len(ANCHORS), literals=len(LITERALS))))


if __name__ == '__main__':
    main()
