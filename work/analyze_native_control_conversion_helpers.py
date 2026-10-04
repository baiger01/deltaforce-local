"""Offline exact instruction audit of three fixed, saved field continuations."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

import capstone
from capstone.x86 import X86_OP_IMM
import read_native_control_continuations as scope

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT/'work/native-client-tests/1790883169018138400/ds-native-control-code/continuations'
REPORT_SHA = '505520dd30a0f8234075b7ce29708467a41ade902027d2711b2092c6677a3964'
OUTPUT = ROOT/'work/evidence/native-control-conversion-helpers-semantics.json'
SAMPLES = (
    (0x10b4b540, 87, '38429d4d0fdbfa5a87ddd45c6392d0ecabcda686ed986ff80ec2c73b87e5abca',
     '7b3683de1f5e53f9f6f774d1e25f8d21f8842980d7ef412c6fd8d4e9062ba7b8'),
    (0xd60360, 164, 'fa9e5381d1118bd7c38be385edeaf5140a2406044b6db9b69599e9b71708101e',
     '34b396f022a4c26a0179bf334620b5b8c4493027d6f62dd4fb27ad677ff1c792'),
    (0xd92e70, 212, 'ee9a6dd31618cc831363ec0d2cffe0243d56fa3d4a9c6335d63cf72080e896ed',
     '2742121e697f1978fb6e30d99b8ab4eda6e23d5a91c0d905ce020ec8f05cbfa8'),
)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def decode(code, rva):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, rva))
    cursor = rva
    for ins in instructions:
        if ins.address != cursor:
            raise ValueError('Noncontiguous saved instruction decode')
        cursor += ins.size
    if cursor != rva+len(code):
        raise ValueError('Saved code does not completely decode')
    return instructions


def rows(instructions, begin, end):
    return [{'rva': hex(i.address), 'bytes_hex': bytes(i.bytes).hex(),
             'mnemonic': i.mnemonic, 'operands': i.op_str}
            for i in instructions if begin <= i.address < end]


def assert_ins(instructions, rva, mnemonic, operands):
    ins = next((i for i in instructions if i.address == rva), None)
    if ins is None or (ins.mnemonic, ins.op_str) != (mnemonic, operands):
        raise ValueError('Fixed semantic instruction witness mismatch')
    return ins


def saved_sample(report, spec):
    rva, length, code_hash, file_hash = spec
    label = 'unknown_control_continuation_'+format(rva, 'x')
    records = [v for v in report['functions'] if v.get('name') == label]
    if len(records) != 1:
        raise ValueError('Saved continuation report count mismatch')
    row = records[0]
    if (row.get('rva') != hex(rva) or row.get('code_bytes') != length or
            row.get('read_succeeded') is not True or row.get('code_sha256') != code_hash or
            row.get('file_sha256') != file_hash or row.get('disassembled_bytes') != length or
            row.get('full_linear_decode') is not True):
        raise ValueError('Saved continuation report identity mismatch')
    path = FOLDER/(label+'.dfcode')
    if path.stat().st_size != length+32:
        raise ValueError('Saved continuation length mismatch')
    with path.open('rb') as stream:
        sample = stream.read(length+33)
    if len(sample) != length+32 or sha(sample) != file_hash:
        raise ValueError('Saved continuation file SHA mismatch')
    magic, at, size, _private_module_base = struct.unpack('<4Q', sample[:32])
    code = sample[32:]
    if magic != scope.MAGIC or (at, size) != (rva, length) or sha(code) != code_hash:
        raise ValueError('Saved continuation header/code SHA mismatch')
    instructions = decode(code, rva)
    asm = (FOLDER/(label+'.asm.txt')).read_bytes()
    expected = ('\n'.join(f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in instructions)+'\n').encode()
    if asm.replace(b'\r\n', b'\n') != expected:
        raise ValueError('Saved assembly differs from independently decoded sample')
    return instructions, {'sample_relative_path': path.relative_to(ROOT).as_posix(),
        'rva': hex(rva), 'code_bytes': length, 'file_sha256': file_hash,
        'code_sha256': code_hash, 'asm_sha256': sha(asm), 'instruction_count': len(instructions),
        'header_full_file_payload_SHA_and_complete_decode_verified': True,
        'saved_asm_matches_independent_decode': True}


def run(game_root):
    report = scope.sealed_json(FOLDER/'result.json', REPORT_SHA)
    plan = scope.build_plan(game_root)  # Immutable disk validation only; no process APIs.
    if (report.get('client_sha256') != scope.SOURCE_SHA or
            report.get('status') != 'bounded_read_attempt_complete' or
            report.get('actual_code_bytes') != 2346 or report.get('offline_plan') != plan or
            len(report.get('functions', [])) != 4):
        raise ValueError('Saved continuation report/plan identity mismatch')
    decoded, proofs = {}, []
    for spec, root in zip(SAMPLES, plan['continuation_roots'][:3]):
        instructions, proof = saved_sample(report, spec)
        if next(v for v in report['functions'] if v['rva'] == hex(spec[0])).get('source_evidence') != root:
            raise ValueError('Saved continuation exact root source-evidence mismatch')
        proof['immutable_span'] = root['immutable_span']
        proof['source_direct_call_evidence'] = root['source_e8_calls']
        decoded[spec[0]] = instructions
        proofs.append(proof)
    scalar, narrow, wide = (decoded[x[0]] for x in SAMPLES)
    witnesses = (
        (scalar, 0x10b4b54a, 'test', 'byte ptr [rcx + 0x28], 1'),
        (scalar, 0x10b4b554, 'mov', 'r8d, 4'),
        (scalar, 0x10b4b55f, 'call', 'qword ptr [rax + 0x60]'),
        (scalar, 0x10b4b564, 'bswap', 'eax'),
        (scalar, 0x10b4b57d, 'bswap', 'eax'),
        (narrow, 0xd6037f, 'cmovle', 'r11d, edx'),
        (narrow, 0xd603a0, 'movsx', 'ecx, byte ptr [r8 + rdx]'),
        (narrow, 0xd603a5, 'mov', 'word ptr [rdi + rdx*2], cx'),
        (narrow, 0xd603c4, 'cmp', 'byte ptr [rcx + r8], 0'),
        (narrow, 0xd603cb, 'mov', 'word ptr [rdi + rcx*2], r9w'),
        (wide, 0xd92eb0, 'movsx', 'edx, word ptr [r8 + rcx*2]'),
        (wide, 0xd92eb5, 'movsx', 'eax, dl'),
        (wide, 0xd92ebb, 'cmp', 'ax, dx'),
        (wide, 0xd92ec0, 'test', 'dl, dl'),
        (wide, 0xd92f04, 'mov', 'byte ptr [rcx + rdi], r9b'),
    )
    for value in witnesses:
        assert_ins(*value)
    # The fifth stack argument is explicitly '?', not an inferred code page.
    fixed = scope.sealed_json(scope.FIXED_PLAN, scope.FIXED_PLAN_SHA)
    source_row = fixed['sources'][0]
    source = (ROOT/source_row['path']).read_bytes()
    scope.validate_source(source, source_row, scope.SOURCE_SPECS[0])
    caller = decode(source[32:], scope.SOURCE_SPECS[0][0])
    assert_ins(caller, 0x109ea696, 'mov', 'word ptr [rsp + 0x20], 0x3f')
    assert_ins(caller, 0x109ea69d, 'call', '0xd60360')
    assert_ins(caller, 0x109ea7e2, 'mov', 'byte ptr [rsp + 0x20], 0x3f')
    assert_ins(caller, 0x109ea7fa, 'call', '0xd92e70')
    rules = [
        {'id': 'scalar_loading_swap', 'statement': 'When archive+0x28 mask1 is set, serialize exactly 4 bytes into original scalar, then bswap32 in place; return archive. There is no explicit error/result guard before bswap; insufficient-input behavior belongs to the unanalysed virtual serializer and caller.',
         'instructions': rows(scalar, 0x10b4b54a, 0x10b4b576)},
        {'id': 'scalar_saving_swap', 'statement': 'When archive+0x28 mask1 is clear, bswap32 a temporary copy, serialize exactly 4 bytes from that temporary, leave original scalar unchanged; return archive.',
         'instructions': rows(scalar, 0x10b4b576, 0x10b4b597)},
        {'id': 'narrow_counted_conversion', 'statement': 'Signed32 min(destination capacity EDx, source count R9d) is copied. Explicit count controls the loop; NUL bytes do not terminate it.',
         'instructions': rows(narrow, 0xd60374, 0xd603b7)},
        {'id': 'narrow_high_byte_replacement', 'statement': 'First pass sign-extends each source byte to 16 bits. If any source byte has its sign bit set, second pass overwrites every 0x80..0xff position with 16-bit fifth argument; 0x00..0x7f remain equal code units. Thus this is ASCII plus replacement, not Latin1, UTF8, or a system code page.',
         'instructions': rows(narrow, 0xd603a0, 0xd603d8)},
        {'id': 'narrow_return_and_unknown_callback', 'statement': 'On replacement branch call109fe1c0 receives original source and copied count; no result is tested, and this helper has no archive pointer or archive error write. Callback side effects are not established. Return NULL if signed capacity < signed source count, else destination+copied_count*2.',
         'instructions': rows(narrow, 0xd603d8, 0xd603ef)},
        {'id': 'wide_counted_conversion', 'statement': 'Signed32 min(destination capacity EDx, source count R9d) controls the entire copy. Each source is a 16-bit code unit, not a Unicode scalar; NUL code units do not stop the loop.',
         'instructions': rows(wide, 0xd92e8a, 0xd92ead)},
        {'id': 'wide_ascii_only', 'statement': 'A unit is valid only when it equals sign-extended low byte AND low byte is nonnegative: exactly 0x0000..0x007f. All other units, including 0x0080,0x00e9,0xff80,0xffff and surrogate units, are replaced by byte fifth argument.',
         'instructions': rows(wide, 0xd92eb0, 0xd92f10)},
        {'id': 'wide_return_and_unknown_callback', 'statement': 'Replacement branch calls109fdff0 with original source and copied count; result is ignored. No archive error write exists in this helper. Callback side effects remain unknown. Return NULL on signed capacity<count, else destination+copied_count.',
         'instructions': rows(wide, 0xd92f10, 0xd92f44)},
        {'id': 'string_caller_replacement_constant', 'statement': 'Saved109ea340 passes fifth argument003f for narrow-to-wide, and3f for wide-to-narrow; return pointers from conversions are not tested in these shown caller continuations.',
         'instructions': rows(caller, 0x109ea67f, 0x109ea6a6)+rows(caller, 0x109ea7dd, 0x109ea810)},
        {'id': 'string_header_swap_scope', 'statement': '109ea340 fallback integer serialization selects10b4b540 when archive+0x29 mask20 is set. It also contains a direct buffer-cache fast load before that fallback; this audit does not establish the cache/flag coexistence invariant. Memory flags and offsets are not network wire bits.',
         'instructions': rows(caller, 0x109ea37a, 0x109ea3bc)+rows(caller, 0x109ea8cb, 0x109ea8ec)},
    ]
    optional = []
    executable = Path(game_root)/scope.EXECUTABLE_RELATIVE
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = scope.Image(raw)
        for instructions, call_rva, target in ((narrow, 0xd603de, 0x109fe1c0), (wide, 0xd92f16, 0x109fdff0)):
            ins = assert_ins(instructions, call_rva, 'call', hex(target))
            if (ins.size != 5 or ins.bytes[0] != 0xe8 or ins.operands[0].type != X86_OP_IMM or
                    call_rva+5+struct.unpack('<i', ins.bytes[1:])[0] != target):
                raise ValueError('Optional conversion callback E8 evidence mismatch')
            root, length, fragments = image.function_span(target)
            optional.append({'call_rva': hex(call_rva), 'call_bytes_hex': bytes(ins.bytes).hex(),
                'target_rva': hex(target), 'source_code_sha256': proofs[1 if target == 0x109fe1c0 else 2]['code_sha256'],
                'immutable_root': list(map(hex, root)), 'complete_code_bytes': length,
                'fragments': [[hex(a), hex(b)] for a, b in fragments],
                'identity_and_callback_side_effects_verified': False, 'new_collection_requested': False})
    result = {'kind': 'native_control_conversion_exact_instruction_audit',
        'client_sha256': scope.SOURCE_SHA, 'report_sha256': REPORT_SHA,
        'sealed_source_plan_sha256': scope.FIXED_PLAN_SHA, 'samples': proofs,
        'string_caller_file_sha256': source_row['file_sha256'],
        'string_caller_code_sha256': source_row['code_sha256'], 'rules': rules,
        'codec_suggestions': {
            'narrow_decode': 'After existing forced last-byte NUL logic, widen b<=0x7f as b, else0x003f. Preserve interior NUL. Never call latin1/utf8 decoding for this native narrow profile.',
            'narrow_write_converter': 'For an explicitly selected narrow branch, encode units<=0x7f as bytes, otherwise3f. Keep default FString writer choosing UTF16 for nonASCII according to prior109ea340 evidence.',
            'integer_swap': 'Add explicit swap-enabled scalar32 helper semantics: 32-bit bit pattern uses big-endian wire bytes on x86 through this fallback; parse as signed for string count. Loading mutates original scalar, saving uses a temporary. Do not claim packet-wide endian/version.',
            'local_validation': 'Negative capacities/counts and size caps may be rejected by the local codec; these are local interface limits, not constraints proved by conversion native helper. Conversion callbacks remain external unknown behavior.',
        },
        'literal_vectors_derived_from_instructions': [
            {'kind': 'narrow_to_wide', 'source_hex': '00417f80e9ff', 'capacity': 6, 'count': 6,
             'replacement_unit': '0x3f', 'output_units': ['0x0','0x41','0x7f','0x3f','0x3f','0x3f'],
             'return_offset_bytes': 12, 'replacement_callback_invoked': True},
            {'kind': 'wide_to_narrow', 'source_units': ['0x0','0x41','0x7f','0x80','0xe9','0xff80','0xffff','0xd800'],
             'capacity': 8, 'count': 8, 'replacement_byte': '0x3f', 'output_hex': '00417f3f3f3f3f3f',
             'return_offset_bytes': 8, 'replacement_callback_invoked': True},
            {'kind': 'narrow_to_wide_truncated', 'source_hex': '00417f80e9ff', 'capacity': 4, 'count': 6,
             'output_units': ['0x0','0x41','0x7f','0x3f'], 'return_pointer_is_null': True},
            {'kind': 'scalar32_swapped', 'signed_value': -4, 'host_little_endian_hex': 'fcffffff',
             'serialized_hex': 'fffffffc', 'saving_original_value_unchanged': True},
        ],
        'optional_unknown_callback_source_proofs': optional,
        'process_memory_read': False, 'game_launched': False, 'elevation_requested': False,
        'server_modified': False, 'native_control_protocol_complete': False, 'playable_map_verified': False}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.game_root)
    print('Offline audit verified 3 full samples, 143 instructions, 10 exact semantic rules; no process access.')
    print('Evidence SHA256: '+sha(OUTPUT.read_bytes()))
