"""Disk-only exact instruction evidence for the captured 109ea340 serializer."""
import hashlib
import json
import mmap
from pathlib import Path
import struct

import analyze_control_candidate_interval as audit
import plan_native_control_field_helpers as metadata

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT/'work/native-client-tests/1790875160889006700/ds-native-control-code'
SOURCE = FOLDER/'unknown_control_field_109ea340.dfcode'
RVA, LENGTH = 0x109ea340, 1679
FILE_SHA = '1f2746e42afcba80170572265706c823ea15d7068355174412b3346d2faaa6f8'
CODE_SHA = 'ac7168027c0f6346062fe45c773b71bed613431c3d6a01c4415278e7726adf19'
OUTPUT = ROOT/'work/evidence/native-string-field-109ea340-semantics.json'
RULES = (
    ('mode', 'archive+0x28 bit 0 selects the loading branch; otherwise memory-count and non-loading serialization branch. Memory field offsets are not wire bit offsets.', [(0x109ea36a,0x109ea37a),(0x109ea6dd,0x109ea705)]),
    ('signed_count', 'Loading first obtains four bytes into a signed int32. Fast cursor reads dword and advances four; fallback invokes virtual+0x60 with four bytes, or direct 10b4b540 when archive+0x29 bit0x20 is set. Default direct x64 load is little endian; swapped fallback helper semantics remain uncollected.', [(0x109ea37a,0x109ea3cf)]),
    ('negative_and_intmin', 'Negative count selects the two-byte-unit branch. INT32_MIN is rejected before negation, setting both archive+0x29 bits0x01 and0x02. Other negative counts are negated for the payload unit count.', [(0x109ea3bc,0x109ea426)]),
    ('max_units', 'A positive signed int64 at archive+0x38 bounds the absolute serialized unit count, including terminator. A value <=0 disables this particular limit. Exceeding it sets bits0x01|0x02 and exits before string allocation; limit measures units, not payload bytes.', [(0x109ea426,0x109ea487)]),
    ('allocation_zero', 'Calls d67c30 on destination, then adds absolute count to destination+8 and grows if above destination+0xc. Zero count exits without payload. Exact array-reset internals of d67c30 are not included in this sample.', [(0x109ea487,0x109ea4c9)]),
    ('unicode_payload', 'Negative length loads count*2 bytes through archive virtual+0x60. No UTF8 decoding or surrogate validation occurs in this body.', [(0x109ea4c9,0x109ea4e6)]),
    ('unicode_swap', 'When archive+0x29 bit0x20 is set, all count 16-bit units are byte-rotated by8 after loading. This is a directly proved payload swap, independent of the uncollected scalar-header helper.', [(0x109ea4e6,0x109ea519)]),
    ('unicode_tail_nul', 'After payload and optional swapping, destination[count-1] is overwritten with a zero 16-bit unit. Unterminated input is normalized rather than rejected here.', [(0x109ea519,0x109ea53f)]),
    ('unicode_ffff', 'Scans allocated units for the first 0xffff. If found, replaces that unit with0 and recomputes a prefix length by scanning the first NUL. The new array count is prefix+1 for nonempty prefix or0 for empty; removes the rest. With no0xffff this special trimming path does not run, even if another embedded NUL exists.', [(0x109ea53f,0x109ea604)]),
    ('ansi_read', 'Positive length loads count bytes to a temporary byte buffer and overwrites byte[count-1] with0. Calls d60360 with destination16-bit buffer, destination count, byte source, source count and 0x003f replacement parameter. Exact non-ASCII byte mapping is delegated and remains unverified.', [(0x109ea604,0x109ea6c3)]),
    ('one_unit_empty', 'Absolute count1 reaches a d67c30(destination,0) call after payload processing. A one-unit payload is therefore NUL-only after tail normalization. Count0 consumes no payload.', [(0x109ea6c3,0x109ea6dd)]),
    ('save_encoding_choice', 'Non-loading path calls archive virtual+0x88 with destination Num*2/Max*2. Archive+0x28 bit0x40 forces the wide branch. Otherwise scans 16-bit units only until the first NUL: any encountered unit>0x7f selects wide; all visited units<=0x7f select narrow.', [(0x109ea6dd,0x109ea739)]),
    ('ansi_save_count', 'Narrow branch uses destination+8 Num as positive count. Header serialization uses the same cursor/fallback pattern: notably the fast cursor path reads a dword rather than storing it. Ordinary writer semantics require archive virtual+0x60 to provide the writer fallback.', [(0x109ea739,0x109ea78a)]),
    ('ansi_save_payload', 'If count is nonzero, temporary conversion calls d92e70 with a 16-bit source, count-sized byte destination, source/destination counts, and 0x3f default byte. Then archive virtual+0x60 serializes exactly the original positive count bytes. Non-ASCII conversion internals remain unknown.', [(0x109ea78a,0x109ea849)]),
    ('unicode_save_count', 'For a conventional NUL-terminated 16-bit array with Num=N>0, computes content units N-1 then adds one terminator, serializing signed -N. Forced-wide empty array uses the verified static NUL literal, resulting in count-1 and one two-byte NUL. Nonconventional unterminated source-array paths are retained as native internal behavior, not accepted backend input.', [(0x109ea849,0x109ea8fd)]),
    ('unicode_save_payload', 'Wide branch serializes count*2 bytes. No-swap uses original buffer. Swap branch copies to temporary and byte-rotates every 16-bit unit before archive virtual+0x60. The payload includes the terminating unit for conventional input.', [(0x109ea8fd,0x109ea9a5)]),
    ('errors_and_return', 'This routine returns the original archive receiver. Length violations set two error bits directly; header/payload shortage handling and cursor bounds errors are delegated to archive Serialize/10b4b540, not independently implemented here.', [(0x109ea9a5,0x109ea9cf)]),
)


def run():
    result = audit.load_json(FOLDER/'result.json')
    row = next(x for x in result['functions'] if x['name'] == SOURCE.stem)
    if (result.get('client_sha256') != audit.IMAGE_SHA or row.get('read_succeeded') is not True or
            row.get('rva') != hex(RVA) or row.get('code_bytes') != LENGTH or
            row.get('file_sha256') != FILE_SHA or row.get('code_sha256') != CODE_SHA or
            row.get('disassembled_bytes') != LENGTH):
        raise ValueError('Native string source/report identity mismatch')
    code, file_sha = audit.dfcode(SOURCE, RVA, LENGTH, FILE_SHA, CODE_SHA)
    decoder = audit.capstone.Cs(audit.capstone.CS_ARCH_X86,audit.capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code,RVA))
    if sum(x.size for x in instructions) != LENGTH or instructions[-1].address+instructions[-1].size != RVA+LENGTH:
        raise ValueError('Native string implementation decode is incomplete')
    expected_asm = '\n'.join(f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in instructions)+'\n'
    asm = SOURCE.with_suffix('.asm.txt')
    if asm.read_text(encoding='utf-8') != expected_asm:
        raise ValueError('Saved asm differs from independent dfcode disassembly')
    by_rva = {x.address:x for x in instructions}
    def record(ins):
        return {'rva':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex(),
                'mnemonic':ins.mnemonic,'operands':ins.op_str}
    rules = []
    for name, meaning, ranges in RULES:
        evidence = []
        for first,last in ranges:
            if first not in by_rva or not (last in by_rva or last == RVA+LENGTH):
                raise ValueError('Rule range is not on verified instruction boundaries')
            evidence.extend(record(i) for i in instructions if first<=i.address<last)
        rules.append({'rule':name,'semantics':meaning,'instruction_ranges':[[hex(x),hex(y)] for x,y in ranges],
                      'exact_instructions':evidence})
    executable = Path('D:/三角洲/WeGameApps/rail_apps/DeltaForce(2001918)')/audit.EXE_RELATIVE
    with executable.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw:
        if audit.sha(raw) != audit.IMAGE_SHA:
            raise ValueError('Immutable Shipping version hash mismatch')
        image = audit.Image(raw)
        span = metadata.function_span(image,RVA)
        if span['root'] != ['0x109ea340','0x109ea9cf','0x1bdd77ec'] or span['code_bytes'] != LENGTH:
            raise ValueError('Complete saved implementation and immutable root differ')
        logs = []
        for address,literal in ((0x109ea3f1,'Archive is corrupted'),
                                (0x109ea454,'String is too large (Size: %i, Max: %i)')):
            ins = by_rva[address]
            target = ins.address+ins.size+ins.operands[1].mem.disp
            value = literal.encode('utf-16le')+b'\0\0'
            if image.data(target,len(value)) != value:
                raise ValueError('Serializer immutable error log differs')
            logs.append({'instruction':record(ins),'literal_rva':hex(target),'literal':literal,
                         'literal_bytes_sha256':audit.sha(value)})
        ins = by_rva[0x109ea6f8]
        empty_rva = ins.address+ins.size+ins.operands[1].mem.disp
        if image.data(empty_rva,2) != b'\0\0':
            raise ValueError('Forced-wide empty source is not a UTF16 NUL')
        lower = []
        for target,role,required in ((0x10b4b540,'bit0x20 scalar-header serialization helper; swap internals unverified',True),
                                     (0xd60360,'byte-to-16bit-unit conversion; non-ASCII mapping unverified',True),
                                     (0xd92e70,'16bit-unit-to-byte conversion; fallback mapping unverified',True),
                                     (0xd67c30,'destination array reset/empty candidate; object metadata effects unverified',False)):
            calls = []
            for ins in instructions:
                if (ins.mnemonic=='call' and ins.size==5 and ins.bytes[0]==0xe8 and
                        ins.operands[0].type==audit.X86_OP_IMM and ins.operands[0].imm==target):
                    if ins.address+5+struct.unpack('<i',ins.bytes[1:])[0] != target:
                        raise ValueError('Lower-helper exact E8 mismatch')
                    calls.append(record(ins))
            if not calls:
                raise ValueError('Lower-helper has no exact saved direct source call')
            lower.append({'target_rva':hex(target),'role_supported_by_call_dataflow':role,
                          'required_to_complete_external_conversion_or_scalar_swap_semantics':required,
                          'exact_source_e8_calls':calls,'immutable_span':metadata.function_span(image,target),
                          'runtime_sample_not_collected_by_this_analysis':True,
                          'formal_signature_or_method_name_verified':False})
    return {'kind':'native_string_field_serializer_exact_instruction_audit',
        'client_sha256':audit.IMAGE_SHA,'source_sample_relative_path':SOURCE.relative_to(ROOT).as_posix(),
        'source_report_sha256':audit.sha((FOLDER/'result.json').read_bytes()),
        'source_file_sha256':file_sha,'source_code_sha256':CODE_SHA,
        'source_asm_sha256':audit.sha(asm.read_bytes()),'rva':hex(RVA),'payload_bytes':LENGTH,
        'independent_instruction_count':len(instructions),'full_decode_verified':True,
        'report_header_and_sha_verified':True,'immutable_complete_function':span,
        'process_access':False,'game_launched':False,'elevation_requested':False,
        'reader_runner_wrapper_modified':False,'server_modified':False,
        'raw_cookie_or_aslr_exported':False,'rules':rules,'immutable_error_logs':logs,
        'forced_wide_empty_literal_rva':hex(empty_rva),'forced_wide_empty_literal_verified':True,
        'lower_helpers_fixed_source_proof':lower,
        'minimum_canonical_no_swap_wire_profile':{
            'count':'signed little-endian int32, includes terminator; unit count, not codepoint count',
            'zero':'00000000, no payload',
            'positive':'count bytes including final byte normalized to NUL; ASCII subset mapping is the minimal profile',
            'negative':'abs(count) uint16 units, each two little-endian bytes, final unit normalized to NUL',
            'ascii_example_abc_hex':'0400000061626300',
            'unicode_example_daba_hex':'fdffffff27595d570000',
            'forced_wide_empty_hex':'ffffffff0000',
            'examples_are_derived_expected_bytes_not_observed_packets':True},
        'known_gaps':['Exact scalar byte-swap/header fallback behavior requires the87-byte10b4b540 body.',
            'Non-ASCII narrow-byte conversion/replacement behavior requires d60360 and d92e70 bodies.',
            'Archive virtual Serialize truncation/error propagation and fast-cursor eligibility are upstream behaviors.',
            'Native Num/reset/shrink helpers are not part of the proved wire field itself.'],
        'new_plan_scope_only':{'mandatory_helper_reads':3,'mandatory_helper_bytes':sum(x['immutable_span']['code_bytes'] for x in lower if x['required_to_complete_external_conversion_or_scalar_swap_semantics']),
                               'optional_empty_metadata_helper_bytes':54,'maximum_function_bytes':8192,'maximum_fragments':32},
        'complete_external_conversion_and_header_swap_semantics_verified':False,
        'standalone_wire_bunch_decoder_verified':False,'playable_map_verified':False}


if __name__=='__main__':
    evidence=run()
    OUTPUT.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'evidence':OUTPUT.relative_to(ROOT).as_posix(),'rules':len(evidence['rules']),
        'source_full_decode_bytes':evidence['payload_bytes'],'lower_scope':evidence['new_plan_scope_only'],
        'process_access':False}))
