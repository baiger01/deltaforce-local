"""Offline audit of the complete sender wrapper and fixed Control candidate."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from capstone.x86 import X86_OP_MEM, X86_REG_RIP
import read_native_sender_body as reader

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT/'work/native-client-tests/1790886060666299700/ds-native-control-code'
REPORT_SHA = '40d6337ba86d3faf45627c8267c146536b2881b49bd4a4d06d4e2c8f9cdd9ca3'
OUTPUT = ROOT/'work/evidence/native-control-sender-1790886060666299700-semantics.json'
SAMPLES = (
    ('SendBunch.complete_wrapper', 0x5bfbfd0, 36,
     'd32ce5d7dc39b38db0022b7a4a6d8b5636fa84b1a12d6a6ddf34dfae7d7a0dd0',
     'c0c824a5e685328a9310cf98569c920432cf65f28cf6b958280c225741939279'),
    ('Control.SendBunch.static_slot_candidate', 0x1286d3a0, 463,
     'bf458f9211e0572d5f9b35b6b8d637fe042f3e7c8a0407fe6af5b95dc2f51338',
     '93764563d5585389fffeaf4ca71e83f0cc09aeb6461dd305bdd6742fe6fafcfb'),
)
RECEIVE_PATH = ROOT/'work/native-client-tests/1790847786646593300/ds-native-control-code/UChannel.ReceivedNextBunch.direct_log_supported.dfcode'
RECEIVE_FILE_SHA = 'd08e63d05a9368d2926b7b0a426f4e1885724bef248773111463157df4560451'
RECEIVE_CODE_SHA = 'e3644fb80684cd50f280627453846c941aa4d3caf73a24240f9f4f5602e59ea8'
BASE_AUDIT = ROOT/'work/evidence/native-base-sender-1790886060666299700-audit.json'
BASE_AUDIT_SHA = '023879956ca5cdd8b179856b8ce84ab857c9fd249276e037bb609c2af433adb5'
LOGS = (
    (0x1286d40a, 0x1b14b0e0, 'Control channel bunch overflowed'),
    (0x1286d458, 0x1b14b060, 'Overflowed control channel message queue, disconnecting client'),
)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def ins_rows(instructions, begin, end):
    return [{'rva': hex(i.address), 'bytes_hex': bytes(i.bytes).hex(),
             'mnemonic': i.mnemonic, 'operands': i.op_str}
            for i in instructions if begin <= i.address < end]


def exact_instruction(instructions, rva, mnemonic, operands):
    ins = next((i for i in instructions if i.address == rva), None)
    if ins is None or (ins.mnemonic, ins.op_str) != (mnemonic, operands):
        raise ValueError('Control sender exact semantic instruction witness mismatch')
    return ins


def load_sample(report, root, spec):
    label, rva, length, file_hash, code_hash = spec
    rows = [v for v in report.get('functions', []) if v.get('name') == label]
    if (len(rows) != 1 or rows[0].get('rva') != hex(rva) or rows[0].get('code_bytes') != length or
            rows[0].get('file_sha256') != file_hash or rows[0].get('code_sha256') != code_hash or
            rows[0].get('read_succeeded') is not True or rows[0].get('disassembled_bytes') != length or
            rows[0].get('immutable_source_evidence') != root):
        raise ValueError('Control sender saved report row identity mismatch')
    path = FOLDER/(label+'.dfcode')
    if path.stat().st_size != length+32:
        raise ValueError('Control sender saved sample length mismatch')
    with path.open('rb') as stream:
        sample = stream.read(length+33)
    if len(sample) != length+32 or sha(sample) != file_hash:
        raise ValueError('Control sender full file SHA mismatch')
    magic, at, size, _private_module_base = struct.unpack('<4Q', sample[:32])
    code = sample[32:]
    if (magic, at, size) != (reader.MAGIC, rva, length) or sha(code) != code_hash:
        raise ValueError('Control sender header/code SHA mismatch')
    instructions = reader.complete_decode(code, rva, length)
    fragment_decoded = []
    for begin, end in root['fragments']:
        begin, end = int(begin, 16), int(end, 16)
        part = reader.complete_decode(code[begin-rva:end-rva], begin, end-begin)
        fragment_decoded.extend(part)
    if [(i.address, bytes(i.bytes)) for i in fragment_decoded] != [(i.address, bytes(i.bytes)) for i in instructions]:
        raise ValueError('Control sender independent fragment decode mismatch')
    asm = (FOLDER/(label+'.asm.txt')).read_bytes()
    expected = ('\n'.join(f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in instructions)+'\n').encode()
    if asm.replace(b'\r\n', b'\n') != expected:
        raise ValueError('Control sender saved assembly differs from independent decode')
    return code, instructions, {'relative_path': path.relative_to(ROOT).as_posix(), 'rva': hex(rva),
        'payload_bytes': length, 'file_sha256': file_hash, 'code_sha256': code_hash,
        'asm_sha256': sha(asm), 'instruction_count': len(instructions),
        'full_file_header_code_SHA_and_decode_verified': True,
        'individual_fragment_decode_verified': True, 'saved_asm_matches_independent_decode': True,
        'immutable_span': root}


def receive_relation():
    if RECEIVE_PATH.stat().st_size != 3184:
        raise ValueError('Saved receiver source length mismatch')
    sample = RECEIVE_PATH.read_bytes()
    magic, rva, length, _private_module_base = struct.unpack('<4Q', sample[:32])
    if (sha(sample) != RECEIVE_FILE_SHA or sha(sample[32:]) != RECEIVE_CODE_SHA or
            (magic, rva, length) != (reader.MAGIC, 0x12867ac0, 3152)):
        raise ValueError('Saved receiver source header/SHA mismatch')
    instructions = reader.complete_decode(sample[32:], rva, length)
    for witness in (
        (0x12867adc, 'test', 'byte ptr [rdx + 0xe4], 0x10'),
        (0x12867af5, 'movsxd', 'rbx, dword ptr [rdx + 0xd0]'),
        (0x12867afc, 'add', 'rcx, 0x1500'),
        (0x12867b0d, 'mov', 'eax, dword ptr [rdi + 0xe0]'),
        (0x12867b17, 'mov', 'dword ptr [rdx], eax'),
    ):
        exact_instruction(instructions, *witness)
    return {'relative_path': RECEIVE_PATH.relative_to(ROOT).as_posix(),
        'file_sha256': RECEIVE_FILE_SHA, 'code_sha256': RECEIVE_CODE_SHA, 'payload_bytes': length,
        'full_decode_verified': True, 'instruction_count': len(instructions),
        'receive_commit_evidence': ins_rows(instructions, 0x12867adc, 0x12867b19),
        'relationship': 'Receiver reliable flag is FInBunch+e4 mask10; it reads incoming ChIndex+d0 and ChSequence+e0 and commits connection incoming-reliable array+1500. Current Control sender has no such sequence write. Its queued payload does not replace a decoded incoming bunch.',
        'memory_offsets_are_not_wire_bits': True, 'send_and_receive_sequence_domains_are_distinct': True}


def run(game_root):
    report = reader.sealed_json(FOLDER/'result.json', REPORT_SHA)
    plan = reader.build_plan(game_root)
    expected_names = [v['label'] for v in plan['initial_reads']]+[plan['conditional_single_e8_read']['label']]
    if (report.get('client_sha256') != reader.SOURCE_SHA or report.get('offline_plan') != plan or
            report.get('status') != 'bounded_read_attempt_complete' or
            report.get('actual_read_count') != 3 or report.get('actual_code_bytes') != 3737 or
            [v.get('name') for v in report.get('functions', [])] != expected_names):
        raise ValueError('Control sender report/plan identity mismatch')
    wrapper_code, wrapper, wrapper_proof = load_sample(report, plan['initial_reads'][0], SAMPLES[0])
    code, control, control_proof = load_sample(report, plan['initial_reads'][1], SAMPLES[1])
    sealed = reader.sealed_json(reader.FIXED_PLAN, reader.FIXED_PLAN_SHA)
    wrapper_semantics = reader.validate_wrapper(wrapper_code, reader.source_prefix(sealed))
    if report['functions'][0].get('wrapper_verification') != wrapper_semantics:
        raise ValueError('Control sender saved wrapper-verification mismatch')
    direct = reader.conditional_e8(code)
    recorded = report['functions'][1].get('conditional_direct_e8_proof', {})
    if (any(recorded.get(k) != v for k, v in direct.items()) or
            recorded.get('source_file_sha256') != SAMPLES[1][3] or
            recorded.get('independent_target_source_evidence') != plan['conditional_single_e8_read']):
        raise ValueError('Control sender same-source conditional call proof mismatch')
    for witness in (
        (0x1286d3af, 'mov', 'eax, dword ptr [rcx + 0x80]'),
        (0x1286d3c0, 'jg', '0x1286d448'),
        (0x1286d3d4, 'add', 'eax, 0xff'),
        (0x1286d3d9, 'cmp', 'dword ptr [rcx + 0x50], eax'),
        (0x1286d3e2, 'test', 'byte ptr [r8 + 0x29], 1'),
        (0x1286d3e9, 'call', '0x1286c6f0'),
        (0x1286d448, 'cmp', 'eax, 0x8000'),
        (0x1286d486, 'mov', 'dword ptr [rax + 0x15c], 1'),
        (0x1286d49a, 'lea', 'rdi, [rcx + 0x78]'),
        (0x1286d4bf, 'lea', 'rbx, [rbx + rbx*2]'),
        (0x1286d53c, 'call', '0x1497fcb6'),
        (0x1286d54c, 'mov', 'dword ptr [r14 + 0x10], eax'),
        (0x1286d562, 'mov', 'qword ptr [rsi], 0xffffffffffffffff'),
    ):
        exact_instruction(control, *witness)
    logs = []
    executable = Path(game_root)/reader.EXECUTABLE_RELATIVE
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = reader.Image(raw)
        for site, target, text in LOGS:
            ins = next(i for i in control if i.address == site)
            if (ins.mnemonic != 'lea' or len(ins.operands) != 2 or ins.operands[1].type != X86_OP_MEM or
                    ins.operands[1].mem.base != X86_REG_RIP or
                    site+ins.size+ins.operands[1].mem.disp != target):
                raise ValueError('Control sender log RIP reference mismatch')
            encoded = text.encode('utf-16le')+b'\0\0'
            if image.data(target, len(encoded)) != encoded:
                raise ValueError('Control sender immutable log literal mismatch')
            logs.append({'instruction_rva': hex(site), 'instruction_bytes_hex': bytes(ins.bytes).hex(),
                'string_rva': hex(target), 'text': text, 'string_bytes_sha256': sha(encoded)})
    peer = reader.sealed_json(BASE_AUDIT, BASE_AUDIT_SHA)
    if peer.get('result_sha256') != REPORT_SHA or peer.get('source_sha256') != reader.SOURCE_SHA:
        raise ValueError('Independent base audit source/report identity mismatch')
    rules = [
        {'id': 'wrapper_ABI', 'effect': 'Named wrapper saves original RCX return buffer, loads vptr from original RDX receiver, sets internal RCX=receiver/RDX=return buffer, preserves R8 bunch/R9 bool, calls slot2b8, then returns original return buffer after normal stack/register epilogue. This proves wrapper ABI behavior, not live instance ownership.',
         'instructions': ins_rows(wrapper, reader.PREFIX_RVA, reader.PREFIX_RVA+36)},
        {'id': 'FIFO_precedence', 'effect': 'Signed queued_count at channel+80 is tested first. Positive count<32768 appends instead of directly sending, regardless of NumOutRec or Bunch.IsError. Count>=32768 goes to the disconnect-marker branch. Thus queued messages do not get bypassed by a new immediate send.',
         'instructions': ins_rows(control, 0x1286d3af, 0x1286d3c6)+ins_rows(control, 0x1286d448, 0x1286d44f)},
        {'id': 'backpressure_threshold', 'effect': 'Only when queued_count is not positive, compute255+((FOutBunch byte+f0>>2)&1). Signed channel+50 (NumOutRec, independently supported by base log audit) >= threshold queues this payload. The f0/mask4 role remains a closing inference, not a named or wire bClose bit.',
         'instructions': ins_rows(control, 0x1286d3c6, 0x1286d3e2)},
        {'id': 'direct_delegation', 'effect': 'Below the backlog threshold and archive byte+29 mask1 clear, call1286c6f0 with original RCX channel, RDX output range buffer, R8 bunch, R9 allow-merge bool. No argument register is changed by the gates. Return output buffer; this layer assigns no reliable sequence.',
         'instructions': ins_rows(control, 0x1286d3af, 0x1286d401)},
        {'id': 'overflowed_bunch', 'effect': 'After queue/backpressure gates only, archive byte+29 mask1 set emits the overflowed-bunch diagnostic when logging permits, then invokes connection vptr+2d8 with RDX=0, then writes allFF output marker. Exact virtual callee identity and disconnect timing are not verified.',
         'instructions': ins_rows(control, 0x1286d401, 0x1286d448)},
        {'id': 'queue_limit', 'effect': 'Existing queued_count>=32768 emits the disconnecting-client diagnostic when logging permits, writes1 to connection+15c, and returns allFF marker without appending. It does not call virtual2d8 in this branch.',
         'instructions': ins_rows(control, 0x1286d448, 0x1286d495)},
        {'id': 'queue_entry_layout', 'effect': 'The observed collection at channel+78 has count+8/capacity+c. New slot is at old_count*24. Zero its24 bytes, then allocate its byte buffer to ceil(source bit_count/8), where source bit_count is qword at bunch+a0. Queue allocation helpers are not newly analysed.',
         'instructions': ins_rows(control, 0x1286d495, 0x1286d50b)},
        {'id': 'queued_payload_copy', 'effect': 'Copy ceil(bit_count/8) raw bytes from source buffer accessor at bunch+90 into new slot byte-buffer accessor. Store source bit_count truncated to DWORD in slot+10. No reliable sequence, open/close flag, merge bool or complete FOutBunch object is saved by this function. Padding bytes beyond valid bit_count are not established wire bits.',
         'instructions': ins_rows(control, 0x1286d50b, 0x1286d555)},
        {'id': 'deferred_or_refused_return', 'effect': 'Every cached or locally refused branch writes qword FFFFFFFFFFFFFFFF into caller output buffer and returns that buffer. This is consistent with invalid/no-immediate-send FPacketIdRange, not a success acknowledgement. The direct-delegation branch keeps the lower result.',
         'instructions': ins_rows(control, 0x1286d555, 0x1286d56f)},
    ]
    result = {'kind': 'native_control_sender_complete_instruction_semantics',
        'client_sha256': reader.SOURCE_SHA, 'source_report_sha256': REPORT_SHA,
        'source_plan_sha256': reader.FIXED_PLAN_SHA, 'samples': [wrapper_proof, control_proof],
        'wrapper_semantics': wrapper_semantics, 'same_source_direct_lower_call': recorded,
        'immutable_logs': logs, 'rules': rules, 'decoded_receive_relation': receive_relation(),
        'independent_base_NumOutRec_crosscheck': {'audit_relative_path': BASE_AUDIT.relative_to(ROOT).as_posix(),
            'audit_sha256': BASE_AUDIT_SHA, 'source_code_sha256': peer['sample_code_sha256'],
            'source_file_sha256': peer['sample_file_sha256'], 'field_offset': '0x50',
            'label': 'NumOutRec', 'exact_log_rva': '0x1b14a850',
            'qualification': 'Peer verified complete base sample and instruction/log dataflow; this analysis does not reinterpret or recollect that body.'},
        'implementation_suggestions': [
            'Keep outgoing queued control payload separate from incoming decoded-bunch state. Preserve FIFO and exact valid bit count.',
            'Model the two cached-message/backpressure gates before the direct-send overflow check if reproducing native order; reject invalid negative counts as an explicit local interface rule.',
            'NumOutRec is an outgoing pending-record count, not ChSequence. This Control function does not allocate reliable sequence numbers.',
            'Use allFF result to represent deferred/no immediate packet range, not a purchase/login/ACK success. Upper-layer operation success requires actual later network progress.',
            'Flush selection, reconstruction of outgoing flags, reliable sequence assignment, native wire header writer and UDP integration remain outside this observed function. Do not infer them from queued bytes alone.',
        ],
        'memory_offsets_are_not_wire_bits': True, 'actual_instance_vptr_or_table_ownership_verified': False,
        'live_process_read': False, 'game_launched': False, 'elevation_requested': False,
        'server_modified': False, 'packet_header_wire_layout_verified': False, 'playable_map_verified': False}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    args = parser.parse_args()
    run(args.game_root)
    print('Offline sender audit: 36+463 bytes,119 instructions,4 exact fragments,9 rules verified. No process access.')
    print('Evidence SHA256: '+sha(OUTPUT.read_bytes()))
