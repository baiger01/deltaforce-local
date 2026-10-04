"""Reproducible, offline audit of two collected native bunch receive functions.

Reads fixed saved code and immutable image log strings only. FInBunch memory
offsets describe an already decoded object; they are not network bit offsets.
This does not launch, access, patch or acknowledge a native client.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parent.parent
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SAMPLES = Path('work/native-client-tests/1790845340083127000/ds-native-control-code')
EXPECTED = (
    ('UChannel.ReceivedRawBunch.implementation', 0x12868710, 944,
     '06c81120e891c6a4ef02a408fc5bf19271f0419d9521316ebcfaebca2dd00773'),
    ('UChannel.ReceivedSequencedBunch.implementation', 0x12868ac0, 266,
     'fe6d79f18c669a200d042ed7c66c8bb190f9ac7534e4d924633893c4bedf2c48'),
)
LOG_TERMS = ('ReceiveNetGUIDBunch', 'ReceivedNextBunch', 'reliable messages',
             'bLocalSkipAck', 'Bunch.bClose', 'ConditionalCleanUp')
EXPECTED_CALLS = {0x12868780: 0x12bc5540, 0x12868922: 0x12867ac0,
                  0x12868a10: 0x12867ac0, 0x12868ba1: 0x1284d350}


def image_log(raw, pe, rva):
    section = pe.get_section_by_rva(rva)
    if (section is None or section.Characteristics & 0x20000000 or
            not section.VirtualAddress <= rva < section.VirtualAddress + section.SizeOfRawData):
        return None
    offset = pe.get_offset_from_rva(rva)
    available = min(1024, section.VirtualAddress + section.SizeOfRawData - rva)
    block = raw[offset:offset + available]
    for end in range(0, len(block) - 1, 2):
        if block[end:end + 2] == b'\0\0':
            try:
                value = block[:end].decode('utf-16-le', errors='strict')
            except UnicodeError:
                return None
            return value if any(term in value for term in LOG_TERMS) else None
    return None


def audit(raw):
    if hashlib.sha256(raw).hexdigest() != CLIENT_SHA:
        raise ValueError('Shipping image identity mismatch')
    pe = pefile.PE(data=raw, fast_load=True)
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = True
    rows, verified_calls = [], set()
    for label, rva, length, expected_sha in EXPECTED:
        relative = SAMPLES / (label + '.dfcode')
        saved = (ROOT / relative).read_bytes()
        if len(saved) != length + 32:
            raise ValueError('Saved code size mismatch')
        magic, saved_rva, saved_length, _private_aslr_base = struct.unpack('<4Q', saved[:32])
        code = saved[32:]
        code_sha = hashlib.sha256(code).hexdigest()
        if (magic != 0x0000000145444344 or (saved_rva, saved_length) != (rva, length)
                or code_sha != expected_sha):
            raise ValueError('Saved code identity mismatch')
        instructions = list(engine.disasm(code, rva))
        if not instructions or sum(item.size for item in instructions) != length:
            raise ValueError('Saved implementation is not completely decoded')
        logs = []
        for item in instructions:
            if item.address in EXPECTED_CALLS:
                if (item.mnemonic != 'call' or len(item.operands) != 1 or
                        item.operands[0].type != X86_OP_IMM or
                        item.operands[0].imm != EXPECTED_CALLS[item.address]):
                    raise ValueError('Named receive direct-call anchor mismatch')
                verified_calls.add(item.address)
            if item.mnemonic != 'lea':
                continue
            for operand in item.operands:
                if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                    continue
                target = item.address + item.size + operand.mem.disp
                value = image_log(raw, pe, target)
                if value is not None:
                    logs.append({'instruction_rva': hex(item.address),
                                 'string_rva': hex(target), 'text': value})
        rows.append({'method': label, 'source_relative_to_project_root': relative.as_posix(),
                     'rva': hex(rva), 'code_bytes': length, 'code_sha256': code_sha,
                     'file_sha256': hashlib.sha256(saved).hexdigest(),
                     'terminal_return_decoded': instructions[-1].mnemonic == 'ret',
                     'immutable_log_references': logs})
    observed_logs = [entry['text'] for row in rows for entry in row['immutable_log_references']]
    if verified_calls != set(EXPECTED_CALLS):
        raise ValueError('Named receive direct-call anchor is absent')
    if not all(any(term in text for text in observed_logs) for term in LOG_TERMS):
        raise ValueError('Required receive semantics log evidence is incomplete')
    return {
        'kind': 'native_decoded_bunch_receive_dataflow', 'client_sha256': CLIENT_SHA,
        'client_relative_to_game_root': 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe',
        'image_modified': False, 'client_launched': False, 'process_access': False,
        'code_samples': rows,
        'memory_fields': [
            {'object': 'FInBunch', 'offset': '0xe0', 'width_bits': 32,
             'observed_use': 'Signed sequence comparison, queue sorting and duplicate sequence removal.'},
            {'object': 'FInBunch', 'offset': '0xe4', 'mask': '0x10',
             'observed_use': 'Reliable sequence gate; too many reliable messages log supports the role.'},
            {'object': 'FInBunch', 'offset': '0xc0',
             'observed_use': 'Pointer to next queued bunch.'},
            {'object': 'FInBunch', 'offset': '0x29', 'mask': '0x01',
             'observed_use': 'Bunch.IsError flag, also set when pending queue reaches 256 entries.'},
            {'object': 'FInBunch', 'offset': '0xe5', 'mask': '0x01',
             'observed_use': 'ReceiveNetGUIDBunch gate unless a connection mode flag is set.'},
            {'object': 'FInBunch', 'offset': '0xe4', 'mask': '0x02',
             'observed_use': 'Bunch.bClose; leads to ConditionalCleanUp.'},
            {'object': 'UChannel', 'offset': '0x34', 'width_bits': 32,
             'observed_use': 'Channel index, used for connection reliable sequence table.'},
            {'object': 'UChannel', 'offset': '0x58', 'observed_use': 'Pending reliable bunch queue head.'},
            {'object': 'UChannel', 'offset': '0x4c', 'width_bits': 32,
             'observed_use': 'Pending queue count; native error threshold is 256.'},
        ],
        'direct_processing_calls': [
            {'target_rva': '0x12867ac0', 'call_rvas': ['0x12868922', '0x12868a10'],
             'log_supported_name': 'ReceivedNextBunch', 'runtime_body_collected': False},
            {'target_rva': '0x12bc5540', 'call_rvas': ['0x12868780'],
             'log_supported_name': 'ReceiveNetGUIDBunch', 'runtime_body_collected': False},
            {'target_rva': '0x1284d350', 'call_rvas': ['0x12868ba1'],
             'log_supported_name': 'ConditionalCleanUp', 'runtime_body_collected': False},
        ],
        'virtual_control_dispatch': {'instruction_rva': '0x12868ad9',
                                    'slot_offset': '0x288', 'concrete_override_identified': False},
        'limits_of_evidence': [
            'These functions receive an already constructed FInBunch. Memory offsets do not define wire bit order.',
            'The reliable bunch sequence is separate from the candidate 14-bit packet sequence.',
            'RawBunch sorts non-next sequences but does not itself demonstrate every old-message rejection rule.',
            'The actual control override and upstream packet/bunch-header decoder remain unverified.',
        ],
        'native_control_protocol_verified': False, 'playable_map_verified': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', required=True, type=Path)
    args = parser.parse_args()
    image = args.game_root / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with image.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        result = audit(raw)
    output = ROOT / 'work/evidence/native-control-receive-dataflow.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'saved_relative_to_project_root': output.relative_to(ROOT).as_posix(),
                      'sample_count': len(result['code_samples']),
                      'receive_log_references': sum(len(row['immutable_log_references'])
                                                   for row in result['code_samples']),
                      'process_access': False, 'native_control_protocol_verified': False}))


if __name__ == '__main__':
    main()
