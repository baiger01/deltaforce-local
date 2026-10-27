"""Interpret bounded scalar instructions from the sealed native RNG report."""
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'work/evidence/map-system-audit-20261018/native-spawn-selection-base-rng.json'
SOURCE_SHA = 'd666f9b1371be62af6879cc5485279fe5c1c3593da63d639482ea1e56cff1907'
MASK = (1 << 64)-1


def instruction_map():
    raw = SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA
    report = json.loads(raw)
    assert report['process_access'] is False and report['client_launched'] is False
    return {int(row['rva'], 16): row for function in report['functions'] for row in function['instructions']}


def run(first, stop, registers, memory):
    code = instruction_map()
    registers, memory = dict(registers), dict(memory)
    zero, pc = False, first

    def address(operand):
        expression = operand.split('[', 1)[1].split(']', 1)[0].replace(' - ', ' + -')
        value = 0
        for term in expression.split(' + '):
            parts = term.split('*')
            base = registers.get(parts[0]) if parts[0] in registers else int(parts[0], 0)
            value += base * (int(parts[1], 0) if len(parts) == 2 else 1)
        return value & MASK

    def read(operand):
        if '[' in operand:
            assert operand.startswith('qword ptr ')
            return memory.get(address(operand), 0)
        return registers.get(operand) if operand in registers else int(operand, 0)

    def write(operand, value):
        value &= MASK
        if '[' in operand:
            assert operand.startswith('qword ptr ')
            memory[address(operand)] = value
        else:
            assert re.fullmatch(r'r(?:ax|bx|cx|dx|di|si|[89]|1[0-5])', operand)
            registers[operand] = value

    for _ in range(256):
        if pc == stop:
            return registers, memory
        row = code[pc]
        mnemonic, operands = row['mnemonic'], row['operands'].split(', ')
        following = pc + len(bytes.fromhex(row['bytes']))
        if mnemonic in ('mov', 'movabs'):
            write(operands[0], read(operands[1]))
        elif mnemonic == 'lea':
            write(operands[0], address(operands[1]))
        elif mnemonic in ('xor', 'imul', 'shl', 'shr', 'ror'):
            left, right = read(operands[0]), read(operands[1])
            if mnemonic == 'xor':
                value = left ^ right
            elif mnemonic == 'imul':
                value = left * right
            elif mnemonic == 'shl':
                value = left << (right & 63)
            elif mnemonic == 'shr':
                value = left >> (right & 63)
            else:
                right &= 63
                value = (left >> right) | (left << (64-right))
            write(operands[0], value)
        elif mnemonic == 'test':
            zero = (read(operands[0]) & read(operands[1])) == 0
        elif mnemonic in ('je', 'jne'):
            if zero == (mnemonic == 'je'):
                following = int(operands[0], 0)
        else:
            raise ValueError('Unexpected native oracle instruction '+str(row))
        pc = following
    raise ValueError('Native RNG oracle exceeded its fixed instruction budget')


def seed_state(seed):
    _, memory = run(0xc40447c, 0xc40456a, dict(rbx=0x10000, rdx=seed), {})
    return [memory[0x10000+offset] for offset in (0xc8, 0xd0, 0xd8, 0xe0)]


def next_state(state):
    memory = {0x10000+index*8: value for index, value in enumerate(state)}
    registers, memory = run(0xc41f878, 0xc41f8c1, dict(rbx=0x10000, rdi=0, rsp=0x20000), memory)
    return registers['rdi'], [memory[0x10000+index*8] for index in range(4)]


def vectors():
    result = []
    for seed in (0, 1, 2, 0xe9b1526, (1 << 32)-1, 1 << 32, (1 << 63), MASK):
        initial = seed_state(seed)
        state, outputs = list(initial), []
        for _ in range(8):
            value, state = next_state(state)
            outputs.append(value)
        result.append(dict(seed=seed, initial_state=initial, next_uint64=outputs, final_state=state))
    return dict(kind='offline_native_instruction_interpreter_rng_vectors', native_code_executed=False,
                process_access=False, report_relative_path=SOURCE.relative_to(ROOT).as_posix(),
                report_sha256=SOURCE_SHA, vectors=result)


def player_start_before(left_xyz, right_xyz):
    path = SOURCE.parent / 'native-spawn-playerstart-fixed-order-comparator.json'
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '146860446835274bb6462d5f4c95fd2c8f3e490ac9d8287e2e81d8c9ccaa3c73'
    rows = json.loads(raw)['functions'][0]['instructions']
    registers = dict(xmm8=left_xyz[0], xmm6=left_xyz[1], xmm7=left_xyz[2])
    result = None
    for row in rows:
        rva = int(row['rva'], 16)
        if not 0xc44ac9d <= rva <= 0xc44acea:
            continue
        mnemonic, operands = row['mnemonic'], row['operands'].split(', ')
        if mnemonic == 'movss':
            offset = 0 if operands[1] == 'dword ptr [rax]' else int(operands[1].split(' + ')[1][:-1], 0)
            registers[operands[0]] = right_xyz[offset//4]
        elif mnemonic in ('mulss', 'addss'):
            left, right = registers[operands[0]], registers[operands[1]]
            value = left*right if mnemonic == 'mulss' else left+right
            registers[operands[0]] = struct.unpack('<f', struct.pack('<f', value))[0]
        elif mnemonic == 'comiss':
            result = registers[operands[0]] > registers[operands[1]]
        elif mnemonic == 'seta':
            assert result is not None
            return result
        else:
            assert mnemonic == 'movaps'
    raise ValueError('Native PlayerStart compare subset was not reached')


if __name__ == '__main__':
    raw = (json.dumps(vectors(), indent=2, sort_keys=True)+'\n').encode()
    target = SOURCE.parent / 'native-spawn-rng-instruction-oracle-vectors.json'
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=target.relative_to(ROOT).as_posix(), sha256=hashlib.sha256(raw).hexdigest())))
