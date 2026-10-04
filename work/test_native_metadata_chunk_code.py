"""Interpret only arithmetic/branches in two saved helper intervals, offline.

This does not load or invoke native code. Global scalar values are synthetic;
the exact instruction stream and internal dispatch tables are source-pinned.
"""
import hashlib
import json
from pathlib import Path
import struct
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import native_metadata_objects as objects

BASE = Path(__file__).resolve().parent.parent


def native_divisor(root, outer, inner, parameter):
    path = BASE / root['code_relative_path']
    blob = path.read_bytes()
    if hashlib.sha256(blob).hexdigest() != root['file_sha256']:
        raise ValueError('Saved helper file mismatch')
    magic, version, start, size, image_base = struct.unpack('<4sIQQQ', blob[:32])
    code = blob[32:]
    if (magic != b'DCDE' or version != 1 or start != int(root['begin'], 16)
            or len(code) != size or hashlib.sha256(code).hexdigest() != root['code_sha256']):
        raise ValueError('Saved helper header/code mismatch')
    dis = Cs(CS_ARCH_X86, CS_MODE_64)
    dis.detail = True
    instructions = {i.address: i for i in dis.disasm(
        code[:int(root['dispatch_table_rva'], 16)-start], start
    )}
    globals_by_rva = {objects.OUTER_SELECTOR_RVA: outer,
                      objects.PARAMETER_RVA: parameter}
    for selected in range(10):
        globals_by_rva[objects.INNER_SELECTORS_RVA+4*selected] = inner
    regs = {'rcx': 1234567}
    aliases = {'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'r8d': 'r8'}
    pc, zero, carry = start, False, False

    def reg(name):
        value = regs.get(aliases.get(name, name), 0)
        return value & 0xFFFFFFFF if name in aliases else value

    def store(name, value):
        mask = 0xFFFFFFFF if name in aliases else (1 << 64)-1
        regs[aliases.get(name, name)] = value & mask

    def address(ins, operand):
        mem = operand.mem
        base_name = ins.reg_name(mem.base)
        base = ins.address+ins.size if base_name == 'rip' else reg(base_name)
        index = reg(ins.reg_name(mem.index)) if mem.index else 0
        return base+index*mem.scale+mem.disp

    def value(ins, operand):
        if operand.type == X86_OP_IMM:
            return operand.imm
        if operand.type == X86_OP_REG:
            return reg(ins.reg_name(operand.reg))
        if operand.type == X86_OP_MEM:
            at = address(ins, operand)
            if at in globals_by_rva:
                return globals_by_rva[at]
            if start <= at <= start+len(code)-4:
                return struct.unpack_from('<I', code, at-start)[0]
        raise ValueError('Instruction reads outside pinned code/synthetic scalar cells')

    for _ in range(500):
        ins = instructions[pc]
        op, operands = ins.mnemonic, ins.operands
        next_pc = pc+ins.size
        if op == 'idiv':
            return value(ins, operands[0])
        if op == 'mov':
            store(ins.reg_name(operands[0].reg), value(ins, operands[1]))
        elif op == 'lea':
            store(ins.reg_name(operands[0].reg), address(ins, operands[1]))
        elif op in ('xor', 'add', 'and', 'or', 'shl'):
            a, b = value(ins, operands[0]), value(ins, operands[1])
            result = {'xor': lambda: a ^ b, 'add': lambda: a+b,
                      'and': lambda: a & b, 'or': lambda: a | b,
                      'shl': lambda: a << b}[op]()
            store(ins.reg_name(operands[0].reg), result)
        elif op == 'dec':
            store(ins.reg_name(operands[0].reg), value(ins, operands[0])-1)
        elif op == 'test':
            zero, carry = (value(ins, operands[0]) & value(ins, operands[1])) == 0, False
        elif op == 'cmp':
            a, b = value(ins, operands[0]), value(ins, operands[1]) & 0xFFFFFFFF
            zero, carry = a == b, a < b
        elif op == 'cdqe':
            eax = reg('eax')
            store('rax', eax if eax < 0x80000000 else eax-(1 << 32))
        elif op == 'cdq':
            store('edx', 0 if reg('eax') < 0x80000000 else 0xFFFFFFFF)
        elif op == 'jmp':
            next_pc = value(ins, operands[0])
        elif op in ('je', 'jne', 'ja'):
            take = {'je': zero, 'jne': not zero, 'ja': not zero and not carry}[op]
            if take:
                next_pc = value(ins, operands[0])
        else:
            raise ValueError('Unapproved offline arithmetic instruction: '+op)
        pc = next_pc
    raise ValueError('Fixed helper instruction budget exceeded')


class NativeDivisorTests(unittest.TestCase):
    def test_all_proved_selector_paths_against_saved_instructions(self):
        source = json.loads((BASE/'work/evidence/native-object-registry-split-helper.json').read_text())
        checked = 0
        for outer in (0, *range(1, 11), 11, 0xFFFFFFFF):
            for inner in (*range(22), 0xFFFFFFFF):
                for parameter in (0, 1, 42, 62, 63, 0xFFFFFFFF):
                    actual = [native_divisor(root, outer, inner, parameter)
                              for root in source['roots']]
                    self.assertEqual(actual[0], actual[1])
                    if actual[0]:
                        self.assertEqual(objects._chunk_divisor(outer, inner, parameter), actual[0])
                    else:
                        with self.assertRaises(objects.ObjectMetadataError):
                            objects._chunk_divisor(outer, inner, parameter)
                    checked += 1
        self.assertEqual(checked, 1794)


if __name__ == '__main__':
    unittest.main()
