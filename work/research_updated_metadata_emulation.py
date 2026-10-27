"""Synthetic offline x64 emulation; never opens or writes a game process.

Unicorn interprets only explicitly hash-pinned saved instructions, with synthetic
buffers, selectors and stacks. This proves arithmetic/character behavior only.
"""
import argparse
import json
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_EFLAGS,
)

from research_updated_metadata_roots import ROOT, PINS, ForensicObservation, sha, disasm, NewImage
from native_metadata_objects import _chunk_divisor, ObjectMetadataError
from native_metadata_names import _key

IMAGE = 0x140000000
STACK = 0x70000000
BUFFER = 0x71000000
SENTINEL = 0x72000000


class SyntheticMachine:
    def __init__(self, observation, ranges, globals_page=None):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        pages = set()
        for rva, size in ranges:
            lo, hi = rva & ~0xfff, (rva+size+0xfff)&~0xfff
            for page in range(lo, hi, 0x1000):
                if page not in pages:
                    self.uc.mem_map(IMAGE+page, 0x1000)
                    pages.add(page)
            self.uc.mem_write(IMAGE+rva, observation.read(rva, size))
        for at, size in [(STACK, 0x10000), (BUFFER, 0x4000), (SENTINEL, 0x1000)]:
            self.uc.mem_map(at, size)
        if globals_page:
            self.uc.mem_map(IMAGE+globals_page, 0x1000)
        self.zero_idiv = False
        if globals_page:
            idiv_addresses = {IMAGE+i.address for rva, size in ranges
                              for i in disasm(observation, rva, size) if i.mnemonic == 'idiv'}

            def intercept_idiv(uc, address, size, user_data):
                if address in idiv_addresses and uc.reg_read(UC_X86_REG_R8) & 0xffffffff == 0:
                    self.zero_idiv = True
                    uc.emu_stop()

            self.uc.hook_add(UC_HOOK_CODE, intercept_idiv)

    def write_u32(self, rva, value):
        self.uc.mem_write(IMAGE+rva, struct.pack('<I', value & 0xffffffff))

    def call(self, rva, rcx, edx, budget=100000):
        self.zero_idiv = False
        rsp = STACK+0xff00
        self.uc.mem_write(rsp, struct.pack('<Q', SENTINEL))
        for reg, value in [(UC_X86_REG_RCX, rcx), (UC_X86_REG_RDX, edx),
                           (UC_X86_REG_RSP, rsp), (UC_X86_REG_EFLAGS, 2)]:
            self.uc.reg_write(reg, value)
        self.uc.emu_start(IMAGE+rva, SENTINEL, count=budget)
        if self.zero_idiv:
            raise ZeroDivisionError('Native IDIV zero intercepted before emulation')
        if self.uc.reg_read(UC_X86_REG_RIP) != SENTINEL:
            raise ValueError(f'Synthetic execution did not return: entry={rva:x}, '
                             f'rip={self.uc.reg_read(UC_X86_REG_RIP):x}')
        return self.uc.reg_read(UC_X86_REG_RAX) & 0xffffffff


def divisor_checks(label):
    observation = ForensicObservation(label)
    shift = 0 if label == 'old' else 0x80
    globals_shift = 0 if label == 'old' else 0x40
    quotient, remainder = 0xd60500+shift, 0xd60d00+shift
    outer_cell = 0x1e318784+globals_shift
    inner_cell = 0x1e31878c+globals_shift
    parameter_cell = 0x1e3187b4+globals_shift
    machine = SyntheticMachine(observation, [(quotient, 0x63c), (remainder, 0x66c)], 0x1e318000)
    selectors = list(range(22)) + [0xffffffff]
    parameters = list(range(64)) + [0x80000000, 0x8000003f, 0xffffffc0, 0xffffffff]
    cases = failures = successes = 0
    observed_divisors = set()
    for outer in list(range(12)) + [0xffffffff]:
        machine.write_u32(outer_cell, outer)
        for slot in range(10):
            machine.write_u32(inner_cell+slot*4, 0xdeadbeef)
        for inner in selectors:
            if 1 <= outer <= 10:
                machine.write_u32(inner_cell+4*(outer-1), inner)
            for parameter in parameters:
                machine.write_u32(parameter_cell, parameter)
                try:
                    divisor = _chunk_divisor(outer, inner, parameter)
                except ObjectMetadataError:
                    divisor = 0
                for is_remainder, function in [(False, quotient), (True, remainder)]:
                    cases += 1
                    try:
                        value = machine.call(function, 0x12345678, 0, budget=256)
                    except ValueError as error:
                        raise ValueError(f'{label}/{outer}/{inner}/{parameter}: {error}') from error
                    except ZeroDivisionError:
                        if (divisor != 0
                                or machine.uc.reg_read(UC_X86_REG_R8) & 0xffffffff != 0):
                            raise
                        rip = machine.uc.reg_read(UC_X86_REG_RIP)-IMAGE
                        if observation.read(rip, 3) != bytes.fromhex('41f7f8'):
                            raise ValueError('Synthetic exception is not native IDIV zero')
                        failures += 1
                        continue
                    if not divisor:
                        raise ValueError('Native IDIV zero unexpectedly succeeded')
                    expected = (0x12345678 % divisor if is_remainder else 0x12345678 // divisor)
                    if value != expected:
                        raise ValueError(f'Chunk arithmetic mismatch: {label}/{outer}/{inner}/{parameter}')
                    successes += 1
                    observed_divisors.add(divisor)
    boundary_cases = 0
    for outer in [0, 1, 10, 11, 0xffffffff]:
        machine.write_u32(outer_cell, outer)
        for inner in range(21):
            if 1 <= outer <= 10:
                machine.write_u32(inner_cell+4*(outer-1), inner)
            for parameter in [0, 1, 16, 62, 63, 0xffffffff]:
                machine.write_u32(parameter_cell, parameter)
                try:
                    divisor = _chunk_divisor(outer, inner, parameter)
                except ObjectMetadataError:
                    continue
                for index in [0, 1, divisor-1, divisor, divisor+1, 0x7fffffff]:
                    for is_remainder, function in [(False, quotient), (True, remainder)]:
                        expected = index % divisor if is_remainder else index // divisor
                        if machine.call(function, index, 0, budget=256) != expected:
                            raise ValueError('Chunk boundary arithmetic mismatch')
                        boundary_cases += 1
    return dict(build=label, cases=cases, valid_results=successes,
        idiv_zero_preexecution_stops=failures, boundary_cases=boundary_cases,
        tested_outer_selectors=list(range(12))+[0xffffffff], tested_inner_selectors=selectors,
        tested_parameters=parameters, all_64_low_bit_residues=True,
        every_other_inner_cell_poisoned=True, distinct_valid_divisors=len(observed_divisors),
        python_reference='native_metadata_objects._chunk_divisor',
        source=observation.source_evidence())


def name_checks(label):
    observation = ForensicObservation(label)
    narrow = 0x10b5fd00 if label == 'old' else 0x10b5f6d0
    wide = 0x10b5ff10 if label == 'old' else 0x10b5f8e0
    machine = SyntheticMachine(observation, [(narrow, 0x210), (wide, 0x284)])
    calls = bytes_compared = 0
    for is_wide, function in [(False, narrow), (True, wide)]:
        unit_bytes = 2 if is_wide else 1
        mask = 0xffff if is_wide else 0xff
        for length in range(1, 1024):
            values = [(i*37+0x81) & mask for i in range(length)]
            for zero_first in [False, True]:
                units = values.copy()
                units[0] = 0 if zero_first else 0x81
                payload = b''.join(x.to_bytes(unit_bytes, 'little') for x in units)
                expected = units.copy()
                if not zero_first:
                    key = _key(length, is_wide)
                    for index in range(0, length, 2 if is_wide else 1):
                        expected[index] ^= key
                expected_raw = b''.join(x.to_bytes(unit_bytes, 'little') for x in expected)
                before, after = bytes.fromhex('f1e2d3c4'), bytes.fromhex('b5a69788')
                machine.uc.mem_write(BUFFER, before+payload+after)
                machine.call(function, BUFFER+len(before), length)
                actual = bytes(machine.uc.mem_read(BUFFER, len(before)+len(payload)+len(after)))
                if actual != before+expected_raw+after:
                    raise ValueError(f'Native name transform mismatch: {label}/{is_wide}/{length}/{zero_first}')
                calls += 1
                bytes_compared += len(payload)
    return dict(build=label, cases=calls, payload_bytes_compared=bytes_compared,
        lengths_inclusive=[1, 1023], tested_widths=[1, 2], first_unit_cases=['nonzero', 'zero'],
        all_nine_dispatch_cases=True, prefix_suffix_canaries_intact=True,
        wide_step_verified='only indexes 0, 2, 4, ... are XORed',
        python_reference='native_metadata_names._key', source=observation.source_evidence())


def path_checks():
    """Interpret native recursion/separators with explicit synthetic string ABI stubs."""
    observation = ForensicObservation('new')
    machine = SyntheticMachine(observation, [(0x10eaca30, 0x148),
        (0x10eacb80, 0x12e), (0x10e55e80, 0xb3)])
    uc = machine.uc
    for rva in [0x1e34c000, 0x1d59d000, 0x10b5b000, 0x109ed000]:
        uc.mem_map(IMAGE+rva, 0x1000)
    callback = 0x73000000
    uc.mem_map(callback, 0x1000)
    uc.mem_write(callback, bytes.fromhex('488b01c3'))  # synthetic FString data getter
    uc.mem_write(IMAGE+0x1d59de88, struct.pack('<Q', callback))
    package_class = BUFFER+0x3000
    uc.mem_write(IMAGE+0x1e34cad0, struct.pack('<Q', package_class))
    fstring, chars = BUFFER+0x100, BUFFER+0x1000
    tokens = {}
    stub_calls = []

    def return_from_stub(value):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        address, = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))
        uc.reg_write(UC_X86_REG_RAX, value)
        uc.reg_write(UC_X86_REG_RSP, rsp+8)
        uc.reg_write(UC_X86_REG_RIP, address)

    def append(value):
        data, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(fstring, 16)))
        if not data:
            data, capacity = chars, 512
        prefix = bytes(uc.mem_read(data, max(0, count-1)*2)) if count else b''
        text = prefix+value.encode('utf-16-le')+b'\0\0'
        uc.mem_write(data, text)
        uc.mem_write(fstring, struct.pack('<QII', data, len(text)//2, capacity))

    def native_string_boundary(uc, address, size, user_data):
        rcx, rdx = uc.reg_read(UC_X86_REG_RCX), uc.reg_read(UC_X86_REG_RDX)
        if address == IMAGE+0x10b5b890:
            if rdx != fstring:
                raise ValueError('Path append FString receiver mismatch')
            token, = struct.unpack('<Q', bytes(uc.mem_read(rcx, 8)))
            append(tokens[token])
            stub_calls.append('name_append')
            return_from_stub(fstring)
        elif address == IMAGE+0x109ed310:
            if rcx != fstring or rdx != IMAGE+0x14ec37c8 or uc.reg_read(UC_X86_REG_R8) != 4:
                raise ValueError('Path None literal append mismatch')
            append('None')
            stub_calls.append('None_literal_append')
            return_from_stub(fstring)

    uc.hook_add(UC_HOOK_CODE, native_string_boundary)
    cases = []
    for depth in [0, 1, 2, 3, 8, 16, 32]:
        for package_at in [-1, 0, 1, max(0, depth-2)]:
            if package_at >= depth:
                continue
            nodes = [BUFFER+0x2000+0x40*i for i in range(depth)]
            names = [f'Node{i}' for i in range(depth)]
            classes = [package_class if i == package_at else package_class+0x100 for i in range(depth)]
            # Every non-package Outer except the root has a valid parent. A root
            # with children must be a Package to avoid the native null-parent dereference.
            if depth > 1:
                classes[0] = package_class
            for i, address in enumerate(nodes):
                token = 100+i
                tokens[token] = names[i]
                data = bytearray(0x40)
                struct.pack_into('<Q', data, 8, classes[i])
                struct.pack_into('<Q', data, 0x10, nodes[i-1] if i else 0)
                struct.pack_into('<Q', data, 0x1c, token)
                uc.mem_write(address, bytes(data))
            expected = names[0] if depth else 'None'
            for i in range(1, depth):
                outer_class = classes[i-1]
                separator = (':' if outer_class != package_class and i >= 2
                             and classes[i-2] == package_class else '.')
                expected += separator+names[i]
            for function in [0x10eaca30, 0x10eacb80]:
                uc.mem_write(fstring, bytes(16))
                before = len(stub_calls)
                if function == 0x10eaca30:
                    uc.reg_write(UC_X86_REG_R8, 0)
                    machine.call(function, nodes[-1] if nodes else 0, fstring)
                else:
                    uc.reg_write(UC_X86_REG_R8, fstring)
                    machine.call(function, nodes[-1] if nodes else 0, 0)
                data, count, _ = struct.unpack('<QII', bytes(uc.mem_read(fstring, 16)))
                actual = bytes(uc.mem_read(data, (count-1)*2)).decode('utf-16-le')
                if actual != expected:
                    raise ValueError(f'Path control-flow mismatch: {function:x}/{depth}/{package_at}/{actual}')
                cases.append(dict(function=hex(function), depth=depth,
                    additional_package_class_index=package_at, expected=expected, observed=actual,
                    intercepted_string_calls=len(stub_calls)-before))
    return dict(build='new', cases=len(cases), results=cases,
        actual_native_path_control_flow_interpreted=True,
        native_package_class_getter_fast_path_interpreted=True,
        external_string_helpers_are_explicit_synthetic_stubs=True,
        no_native_string_allocation_or_runtime_metadata_proved=True,
        source=observation.source_evidence())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--names-only', action='store_true')
    args = parser.parse_args()
    result = dict(kind='synthetic_offline_updated_metadata_emulation',
        emulator='Unicorn '+unicorn.__version__, process_accessed=False,
        process_memory_written=False, native_getter_called=False,
        synthetic_emulator_memory_written=True, runtime_metadata_recovered=False,
        native_protocol_compatibility_verified=False,
        script_sha256=sha(__import__('pathlib').Path(__file__).read_bytes()),
        pure_helper_source_pins={name:sha((ROOT/'work'/name).read_bytes()) for name in [
            'native_metadata_objects.py', 'native_metadata_names.py']},
        names=[name_checks(label) for label in PINS])
    result['paths'] = path_checks()
    if not args.names_only:
        result['divisors'] = [divisor_checks(label) for label in PINS]
    output = ROOT/'work/evidence/updated-metadata-roots-79fb7b10-emulation.json'
    output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(output=str(output.relative_to(ROOT)), sha256=sha(output.read_bytes()),
        names=[{k:r[k] for k in ('build', 'cases')} for r in result['names']],
        divisors=[{k:r[k] for k in ('build', 'cases', 'boundary_cases', 'idiv_zero_preexecution_stops')}
                  for r in result.get('divisors', [])])))


if __name__ == '__main__':
    main()
