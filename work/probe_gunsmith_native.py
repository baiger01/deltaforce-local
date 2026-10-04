"""Read-only native socket helper evidence; never executes the game binary."""

import argparse
from contextlib import redirect_stdout, redirect_stderr
import ctypes
import mmap
from pathlib import Path
import re
import struct
import sys

import capstone
import pefile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('names', nargs='*')
    parser.add_argument('--rva', nargs='+', type=lambda value: int(value, 0), default=[])
    parser.add_argument('--pid', type=int)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--full-range', action='store_true')
    args = parser.parse_args()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        sys.argv = [value for value in sys.argv if value not in ('--output', str(args.output))]
        with args.output.open('w', encoding='utf-8') as output:
            with redirect_stdout(output), redirect_stderr(output):
                main()
        return
    pe = pefile.PE(str(args.binary), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if args.pid:
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.ReadProcessMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        psapi.EnumProcessModulesEx.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong)
        handle = kernel.OpenProcess(0x410, False, args.pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            modules = (ctypes.c_void_p * 1024)()
            needed = ctypes.c_ulong()
            if not psapi.EnumProcessModulesEx(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3):
                raise ctypes.WinError(ctypes.get_last_error())
            base = modules[0]
            print('READONLY_MEMORY', args.pid, 'image_base', hex(base))
            for rva in args.rva:
                buffer = ctypes.create_string_buffer(256)
                read = ctypes.c_size_t()
                if not kernel.ReadProcessMemory(handle, base + rva, buffer, len(buffer), ctypes.byref(read)):
                    raise ctypes.WinError(ctypes.get_last_error())
                print('FUNCTION', hex(rva))
                print('CODE_BYTES', buffer.raw[:read.value].hex())
                for ins in disassembler.disasm(buffer.raw[:read.value], base + rva):
                    print(hex(ins.address - base), ins.mnemonic, ins.op_str)
                    if ins.mnemonic == 'ret' and not args.full_range:
                        break
        finally:
            kernel.CloseHandle(handle)
        return
    with args.binary.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for rva in args.rva:
            offset = pe.get_offset_from_rva(rva)
            print('FUNCTION', hex(rva))
            for ins in disassembler.disasm(data[offset:offset + 160], image_base + rva):
                print(hex(ins.address - image_base), ins.mnemonic, ins.op_str)
                if ins.mnemonic == 'ret':
                    break
        targets = {}
        for name in args.names:
            for encoding in ('ascii', 'utf-16le'):
                needle = name.encode(encoding)
                start = 0
                while (offset := data.find(needle, start)) >= 0:
                    start = offset + len(needle)
                    rva = pe.get_rva_from_offset(offset)
                    targets[rva] = name
                    print('STRING', name, encoding, 'raw', hex(offset), 'rva', hex(rva))
        for section in pe.sections:
            raw_start = section.PointerToRawData
            raw = data[raw_start:raw_start + section.SizeOfRawData]
            if section.Characteristics & 0x20000000:
                for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....', raw, re.DOTALL):
                    rva = section.VirtualAddress + match.start()
                    target = rva + 7 + struct.unpack_from('<i', match.group(), 3)[0]
                    if target in targets:
                        print('LEA_REFERENCE', targets[target], 'rva', hex(rva))
                        start = max(0, match.start() - 48)
                        for ins in disassembler.disasm(raw[start:match.start() + 80], image_base + section.VirtualAddress + start):
                            print(hex(ins.address - image_base), ins.mnemonic, ins.op_str)
            for target, name in targets.items():
                needle = struct.pack('<Q', image_base + target)
                for match in re.finditer(re.escape(needle), raw):
                    at = match.start()
                    print('POINTER_REFERENCE', name, section.Name, hex(section.VirtualAddress + at),
                          [hex(v) for v in struct.unpack('<QQQQ', raw[max(0, at - 8):max(0, at - 8) + 32])])


if __name__ == '__main__':
    main()
