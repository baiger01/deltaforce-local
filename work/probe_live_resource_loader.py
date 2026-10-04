"""Capture fixed, named image-loader code from an already-running shadow client.

This diagnostic uses QUERY_INFORMATION and VM_READ only. It does not launch,
patch, hook, call client functions, follow heap pointers, or read player objects.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import struct

from local_game_paths import game_paths


ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CLIENT_RELATIVE_PATH = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
SOURCE_EVIDENCE = 'work/evidence/resource-image-routing-findings-20261004.md'

# Each tuple contains the original 48-byte registration's five pointer RVAs
# followed by its packed argument descriptor. No pointer is a traversal target.
REGISTRATIONS = {
    'Get': (0x18bdd6d0, (0x14ee5fa0, 0xd50d080, 0xd50d8c0,
                         0x18bdd9c8, 0x1d2d8340, 0x100000001)),
    'RequestAsyncLoad': (0x18bdd760, (0x169e0e50, 0xd50d090, 0xd50d7b0,
                                      0x14ee202c, 0x1d2d8360, 3)),
    'FastRequestAsyncLoad': (0x18bdd850, (0x18bc7848, 0xd50d150, 0xe050d0,
                                          0x14ee202c, 0x1d2d83b8, 2)),
    'OnFastLoadComplete': (0x18bdd910, (0x18bdda48, 0xd50d190, 0xe07100,
                                       0x14edf3dc, 0x1d2d83f8, 2)),
}
FIXED_CODE = {
    'Get_callback': (0xd50d080, 16),
    'RequestAsyncLoad_callback': (0xd50d090, 192),
    'FastRequestAsyncLoad_callback': (0xd50d150, 64),
    'OnFastLoadComplete_callback': (0xd50d190, 512),
    'Get_binding': (0xd50d8c0, 512),
    'RequestAsyncLoad_binding': (0xd50d7b0, 512),
    'FastRequestAsyncLoad_binding': (0xe050d0, 512),
    'OnFastLoadComplete_binding': (0xe07100, 512),
}
READ_POLICY = ('Four verified registration rows and names, and eight fixed named '
               'code prefixes in the main executable; no pointer traversal, heap '
               'data, SDK access, memory writes, hooks, or client function calls')


def verify_shadow_executable(path, expected_shadow, installed_source):
    path = Path(path).resolve()
    expected_shadow = Path(expected_shadow).resolve()
    if expected_shadow == Path(installed_source).resolve():
        raise ValueError('The shadow executable must be separate from the installed source')
    if path != expected_shadow:
        raise ValueError('PID does not identify the authorized shadow executable')
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != EXPECTED_PE:
        raise ValueError('Shadow executable differs from the verified source version')
    return digest.hexdigest()


def capture(read, base, module_size):
    spans = {(rva, 48) for rva, _ in REGISTRATIONS.values()}
    spans.update((row[0], 32) for _, row in REGISTRATIONS.values())
    spans.update(FIXED_CODE.values())
    if (not isinstance(base, int) or base <= 0 or not isinstance(module_size, int)
            or module_size <= 0 or base + module_size >= 1 << 64
            or any(rva < 0 or rva + size > module_size for rva, size in spans)):
        raise ValueError('Fixed resource witness ranges are outside the native module')
    captured_bytes = 0

    def fixed_read(rva, size):
        nonlocal captured_bytes
        if (rva, size) not in spans:
            raise ValueError('Read is not an approved fixed resource witness range')
        value = read(base + rva, size)
        if not isinstance(value, bytes) or len(value) != size:
            raise ValueError('Resource witness read length differs from its fixed bound')
        captured_bytes += size
        return value

    report = {'native_pe_sha256': EXPECTED_PE, 'module_base': base,
              'module_size': module_size, 'read_policy': READ_POLICY,
              'source_evidence': SOURCE_EVIDENCE, 'registrations': {}, 'fixed_code': {}}
    for name, (rva, source_row) in REGISTRATIONS.items():
        row = struct.unpack('<6Q', fixed_read(rva, 48))
        expected = tuple(base + value for value in source_row[:5]) + (source_row[5],)
        if row != expected:
            raise ValueError(f'Loaded {name} registration differs from the verified source')
        name_bytes = fixed_read(source_row[0], 32)
        if name_bytes.split(b'\0', 1)[0] != name.encode('ascii') or b'\0' not in name_bytes:
            raise ValueError(f'Loaded {name} registration name differs from the source')
        report['registrations'][name] = {
            'registration_rva': rva, 'name_rva': source_row[0],
            'callback_rva': source_row[1], 'binding_rva': source_row[2],
            'return_descriptor_rva': source_row[3],
            'argument_descriptor_rva': source_row[4], 'argument_flags': source_row[5],
            'all_fields_verified': True,
        }
    for name, (rva, size) in FIXED_CODE.items():
        code = fixed_read(rva, size)
        report['fixed_code'][name] = {
            'rva': rva, 'size': size, 'bytes': code.hex(),
            'sha256': hashlib.sha256(code).hexdigest(),
            'scope': 'Bounded code prefix, not a claim of complete function boundaries',
        }
    report['captured_bytes'] = captured_bytes
    return report


class ModuleInfo(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('size', wintypes.DWORD),
                ('entry', ctypes.c_void_p)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'work/evidence/live-resource-loader.json')
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError('Expected an explicit native x64 client PID')
    source_root, shadow_root = game_paths()
    expected_shadow = shadow_root / CLIENT_RELATIVE_PATH
    source_executable = source_root / CLIENT_RELATIVE_PATH
    verify_shadow_executable(expected_shadow, expected_shadow, source_executable)

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                              ctypes.POINTER(ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleInformation.restype = wintypes.BOOL
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                            wintypes.LPWSTR, wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.restype = wintypes.DWORD
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x0410, False, args.pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        modules = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise ValueError('Unexpected native module count')
        image = modules[0]
        path_buffer = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, image, path_buffer, len(path_buffer)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path_buffer.value).resolve() != expected_shadow.resolve():
            raise ValueError('PID does not identify the authorized shadow executable')
        info = ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, image, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())

        def read(address, size):
            if not 0 < size <= 512 or not info.base <= address < address + size <= info.base + info.size:
                raise ValueError('Read is outside the bounded native module witness')
            buffer = ctypes.create_string_buffer(size)
            count = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, buffer, size, ctypes.byref(count)):
                raise ctypes.WinError(ctypes.get_last_error())
            if count.value != size:
                raise ValueError('ReadProcessMemory returned a different witness length')
            return buffer.raw

        report = capture(read, info.base, info.size)
        report['pid'] = args.pid
        report['shadow_executable'] = str(expected_shadow.resolve())
        from probe_live_keybox_registration import capstone_module
        capstone = capstone_module()
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for block in report['fixed_code'].values():
            block['instructions'] = [
                {'rva': item.address - info.base, 'op': item.mnemonic, 'args': item.op_str}
                for item in disassembler.disasm(bytes.fromhex(block['bytes']), info.base + block['rva'])]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'registrations_verified': len(report['registrations']),
                          'fixed_code_ranges': len(report['fixed_code']),
                          'captured_bytes': report['captured_bytes'],
                          'report': str(args.output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
