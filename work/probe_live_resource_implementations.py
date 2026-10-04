"""Read two previously witnessed direct image-loader implementation targets.

Requires an already-running shadow client. No launches, writes, hooks, client
function calls, heap reads, indirect pointer reads, or further jump traversal.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import struct

from local_game_paths import game_paths
import probe_live_resource_loader as registration_probe


ROOT = Path(__file__).resolve().parent.parent
IMPLEMENTATIONS = {
    'FastRequestAsyncLoad': (0xd50d150, 0xd4cf330),
    'OnFastLoadComplete': (0xd50d190, 0xd4e0f20),
}
IMPLEMENTATION_SIZE = 2048
READ_POLICY = ('Existing four verified registration rows, names and eight named '
               'code prefixes, followed by exactly two independently witnessed '
               'direct-entry targets of 2048 bytes each; no other jump or pointer '
               'traversal, heap data, SDK access, writes, hooks or function calls')


def capture_implementations(read, base, module_size):
    if any(target < 0 or target + IMPLEMENTATION_SIZE > module_size
           for _, target in IMPLEMENTATIONS.values()):
        raise ValueError('Implementation witness exceeds the main module')
    report = registration_probe.capture(read, base, module_size)
    for name, (entry, target) in IMPLEMENTATIONS.items():
        block = report['fixed_code'][name + '_callback']
        code = bytes.fromhex(block['bytes'])
        if block['rva'] != entry or len(code) < 5 or code[0] != 0xe9:
            raise ValueError(f'{name} entry is not the witnessed direct jump')
        actual_target = entry + 5 + struct.unpack_from('<i', code, 1)[0]
        if actual_target != target:
            raise ValueError(f'{name} direct-entry target differs from the witnessed implementation')
    report['implementations'] = {}
    report['read_policy'] = READ_POLICY
    report['implementation_source'] = 'work/evidence/resource-runtime-witness-findings-20261004.md'
    for name, (entry, target) in IMPLEMENTATIONS.items():
        code = read(base + target, IMPLEMENTATION_SIZE)
        if not isinstance(code, bytes) or len(code) != IMPLEMENTATION_SIZE:
            raise ValueError('Implementation witness read length differs from its fixed bound')
        report['implementations'][name] = {
            'entry_rva': entry, 'direct_entry_jump_verified': True,
            'rva': target, 'size': IMPLEMENTATION_SIZE, 'bytes': code.hex(),
            'sha256': hashlib.sha256(code).hexdigest(),
            'scope': 'Fixed code prefix only; contained branch/call targets are not followed',
        }
        report['captured_bytes'] += IMPLEMENTATION_SIZE
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'work/evidence/live-resource-implementations.json')
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError('Expected an explicit native x64 client PID')
    source_root, shadow_root = game_paths()
    expected_shadow = shadow_root / registration_probe.CLIENT_RELATIVE_PATH
    source_executable = source_root / registration_probe.CLIENT_RELATIVE_PATH
    registration_probe.verify_shadow_executable(expected_shadow, expected_shadow, source_executable)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                              ctypes.POINTER(registration_probe.ModuleInfo), wintypes.DWORD]
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
        info = registration_probe.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, image, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        allowed = {(rva, 48) for rva, _ in registration_probe.REGISTRATIONS.values()}
        allowed.update((row[0], 32) for _, row in registration_probe.REGISTRATIONS.values())
        allowed.update(registration_probe.FIXED_CODE.values())
        allowed.update((target, IMPLEMENTATION_SIZE) for _, target in IMPLEMENTATIONS.values())

        def read(address, size):
            if ((address - info.base, size) not in allowed or not 0 < size <= IMPLEMENTATION_SIZE
                    or not info.base <= address < address + size <= info.base + info.size):
                raise ValueError('Read is outside the approved fixed native module witness')
            buffer = ctypes.create_string_buffer(size)
            count = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, buffer, size, ctypes.byref(count)):
                raise ctypes.WinError(ctypes.get_last_error())
            if count.value != size:
                raise ValueError('ReadProcessMemory returned a different witness length')
            return buffer.raw

        report = capture_implementations(read, info.base, info.size)
        report['pid'] = args.pid
        report['shadow_executable'] = str(expected_shadow.resolve())
        from probe_live_keybox_registration import capstone_module
        capstone = capstone_module()
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for block in (*report['fixed_code'].values(), *report['implementations'].values()):
            block['instructions'] = [
                {'rva': item.address - info.base, 'op': item.mnemonic, 'args': item.op_str}
                for item in disassembler.disasm(bytes.fromhex(block['bytes']), info.base + block['rva'])]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'registrations_verified': len(report['registrations']),
                          'implementation_ranges': len(report['implementations']),
                          'captured_bytes': report['captured_bytes'], 'report': str(args.output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    try:
        main()
    except OSError as error:
        print(json.dumps({'status': 'not_captured', 'type': type(error).__name__,
                          'windows_error': getattr(error, 'winerror', None)}))
        raise SystemExit(1)
