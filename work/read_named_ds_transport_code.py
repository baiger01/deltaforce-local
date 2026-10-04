"""Read fixed, evidenced transport functions after normal Windows authorization.

No game launch, injection, memory write, credential/heap read or enforcement
change. Access denial is recorded and terminates this attempt. Direct jumps from
named image code may be followed once within independently verified PE unwind
bounds. Obtaining code does not establish an incoming packet transform.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

import capstone
import pefile
import psutil

from capture_official_ds import SOURCE_SHA, digest, verified_pids, save

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / 'work/evidence/ds-readonly-transport'
TARGETS = {'ReceivedRawPacket': 0x11d8a90, 'OnPacketRecv': 0x5cc9b90,
           'OnPacketSend': 0x5cca120, 'InitLocalConnection': 0x5be6c90}
PREDECESSOR = OUTPUT / '1790822317907608300'
IMPLEMENTATIONS = {
    'OnPacketRecv': (0x49c0f60, 0x49c1023, '51a135b654e32fa1d389ef0b742602c360b005f48c9af2625f1d65c9f1db52f5'),
    'OnPacketSend': (0x49c1200, 0x49c12ba, '8304d42218b4a7def9d596d0dc15ee2b4c2d7b6292f82730ee874dd198b7bcc3'),
}
IMPLEMENTATION_FRAGMENTS = {
    'OnPacketRecv': ((0x49c0f60, 0x49c1023), (0x49c1023, 0x49c1195),
                     (0x49c1195, 0x49c11fc)),
    'OnPacketSend': ((0x49c1200, 0x49c12ba), (0x49c12ba, 0x49c1375),
                     (0x49c1375, 0x49c13d8)),
}
DRIVER_BINDINGS = {
    'OnConnectionRecv': (0x162aee20, 0x5c0eb00),
    'OnConnectionSend': (0x162aee50, 0x5c0ef30),
    'InitRemoteConnection': (0x16232ef0, 0x5cc9310),
}
MAX_DRIVER_FUNCTION_BYTES = 8192


def validate_driver_bindings(executable):
    """Require exact names and code pointers in the same immutable PE image."""
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        pe = pefile.PE(data=raw, fast_load=True)
        base = pe.OPTIONAL_HEADER.ImageBase
        for name, (record_rva, code_rva) in DRIVER_BINDINGS.items():
            record_offset = pe.get_offset_from_rva(record_rva)
            name_va, code_va = struct.unpack_from('<QQ', raw, record_offset)
            name_offset = pe.get_offset_from_rva(name_va - base)
            if (raw[name_offset:name_offset + len(name) + 1] != name.encode('ascii') + b'\0' or
                    code_va - base != code_rva):
                raise ValueError('Named driver reflection record mismatch')
            if not any(s.Characteristics & 0x20000000 and s.VirtualAddress <= code_rva <
                       s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections):
                raise ValueError('Named driver prefix is not image code')


def direct_implementation_span(executable, prefix_rva, code):
    """Follow one E9 only; never dereference a live object or virtual table."""
    if len(code) != 32 or code[0] != 0xe9:
        raise ValueError('Named prefix is not a direct E9 jump')
    target = prefix_rva + 5 + struct.unpack_from('<i', code, 1)[0]
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        pe = pefile.PE(data=raw, fast_load=True)
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        offset = pe.get_offset_from_rva(directory.VirtualAddress)
        count = directory.Size // 12
        low, high = 0, count
        while low < high:
            middle = (low + high) // 2
            if struct.unpack_from('<I', raw, offset + middle * 12)[0] < target:
                low = middle + 1
            else:
                high = middle
        if low >= count:
            raise ValueError('Direct target has no image unwind entry')
        root = struct.unpack_from('<III', raw, offset + low * 12)
        if root[0] != target or not target < root[1] <= target + MAX_DRIVER_FUNCTION_BYTES:
            raise ValueError('Direct target does not start a bounded image function')
        root_unwind = pe.get_offset_from_rva(root[2])
        root_flags = raw[root_unwind]
        if root_flags & 7 != 1 or root_flags >> 3 == 4:
            raise ValueError('Direct target is an unwind continuation rather than a root')
        end = root[1]
        fragments = [root[:2]]
        for index in range(low + 1, min(count, low + 32)):
            entry = struct.unpack_from('<III', raw, offset + index * 12)
            if entry[0] != end:
                break
            unwind = pe.get_offset_from_rva(entry[2])
            version_flags, _prolog, code_count, _frame = struct.unpack_from('<4B', raw, unwind)
            if version_flags & 7 != 1 or version_flags >> 3 != 4:
                break
            chain = unwind + 4 + 4 * ((code_count + 1) // 2)
            if struct.unpack_from('<III', raw, chain) != root:
                break
            if not entry[0] < entry[1] <= target + MAX_DRIVER_FUNCTION_BYTES:
                raise ValueError('Direct implementation exceeds the declared code budget')
            end = entry[1]
            fragments.append(entry[:2])
        if not any(s.Characteristics & 0x20000000 and s.VirtualAddress <= target < end <=
                   s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections):
            raise ValueError('Direct implementation is outside executable image bounds')
        return target, end - target, fragments


def fixed_targets(executable, implementation_code):
    if not implementation_code:
        return {name: (rva, 32) for name, rva in TARGETS.items()}
    # A prior named binding must directly jump to this exact function, and
    # the immutable PE unwind table must independently bound the whole read.
    # These implementations have chained unwind fragments; the first .pdata
    # entry alone stops before the transport implementation begins.
    evidence = json.loads((PREDECESSOR / 'result.json').read_text(encoding='utf-8'))
    if evidence['client_sha256'] != SOURCE_SHA:
        raise ValueError('Predecessor client identity mismatch')
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        pe = pefile.PE(data=raw, fast_load=True)
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        start = pe.get_offset_from_rva(directory.VirtualAddress)
        count = directory.Size // 12
        targets = {}
        for name, (rva, end, pin) in IMPLEMENTATIONS.items():
            sample = (PREDECESSOR / (name + '.dfcode')).read_bytes()
            magic, previous_rva, length, _private_base = struct.unpack('<4Q', sample[:32])
            code = sample[32:]
            if (magic != 0x0000000145444344 or previous_rva != TARGETS[name] or
                    length != 32 or len(code) != 32 or hashlib.sha256(code).hexdigest() != pin or
                    code[0] != 0xe9 or previous_rva + 5 + struct.unpack('<i', code[1:5])[0] != rva):
                raise ValueError('Named predecessor jump evidence mismatch')
            low, high = 0, count
            while low < high:
                middle = (low + high) // 2
                first = struct.unpack_from('<I', raw, start + middle * 12)[0]
                if first < rva:
                    low = middle + 1
                else:
                    high = middle
            if low >= count or struct.unpack_from('<II', raw, start + low * 12) != (rva, end):
                raise ValueError('Function unwind boundary mismatch')
            root_entry = struct.unpack_from('<III', raw, start + low * 12)
            previous_end = rva
            for index, (fragment_rva, fragment_end) in enumerate(IMPLEMENTATION_FRAGMENTS[name]):
                entry = struct.unpack_from('<III', raw, start + (low + index) * 12)
                if entry[:2] != (fragment_rva, fragment_end) or fragment_rva != previous_end:
                    raise ValueError('Transport fragment boundary mismatch')
                if index:
                    unwind_offset = pe.get_offset_from_rva(entry[2])
                    version_flags, _prolog, code_count, _frame = struct.unpack_from('<4B', raw, unwind_offset)
                    chain_offset = unwind_offset + 4 + 4 * ((code_count + 1) // 2)
                    if (version_flags & 7 != 1 or version_flags >> 3 != 4 or
                            struct.unpack_from('<III', raw, chain_offset) != root_entry):
                        raise ValueError('Transport continuation does not chain to the named function')
                previous_end = fragment_end
            end = previous_end
            if not any(s.Characteristics & 0x20000000 and s.VirtualAddress <= rva < end <=
                       s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections):
                raise ValueError('Function is outside immutable executable section')
            targets[name] = (rva, end - rva)
    return targets


class Module(C.Structure):
    _fields_ = [('dwSize', W.DWORD), ('th32ModuleID', W.DWORD), ('th32ProcessID', W.DWORD),
                ('GlblcntUsage', W.DWORD), ('ProccntUsage', W.DWORD), ('modBaseAddr', C.c_void_p),
                ('modBaseSize', W.DWORD), ('hModule', W.HMODULE), ('szModule', W.WCHAR * 256),
                ('szExePath', W.WCHAR * 260)]


class Memory(C.Structure):
    _fields_ = [('BaseAddress', C.c_void_p), ('AllocationBase', C.c_void_p),
                ('AllocationProtect', W.DWORD), ('PartitionId', W.WORD), ('RegionSize', C.c_size_t),
                ('State', W.DWORD), ('Protect', W.DWORD), ('Type', W.DWORD)]


def kernel():
    api = C.WinDLL('kernel32', use_last_error=True)
    definitions = {
        'OpenProcess': ([W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
        'CloseHandle': ([W.HANDLE], W.BOOL),
        'CreateToolhelp32Snapshot': ([W.DWORD, W.DWORD], W.HANDLE),
        'Module32FirstW': ([W.HANDLE, C.POINTER(Module)], W.BOOL),
        'Module32NextW': ([W.HANDLE, C.POINTER(Module)], W.BOOL),
        'VirtualQueryEx': ([W.HANDLE, C.c_void_p, C.POINTER(Memory), C.c_size_t], C.c_size_t),
        'ReadProcessMemory': ([W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)], W.BOOL),
        'WaitForSingleObject': ([W.HANDLE, W.DWORD], W.DWORD),
        'GetProcessId': ([W.HANDLE], W.DWORD),
    }
    for name, (arguments, result) in definitions.items():
        function = getattr(api, name)
        function.argtypes, function.restype = arguments, result
    return api


def collect(game_root, folder, implementation_code=False, wait_seconds=0):
    executable = game_root / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    if digest(executable) != SOURCE_SHA:
        raise ValueError('Client version hash mismatch')
    targets = fixed_targets(executable, implementation_code)
    if implementation_code:
        validate_driver_bindings(executable)
        targets.update({name: (rva, 32) for name, (_, rva) in DRIVER_BINDINGS.items()})
    report = {'kind': 'bounded_named_transport_code_read', 'client_sha256': SOURCE_SHA,
              'game_modified': False, 'process_memory_written': False, 'credential_memory_read': False,
              'maximum_code_bytes': sum(size for _, size in targets.values()) +
                  (len(DRIVER_BINDINGS) * MAX_DRIVER_FUNCTION_BYTES if implementation_code else 0),
              'implementation_code': implementation_code,
              'named_driver_direct_code_requested': implementation_code,
              'functions': [], 'incoming_transform_identified': False,
              'observed_at_utc': datetime.now(timezone.utc).isoformat()}
    pids = verified_pids(executable)
    deadline = time.monotonic() + wait_seconds
    report['status'] = 'waiting_for_original_game' if not pids else 'process_identified'
    save(folder / 'result.json', report)
    while not pids and time.monotonic() < deadline:
        time.sleep(1)
        pids = verified_pids(executable)
    api = kernel()
    handle = api.OpenProcess(0x1010, False, pids[0]) if len(pids) == 1 else None
    if not handle:
        report.update(status='read_not_permitted' if len(pids) == 1 else 'original_process_not_unique',
                      windows_error=C.get_last_error() if len(pids) == 1 else None)
        save(folder / 'result.json', report)
        return report
    expected = os.path.normcase(str(executable.resolve()))
    process_start = psutil.Process(pids[0]).create_time()
    snapshot = api.CreateToolhelp32Snapshot(0x18, pids[0])
    try:
        base, size = None, None
        if snapshot and snapshot != C.c_void_p(-1).value:
            item = Module()
            item.dwSize = C.sizeof(item)
            ok = api.Module32FirstW(snapshot, C.byref(item))
            while ok:
                if os.path.normcase(str(Path(item.szExePath).resolve())) == expected:
                    base, size = item.modBaseAddr, item.modBaseSize
                    break
                ok = api.Module32NextW(snapshot, C.byref(item))
        if base is None:
            report.update(status='module_identity_unavailable', windows_error=C.get_last_error())
        else:
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            plan = list(targets.items())
            for name, (rva, length) in plan:
                if psutil.Process(pids[0]).create_time() != process_start:
                    raise RuntimeError('Original process identity changed')
                address, memory = base + rva, Memory()
                entry = {'method': name, 'rva': hex(rva), 'code_bytes': length, 'read_succeeded': False}
                valid = (rva + length <= size and
                         api.VirtualQueryEx(handle, address, C.byref(memory), C.sizeof(memory)) == C.sizeof(memory) and
                         memory.State == 0x1000 and memory.Type == 0x1000000 and
                         memory.AllocationBase == base and memory.Protect & 0xff in (0x10, 0x20, 0x40, 0x80) and
                         not memory.Protect & 0x100 and address + length <= memory.BaseAddress + memory.RegionSize)
                if not valid:
                    entry['read_refused_reason'] = 'image_executable_page_guard_not_satisfied'
                else:
                    buffer, copied = (C.c_ubyte * length)(), C.c_size_t()
                    if api.ReadProcessMemory(handle, address, buffer, length, C.byref(copied)) and copied.value == length:
                        code = bytes(buffer)
                        instructions = list(decoder.disasm(code, rva))
                        entry.update(read_succeeded=True, code_sha256=hashlib.sha256(code).hexdigest(),
                                     first_instructions=[f'{ins.mnemonic} {ins.op_str}'
                                                         for ins in instructions[:5]],
                                     disassembled_bytes=sum(ins.size for ins in instructions))
                        (folder / (name + '.dfcode')).write_bytes(struct.pack('<4Q', 0x0000000145444344, rva, length, base) + code)
                        (folder / (name + '.asm.txt')).write_text('\n'.join(
                            f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}' for ins in instructions) + '\n', encoding='utf-8')
                        if implementation_code and name in DRIVER_BINDINGS:
                            try:
                                target, span, fragments = direct_implementation_span(executable, rva, code)
                                entry['direct_implementation_follow'] = {
                                    'target_rva': hex(target), 'code_bytes': span,
                                    'source_prefix_sha256': entry['code_sha256'],
                                    'unwind_fragments': [[hex(a), hex(b)] for a, b in fragments]}
                                plan.append((name + '.implementation', (target, span)))
                            except ValueError as error:
                                entry['direct_implementation_not_followed'] = str(error)
                    else:
                        entry['windows_error'] = C.get_last_error()
                report['functions'].append(entry)
            report['status'] = 'bounded_read_attempt_complete'
    finally:
        if snapshot and snapshot != C.c_void_p(-1).value:
            api.CloseHandle(snapshot)
        api.CloseHandle(handle)
    save(folder / 'result.json', report)
    return report


def elevate(game_root, implementation_code=False, wait_seconds=0):
    class ShellInfo(C.Structure):
        _fields_ = [('cbSize', W.DWORD), ('fMask', W.ULONG), ('hwnd', W.HWND),
                    ('lpVerb', W.LPCWSTR), ('lpFile', W.LPCWSTR), ('lpParameters', W.LPCWSTR),
                    ('lpDirectory', W.LPCWSTR), ('nShow', C.c_int), ('hInstApp', W.HINSTANCE),
                    ('lpIDList', C.c_void_p), ('lpClass', W.LPCWSTR), ('hkeyClass', W.HKEY),
                    ('dwHotKey', W.DWORD), ('hIcon', W.HANDLE), ('hProcess', W.HANDLE)]
    OUTPUT.mkdir(parents=True, exist_ok=True)
    folder = OUTPUT / str(time.time_ns())
    folder.mkdir()
    request = {'game_root': str(game_root.resolve()), 'helper_sha256': digest(Path(__file__)),
               'implementation_code': implementation_code, 'wait_for_game_seconds': wait_seconds}
    save(folder / 'request.json', request)
    info = ShellInfo()
    info.cbSize, info.fMask, info.lpVerb, info.lpFile = C.sizeof(info), 0x140, 'runas', sys.executable
    user = C.WinDLL('user32', use_last_error=True)
    user.GetForegroundWindow.argtypes = []
    user.GetForegroundWindow.restype = W.HWND
    info.hwnd = user.GetForegroundWindow()
    info.lpParameters = subprocess.list2cmdline([str(Path(__file__).resolve()), '--worker', str(folder)])
    info.lpDirectory, info.nShow = str(ROOT), 0
    shell = C.WinDLL('shell32', use_last_error=True).ShellExecuteExW
    shell.argtypes, shell.restype = [C.POINTER(ShellInfo)], W.BOOL
    scope = ('two verified transport functions and three named driver paths '
             '(25812 bytes maximum)') if implementation_code else 'four fixed code prefixes (128 bytes maximum)'
    print('Requesting normal Windows authorization for ' + scope, flush=True)
    if not shell(C.byref(info)):
        save(folder / 'result.json', {'status': 'authorization_failed', 'windows_error': C.get_last_error()})
        return 1
    api = kernel()
    try:
        if not info.hProcess:
            raise RuntimeError('Code reader process handle unavailable')
        print(json.dumps({'helper_pid': api.GetProcessId(info.hProcess),
                          'result_relative_to_project_root': (folder / 'result.json').relative_to(ROOT).as_posix()}), flush=True)
        # Worker performs one bounded read and exits; no repeated access retry.
        while api.WaitForSingleObject(info.hProcess, 1000) == 258:
            pass
    finally:
        if info.hProcess:
            api.CloseHandle(info.hProcess)
    result = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
    print(json.dumps(result, indent=2), flush=True)
    return 0 if any(entry.get('read_succeeded') for entry in result.get('functions', [])) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path)
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--implementation-code', action='store_true')
    parser.add_argument('--wait-for-game-seconds', type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.wait_for_game_seconds <= 300:
        parser.error('Wait must be between zero and 300 seconds')
    if args.worker:
        folder = args.worker.resolve()
        if folder.parent != OUTPUT.resolve():
            parser.error('Worker request must be in this code-read directory')
        request = json.loads((folder / 'request.json').read_text(encoding='utf-8'))
        if request['helper_sha256'] != digest(Path(__file__)):
            parser.error('Code reader changed after preparation')
        try:
            result = collect(Path(request['game_root']), folder, request.get('implementation_code', False),
                             request.get('wait_for_game_seconds', 0))
        except Exception as error:
            result = {'status': 'bounded_read_failed', 'error_type': type(error).__name__,
                      'game_modified': False, 'functions': []}
            save(folder / 'result.json', result)
        raise SystemExit(0 if any(e.get('read_succeeded') for e in result.get('functions', [])) else 1)
    if args.game_root is None:
        parser.error('Provide the original game root')
    raise SystemExit(elevate(args.game_root, args.implementation_code, args.wait_for_game_seconds))
