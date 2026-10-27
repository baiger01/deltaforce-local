"""Read one fixed code span to recheck missing UObject path source evidence.

The RVA is an unverified research landmark from a preserved offline validator,
not authority to read object fields. No heap reads, native calls or launches.
"""

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from local_game_paths import game_paths
import probe_live_local_image_loader as local

ROOT = Path(__file__).resolve().parent.parent
CODE_RVA = 0x10ead090
CODE_SIZE = 1024
MODULE_SIZE = 0x1ff8f000
LANDMARK_FILE = ROOT / 'work/offline_validate_metadata_paths.py'
LANDMARK_SHA = '3ddb22450346e9c74754c4275724512beb3cc4f53a414db989d01454862c56f2'


def verify_landmark(path=LANDMARK_FILE):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size < 65536:
        raise ValueError('bounded_preserved_landmark_file_required')
    with path.open('rb') as stream:
        raw = stream.read(65536)
    if hashlib.sha256(raw).hexdigest() != LANDMARK_SHA:
        raise ValueError('preserved_landmark_file_sha256_changed')
    return LANDMARK_SHA


def capture(read, base, module_size, creation, expected_creation):
    local.verify_creation(creation, expected_creation)
    if module_size != MODULE_SIZE:
        raise ValueError('source_module_size_changed')
    if (type(base) is not int or base < 0x10000
            or base + module_size > 0x800000000000):
        raise ValueError('invalid_main_module_base')
    if not 0 <= CODE_RVA < CODE_RVA + CODE_SIZE <= module_size:
        raise ValueError('fixed_code_span_outside_main_module')
    raw = read(base + CODE_RVA, CODE_SIZE)
    if not isinstance(raw, bytes) or len(raw) != CODE_SIZE:
        raise ValueError('short_fixed_metadata_code_read')
    return {
        'native_pe_sha256': local.source.EXPECTED_PE,
        'module_base': hex(base), 'module_size': module_size,
        'process_created_unix': creation,
        'landmark_file': LANDMARK_FILE.relative_to(ROOT).as_posix(),
        'landmark_file_sha256': LANDMARK_SHA,
        'landmark_status': 'Preserved script address only; source bytes independently rechecked after capture',
        'code': {'rva': CODE_RVA, 'size': CODE_SIZE, 'bytes': raw.hex(),
                 'sha256': hashlib.sha256(raw).hexdigest()},
        'captured_bytes': CODE_SIZE,
        'schema_verified': False, 'object_fields_read': False,
        'heap_read': False, 'native_called': False,
        'scope': 'One fixed1024B main-module code span; no targets or pointers followed',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--shadow-game', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    local.verify_creation(args.expected_create_time, args.expected_create_time)
    verify_landmark()
    game_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = local.output_path(args.output, game_root, shadow_root)
    installed = game_root / local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / local.source.CLIENT_RELATIVE_PATH
    local.source.verify_shadow_executable(shadow, shadow, installed)
    with installed.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != local.source.EXPECTED_PE:
            raise ValueError('original_source_executable_sha256_mismatch')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(local.source.ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleInformation.restype = wintypes.BOOL
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.restype = wintypes.DWORD
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x0410, False, args.pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        def created():
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            ticks = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            return ticks / 10000000 - 11644473600
        creation = created()
        local.verify_creation(creation, args.expected_create_time)
        modules = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise ValueError('unexpected_native_module_count')
        path = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, modules[0], path, len(path)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path.value).resolve() != shadow.resolve():
            raise ValueError('PID_does_not_identify_authorized_shadow_executable')
        info = local.source.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        def read(address, size):
            if (address, size) != (info.base + CODE_RVA, CODE_SIZE):
                raise ValueError('read_outside_fixed_metadata_code_scope')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_fixed_metadata_code_read')
            return raw.raw
        report = capture(read, info.base, info.size, creation, args.expected_create_time)
        local.verify_creation(created(), creation)
        report.update(pid=args.pid, shadow_executable=str(shadow.resolve()),
                      process_creation_rechecked=True,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'captured_bytes': CODE_SIZE, 'schema_verified': False, 'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
