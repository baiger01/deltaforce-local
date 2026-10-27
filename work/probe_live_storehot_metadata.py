"""Explicit shadow-process adapter for the source-gated StoreHot metadata reader.

No launches, native calls, game writes, hooks or heap scans. Default mode reads
only metadata. The optional image reader requires its separate typed contract.
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
import read_live_storehot_metadata as metadata
import read_live_storehot_image_rows as image_rows


def reader_contract(with_image_rows=False, source_pe=None):
    if type(with_image_rows) is not bool:
        raise ValueError('explicit_boolean_image_rows_mode_required')
    reader = image_rows if with_image_rows else metadata
    contract = reader.load_contract(source_pe=source_pe) if with_image_rows and source_pe is not None else reader.load_contract()
    return reader, contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--shadow-game', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image-rows', action='store_true',
                        help='Read four source-identified image rows only after the runtime RowStruct gate')
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    local.verify_creation(args.expected_create_time, args.expected_create_time)
    installed_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / local.source.CLIENT_RELATIVE_PATH
    reader, contract = reader_contract(args.image_rows, installed)
    local.source.verify_shadow_executable(shadow, shadow, installed)
    with installed.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != metadata.SOURCE_PE:
            raise ValueError('original_source_executable_sha256_mismatch')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
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
        modules, needed = (wintypes.HMODULE * 1024)(), wintypes.DWORD()
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
        if info.size != metadata.MODULE_SIZE:
            raise ValueError('source_module_size_changed')
        metadata._base(info.base, info.size)
        total = 0
        def read(address, size):
            nonlocal total
            metadata._base(address, size)
            if size > 1024 or total + size > metadata.MAX_TOTAL_READ:
                raise ValueError('bounded_metadata_adapter_read_budget_exceeded')
            total += size
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_metadata_adapter_read')
            return raw.raw
        report = reader.capture(read, info.base, contract)
        local.verify_creation(created(), creation)
        report.update(pid=args.pid, module_base=hex(info.base), module_size=info.size,
                      process_created_unix=creation, process_creation_rechecked=True,
                      shadow_executable=str(shadow.resolve()), game_launched=False,
                      image_rows_mode=args.image_rows,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'reason': report.get('reason'),
                          'captured_bytes': report['captured_bytes'], 'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
