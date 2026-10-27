"""Opt-in typed package-cache metadata for12 closed original shop image paths.

Default: zero process access. The enabled mode accepts only an explicitly
identified shadow PID and observed creation time; no path, pointer, or RVA CLI.
No game launch, native call, hook, process write, or original/shadow file write.
"""

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
from pathlib import Path

from local_game_paths import game_paths
import package_cache_path_lookup as paths
import probe_live_local_image_loader as local


def module_spans(contract):
    return {(rva, len(data)) for rva, data in contract.blocks} | {
        (paths.ROOT_SLOT, 8), (paths.LOWER_RVA, 128), (paths.CRC_RVA, 1024),
        (paths.ALLOCATOR_SLOT, 8), (paths.DELIMITER_SLOT, 8), (paths.DELIMITER_RVA, 4)}


def bounded_read_arguments(address, size, base, spans, total):
    paths._address(address, size)
    if not 0 < size <= 1024 or total + size > paths.MAX_TOTAL_READ:
        raise ValueError('package_cache_adapter_read_budget_exceeded')
    module_end = base + paths.MODULE_SIZE
    if address < module_end and address + size > base:
        if (address - base, size) not in spans:
            raise ValueError('package_cache_adapter_module_read_not_source_qualified')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--shadow-game', type=Path, required=True)
    parser.add_argument('--enable-diagnostic', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    local.verify_creation(args.expected_create_time, args.expected_create_time)
    installed_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / local.source.CLIENT_RELATIVE_PATH
    if not args.enable_diagnostic:
        report = paths.capture(None, 0, None)
        report.update(process_accessed=False, game_launched=False, pointer_followed=False,
                      scope='Disabled by default; no process access')
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': 'disabled', 'process_accessed': False, 'report': str(output)}))
        return
    local.source.verify_shadow_executable(shadow, shadow, installed)
    contract = paths.load_contract(installed)
    spans = module_spans(contract)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                              ctypes.POINTER(local.source.ModuleInfo), wintypes.DWORD]
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
        if info.size != paths.MODULE_SIZE:
            raise ValueError('source_module_size_changed')
        total = 0

        def read(address, size):
            nonlocal total
            bounded_read_arguments(address, size, info.base, spans, total)
            total += size
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_package_cache_adapter_read')
            return raw.raw

        report = paths.capture(read, info.base, contract, enabled=True)
        local.verify_creation(created(), creation)
        report.update(pid=args.pid, module_base=hex(info.base), module_size=info.size,
                      process_created_unix=creation, process_creation_rechecked=True,
                      shadow_executable=str(shadow.resolve()), process_accessed=True,
                      game_launched=False, arbitrary_heap_scanned=False,
                      source_input='Full-SHA-pinned static catalog;12 fields from4 original rows',
                      runtime_selected_rows_compared=False,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        if total != report['captured_bytes']:
            raise ValueError('package_cache_adapter_read_total_changed')
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'reason': report.get('reason'),
                          'captured_bytes': total, 'paths': len(report.get('paths', ())),
                          'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
