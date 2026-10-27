"""Observe two source-witnessed FileExists-route getter code ranges.

The first range is only a 16-byte prefix without a .pdata function extent.
The second is its original .pdata-bounded 31-byte function. No getter calls,
returned pointers, contained calls or virtual methods are followed.
"""

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from local_game_paths import game_paths
import probe_live_local_image_loader as local
from read_keybox_manager_interface import MODULE_SIZE


ROOT = Path(__file__).resolve().parent.parent
SOURCE_PE = local.source.EXPECTED_PE
SOURCE_CAPTURE = ROOT / 'work/evidence/live-local-image-package-brush-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '01f326632251d583a7db7eefa63929caceacc6ec9d7dc0a72612da1c97d35d09'
CALLER_RVA, CALLER_SIZE = 0x10ecd110, 1024
CALLER_SHA = 'a577995db5aa053db3a4aca176bd0352d104530972184f531822d1ad0ad96635'
FIRST_RVA, FIRST_SIZE = 0x10a2d880, 16
SECOND_RVA, SECOND_SIZE = 0x10a33080, 31
EDGES = ((0x10ecd287, FIRST_RVA, bytes.fromhex('e8f405b6ff')),
         (0x10ecd28f, SECOND_RVA, bytes.fromhex('e8ec5db6ff')))
METADATA = (
    ('caller_pdata', 510416412, '10d1ec105bd3ec10dc06e11b',
     'dcbad3401942aa79c0849becdcf4389f53b00f4d07dd2c00b9d14a65382c379a'),
    ('caller_unwind', 467729116, '011a0a001a7413001a6412001a5411001a3410001ad216e0',
     'f036f13a657e761fef80cd74418e7fef7bf2ee0fdf4da9069ed5285e0b8c1102'),
    ('first_previous_pdata', 510240744, '62d8a2106ad8a2106048701c',
     '172e37b3d07f01a2a7a16683af40f8fef8ab5bf7632a85e8a1d181442cc256b3'),
    ('first_next_pdata', 510240756, '90d8a21019d9a210f4b3dc1b',
     '60caa9caf3fdda0280331bfe4093ab54654757c12ed0e4ed2ae5b6fd088c28f0'),
    ('second_pdata', 510241596, '8030a3109f30a310acb3dc1b',
     '30083ba5182bdae4b72262d400b7c9fbdf51d83f9eeb30e40db3a5be6be8d399'),
    ('second_unwind', 467445676, '0106020006320230',
     'eb874a2d5756386f3a7d463290a08f132ac00fa4e4080cfb811bafc05b2569b2'),
)
DISK_CODE = (
    ('caller', 283952912, 587,
     '837a61c0165f8ffdfae2fad8503f0934ab5a2cf37fecbbd18ea99e1c1106c414'),
    ('first_prefix', 279105152, FIRST_SIZE,
     'ec3aed7e618737a9c762190a98c657131d299392bbdbcab1f53b545c93336156'),
    ('second', 279127680, SECOND_SIZE,
     '71ece75fe249ba00133871fc770979874ab1343e6219a6e727ab99b8caf81028'),
)


def verify_calls(code):
    for site, target, expected in EDGES:
        raw = code[site - CALLER_RVA:site - CALLER_RVA + 5]
        if (raw != expected or site + 5 + struct.unpack_from('<i', raw, 1)[0] != target):
            raise ValueError('fileexists_getter_direct_E8_witness_changed')


def verify_caller(code):
    if len(code) != CALLER_SIZE or hashlib.sha256(code).hexdigest() != CALLER_SHA:
        raise ValueError('fileexists_getter_fresh_caller_hash_changed')
    verify_calls(code)


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_fileexists_source_required')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_fileexists_source_full_hash_changed')
    report = json.loads(raw)
    if report.get('native_pe_sha256') != SOURCE_PE:
        raise ValueError('saved_fileexists_source_PE_changed')
    block = report['package_brush']['PackagePathPredicate']
    if (block['rva'], block['size'], block['sha256']) != (CALLER_RVA, CALLER_SIZE, CALLER_SHA):
        raise ValueError('saved_fileexists_source_caller_coordinates_changed')
    verify_caller(bytes.fromhex(block['bytes']))
    return SOURCE_CAPTURE_SHA


def verify_metadata(read_at):
    qualified = {}
    for name, offset, expected, digest in METADATA:
        raw = read_at(offset, len(bytes.fromhex(expected)))
        if (not isinstance(raw, bytes) or raw.hex() != expected
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_fileexists_getter_metadata_changed_' + name)
        qualified[name] = {'file_offset': offset, 'bytes': raw.hex(), 'sha256': digest}
    disk = {}
    for name, offset, size, digest in DISK_CODE:
        raw = read_at(offset, size)
        if (not isinstance(raw, bytes) or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_fileexists_getter_disk_code_changed_' + name)
        disk[name] = {'file_offset': offset, 'size': size, 'sha256': digest,
                      'runtime_plaintext_hash': False}
    return {'metadata': qualified, 'disk_code': disk,
            'caller': {'begin_rva': CALLER_RVA, 'end_exclusive_rva': 0x10ecd35b,
                       'function_bytes': 587, 'captured_prefix_bytes': CALLER_SIZE},
            'first_getter': {'begin_rva': FIRST_RVA, 'prefix_bytes': FIRST_SIZE,
                             'function_complete': False, 'covering_pdata_row': False,
                             'preceding_pdata_end_rva': 0x10a2d86a,
                             'next_pdata_begin_rva': 0x10a2d890},
            'second_getter': {'begin_rva': SECOND_RVA, 'end_exclusive_rva': 0x10a3309f,
                              'function_bytes': SECOND_SIZE, 'function_complete': True}}


def verify_original(path):
    with Path(path).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_PE:
            raise ValueError('original_fileexists_source_PE_sha256_mismatch')
        def read_at(offset, size):
            stream.seek(offset)
            return stream.read(size)
        return verify_metadata(read_at)


def allowed_spans():
    return {(CALLER_RVA, CALLER_SIZE), (FIRST_RVA, FIRST_SIZE), (SECOND_RVA, SECOND_SIZE)}


def capture(read, base, module_size, *, source_digest, actual_created, expected_created):
    local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_fileexists_source_required')
    spans = allowed_spans()
    if (type(base) is not int or type(module_size) is not int or base <= 0 or module_size <= 0
            or base + module_size >= 0x800000000000
            or any(not 0 <= rva < rva + size <= module_size for rva, size in spans)):
        raise ValueError('fixed_fileexists_getter_ranges_outside_module')
    total = 0
    def fixed(rva, size, complete):
        nonlocal total
        if (rva, size) not in spans or not 0 < size <= 1024:
            raise ValueError('read_outside_fixed_fileexists_getter_scope')
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_fileexists_getter_read')
        total += size
        return {'rva': rva, 'size': size, 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest(), 'function_complete': complete}
    caller = fixed(CALLER_RVA, CALLER_SIZE, False)
    verify_caller(bytes.fromhex(caller['bytes']))
    first = fixed(FIRST_RVA, FIRST_SIZE, False)
    second = fixed(SECOND_RVA, SECOND_SIZE, True)
    return {'native_pe_sha256': SOURCE_PE, 'source_capture_sha256': source_digest,
            'source_code': caller,
            'fixed_code': {'FileExistsFirstGetterPrefix': first, 'FileExistsSecondGetter': second},
            'direct_E8_witnesses_verified': True, 'fresh_caller_full_span_verified': True,
            'captured_bytes': total, 'heap_read': False, 'pointer_followed': False,
            'native_called': False, 'game_launched': False,
            'filesystem_pointer_contract_proven': False, 'fileexists_outcome_proven': False,
            'scope': 'Pinned1024B caller and both exact E8 witnesses; fixed first16B getter '
                     'prefix and original-pdata-bounded second31B getter; no heap, singleton '
                     'slot, contained call or vtable follow; no native call or game write'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--shadow-game', type=Path, required=True)
    parser.add_argument('--source-capture', type=Path, default=SOURCE_CAPTURE)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    digest = load_source(args.source_capture)
    installed_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / local.source.CLIENT_RELATIVE_PATH
    extents = verify_original(installed)
    local.source.verify_shadow_executable(shadow, shadow, installed)
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
            raise ValueError('unexpected_fileexists_module_count')
        path = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, modules[0], path, len(path)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path.value).resolve() != shadow.resolve():
            raise ValueError('PID_does_not_identify_authorized_shadow_executable')
        info = local.source.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.size != MODULE_SIZE:
            raise ValueError('source_fileexists_module_size_changed')
        def read(address, size):
            if ((address - info.base, size) not in allowed_spans() or not 0 < size <= 1024
                    or not info.base <= address < address + size <= info.base + info.size):
                raise ValueError('process_read_outside_fixed_fileexists_getter_scope')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_fileexists_getter_adapter_read')
            return raw.raw
        report = capture(read, info.base, info.size, source_digest=digest,
                         actual_created=creation, expected_created=args.expected_create_time)
        local.verify_creation(created(), creation)
        report.update(source_extents=extents, source_extents_verified=True, pid=args.pid,
                      module_base=hex(info.base), module_size=info.size,
                      process_created_unix=creation, process_creation_rechecked=True,
                      shadow_executable=str(shadow.resolve()), process_accessed=True,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'captured_bytes': report['captured_bytes'], 'heap_read': False,
                          'pointer_followed': False, 'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
