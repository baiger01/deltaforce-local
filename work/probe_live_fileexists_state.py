"""Observe one source-proven module receiver slot and its direct initializer code.

Fixed reads only. The module slot's first qword is recorded without following it.
No native getter, initializer or virtual query is called by this observer.
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
import probe_live_fileexists_getters as prior


SOURCE_CAPTURE = prior.ROOT / 'work/evidence/live-package-fileexists-getters-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '91b270aff468d39b242f9c4cf8277982261a1a69ca55ad4a47a1178faa0d5301'
FIRST_SHA = '6da3eb4deeba44e9e375ffec3838d83e3e34e63bbe9e958d260246356bf5155a'
SECOND_SHA = '484622aee72331c342e2242b3c224b8fb4f0398b22aacdfb0413e44ff40765df'
SLOT_RVA = 0x1e2eff78
SLOT_LEA = bytes.fromhex('488d05f1268c0d')
INIT_SITE, INIT_RVA, INIT_SIZE = 0x10a33091, 0x10b68b50, 98
INIT_CALL = bytes.fromhex('e8ba5a1300')
INIT_DISK_OFFSET = 280396112
INIT_DISK_SHA = '4be1d3e3797ce7444fbe043ba6ad56e4d4c208a59d52062b58ec88515f088555'
INIT_METADATA = (
    ('pdata', 510302652, '508bb610b28bb610f4b3dc1b',
     'f4313f7a290dc651d58b41184d730f2b129076d3dbd59721ebaa22271db7c612'),
    ('unwind', 467445748, '0104010004420000',
     '2d8867f028f39ef522d70e56d169d2fbb9046163869f9360ec470bdd2040cd24'),
)


def verify_getters(first, second):
    if (len(first) != prior.FIRST_SIZE or hashlib.sha256(first).hexdigest() != FIRST_SHA
            or len(second) != prior.SECOND_SIZE or hashlib.sha256(second).hexdigest() != SECOND_SHA):
        raise ValueError('fileexists_state_fresh_getter_hash_changed')
    if (first[:7] != SLOT_LEA or first[7:] != b'\xc3' + b'\xcc' * 8
            or prior.FIRST_RVA + 7 + struct.unpack_from('<i', first, 3)[0] != SLOT_RVA):
        raise ValueError('fileexists_state_exact_leaf_LEA_RET_changed')
    at = INIT_SITE - prior.SECOND_RVA
    if (second[at:at + 5] != INIT_CALL
            or INIT_SITE + 5 + struct.unpack_from('<i', second, at + 1)[0] != INIT_RVA
            or second[6:9] != bytes.fromhex('488b01')
            or second[9:17] != bytes.fromhex('488bd94885c07508')
            or second[22:25] != bytes.fromhex('488903')):
        raise ValueError('fileexists_state_exact_qword_and_initializer_contract_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_fileexists_getters_source_required')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_fileexists_getters_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != prior.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA):
        raise ValueError('saved_fileexists_getters_source_chain_changed')
    caller = d['source_code']
    if (caller['rva'], caller['size'], caller['sha256']) != (
            prior.CALLER_RVA, prior.CALLER_SIZE, prior.CALLER_SHA):
        raise ValueError('saved_fileexists_getters_caller_coordinates_changed')
    prior.verify_caller(bytes.fromhex(caller['bytes']))
    blocks = d['fixed_code']
    first, second = blocks['FileExistsFirstGetterPrefix'], blocks['FileExistsSecondGetter']
    if ((first['rva'], first['size'], first['sha256']) != (prior.FIRST_RVA, 16, FIRST_SHA)
            or (second['rva'], second['size'], second['sha256']) != (prior.SECOND_RVA, 31, SECOND_SHA)):
        raise ValueError('saved_fileexists_getter_coordinates_changed')
    verify_getters(bytes.fromhex(first['bytes']), bytes.fromhex(second['bytes']))
    return SOURCE_CAPTURE_SHA


def verify_init_metadata(read_at):
    rows = {}
    for name, offset, expected, digest in INIT_METADATA:
        raw = read_at(offset, len(bytes.fromhex(expected)))
        if (not isinstance(raw, bytes) or raw.hex() != expected
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_fileexists_initializer_metadata_changed_' + name)
        rows[name] = {'file_offset': offset, 'bytes': raw.hex(), 'sha256': digest}
    code = read_at(INIT_DISK_OFFSET, INIT_SIZE)
    if (not isinstance(code, bytes) or len(code) != INIT_SIZE
            or hashlib.sha256(code).hexdigest() != INIT_DISK_SHA):
        raise ValueError('original_fileexists_initializer_disk_code_changed')
    return {'begin_rva': INIT_RVA, 'end_exclusive_rva': 0x10b68bb2, 'function_bytes': INIT_SIZE,
            'metadata': rows, 'disk_code_offset': INIT_DISK_OFFSET,
            'disk_code_sha256': INIT_DISK_SHA, 'runtime_plaintext_hash': False}


def verify_original(path):
    original = prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(offset, size):
            stream.seek(offset)
            return stream.read(size)
        original['initializer'] = verify_init_metadata(read_at)
    return original


def allowed_spans():
    return {*prior.allowed_spans(), (INIT_RVA, INIT_SIZE), (SLOT_RVA, 8)}


def capture(read, base, module_size, *, source_digest, actual_created, expected_created):
    prior.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_fileexists_getters_source_required')
    spans = allowed_spans()
    if (type(base) is not int or type(module_size) is not int or base <= 0 or module_size <= 0
            or base + module_size >= 0x800000000000
            or any(not 0 <= rva < rva + size <= module_size for rva, size in spans)):
        raise ValueError('fixed_fileexists_state_ranges_outside_module')
    total = 0
    def fixed(rva, size):
        nonlocal total
        if (rva, size) not in spans or not 0 < size <= 1024:
            raise ValueError('read_outside_fixed_fileexists_state_scope')
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_fileexists_state_read')
        total += size
        return {'rva': rva, 'size': size, 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest()}
    caller = fixed(prior.CALLER_RVA, prior.CALLER_SIZE)
    prior.verify_caller(bytes.fromhex(caller['bytes']))
    first = fixed(prior.FIRST_RVA, prior.FIRST_SIZE)
    second = fixed(prior.SECOND_RVA, prior.SECOND_SIZE)
    verify_getters(bytes.fromhex(first['bytes']), bytes.fromhex(second['bytes']))
    initializer = fixed(INIT_RVA, INIT_SIZE)
    slot = fixed(SLOT_RVA, 8)
    repeated = fixed(SLOT_RVA, 8)
    if repeated['bytes'] != slot['bytes']:
        raise ValueError('fileexists_receiver_slot_changed_during_capture')
    slot['first_qword'] = hex(struct.unpack('<Q', bytes.fromhex(slot['bytes']))[0])
    slot['pointer_followed'] = False
    first.update(control_flow_complete_leaf=True, body_bytes=8, extent_from_pdata=False)
    second['function_complete'] = True
    initializer['function_complete'] = True
    return {'native_pe_sha256': prior.SOURCE_PE, 'source_capture_sha256': source_digest,
            'source_code': caller,
            'fixed_code': {'FileExistsFirstGetterLeaf': first, 'FileExistsSecondGetter': second,
                           'FileExistsReceiverInitializer': initializer},
            'receiver_slot': slot, 'receiver_slot_rechecked': True,
            'leaf_LEA_RET_and_qword_contract_verified': True,
            'direct_initializer_E8_verified': True, 'captured_bytes': total,
            'heap_read': False, 'pointer_followed': False, 'native_called': False,
            'game_launched': False, 'filesystem_object_identity_proven': False,
            'fileexists_outcome_proven': False,
            'scope': 'Pinned caller1024B/getters16B+31B; exact LEA+RET and qword contract; '
                     'original-pdata initializer98B; source-fixed module receiver slot8B '
                     'plus8B recheck; no heap, pointer/call/vtable follow, native call or game write'}


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
    output = prior.local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / prior.local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / prior.local.source.CLIENT_RELATIVE_PATH
    extents = verify_original(installed)
    prior.local.source.verify_shadow_executable(shadow, shadow, installed)
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
                                             ctypes.POINTER(prior.local.source.ModuleInfo), wintypes.DWORD]
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
        prior.local.verify_creation(creation, args.expected_create_time)
        modules, needed = (wintypes.HMODULE * 1024)(), wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise ValueError('unexpected_fileexists_state_module_count')
        path = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, modules[0], path, len(path)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path.value).resolve() != shadow.resolve():
            raise ValueError('PID_does_not_identify_authorized_shadow_executable')
        info = prior.local.source.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.size != prior.MODULE_SIZE:
            raise ValueError('source_fileexists_state_module_size_changed')
        def read(address, size):
            if ((address - info.base, size) not in allowed_spans() or not 0 < size <= 1024
                    or not info.base <= address < address + size <= info.base + info.size):
                raise ValueError('process_read_outside_fixed_fileexists_state_scope')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_fileexists_state_adapter_read')
            return raw.raw
        report = capture(read, info.base, info.size, source_digest=digest,
                         actual_created=creation, expected_created=args.expected_create_time)
        prior.local.verify_creation(created(), creation)
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
