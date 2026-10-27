"""Observe the one original-pdata-qualified target of the source FileExists route.

Fresh fixed caller/getters and six bounded chain qwords precede exactly 46 target
code bytes. No object body, contained call, virtual/native call or game write.
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
import probe_live_fileexists_receiver as prior


SOURCE_CAPTURE = prior.prior.prior.ROOT / 'work/evidence/live-package-fileexists-receiver-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '956566c0593cbda503904ec1c92ec69cba7dee7e92ec4e0fba51819522aa4410'
TARGET_RVA, TARGET_SIZE = 0x124677e0, 46
TARGET_DISK_OFFSET = 306605536
TARGET_DISK_SHA = '98ccef8ef09a60e11f98a7c5e1b7e466a6e0a4799343e2827b07db735f2b88e9'
TARGET_METADATA = (
    ('pdata', 511490544, 'e07746120e784612c482e61b',
     '82cc0543ad763a47b97ccc8d740be8099df4e6f8c01a5937de0ce43d2c11c121'),
    ('unwind', 468088516, '010a04000a540a000a520670',
     '65d0dc903fa64d73cfbc590e20e2020187fc493204a441da1e106eec76424f4e'),
)
getters = prior.prior.prior


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_fileexists_receiver_source_required')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_fileexists_receiver_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != getters.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('receiver_slot_rva') != prior.prior.SLOT_RVA
            or d.get('virtual_callsite_rva') != prior.VIRTUAL_SITE
            or d.get('virtual_target_rva') != TARGET_RVA
            or d.get('virtual_slot_rva') != d.get('vtable_rva') + prior.VIRTUAL_OFFSET
            or d.get('data_qword_reads') != 6 or not d.get('receiver_chain_rechecked')):
        raise ValueError('saved_fileexists_receiver_target_source_chain_changed')
    caller = d['source_code']
    if (caller['rva'], caller['size'], caller['sha256']) != (
            getters.CALLER_RVA, getters.CALLER_SIZE, getters.CALLER_SHA):
        raise ValueError('saved_fileexists_target_caller_coordinates_changed')
    code = bytes.fromhex(caller['bytes'])
    getters.verify_caller(code)
    prior.verify_virtual_callsite(code)
    first, second = (d['fixed_code'][n] for n in
                     ('FileExistsFirstGetterLeaf', 'FileExistsSecondGetter'))
    if ((first['rva'], first['size'], first['sha256']) != (getters.FIRST_RVA, 16, prior.prior.FIRST_SHA)
            or (second['rva'], second['size'], second['sha256']) != (
                getters.SECOND_RVA, 31, prior.prior.SECOND_SHA)):
        raise ValueError('saved_fileexists_target_getter_coordinates_changed')
    prior.prior.verify_getters(bytes.fromhex(first['bytes']), bytes.fromhex(second['bytes']))
    # Captured receiver addresses are provenance only, never current selectors.
    return SOURCE_CAPTURE_SHA


def verify_target_metadata(read_at):
    rows = {}
    for name, offset, expected, digest in TARGET_METADATA:
        raw = read_at(offset, len(bytes.fromhex(expected)))
        if (not isinstance(raw, bytes) or raw.hex() != expected
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_fileexists_target_metadata_changed_' + name)
        rows[name] = {'file_offset': offset, 'bytes': raw.hex(), 'sha256': digest}
    code = read_at(TARGET_DISK_OFFSET, TARGET_SIZE)
    if (not isinstance(code, bytes) or len(code) != TARGET_SIZE
            or hashlib.sha256(code).hexdigest() != TARGET_DISK_SHA):
        raise ValueError('original_fileexists_target_disk_code_changed')
    return {'begin_rva': TARGET_RVA, 'end_exclusive_rva': TARGET_RVA + TARGET_SIZE,
            'function_bytes': TARGET_SIZE, 'metadata': rows,
            'disk_code_offset': TARGET_DISK_OFFSET, 'disk_code_sha256': TARGET_DISK_SHA,
            'runtime_plaintext_hash': False}


def verify_original(path):
    extents = prior.prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(offset, size):
            stream.seek(offset)
            return stream.read(size)
        extents['virtual_target'] = verify_target_metadata(read_at)
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_fileexists_receiver_source_required')
    if (type(base) is not int or type(module_size) is not int
            or not 0 <= TARGET_RVA < TARGET_RVA + TARGET_SIZE <= module_size):
        raise ValueError('fixed_fileexists_target_code_range_outside_module')
    report = prior.capture(read, query, base, module_size,
                           source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    if report['virtual_target_rva'] != TARGET_RVA:
        raise ValueError('fresh_fileexists_receiver_virtual_target_changed')
    raw = read(base + TARGET_RVA, TARGET_SIZE)
    if not isinstance(raw, bytes) or len(raw) != TARGET_SIZE:
        raise ValueError('short_fixed_fileexists_target_code_read')
    report.update(source_capture_sha256=source_digest, target_code_read=True,
                  target_code={'rva': TARGET_RVA, 'size': TARGET_SIZE,
                               'end_exclusive_rva': TARGET_RVA + TARGET_SIZE,
                               'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                               'function_complete': False, 'pdata_segment_complete': True,
                               'extent_from_original_pdata': True},
                  captured_bytes=report['captured_bytes'] + TARGET_SIZE,
                  scope='Fresh source-pinned caller1024B/getters16B+31B and exact vtable+0x78 callsite; '
                        'source-fixed slot, receiver first qword and module vtable+0x78, six8B reads '
                        'including all three rechecks; one original-pdata-bounded target46B after '
                        'stable selected chain; no body, enumeration, contained call follow or native call')
    return report


def main(continuation=False):
    if continuation == 16:
        import probe_live_fileexists_pak_entry_headers as observer
    elif continuation == 15:
        import probe_live_fileexists_pak_decode as observer
    elif continuation == 14:
        import probe_live_fileexists_pak_entries as observer
    elif continuation == 13:
        import probe_live_fileexists_pak_helpers as observer
    elif continuation == 12:
        import probe_live_fileexists_pak_headers as observer
    elif continuation == 10:
        import probe_live_fileexists_pak_lookup as observer
    elif continuation == 9:
        import probe_live_fileexists_candidate_tail as observer
    elif continuation == 8:
        import probe_live_fileexists_directory_state as observer
    elif continuation == 7:
        import probe_live_fileexists_package_candidates as observer
    elif continuation == 6:
        import probe_live_fileexists_hash_leaf as observer
    elif continuation == 5:
        import probe_live_fileexists_index_code as observer
    elif continuation == 4:
        import probe_live_fileexists_lookup_body as observer
    elif continuation == 3:
        import probe_live_fileexists_lookup as observer
    elif continuation == 2:
        import probe_live_fileexists_continuations as observer
    elif continuation:
        import probe_live_fileexists_edges as observer
    else:
        observer = None
    parser = argparse.ArgumentParser(description=observer.__doc__ if observer else __doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--shadow-game', type=Path, required=True)
    parser.add_argument('--source-capture', type=Path, default=observer.SOURCE_CAPTURE if observer else SOURCE_CAPTURE)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    digest = observer.load_source(args.source_capture) if observer else load_source(args.source_capture)
    installed_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = getters.local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / getters.local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / getters.local.source.CLIENT_RELATIVE_PATH
    extents = observer.verify_original(installed) if observer else verify_original(installed)
    getters.local.source.verify_shadow_executable(shadow, shadow, installed)
    class MemoryBasicInformation(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('allocation_base', ctypes.c_void_p),
                    ('allocation_protect', wintypes.DWORD), ('partition', wintypes.WORD),
                    ('region_size', ctypes.c_size_t), ('state', wintypes.DWORD),
                    ('protect', wintypes.DWORD), ('kind', wintypes.DWORD)]
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
        ctypes.POINTER(getters.local.source.ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleInformation.restype = wintypes.BOOL
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                            wintypes.LPWSTR, wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.restype = wintypes.DWORD
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = wintypes.BOOL
    kernel.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                     ctypes.POINTER(MemoryBasicInformation), ctypes.c_size_t]
    kernel.VirtualQueryEx.restype = ctypes.c_size_t
    handle = kernel.OpenProcess(0x0410, False, args.pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        def created():
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            return ((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime) / 10000000 - 11644473600
        creation = created()
        getters.local.verify_creation(creation, args.expected_create_time)
        modules, needed = (wintypes.HMODULE * 1024)(), wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise ValueError('unexpected_fileexists_target_module_count')
        path = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, modules[0], path, len(path)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path.value).resolve() != shadow.resolve():
            raise ValueError('PID_does_not_identify_authorized_shadow_executable')
        info = getters.local.source.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.size != getters.MODULE_SIZE:
            raise ValueError('source_fileexists_target_module_size_changed')
        observed_code, data_order, target_read = {}, [], False
        target_bytes, extra_reads, observed_extra = None, [], {}
        additional_data_bytes = 0
        extra_spans = ((0x1246780e, 169), (0x12467ca0, 18))
        if continuation >= 2:
            extra_spans += ((0x124678b7, 36), (0x12467cb2, 203))
        if continuation >= 3:
            extra_spans += ((0x12468d40, 37),)
        if continuation >= 4:
            extra_spans += ((0x12468d65, 87), (0x124747b0, 297))
        if continuation >= 5:
            extra_spans += ((0x12468dbc, 183), (0x12468e73, 126), (0x1246d870, 269), (0x10b25360, 364))
        if continuation >= 6:
            extra_spans += ((0x12468ef1, 45), (0x10b08d50, 64))
        if continuation in (7, 9, 10, 13, 15):
            extra_spans += ((0x12467d7d, 203), (0x12467e48, 21))
        if continuation in (8, 12, 14, 16):
            extra_spans += observer.EXTRA_SPANS
        if continuation in (9, 10, 13, 15):
            extra_spans += ((0x12467e5d, 73),)
        if continuation == 10:
            extra_spans += observer.EXTRA_SPANS
        if continuation == 13:
            extra_spans += observer.prior.EXTRA_SPANS + observer.EXTRA_SPANS
        if continuation == 15:
            extra_spans += observer.prior.prior.EXTRA_SPANS + observer.prior.EXTRA_SPANS + observer.EXTRA_SPANS
        code_order = [(getters.CALLER_RVA, 1024), (getters.FIRST_RVA, 16), (getters.SECOND_RVA, 31)]
        def gates():
            if len(observed_code) != 3:
                raise ValueError('fileexists_target_adapter_code_incomplete')
            getters.verify_caller(observed_code[getters.CALLER_RVA])
            prior.verify_virtual_callsite(observed_code[getters.CALLER_RVA])
            prior.prior.verify_getters(observed_code[getters.FIRST_RVA], observed_code[getters.SECOND_RVA])
        def read(address, size):
            nonlocal target_read, target_bytes, additional_data_bytes
            key = (address - info.base, size)
            if key in getters.allowed_spans():
                if (len(observed_code) >= len(code_order) or key != code_order[len(observed_code)]
                        or data_order or target_read):
                    raise ValueError('fileexists_target_adapter_code_order_changed')
            elif key == (TARGET_RVA, TARGET_SIZE):
                gates()
                if (target_read or len(data_order) != 6 or data_order[:3] != data_order[3:]
                        or data_order[2][1] != info.base + TARGET_RVA):
                    raise ValueError('fileexists_target_adapter_stable_selected_target_required')
            elif observer and key in extra_spans:
                gates()
                observer.verify_target(target_bytes)
                if continuation >= 2 and len(extra_reads) >= 2:
                    observer.verify_previous_edges({rva: observed_extra[rva]
                                                    for rva in (0x1246780e, 0x12467ca0)})
                if continuation >= 3 and len(extra_reads) >= 4:
                    observer.verify_previous_continuations({rva: observed_extra[rva]
                                                           for rva in (0x124678b7, 0x12467cb2)})
                if continuation >= 4 and len(extra_reads) >= 5:
                    observer.verify_previous_lookup(observed_extra[0x12468d40])
                if continuation >= 5 and len(extra_reads) >= 7:
                    observer.verify_previous_lookup_body({rva: observed_extra[rva]
                                                         for rva in (0x12468d65, 0x124747b0)})
                if continuation >= 6 and len(extra_reads) >= 11:
                    observer.verify_previous_index_code({rva: observed_extra[rva]
                                                        for rva in (0x12468dbc, 0x12468e73, 0x1246d870, 0x10b25360)})
                if continuation >= 7 and len(extra_reads) >= 13:
                    observer.verify_previous_hash_leaf({rva: observed_extra[rva]
                                                       for rva in (0x12468ef1, 0x10b08d50)})
                if continuation in (9, 10, 13, 15) and len(extra_reads) >= 15:
                    observer.verify_previous_candidate({rva: observed_extra[rva]
                                                       for rva in (0x12467d7d, 0x12467e48)})
                if continuation in (10, 13, 15) and len(extra_reads) >= 16:
                    observer.verify_previous_candidate_tail(observed_extra[0x12467e5d])
                if continuation in (13, 15) and len(extra_reads) >= 18:
                    observer.verify_previous_pak_lookup({rva:observed_extra[rva] for rva in (0x12467eb0,0x12467fe8)})
                if continuation == 15 and len(extra_reads) >= 21:
                    observer.verify_helpers({rva:observed_extra[rva] for rva in (0xdb8360,0x10b2b9b0,0x1246ac20)})
                if (not target_read or len(data_order) != 6 or data_order[:3] != data_order[3:]
                        or len(extra_reads) >= len(extra_spans) or key != extra_spans[len(extra_reads)]
                        or not 0 <= key[0] < key[0] + size <= info.size):
                    raise ValueError('fileexists_edges_adapter_scope_or_order_changed')
            elif continuation in (8, 12, 14, 16) and len(extra_reads) == len(extra_spans):
                gates()
                observer.check_data_read(address, size, info.base, info.size, additional_data_bytes)
            else:
                gates()
                if size != 8 or len(data_order) >= 6 or target_read:
                    raise ValueError('fileexists_target_adapter_data_scope_exceeded')
                n = len(data_order)
                expected = (info.base + prior.prior.SLOT_RVA if n == 0 else data_order[0][1] if n == 1
                            else data_order[1][1] + prior.VIRTUAL_OFFSET if n == 2 else data_order[n - 3][0])
                if address != expected:
                    raise ValueError('fileexists_target_adapter_address_not_source_selected')
                prior.canonical(address, 8)
                if n in (2, 5) and not info.base <= address < address + 8 <= info.base + info.size:
                    raise ValueError('fileexists_target_adapter_virtual_slot_outside_module')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_fileexists_target_adapter_read')
            if key in getters.allowed_spans():
                observed_code[key[0]] = raw.raw
            elif key == (TARGET_RVA, TARGET_SIZE):
                target_read = True
                target_bytes = raw.raw
            elif observer and key in extra_spans:
                extra_reads.append(key)
                observed_extra[key[0]] = raw.raw
            elif continuation in (8, 12, 14, 16) and len(extra_reads) == len(extra_spans):
                additional_data_bytes += size
            else:
                data_order.append((address, struct.unpack('<Q', raw.raw)[0]))
            return raw.raw
        def query(address):
            region = MemoryBasicInformation()
            if kernel.VirtualQueryEx(handle, address, ctypes.byref(region), ctypes.sizeof(region)) != ctypes.sizeof(region):
                raise ctypes.WinError(ctypes.get_last_error())
            return {'base': region.base, 'size': region.region_size, 'state': region.state, 'protect': region.protect}
        capture_stage = observer.capture if observer else capture
        report = capture_stage(read, query, info.base, info.size, source_digest=digest,
                               actual_created=creation, expected_created=args.expected_create_time)
        getters.local.verify_creation(created(), creation)
        report.update(source_extents=extents, source_extents_verified=True, pid=args.pid,
                      module_base=hex(info.base), module_size=info.size,
                      process_created_unix=creation, process_creation_rechecked=True,
                      shadow_executable=str(shadow.resolve()), process_accessed=True,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'captured_bytes': report['captured_bytes'], 'target_rva': hex(TARGET_RVA),
                          'target_code_sha256': report['target_code']['sha256'], 'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
