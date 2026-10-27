"""Observe the source-pinned FileExists receiver and its sole vtable+0x78 target.

Exactly three code spans and at most six qwords are read. No enumeration,
virtual/native call, target-code read, object-body read or game write is allowed.
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
import probe_live_fileexists_state as prior


SOURCE_CAPTURE = prior.prior.ROOT / 'work/evidence/live-package-fileexists-state-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '84e37d608047839a1c9fb0d8acb39b451e657c55d3e9b1d6477ba2178fa2ee4e'
INIT_SHA = 'e1b09c1ef003757c98980807e6d8d99dd421a1055ec4ea27434f51f94bde22e3'
VIRTUAL_SITE, VIRTUAL_OFFSET = 0x10ecd2be, 0x78
VIRTUAL_CHAIN_SITE = 0x10ecd2b5
VIRTUAL_CHAIN = bytes.fromhex('498b06488bd7498bceff5078')


def verify_virtual_callsite(caller):
    at = VIRTUAL_CHAIN_SITE - prior.prior.CALLER_RVA
    if (caller[at:at + len(VIRTUAL_CHAIN)] != VIRTUAL_CHAIN
            or caller[VIRTUAL_SITE - prior.prior.CALLER_RVA:
                      VIRTUAL_SITE - prior.prior.CALLER_RVA + 3] != b'\xff\x50\x78'):
        raise ValueError('fileexists_receiver_virtual_callsite_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_fileexists_state_source_required')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_fileexists_state_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != prior.prior.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA):
        raise ValueError('saved_fileexists_state_source_chain_changed')
    caller = d['source_code']
    if (caller['rva'], caller['size'], caller['sha256']) != (
            prior.prior.CALLER_RVA, 1024, prior.prior.CALLER_SHA):
        raise ValueError('saved_fileexists_receiver_caller_coordinates_changed')
    code = bytes.fromhex(caller['bytes'])
    prior.prior.verify_caller(code)
    verify_virtual_callsite(code)
    first = d['fixed_code']['FileExistsFirstGetterLeaf']
    second = d['fixed_code']['FileExistsSecondGetter']
    if ((first['rva'], first['size'], first['sha256']) != (prior.prior.FIRST_RVA, 16, prior.FIRST_SHA)
            or (second['rva'], second['size'], second['sha256']) != (
                prior.prior.SECOND_RVA, 31, prior.SECOND_SHA)):
        raise ValueError('saved_fileexists_receiver_getter_coordinates_changed')
    prior.verify_getters(bytes.fromhex(first['bytes']), bytes.fromhex(second['bytes']))
    init = d['fixed_code']['FileExistsReceiverInitializer']
    raw_init = bytes.fromhex(init['bytes'])
    if ((init['rva'], init['size'], init['sha256']) != (prior.INIT_RVA, 98, INIT_SHA)
            or len(raw_init) != 98 or hashlib.sha256(raw_init).hexdigest() != INIT_SHA):
        raise ValueError('saved_fileexists_receiver_initializer_changed')
    # Snapshot receiver pointers are not used to select a current address.
    return SOURCE_CAPTURE_SHA


def canonical(address, alignment):
    if (type(address) is not int or not 0x10000 <= address < 0x800000000000
            or address % alignment):
        raise ValueError('fileexists_receiver_pointer_not_canonical_or_aligned')


def readable_region(region, address):
    if (not isinstance(region, dict) or any(type(region.get(k)) is not int
            for k in ('base', 'size', 'state', 'protect'))):
        raise ValueError('fileexists_receiver_region_metadata_invalid')
    begin, size = region['base'], region['size']
    if (begin <= 0 or size <= 0 or begin + size >= 0x800000000000
            or region['state'] != 0x1000 or region['protect'] & 0x101
            or region['protect'] & 0xff not in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)
            or not begin <= address < address + 8 <= begin + size):
        raise ValueError('fileexists_receiver_qword_not_in_readable_committed_region')


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    prior.prior.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_fileexists_state_source_required')
    code_spans = prior.prior.allowed_spans()
    module_spans = {*code_spans, (prior.SLOT_RVA, 8)}
    if (type(base) is not int or type(module_size) is not int or base <= 0 or module_size <= 0
            or base + module_size >= 0x800000000000
            or any(not 0 <= rva < rva + size <= module_size for rva, size in module_spans)):
        raise ValueError('fixed_fileexists_receiver_ranges_outside_module')
    total, data_reads = 0, []
    def fixed(rva, size):
        nonlocal total
        if (rva, size) not in code_spans:
            raise ValueError('fileexists_receiver_code_read_not_in_fixed_scope')
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_receiver_code_read')
        total += size
        return {'rva': rva, 'size': size, 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest()}
    caller = fixed(prior.prior.CALLER_RVA, 1024)
    prior.prior.verify_caller(bytes.fromhex(caller['bytes']))
    verify_virtual_callsite(bytes.fromhex(caller['bytes']))
    first, second = fixed(prior.prior.FIRST_RVA, 16), fixed(prior.prior.SECOND_RVA, 31)
    prior.verify_getters(bytes.fromhex(first['bytes']), bytes.fromhex(second['bytes']))
    def qword(address, role):
        nonlocal total
        canonical(address, 8)
        if len(data_reads) >= 6:
            raise ValueError('fileexists_receiver_six_qword_limit_exceeded')
        region = query(address)
        readable_region(region, address)
        raw = read(address, 8)
        if not isinstance(raw, bytes) or len(raw) != 8:
            raise ValueError('short_receiver_qword_read')
        total += 8
        block = {'address': hex(address), 'size': 8, 'role': role,
                 'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                 'region': region}
        data_reads.append(block)
        return struct.unpack('<Q', raw)[0]
    receiver = qword(base + prior.SLOT_RVA, 'source_fixed_receiver_slot')
    canonical(receiver, 8)
    vtable = qword(receiver, 'selected_receiver_first_qword')
    canonical(vtable, 8)
    if not base <= vtable < vtable + VIRTUAL_OFFSET + 8 <= base + module_size:
        raise ValueError('fileexists_receiver_vtable_slot_not_inside_source_module')
    virtual_slot = vtable + VIRTUAL_OFFSET
    target = qword(virtual_slot, 'selected_module_vtable_slot_0x78')
    canonical(target, 1)
    if not base <= target < base + module_size:
        raise ValueError('fileexists_receiver_virtual_target_not_inside_source_module')
    for address, expected, role in ((base + prior.SLOT_RVA, receiver, 'receiver_slot_recheck'),
                                    (receiver, vtable, 'receiver_first_qword_recheck'),
                                    (virtual_slot, target, 'vtable_slot_0x78_recheck')):
        if qword(address, role) != expected:
            raise ValueError('fileexists_receiver_chain_changed_during_capture')
    return {'native_pe_sha256': prior.prior.SOURCE_PE, 'source_capture_sha256': source_digest,
            'source_code': caller,
            'fixed_code': {'FileExistsFirstGetterLeaf': first, 'FileExistsSecondGetter': second},
            'receiver_slot_rva': prior.SLOT_RVA, 'receiver_pointer': hex(receiver),
            'vtable_rva': vtable - base, 'virtual_slot_rva': virtual_slot - base,
            'virtual_target_rva': target - base, 'virtual_callsite_rva': VIRTUAL_SITE,
            'data_reads': data_reads, 'data_qword_reads': len(data_reads),
            'captured_bytes': total, 'receiver_chain_rechecked': True,
            'heap_read': True, 'pointer_followed': True, 'target_code_read': False,
            'native_called': False, 'game_launched': False,
            'filesystem_class_identity_proven': False, 'fileexists_outcome_proven': False,
            'scope': 'Fresh caller1024B/getters16B+31B and exact vtable+0x78 callsite; '
                     'source-fixed module slot8B, selected receiver first qword8B, only its '
                     'module vtable+0x78 slot8B; all three qwords rechecked, readable region '
                     'gates; target only recorded as module RVA; no enumeration or call'}


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
    output = prior.prior.local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / prior.prior.local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / prior.prior.local.source.CLIENT_RELATIVE_PATH
    extents = prior.verify_original(installed)
    prior.prior.local.source.verify_shadow_executable(shadow, shadow, installed)
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
        ctypes.POINTER(prior.prior.local.source.ModuleInfo), wintypes.DWORD]
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
        prior.prior.local.verify_creation(creation, args.expected_create_time)
        modules, needed = (wintypes.HMODULE * 1024)(), wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise ValueError('unexpected_fileexists_receiver_module_count')
        path = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, modules[0], path, len(path)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path.value).resolve() != shadow.resolve():
            raise ValueError('PID_does_not_identify_authorized_shadow_executable')
        info = prior.prior.local.source.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.size != prior.prior.MODULE_SIZE:
            raise ValueError('source_fileexists_receiver_module_size_changed')
        observed_code, data_order = {}, []
        expected_code_order = [(prior.prior.CALLER_RVA, 1024),
                               (prior.prior.FIRST_RVA, 16), (prior.prior.SECOND_RVA, 31)]
        def read(address, size):
            key = (address - info.base, size)
            if key in prior.prior.allowed_spans():
                if (len(observed_code) >= len(expected_code_order)
                        or key != expected_code_order[len(observed_code)] or len(data_order)):
                    raise ValueError('fileexists_receiver_adapter_code_order_changed')
            else:
                if (size != 8 or len(data_order) >= 6 or len(observed_code) != 3):
                    raise ValueError('fileexists_receiver_adapter_data_scope_exceeded')
                caller = observed_code[prior.prior.CALLER_RVA]
                prior.prior.verify_caller(caller)
                verify_virtual_callsite(caller)
                prior.verify_getters(observed_code[prior.prior.FIRST_RVA],
                                     observed_code[prior.prior.SECOND_RVA])
                expected = (info.base + prior.SLOT_RVA if len(data_order) == 0
                            else data_order[0][1] if len(data_order) == 1
                            else data_order[1][1] + VIRTUAL_OFFSET if len(data_order) == 2
                            else data_order[len(data_order) - 3][0])
                if address != expected:
                    raise ValueError('fileexists_receiver_adapter_address_not_source_selected')
                canonical(address, 8)
                if len(data_order) in (2, 5) and not info.base <= address < address + 8 <= info.base + info.size:
                    raise ValueError('fileexists_receiver_adapter_virtual_slot_outside_module')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_receiver_adapter_read')
            if key in prior.prior.allowed_spans():
                observed_code[key[0]] = raw.raw
            else:
                data_order.append((address, struct.unpack('<Q', raw.raw)[0]))
            return raw.raw
        def query(address):
            region = MemoryBasicInformation()
            if kernel.VirtualQueryEx(handle, address, ctypes.byref(region), ctypes.sizeof(region)) != ctypes.sizeof(region):
                raise ctypes.WinError(ctypes.get_last_error())
            return {'base': region.base, 'size': region.region_size,
                    'state': region.state, 'protect': region.protect}
        report = capture(read, query, info.base, info.size, source_digest=digest,
                         actual_created=creation, expected_created=args.expected_create_time)
        prior.prior.local.verify_creation(created(), creation)
        report.update(source_extents=extents, source_extents_verified=True, pid=args.pid,
                      module_base=hex(info.base), module_size=info.size,
                      process_created_unix=creation, process_creation_rechecked=True,
                      shadow_executable=str(shadow.resolve()), process_accessed=True,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'captured_bytes': report['captured_bytes'],
                          'data_qword_reads': report['data_qword_reads'],
                          'virtual_target_rva': hex(report['virtual_target_rva']), 'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
