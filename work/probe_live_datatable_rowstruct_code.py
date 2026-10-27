"""Capture two source-gated UDataTable/RowStruct fixed module code spans.

No arbitrary addresses, heap reads, native calls, hooks or game launches.
The source metadata identifies the callbacks; owner proof requires offline
analysis of the resulting private code snapshot, and is not presumed here.
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


ROOT = Path(__file__).resolve().parent.parent
MODULE_SIZE = 0x1ff8f000
SOURCE_BASE = 0x140000000
SOURCE_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
RECORDS = (
    ('UDataTable_registry', 494607384, 24,
     '020478717cde00d6c007882eb507d9bfb103feaad0b9c95d6ad431677bc6207b'),
    ('UDataTable_descriptor_callback', 457143008, 8,
     '4e79b2f8d89d416dd7e04d0e98c125f6c2d2f3242eb07f0fb5a6230a560d1f17'),
    ('RowStruct_native_field', 457150752, 24,
     '625bfc0699e04be836aa64bd15b7f25ffffef88a8622a0c1faf9b364132869d6'),
    ('RowStruct_UHT_property', 458071472, 48,
     '576a46274a1cd88b05358de7d8b6d76bcea69d31637ea5f04a29967a14f86e5c'),
)
SPANS = (('UDataTable_descriptor', 0x131a0830, 1024),
         ('RowStruct_UScriptStruct_type_getter', 0x10e06b20, 1024))
OWNER_VTABLE_OFFSET = 457648160
OWNER_VTABLE_SHA = 'ed3927582fda2b92adc44ebfd31ebb58d5f3d6e7b243bdc88b8a8db3ed724710'
OWNER_VTABLE_RECORD = {'name': 'UDataTable_binding_vtable', 'file_offset': OWNER_VTABLE_OFFSET,
                       'size': 48, 'sha256': OWNER_VTABLE_SHA}
OWNER_SPANS = (('UDataTable_binding_slot1', 0x13254570, 128),
               ('UDataTable_binding_slot5', 0x13287f10, 128))
OWNER_LEA = bytes.fromhex('488d0dca2b2d08')
BINDING_DESCRIPTOR_RECORD = {
    'name': 'UDataTable_native_binding_descriptor', 'file_offset': 457152352,
    'size': 40, 'sha256': '4eba9aac20445f830051d600f734335038b083bb7fe2633ff01db856592702dd'}
BINDING_FIELDS_RECORD = {
    'name': 'UDataTable_native_owned_fields', 'file_offset': 457150752,
    'size': 216, 'sha256': 'b6c997a81ce0db1ab4188b25864a92b5ab79464f61ec54b02ebc76ef2b02bff0'}
BINDING_ENTRY = bytes.fromhex('488b0a488d1546241708e94180a0fd')
BINDER_SPANS = (('UDataTable_shared_native_binder', 0x10c8ff60, 1024),)
OWNER_REPORT = 'work/evidence/live-datatable-rowstruct-owner-20261005-private.json'
OWNER_REPORT_SHA = 'a9fc3e96bf60e9718e8a64a2e5cb3224b85109253202e9259c24a222055c58f9'
OWNER_CODE = (
    ('UDataTable_descriptor', 0x131a0830, 1024,
     '5087759024a636833a5f376167abc7bb3f3198710b81147591909da6522a1f0f'),
    ('RowStruct_UScriptStruct_type_getter', 0x10e06b20, 1024,
     '63454ba990371d40a348886dbde283394507c098c8050f40ef6088d3e93aee35'),
    ('UDataTable_binding_slot5', 0x13287f10, 128,
     '0d37b8095a5005519a933a7960236b4168f136f35d0a1e7133d5021f7b77d55f'),
)
TYPE_CLASS_GLOBAL_RVA = 0x1e340a98
BINDER_REPORT = 'work/evidence/live-datatable-rowstruct-binder-20261005-private.json'
BINDER_REPORT_SHA = '33cb81dcd7fb4033090d0ff70af1449d578cd3187dc0c531b110340f562c244e'
BINDER_CODE_SHA = '850ce84bd5b55717fe2649a5e39ddaf097a06902cb13637801fb4f8306e508dd'
BINDER_FIELD_WITNESSES = (
    (0x10c90242, bytes.fromhex('66413b5c2424')),
    (0x10c90251, bytes.fromhex('498b742410')),
    (0x10c9029a, bytes.fromhex('488b16')),
    (0x10c902a7, bytes.fromhex('8b4610')),
    (0x10c902b1, bytes.fromhex('488b5608')),
    (0x10c902d9, bytes.fromhex('410fb7442424')),
    (0x10c902e1, bytes.fromhex('4983c618')),
    (0x10c902e7, bytes.fromhex('0f8c64ffffff')),
)


def verify_records(exact, text):
    values, records = [], []
    for name, offset, size, expected in RECORDS:
        raw = exact(offset, size)
        if not isinstance(raw, bytes) or len(raw) != size or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('source_named_registration_span_changed')
        values.append(struct.unpack('<' + 'Q' * (size // 8), raw))
        records.append({'name': name, 'file_offset': offset, 'size': size, 'sha256': expected})
    registry, descriptor, native, prop = values
    if (registry != (0x15b3f7ee0, 0x154ed3790, 368)
            or descriptor != (SOURCE_BASE + SPANS[0][1],)
            or native != (0x156bbca88, 0x154ee6620, 40)
            or prop != (0x156bbca88, 0, 0x10000000020001, 0x4500000012,
                        0x2800000001, SOURCE_BASE + SPANS[1][1])
            or text(registry[1]) != 'UDataTable' or text(native[0]) != 'RowStruct'
            or text(native[1]) != 'UScriptStruct *'):
        raise ValueError('source_named_registration_type_or_callback_changed')
    return {'source_pe_sha256': SOURCE_PE, 'status': 'verified_source_callback_records',
            'records': records, 'RowStruct_member_offset': 40,
            'RowStruct_field_type': 'UScriptStruct *', 'UDataTable_registered_size': 368,
            'rowstruct_owner_verified': False}


def verify_owner_vtable(exact):
    raw = exact(OWNER_VTABLE_OFFSET, 48)
    if (not isinstance(raw, bytes) or len(raw) != 48
            or hashlib.sha256(raw).hexdigest() != OWNER_VTABLE_SHA
            or struct.unpack('<6Q', raw) != (0x140d5c590, 0x153254570, 0x140d5c590,
                                           0x140e16270, 0x140d5f350, 0x153287f10)):
        raise ValueError('source_owner_vtable_complete_pin_changed')
    return dict(OWNER_VTABLE_RECORD)


def verify_binding_descriptor(exact):
    descriptor = exact(BINDING_DESCRIPTOR_RECORD['file_offset'], 40)
    fields = b''.join(exact(BINDING_FIELDS_RECORD['file_offset'] + index * 24, 24)
                      for index in range(9))
    if (hashlib.sha256(descriptor).hexdigest() != BINDING_DESCRIPTOR_RECORD['sha256']
            or struct.unpack('<5Q', descriptor) !=
            (0x15b3f91b0, 0x15b3f9390, 0x15b3f9d20, 0x15b3fa038, 0x1000900250001)
            or hashlib.sha256(fields).hexdigest() != BINDING_FIELDS_RECORD['sha256']
            or struct.unpack_from('<3Q', fields) != (0x156bbca88, 0x154ee6620, 40)):
        raise ValueError('source_binding_descriptor_or_owned_fields_changed')
    return {'descriptor': dict(BINDING_DESCRIPTOR_RECORD), 'fields': dict(BINDING_FIELDS_RECORD)}


def verify_source(path, *, owner_bindings=False, shared_binder=False):
    with Path(path).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_PE:
            raise ValueError('original_source_executable_sha256_mismatch')
        stream.seek(0)
        header = stream.read(65536)
        nt = struct.unpack_from('<I', header, 0x3c)[0]
        count = struct.unpack_from('<H', header, nt + 6)[0]
        optional = struct.unpack_from('<H', header, nt + 20)[0]
        base = struct.unpack_from('<Q', header, nt + 48)[0]
        if base != SOURCE_BASE:
            raise ValueError('source_image_base_changed')
        sections = [struct.unpack_from('<4I', header, nt + 24 + optional + i * 40 + 8)
                    for i in range(count)]
        def exact(offset, size):
            if not (type(offset) is int and type(size) is int and offset >= 0 and 0 < size <= 128):
                raise ValueError('source_metadata_read_outside_fixed_scope')
            stream.seek(offset)
            raw = stream.read(size)
            if len(raw) != size:
                raise ValueError('short_source_metadata_read')
            return raw
        def text(address):
            offset = next((raw + address - base - rva for _, rva, size, raw in sections
                           if base + rva <= address and address + 64 <= base + rva + size), None)
            if offset is None:
                raise ValueError('source_name_not_raw_section_backed')
            raw = exact(offset, 64).split(b'\0', 1)[0]
            return raw.decode('ascii')
        proof = verify_records(exact, text)
        if owner_bindings or shared_binder:
            proof['owner_vtable'] = verify_owner_vtable(exact)
        if shared_binder:
            proof['binding_descriptor'] = verify_binding_descriptor(exact)
        return proof


def owner_code_blocks(report):
    if (report.get('native_pe_sha256') != SOURCE_PE
            or report.get('captured_bytes') != 2304
            or report.get('owner_bindings') is not True
            or report.get('heap_read') is not False
            or report.get('native_called') is not False):
        raise ValueError('owner_code_report_scope_changed')
    blocks = []
    for name, rva, size, expected in OWNER_CODE:
        code = report['code'][name]
        raw = bytes.fromhex(code['bytes'])
        if ((code['rva'], code['size'], code['sha256']) != (rva, size, expected)
                or len(raw) != size or hashlib.sha256(raw).hexdigest() != expected):
            raise ValueError('owner_code_report_span_changed')
        blocks.append((rva, raw))
    descriptor, getter, binding = [raw for _, raw in blocks]
    if descriptor[0x1f:0x26] != OWNER_LEA or binding[:15] != BINDING_ENTRY:
        raise ValueError('owner_code_report_binding_chain_changed')
    if (getter[7:14] != bytes.fromhex('488b056a9f530d')
            or 0x10e06b2e + struct.unpack_from('<i', getter, 10)[0] != TYPE_CLASS_GLOBAL_RVA
            or getter[0x11:0x13] != bytes.fromhex('7559')
            or getter[0x5d:0x64] != bytes.fromhex('48891d149f530d')
            or 0x10e06b84 + struct.unpack_from('<i', getter, 0x60)[0] != TYPE_CLASS_GLOBAL_RVA
            or getter[0x73] != 0xc3):
        raise ValueError('owner_type_getter_single_class_global_changed')
    return tuple(blocks)


def shared_binder_code_block(report):
    if (report.get('native_pe_sha256') != SOURCE_PE
            or report.get('captured_bytes') != 3328
            or report.get('shared_binder') is not True
            or report.get('heap_read') is not False
            or report.get('native_called') is not False
            or report.get('source_records', {}).get('binding_descriptor') != {
                'descriptor': BINDING_DESCRIPTOR_RECORD, 'fields': BINDING_FIELDS_RECORD}):
        raise ValueError('shared_binder_report_scope_or_source_changed')
    code = report['code']['UDataTable_shared_native_binder']
    raw = bytes.fromhex(code['bytes'])
    if ((code['rva'], code['size'], code['sha256']) != (0x10c8ff60, 1024, BINDER_CODE_SHA)
            or len(raw) != 1024 or hashlib.sha256(raw).hexdigest() != BINDER_CODE_SHA):
        raise ValueError('shared_binder_report_span_changed')
    for rva, expected in BINDER_FIELD_WITNESSES:
        if raw[rva - 0x10c8ff60:rva - 0x10c8ff60 + len(expected)] != expected:
            raise ValueError('shared_binder_owned_field_loop_changed')
    return 0x10c8ff60, raw


def load_owner_contract(root=ROOT, source_pe=None):
    """Closed disk-source owner chain; runtime must freshly check every block.

    UDataTable's named registry selects its binding factory and vtable; that
    vtable's slot5 passes the native descriptor whose field array contains the
    typed RowStruct member. Its UObject parent descriptor is not an identity.
    """
    if source_pe is None:
        installed, _ = game_paths()
        source_pe = installed / local.source.CLIENT_RELATIVE_PATH
    proof = verify_source(source_pe, shared_binder=True)
    reports = []
    sources = ((OWNER_REPORT, OWNER_REPORT_SHA), (BINDER_REPORT, BINDER_REPORT_SHA))
    for relative, expected in sources:
        path = Path(root) / relative
        if not path.is_file() or not 0 < path.stat().st_size <= 65536:
            raise ValueError('missing_bounded_owner_code_report')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('owner_code_report_complete_digest_changed')
        reports.append(json.loads(raw))
    blocks = owner_code_blocks(reports[0])
    blocks += (shared_binder_code_block(reports[1]),)
    return {'blocks': blocks, 'source_hashes': sources,
            'source_records': proof, 'RowStruct_member_offset': 40,
            'RowStruct_field_type': 'UScriptStruct *',
            'type_class_global_rva': TYPE_CLASS_GLOBAL_RVA,
            'source_rowstruct_owner_verified': True,
            'runtime_rowstruct_identity_verified': False}


def capture(read, base, module_size, creation, expected_creation, proof, *, owner_bindings=False,
            shared_binder=False):
    expected_records = [{'name': name, 'file_offset': offset, 'size': size, 'sha256': digest}
                        for name, offset, size, digest in RECORDS]
    if (proof.get('source_pe_sha256') != SOURCE_PE
            or proof.get('status') != 'verified_source_callback_records'
            or proof.get('records') != expected_records):
        raise ValueError('all_source_callback_records_required_before_process_read')
    owner_bindings = owner_bindings or shared_binder
    if owner_bindings and proof.get('owner_vtable') != OWNER_VTABLE_RECORD:
        raise ValueError('source_owner_vtable_pin_required_before_process_read')
    if shared_binder and proof.get('binding_descriptor') != {
            'descriptor': BINDING_DESCRIPTOR_RECORD, 'fields': BINDING_FIELDS_RECORD}:
        raise ValueError('source_owned_descriptor_pins_required_before_process_read')
    local.verify_creation(creation, expected_creation)
    if module_size != MODULE_SIZE:
        raise ValueError('source_module_size_changed')
    if type(base) is not int or base < 0x10000 or base + module_size > 0x800000000000:
        raise ValueError('invalid_main_module_base')
    spans = SPANS + OWNER_SPANS if owner_bindings else SPANS
    if shared_binder:
        spans += BINDER_SPANS
    if any(not 0 <= rva < rva + size <= module_size for _, rva, size in spans):
        raise ValueError('fixed_code_span_outside_main_module')
    code = {}
    for name, rva, size in SPANS:
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_datatable_code_read')
        code[name] = {'rva': rva, 'size': size, 'sha256': hashlib.sha256(raw).hexdigest(),
                      'bytes': raw.hex()}
    if owner_bindings:
        witness = bytes.fromhex(code['UDataTable_descriptor']['bytes'])[0x1f:0x26]
        if (witness != OWNER_LEA
                or SPANS[0][1] + 0x26 + struct.unpack_from('<i', witness, 3)[0] != 0x1b473420):
            raise ValueError('fresh_owner_vtable_lea_changed_before_binding_reads')
        for name, rva, size in OWNER_SPANS:
            raw = read(base + rva, size)
            if not isinstance(raw, bytes) or len(raw) != size:
                raise ValueError('short_fixed_owner_binding_code_read')
            code[name] = {'rva': rva, 'size': size, 'sha256': hashlib.sha256(raw).hexdigest(),
                          'bytes': raw.hex()}
    if shared_binder:
        witness = bytes.fromhex(code['UDataTable_binding_slot5']['bytes'])[:15]
        if (witness != BINDING_ENTRY
                or 0x13287f1a + struct.unpack_from('<i', witness, 6)[0] != 0x1b3fa360
                or 0x13287f1f + struct.unpack_from('<i', witness, 11)[0] != 0x10c8ff60):
            raise ValueError('fresh_binding_entry_changed_before_shared_binder_read')
        for name, rva, size in BINDER_SPANS:
            raw = read(base + rva, size)
            if not isinstance(raw, bytes) or len(raw) != size:
                raise ValueError('short_fixed_shared_binder_code_read')
            code[name] = {'rva': rva, 'size': size, 'sha256': hashlib.sha256(raw).hexdigest(),
                          'bytes': raw.hex()}
    return {'native_pe_sha256': SOURCE_PE, 'source_records': proof, 'code': code,
            'captured_bytes': sum(size for _, _, size in spans),
            'owner_bindings': owner_bindings, 'rowstruct_owner_verified': False,
            'shared_binder': shared_binder,
            'row_schema_verified': False, 'heap_read': False, 'native_called': False,
            'scope': 'Two fixed1024B source-named callbacks; optional two source-pinned128B '
                     'binding methods after fresh owner LEA; optional fixed1024B shared binder '
                     'after fresh binding entry; module code only, no heap pointers followed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--shadow-game', type=Path, required=True)
    parser.add_argument('--owner-bindings', action='store_true',
                        help='Read two fixed128B binding methods after source vtable and fresh owner LEA gates')
    parser.add_argument('--shared-binder', action='store_true',
                        help='Read fixed1024B shared binder after owned descriptor and fresh binding entry gates')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    local.verify_creation(args.expected_create_time, args.expected_create_time)
    installed_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / local.source.CLIENT_RELATIVE_PATH
    local.source.verify_shadow_executable(shadow, shadow, installed)
    proof = verify_source(installed, owner_bindings=args.owner_bindings, shared_binder=args.shared_binder)
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
        spans = SPANS + OWNER_SPANS if args.owner_bindings or args.shared_binder else SPANS
        if args.shared_binder:
            spans += BINDER_SPANS
        allowed = {(info.base + rva, size) for _, rva, size in spans}
        def read(address, size):
            if (address, size) not in allowed:
                raise ValueError('read_outside_fixed_datatable_code_scope')
            allowed.remove((address, size))
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_fixed_datatable_code_read')
            return raw.raw
        report = capture(read, info.base, info.size, creation, args.expected_create_time, proof,
                         owner_bindings=args.owner_bindings, shared_binder=args.shared_binder)
        local.verify_creation(created(), creation)
        report.update(pid=args.pid, module_base=hex(info.base), module_size=info.size,
                      process_created_unix=creation, process_creation_rechecked=True,
                      shadow_executable=str(shadow.resolve()), game_launched=False,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'captured_bytes': report['captured_bytes'], 'rowstruct_owner_verified': False,
                          'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
