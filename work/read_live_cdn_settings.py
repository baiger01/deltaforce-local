"""Read three source-proven public CDN fields from one typed UAppSetting cache.

No client launch, writes, hooks, calls, heap scan, or account-object access.
All pointer reads derive from the verified SettingCache weak reference and
the observed zero-selector object-array accessor. Unsupported states stop.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import re
import struct
from urllib.parse import urlsplit

from local_game_paths import game_paths
import probe_live_resource_loader as identity
import read_keybox_manager_interface as weak_source


ROOT = Path(__file__).resolve().parents[1]
STORAGE_RVA = 0x1c9fe7b0
MAX_CHARS = 512
FIELDS = (
    ('AppSettingRow.MapleInfo.DefaultCDNUrl', 0x38 + 0x530 + 0x20, 'url'),
    ('AppSettingRow.MapleInfo.CDNUrl_PC', 0x38 + 0x530 + 0x30, 'url'),
    ('AppSettingRow.CDNRoot', 0x38 + 0x5a0, 'prefix'),
)
CODE_WITNESSES = (
    # The same generic accessor/selector proof as the prior keybox observer;
    # its manager slot, class, object header and vtable are never used here.
    *weak_source.CODE_WITNESSES[1:6],
    (0xdba41f, bytes.fromhex('488d0d8a43c41be8f54511104883c038')),
)
NATIVE_RECORDS = (
    (351148240, 'DefaultCDNUrl', 'FString', 0x20),
    (351148264, 'CDNUrl_PC', 'FString', 0x30),
    (351156704, 'MapleInfo', 'FMapleSettingRow', 0x530),
    (351156728, 'CDNRoot', 'FString', 0x5a0),
    (351163096, 'Setting', 'FAppSettingRow', 0x38),
    (351163144, 'SettingCache', 'TWeakObjectPtr<UAppSetting>', 0x140000000 + STORAGE_RVA),
)
PROPERTY_OWNERS = (
    ('AppSettingRow', 480262512, 351271216, 105, 1920,
     ((351267856, 'CDNRoot', 0x5a0), (351267896, 'MapleInfo', 0x530))),
    ('MapleSettingRow', 480262672, 351257376, 10, 112,
     ((351257208, 'CDNUrl_PC', 0x30), (351257248, 'DefaultCDNUrl', 0x20))),
)


def digest_file(path):
    value = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def verify_source_schema(path):
    """Verify the exact installed PE and its named native/UHT field records."""
    path = Path(path)
    if digest_file(path) != identity.EXPECTED_PE:
        raise ValueError('CDN source PE differs from the verified configuration version')
    with path.open('rb') as handle:
        header = handle.read(65536)
        pe = struct.unpack_from('<I', header, 0x3c)[0]
        count = struct.unpack_from('<H', header, pe + 6)[0]
        optional = struct.unpack_from('<H', header, pe + 20)[0]
        base = struct.unpack_from('<Q', header, pe + 48)[0]
        sections = [struct.unpack_from('<4I', header, pe + 24 + optional + i * 40 + 8)
                    for i in range(count)]

        def exact(offset, size):
            handle.seek(offset)
            data = handle.read(size)
            if len(data) != size:
                raise ValueError('Short source configuration schema read')
            return data

        def address_offset(address):
            return next((raw + address - base - rva for _, rva, size, raw in sections
                         if base + rva <= address < base + rva + size), None)

        def text(address):
            offset = address_offset(address)
            if offset is None:
                raise ValueError('Source type/name pointer is not in a raw-backed PE section')
            data = exact(offset, 128).split(b'\0', 1)[0]
            return data.decode('ascii')

        records = []
        for offset, expected_name, expected_kind, expected_member in NATIVE_RECORDS:
            data = exact(offset, 24)
            name, kind, member = struct.unpack('<3Q', data)
            if expected_name == 'SettingCache':
                kind, member = member, kind
            if (text(name), text(kind), member) != (expected_name, expected_kind, expected_member):
                raise ValueError('Named configuration field/type/storage source differs')
            records.append({'file_offset': offset, 'name': expected_name, 'kind': expected_kind,
                            'member_offset_or_storage_va': member,
                            'span_sha256': hashlib.sha256(data).hexdigest()})
        owners = []
        for name, offset, array_offset, n, size, properties in PROPERTY_OWNERS:
            params_bytes = exact(offset, 72)
            params = struct.unpack('<9Q', params_bytes)
            if (text(params[3]), params[4], params[5], params[7] & 0xffffffff,
                    params[7] >> 32, address_offset(params[6])) != (name, size, 8, n, 0x45, array_offset):
                raise ValueError('Named configuration structure ownership differs')
            pointers_bytes = exact(array_offset, n * 8)
            pointers = struct.unpack('<' + 'Q' * n, pointers_bytes)
            for property_offset, field_name, member in properties:
                data = exact(property_offset, 40)
                values = struct.unpack('<5Q', data)
                if (text(values[0]), values[4] >> 32, values[4] & 0xffffffff) != (field_name, member, 1):
                    raise ValueError('Named UHT property member differs')
                if property_offset not in {address_offset(pointer) for pointer in pointers}:
                    raise ValueError('Named UHT property is not owned by its proven source structure')
            owners.append({'name': name, 'params_file_offset': offset, 'size': size,
                           'property_count': n, 'params_sha256': hashlib.sha256(params_bytes).hexdigest(),
                           'property_array_file_offset': array_offset,
                           'property_array_sha256': hashlib.sha256(pointers_bytes).hexdigest()})
        type_bytes = exact(480260160, 24)
        type_name, type_size, _ = struct.unpack('<3Q', type_bytes)
        if (text(type_name), type_size) != ('UAppSetting', 0x7c8):
            raise ValueError('UAppSetting source type differs')
    return {'status': 'verified_source_types', 'source_pe_sha256': identity.EXPECTED_PE,
            'setting_cache_type': 'TWeakObjectPtr<UAppSetting>', 'storage_rva': STORAGE_RVA,
            'setting_type': 'FAppSettingRow', 'setting_member_offset': 0x38,
            'uappsetting_size': 0x7c8, 'native_records': records, 'property_owners': owners,
            'uappsetting_type_file_offset': 480260160,
            'uappsetting_type_span_sha256': hashlib.sha256(type_bytes).hexdigest()}


def public_value(value, kind):
    if not value:
        return True
    if len(value) >= MAX_CHARS or any(ord(char) < 33 or ord(char) > 126 for char in value):
        return False
    if kind == 'prefix':
        return bool(re.fullmatch(r'/?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?', value)
                    and all(part not in ('.', '..') for part in value.split('/')))
    try:
        parsed = urlsplit(value)
        port = parsed.port
        return bool(parsed.scheme in ('http', 'https') and parsed.hostname
                    and re.fullmatch(r'[A-Za-z0-9.-]+', parsed.hostname)
                    and (port is None or 0 < port <= 65535)
                    and parsed.username is None and parsed.password is None
                    and '?' not in value and '#' not in value and '\\' not in value)
    except ValueError:
        return False


class _Skip(Exception):
    pass


def capture(read, base, module_size, schema):
    """Use a bounded read(address,size,module_only=True) callback; never invoke code."""
    result = {'status': 'skipped', 'module_base': base, 'module_size': module_size,
              'source_schema': schema, 'read_set': [], 'fields': [],
              'read_policy': 'Typed SettingCache only: fixed code/globals, one chunk pointer, one object item, three source-proven FString headers and at most 512 UTF16 code units per field; no other object fields, calls, heap scan or writes',
              'native_current_getcdnurl_result_verified': False,
              'native_resource_binding_and_rendering_verified': False}

    def stop(reason):
        raise _Skip(reason)

    def exact(address, size, role, *, heap=False):
        if (type(address) is not int or not 0x10000 <= address < address + size <= 0x800000000000
                or type(size) is not int or not 0 < size <= 1024):
            stop('invalid_derived_read_range')
        if not heap and not base <= address < address + size <= base + module_size:
            stop('module_range_out_of_bounds')
        data = read(address, size, module_only=not heap)
        if not isinstance(data, bytes) or len(data) != size:
            stop('short_read')
        result['read_set'].append({'address': address, 'size': size, 'source': role,
                                   'module_only': not heap})
        return data

    def globals_now():
        return (exact(base + weak_source.SELECTOR_RVA, 4, 'verified_object_index_selector'),
                exact(base + STORAGE_RVA, 8, 'typed_SettingCache_weak_reference'),
                exact(base + weak_source.ARRAY_RVA, 32, 'verified_object_array_header'),
                exact(base + weak_source.OVERRIDE_RVA, 8, 'verified_object_accessor_override'))

    try:
        if (type(base) is not int or base < 0x10000 or module_size != weak_source.MODULE_SIZE
                or base + module_size > 0x800000000000):
            stop('invalid_native_module_identity')
        expected_schema = {'status': 'verified_source_types', 'source_pe_sha256': identity.EXPECTED_PE,
                           'setting_cache_type': 'TWeakObjectPtr<UAppSetting>', 'storage_rva': STORAGE_RVA,
                           'setting_type': 'FAppSettingRow', 'setting_member_offset': 0x38,
                           'uappsetting_size': 0x7c8}
        if not isinstance(schema, dict) or any(schema.get(k) != v for k, v in expected_schema.items()):
            stop('unverified_configuration_source_schema')
        for rva, expected in CODE_WITNESSES:
            if exact(base + rva, len(expected), 'source_proven_configuration_accessor_code') != expected:
                stop('configuration_accessor_code_changed')
        before = globals_now()
        selector = struct.unpack('<I', before[0])[0]
        index, serial = struct.unpack('<ii', before[1])
        bound = struct.unpack_from('<i', before[2], 12)[0]
        array = struct.unpack_from('<Q', before[2], 24)[0]
        override = struct.unpack('<Q', before[3])[0]
        result['weak_reference'] = {'index': index, 'serial': serial, 'object_bound': bound,
                                    'selector': selector, 'accessor_override_present': bool(override)}
        if selector != 0:
            stop('unsupported_object_index_selector')
        if override:
            stop('unsupported_object_accessor_override')
        if serial == 0 or not 0 <= index < bound <= 16 * 1024 * 1024:
            stop('invalid_SettingCache_weak_reference')
        if not array:
            stop('null_object_chunk_array')
        if not 0x10000 <= array < 0x800000000000:
            stop('invalid_object_chunk_array_pointer')
        chunk_index, item_index = divmod(index, 65536)
        slot = array + chunk_index * 8
        chunk = struct.unpack('<Q', exact(slot, 8, 'derived_single_object_chunk_pointer', heap=True))[0]
        if not chunk:
            stop('null_object_chunk')
        if not 0x10000 <= chunk < 0x800000000000:
            stop('invalid_object_chunk_pointer')
        item_address = chunk + item_index * 24
        item = exact(item_address, 24, 'derived_single_SettingCache_object_item', heap=True)
        flags = struct.unpack_from('<I', item, 8)[0]
        item_serial = struct.unpack_from('<i', item, 20)[0]
        obj = struct.unpack_from('<Q', item)[0]
        result['weak_reference'].update(item_serial=item_serial, item_flags=flags,
                                        chunk_index=chunk_index, item_index=item_index)
        if item_serial != serial:
            stop('stale_SettingCache_serial')
        if flags & 0x30000000:
            stop('invalid_SettingCache_object_flags')
        if not obj:
            stop('null_SettingCache_object')
        if not 0x10000 <= obj < 0x800000000000:
            stop('invalid_SettingCache_object_pointer')
        if globals_now() != before or exact(item_address, 24, 'recheck_SettingCache_item', heap=True) != item:
            stop('configuration_reference_changed')
        headers = {}
        for name, offset, _ in FIELDS:
            if offset + 16 > schema['uappsetting_size']:
                stop('configuration_field_outside_proven_type')
            headers[name] = exact(obj + offset, 16, 'typed_FString_header:' + name, heap=True)
        pending = []
        for name, offset, kind in FIELDS:
            pointer, n, capacity = struct.unpack('<Qii', headers[name])
            field = {'field': name, 'object_member_offset': offset,
                     'header_address': obj + offset, 'utf16_count_including_nul': n,
                     'array_capacity': capacity, 'public_value_output_verified': False}
            if not 0 <= n <= capacity <= 4096:
                field['status'] = 'invalid_FString_header'
            elif n == 0:
                field.update(status='empty_in_current_configuration', value='', public_value_output_verified=True)
            elif n > MAX_CHARS:
                field['status'] = 'unsupported_FString_length'
            elif not 0x10000 <= pointer < pointer + n * 2 <= 0x800000000000:
                field['status'] = 'invalid_FString_pointer'
            else:
                if exact(obj + offset, 16, 'recheck_FString_header:' + name, heap=True) != headers[name]:
                    stop('configuration_string_header_changed')
                data = exact(pointer, n * 2, 'bounded_typed_public_FString:' + name, heap=True)
                try:
                    value = data[:-2].decode('utf-16-le', 'strict')
                except UnicodeError:
                    value = None
                if data[-2:] != b'\0\0' or value is None or '\0' in value or not public_value(value, kind):
                    field['status'] = 'filtered_nonpublic_or_invalid_string'
                else:
                    field.update(status='empty_in_current_configuration' if not value else 'observed_public_configuration_value',
                                 value=value, public_value_output_verified=True)
            pending.append(field)
        if globals_now() != before or exact(item_address, 24, 'final_recheck_SettingCache_item', heap=True) != item:
            stop('configuration_reference_changed')
        for name, offset, _ in FIELDS:
            if exact(obj + offset, 16, 'final_recheck_FString_header:' + name, heap=True) != headers[name]:
                stop('configuration_string_header_changed')
        result.update(status='captured_configuration_fields', reason=None,
                      configuration_object_address=obj, app_setting_row_address=obj + 0x38,
                      fields=pending, weak_reference_and_headers_rechecked=True)
    except _Skip as exc:
        result['reason'] = str(exc)
    except (OSError, ValueError, struct.error) as exc:
        result.update(reason='read_failed', error_type=type(exc).__name__)
    result['requested_bytes'] = sum(item['size'] for item in result['read_set'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--game-root')
    parser.add_argument('--shadow-root')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/evidence/live-cdn-settings-private.json')
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('Expected an explicit running native x64 shadow PID')
    installed, shadow = game_paths(args.game_root, args.shadow_root)
    executable = shadow / identity.CLIENT_RELATIVE_PATH
    source = installed / identity.CLIENT_RELATIVE_PATH
    identity.verify_shadow_executable(executable, executable, source)
    schema = verify_source_schema(source)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                             ctypes.POINTER(identity.ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleInformation.restype = wintypes.BOOL
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
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
        if not 0 < needed.value <= ctypes.sizeof(modules):
            raise ValueError('Unexpected native module count')
        path_buffer = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, modules[0], path_buffer, len(path_buffer)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path_buffer.value).resolve() != executable.resolve():
            raise ValueError('PID is not the authorized shadow executable')
        info = identity.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())

        def read(address, size, module_only=True):
            if not 0 < size <= 1024 or not 0x10000 <= address < address + size <= 0x800000000000:
                raise ValueError('Read exceeds the bounded configuration range')
            if module_only and not info.base <= address < address + size <= info.base + info.size:
                raise ValueError('Configuration code/global read is outside the module')
            data = ctypes.create_string_buffer(size)
            actual = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, data, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('Short bounded configuration read')
            return data.raw

        report = capture(read, info.base, info.size, schema)
        report['pid'] = args.pid
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': report['status'], 'reason': report.get('reason'),
                          'fields': len(report['fields']), 'requested_bytes': report['requested_bytes'],
                          'report': str(args.output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
