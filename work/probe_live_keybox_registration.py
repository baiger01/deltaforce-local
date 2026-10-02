"""Read only known KeyBox registrations and their executable-code references.

Requires an already-running native client PID. This never starts the client,
writes process memory, reads account objects, or emits a general memory dump.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import struct
import sys

from local_game_paths import game_paths
from read_keybox_manager_interface import capture as capture_manager_interface
from read_keybox_config_map import capture as capture_config_map
from native_config_names import ConfigNameCodec, read_config_name
from read_keybox_rows import capture as capture_keybox_rows
from read_keybox_rowmap import capture as capture_keybox_rowmap

ROOT = Path(__file__).resolve().parent.parent
IMAGE_BASE = 0x140000000
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
PARAMS = {'KeyBoxRow': 489410080 + 4608, 'KeyBoxUnlockRow': 489410160 + 4608,
          'DFMKeyInfoRow': 489410240 + 4608}
CODE_WITNESSES = {
    0xd3a9930: '4883ec28488b05c5f6dd104885c0751a488d157928750b488d0db2f6dd10e89dcdaf03488b05a6f6dd104883c428c3',
    0xe2c560: '4883ec28488b059d9fd01c4885c0751a488d1569a5bd1b488d0d8a9fd01ce89da20710488b057e9fd01c4883c428c3',
    0xd3c66e0: '4883ec28b910000000e8421435f44885c0741d488d0d560a760bc7400838000000488908c7400c080000004883c428c3',
}
FIXED_CODE = {'package_constructor': (0x10ea66f0, 384),
              'struct_constructor': (0x10ea6820, 768),
              'keybox_ops_construct': (0xd3c7030, 256),
              # Verified direct calls in the first runtime struct-constructor capture.
              'registration_string_conversion': (0xf13910, 384),
              'registration_name_constructor': (0x10b56070, 768),
              # Exact source ClassParams and named function-link records.
              'datatable_class_getter': (0xe2abf0, 192),
              'datatable_get_function_link': (0xe2a7e0, 64),
              'datatable_get_table_function_link': (0xe2a810, 64),
              'registration_name_storage': (0x10b54df0, 272),
              # Verified direct call at RVA 0x10b54edf in the runtime capture.
              'registration_name_entry': (0x10b6edd0, 768),
              'registration_name_lookup': (0x10b6ea10, 1024),
              'registration_name_ascii_copy': (0x10b5fd00, 0x210),
              'registration_name_wide_copy': (0x10b5ff10, 0x290),
              'registration_name_pool_find': (0x10b70cf0, 1024),
              'registration_name_entry_match': (0x10b54060, 1024),
              'datatable_native_registration': (0xe2c1a0, 128),
              'datatable_native_get': (0xe2c950, 512),
              'datatable_native_get_table': (0xe2cab0, 768),
              'datatable_native_lite_interface': (0xe2cf70, 0x150),
              'datatable_native_csv_key': (0xe2ced0, 0xa0),
              'datatable_get_rows_binding_primary': (0xe08f20, 256),
              'datatable_get_rows_binding_secondary': (0xe08200, 256),
              'datatable_lite_content_binding': (0xe078b0, 256),
              'datatable_lite_interface_binding': (0xe09050, 256),
              # Direct Get call and registered class-constructor callback.
              'datatable_manager_get': (0xdba610, 1024),
              'datatable_context_class_link': (0xe28f50, 64),
              'datatable_manager_storage_helper': (0x10ecea20, 512),
              'datatable_context_class_getter': (0x132f07d0, 512),
              'datatable_constructor_callback': (0xe2b4a0, 1024),
              'datatable_constructor_nonnull': (0xd97fe0, 1536),
              'datatable_object_chunk_index': (0xd60500, 0x640),
              'datatable_object_item_index': (0xd60d00, 0x670)}
FIXED_CODE.update({'datatable_content_map_find': (0xdb77b0, 2048),
                   'datatable_content_data_pointer': (0xd968d0, 256),
                   'datatable_lite_rows_primary': (0xdbb5e0, 768),
                   'datatable_lite_rows_secondary': (0xdbb950, 512),
                   'datatable_lite_content_table': (0xdc4bd0, 1024),
                   'datatable_lite_content_valid': (0xdd6320, 512)})
FIXED_DATA = {'package_cache': (0x1e189000, 8), 'package_params': (0x18afc1c0, 32),
              'descrow_cache': (0x1db36508, 8), 'descrow_params': (0x1ca06ae0, 72),
              'keybox_ops_vtable': (0x18b27150, 64),
              'datatable_class_params': (0x14f057a0, 80),
              'datatable_get_function_links': (0x14f05410, 32),
              'datatable_class_label': (0x14f05828, 64),
              'datatable_class_cache': (0x1db36498, 8),
              'datatable_lite_content_descriptor': (0x14ee09d8, 64),
              'datatable_manager_descriptor': (0x14ee6eb0, 64),
              'datatable_lite_interface_descriptor': (0x14ee9988, 64),
              'datatable_manager_storage': (0x1c9fe850, 16),
              'registration_name_pool_header': (0x1e326a80, 16),
              'registration_name_pool_init': (0x1e3267ac, 8),
              'datatable_object_array_header': (0x1e34ee50, 32),
              'datatable_object_accessor_override': (0x1db3a770, 8),
              'datatable_object_index_selector': (0x1e318780, 0x50)}
FIXED_DATA['datatable_content_data_accessor'] = (0x1d59de58, 8)


def reflection_source():
    evidence = ROOT / 'work/evidence/native-keycard-reflection-probe.json'
    if evidence.is_file():
        proof = json.loads(evidence.read_text(encoding='utf-8'))
        origin = evidence.relative_to(ROOT).as_posix()
    else:
        catalog_path = ROOT / 'outputs/df-local-server/protocol/native_keycard_catalog.json'
        catalog = json.loads(catalog_path.read_text(encoding='utf-8')) if catalog_path.is_file() else {}
        registrations = {source['struct']: [source['native_registration']]
                         for source in catalog.get('sources', {}).values() if 'native_registration' in source}
        if set(PARAMS).issubset(registrations):
            proof = {'_source': {'pe_sha256': catalog['native_pe_sha256']}, **registrations}
            origin = catalog_path.relative_to(ROOT).as_posix()
        else:
            # Reproduce the evidence from the installed source; no guessed fields.
            from probe_native_keycard_bindings import main as extract_reflection
            extract_reflection()
            proof = json.loads(evidence.read_text(encoding='utf-8'))
            origin = evidence.relative_to(ROOT).as_posix()
    if proof['_source']['pe_sha256'] != EXPECTED_PE:
        raise ValueError('Original registration evidence version changed')
    for name, rva in PARAMS.items():
        records = proof[name]
        if len(records) != 1 or records[0]['struct_params_offset'] + 4608 != rva:
            raise ValueError('Original named struct registration is not the verified exact source')
    return proof, origin


class ModuleInfo(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('size', wintypes.DWORD), ('entry', ctypes.c_void_p)]


def capstone_module():
    try:
        import capstone
    except ImportError:
        # Installed bundled Python exposes this existing pure-ctypes binding.
        path = Path.home() / 'AppData/Roaming/Python/Python312/site-packages'
        if not (path / 'capstone/__init__.py').is_file():
            raise RuntimeError('Use the bundled Python runtime with its existing capstone package')
        sys.path.insert(0, str(path))
        import capstone
    return capstone


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/evidence/live-keybox-registration.json')
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError('Expected an explicit native x64 client PID')
    proof, proof_origin = reflection_source()
    expected_shadow = game_paths()[1] / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                              ctypes.POINTER(ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                            wintypes.LPWSTR, wintypes.DWORD]
    handle = kernel.OpenProcess(0x0410, False, args.pid)  # QUERY_INFORMATION | VM_READ only.
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        modules = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if needed.value > ctypes.sizeof(modules):
            raise ValueError('Unexpected module count')
        image = modules[0]
        path_buffer = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, image, path_buffer, len(path_buffer)):
            raise ctypes.WinError(ctypes.get_last_error())
        path = Path(path_buffer.value)
        if path.resolve() != expected_shadow.resolve():
            raise ValueError('PID does not identify the authorized shadow native client executable')
        digest = hashlib.sha256()
        with path.open('rb') as source:
            for block in iter(lambda: source.read(8 * 1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != EXPECTED_PE:
            raise ValueError('Native client executable differs from the verified source')
        info = ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, image, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        base, end = info.base, info.base + info.size

        def read(address, size, *, module_only=True):
            if not 0 < size <= 2 * 1024 * 1024 or module_only and not base <= address < address + size <= end:
                raise ValueError('Read is outside the bounded native module metadata/code')
            buffer = ctypes.create_string_buffer(size)
            count = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, buffer, size, ctypes.byref(count)) or count.value != size:
                raise ctypes.WinError(ctypes.get_last_error())
            return buffer.raw

        def text_at(address):
            value = read(address, 128).split(b'\0')[0]
            if not value or any(byte < 32 or byte >= 127 for byte in value):
                raise ValueError('Native property label is not expected ASCII metadata')
            return value.decode('ascii')

        report = {'pid': args.pid, 'native_pe_sha256': EXPECTED_PE, 'module_base': base,
                  'module_size': info.size, 'registrations': {}, 'fixed_code': {}, 'fixed_data': {},
                  'read_policy': 'Verified module code, configuration-manager cache and identified Key/KeyBox rows; no account objects or code execution',
                  'reflection_source': proof_origin,
                  'runtime_witness': 'work/native-client-tests/1790844138358611900/socket-helper-readonly.txt'}
        for rva, expected_hex in CODE_WITNESSES.items():
            expected = bytes.fromhex(expected_hex)
            if read(base + rva, len(expected)) != expected:
                raise ValueError('Loaded getter/factory differs from the verified plaintext witness')
        for name, rva in PARAMS.items():
            pointer = base + rva
            values = struct.unpack('<9Q', read(pointer, 72))
            source = proof[name][0]
            if (text_at(values[3]) != name or values[4] != source['size'] or
                    values[5] != source['alignment'] or values[7] & 0xffffffff != source['property_count']):
                raise ValueError('Loaded struct registration differs from the original named source')
            pointers = struct.unpack('<' + 'Q' * source['property_count'],
                                     read(values[6], 8 * source['property_count']))
            actual = []
            for property_pointer in reversed(pointers):
                property_values = struct.unpack('<5Q', read(property_pointer, 40))
                actual.append((text_at(property_values[0]), property_values[3] & 0xffffffff,
                               property_values[4] >> 32))
            expected = [(field['name'], field['gen_flags'], field['member_offset'])
                        for field in source['properties']]
            if actual != expected:
                raise ValueError('Loaded complete property list differs from the original source')
            report['registrations'][name] = {'params_rva': rva, 'name_rva': values[3] - base,
                'property_names_and_offsets_verified': True,
                'functions': [{'rva': function - base, 'first_256_bytes': read(function, 256).hex()}
                              for function in values[:3] if function]}
        capstone = capstone_module()
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        disassembler.detail = True
        for name, (rva, size) in FIXED_DATA.items():
            blob = read(base + rva, size)
            report['fixed_data'][name] = {'rva': rva, 'size': size, 'bytes': blob.hex(),
                                         'qwords': list(struct.unpack('<' + 'Q' * (size // 8), blob))}
        if text_at(report['fixed_data']['package_params']['qwords'][0]) != '/Script/DFMGlobalDefines':
            raise ValueError('Loaded package parameter identity changed')
        desc = report['fixed_data']['descrow_params']['qwords']
        if text_at(desc[3]) != 'DescRowBase' or desc[4:6] != [16, 8]:
            raise ValueError('Loaded parent struct identity changed')
        if report['fixed_data']['keybox_ops_vtable']['qwords'][3] != base + 0xd3c7030:
            raise ValueError('Loaded KeyBox struct construct slot changed')
        class_params = report['fixed_data']['datatable_class_params']['qwords']
        if class_params[0] != base + 0xe2abf0 or class_params[4] != base + 0x14f053e0:
            raise ValueError('Loaded data-table class function-link source changed')
        links = report['fixed_data']['datatable_get_function_links']['qwords']
        if (links[0] != base + 0xe2a7e0 or text_at(links[1]) != 'Get' or
                links[2] != base + 0xe2a810 or text_at(links[3]) != 'GetDataTable'):
            raise ValueError('Loaded named data-table function links changed')
        class_label = bytes.fromhex(report['fixed_data']['datatable_class_label']['bytes'])
        if class_label.decode('utf-16le').split('\0')[0] != 'UDataTableSystemManagerLite':
            raise ValueError('Loaded data-table class label changed')
        for name, (rva, size) in FIXED_CODE.items():
            code = read(base + rva, size)
            report['fixed_code'][name] = {'rva': rva, 'size': size, 'bytes': code.hex(),
                'instructions': [{'rva': item.address - base, 'op': item.mnemonic, 'args': item.op_str}
                                 for item in disassembler.disasm(code, base + rva)]}
        manager = capture_manager_interface(read, base)
        report['manager_interface'] = manager
        if manager['status'] == 'captured':
            code = bytes.fromhex(manager['target_code_hex'])
            manager['instructions'] = [
                {'rva': item.address - base, 'op': item.mnemonic, 'args': item.op_str}
                for item in disassembler.disasm(code, manager['target_address'])]
        config_map = capture_config_map(read, base)
        report['config_map'] = config_map
        if config_map['status'] == 'captured':
            code = bytes.fromhex(config_map['allocation_accessor_code_hex'])
            config_map['allocation_accessor_instructions'] = [
                {'rva': item.address - base, 'op': item.mnemonic, 'args': item.op_str}
                for item in disassembler.disasm(code, base + config_map['allocation_accessor_rva'])]
            name_codec = ConfigNameCodec(report)
            for entry in config_map.get('entries', []):
                comparison_id, number = struct.unpack('<II', bytes.fromhex(entry['fname_hex']))
                try:
                    entry['name'] = read_config_name(read, base, name_codec, comparison_id, number)
                except (OSError, ValueError, struct.error, UnicodeError) as error:
                    entry['name_status'] = type(error).__name__
        keybox_rows = capture_keybox_rows(read, base, config_map)
        report['keybox_rows'] = keybox_rows
        if keybox_rows['status'] == 'captured':
            for row in keybox_rows['rows']:
                comparison_id, number = struct.unpack('<II', bytes.fromhex(row['item_id_fname_hex']))
                row['item_name'] = read_config_name(read, base, name_codec, comparison_id, number)
        for report_key, table_name in (('keybox_rowmap', 'Key/KeyBox'),
                                       ('keybox_rowmap_short', 'KeyBox')):
            rowmap = capture_keybox_rowmap(read, base, config_map, table_name=table_name)
            report[report_key] = rowmap
            if rowmap['status'] == 'captured':
                code = bytes.fromhex(rowmap['rowmap_accessor_code_hex'])
                rowmap['instructions'] = [
                    {'rva': item.address - base, 'op': item.mnemonic, 'args': item.op_str}
                    for item in disassembler.disasm(code, base + rowmap['rowmap_accessor_rva'])]
                for row in rowmap.get('rows', []):
                    comparison_id, number = struct.unpack('<II', bytes.fromhex(row['item_id_fname_hex']))
                    row['item_name'] = read_config_name(read, base, name_codec, comparison_id, number)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print({'registrations_verified': len(report['registrations']),
               'fixed_code_ranges': len(report['fixed_code']),
               'fixed_data_ranges': len(report['fixed_data']), 'report': str(args.output)})
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
