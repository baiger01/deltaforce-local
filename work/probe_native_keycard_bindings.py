"""Read native keycard struct registrations without modifying the installed PE."""

import json
import hashlib
import mmap
from pathlib import Path
import re
import struct

import pefile

from local_game_paths import game_paths


ROOT = Path(__file__).resolve().parent.parent


def main():
    path = game_paths()[0] / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with path.open('rb') as handle:
        header = handle.read(65536)
        pe = pefile.PE(data=header, fast_load=True)
    # pefile omits out-of-buffer sections when supplied only the header. Read
    # every header record directly; the installed PE repeats the name .std.
    section_table = pe.DOS_HEADER.e_lfanew + 24 + pe.FILE_HEADER.SizeOfOptionalHeader
    sections = []
    for index in range(pe.FILE_HEADER.NumberOfSections):
        offset = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw = struct.unpack_from('<4I', header, offset + 8)
        sections.append((raw, raw_size, pe.OPTIONAL_HEADER.ImageBase + virtual_address))
    report = {}
    with path.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image_base = pe.OPTIONAL_HEADER.ImageBase

        def offset_va(offset):
            return next((base + offset - raw for raw, size, base in sections if raw <= offset < raw + size), None)

        def va_offset(address):
            return next((raw + address - base for raw, size, base in sections if base <= address < base + size), None)

        witnesses = []
        for anchor, expected_name, expected_kind in (
                (413437720, 'LevelExpr', 'int32'), (413437744, 'CycleStartLevel', 'int32'),
                (413477528, 'SeasonID', 'int64'), (413477552, 'BonusRate', 'float'),
                (413502216, 'SeasonID', 'int64'), (413502240, 'Level', 'int32')):
            name_pointer, kind_pointer, member_offset = struct.unpack_from('<3Q', data, anchor)
            name_offset, kind_offset = va_offset(name_pointer), va_offset(kind_pointer)
            name = data[name_offset:name_offset + 128].split(b'\0')[0].decode('ascii')
            kind = data[kind_offset:kind_offset + 32].split(b'\0')[0].decode('ascii')
            if (name, kind) != (expected_name, expected_kind):
                raise ValueError('Native overlay address mapping differs from the corroborated descriptors')
            witnesses.append({'descriptor_offset': anchor, 'name': name, 'kind': kind,
                              'name_va': name_pointer, 'name_file_offset': name_offset})
        report['_source'] = {'pe_sha256': hashlib.sha256(data).hexdigest(),
            'sections': [{'raw_offset': raw, 'raw_size': size, 'virtual_base': base}
                         for raw, size, base in sections],
            'mapping_witnesses': witnesses}

        def text_at(address):
            offset = va_offset(address)
            if offset is None:
                return None
            raw = data[offset:offset + 128].split(b'\0')[0]
            return raw.decode('ascii') if raw and all(32 <= value < 127 for value in raw) else None

        def occurrences(needle):
            offset = data.find(needle)
            while offset >= 0:
                yield offset
                offset = data.find(needle, offset + 1)

        def qwords(offset, count):
            return struct.unpack_from('<' + 'Q' * count, data, offset)

        for name in ('KeyBoxRow', 'KeyBoxUnlockRow', 'DFMKeyInfoRow', 'KeyChainSpaceInfo'):
            registrations = []
            for text_offset in occurrences(name.encode('ascii') + b'\0'):
                address = offset_va(text_offset)
                if address is None:
                    continue
                for reference in occurrences(struct.pack('<Q', address)):
                    if reference % 8:
                        continue
                    params_offset = reference - 24
                    params = qwords(params_offset, 9)
                    count = params[7] & 0xffffffff
                    pointer_offset = va_offset(params[6])
                    if (params[7] >> 32 != 0x45 or params[5] not in (4, 8, 16)
                            or not 0 < count < 200 or pointer_offset is None):
                        continue
                    properties = []
                    for pointer in qwords(pointer_offset, count):
                        offset = va_offset(pointer)
                        if offset is None:
                            break
                        values = qwords(offset, 5)
                        field_name = text_at(values[0])
                        if field_name is None or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', field_name):
                            break
                        properties.append({'name': field_name, 'property_record_offset': offset,
                            'gen_flags': values[3] & 0xffffffff, 'record_flags': values[3] >> 32,
                            'member_offset': values[4] >> 32, 'array_dim': values[4] & 0xffffffff})
                    else:
                        properties.reverse()
                        registrations.append({'struct_params_offset': params_offset,
                            'size': params[4], 'alignment': params[5], 'property_count': count,
                            'property_pointer_array_offset': pointer_offset, 'properties': properties})
            for registration in registrations:
                for field in registration['properties']:
                    field['native_descriptors'] = []
                    name_pointer = qwords(field['property_record_offset'], 1)[0]
                    for reference in occurrences(struct.pack('<Q', name_pointer)):
                        if reference % 8 or reference + 24 > len(data):
                            continue
                        name_va, kind_va, member_offset = qwords(reference, 3)
                        kind = text_at(kind_va)
                        if (member_offset == field['member_offset'] and kind in
                                ('int32', 'int64', 'uint64', 'uint16', 'uint8', 'float',
                                 'FName', 'FString', 'FText', 'FVector', 'bool')):
                            field['native_descriptors'].append({'descriptor_offset': reference,
                                'kind': kind, 'member_offset': member_offset})
            report[name] = registrations
            print(name, [(value['struct_params_offset'], value['property_count'],
                          [field['name'] for field in value['properties']]) for value in registrations])
    output = ROOT / 'work/evidence/native-keycard-reflection-probe.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
