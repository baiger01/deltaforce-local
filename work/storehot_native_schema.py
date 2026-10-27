"""Verify exact original-PE StoreHot row ownership, field names and native types.

Disk-only source verification. Runtime RowStruct identity and table rows are not
read or inferred here. The source contains28 fields and a392-byte native row.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from local_game_paths import game_paths

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
PARAMS_OFFSET = 489450288
PARAMS_SHA = '024f4ebd784e712444838ec7a712fc485584033d7995cc0328df4fbf9b3d8d94'
ARRAY_OFFSET = 414638576
ARRAY_SHA = 'c7f8a36e0075941e3f20f1695bc4f9c58010205f76f20a6be96517a9723aafae'
DESCRIPTORS_OFFSET = 413374544
DESCRIPTORS_SHA = '6880b80b2c3f1c7bb23671a18f19953e8e1f9468d58b58c8bb3dcf739b63000f'
IMAGE_FIELDS = {'TabId': ('uint64', 16), 'IamgeSourceSmall': ('FString', 160),
                'IamgeSourceBig': ('FString', 176), 'ImageSourceLogo': ('FString', 192),
                'MoviesRowName': ('FString', 224), 'BGVideoName': ('FString', 248)}


def verify_schema(path):
    path = Path(path)
    with path.open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != EXPECTED_PE:
            raise ValueError('StoreHot original source PE differs')
        source.seek(0)
        header = source.read(65536)
        nt = struct.unpack_from('<I', header, 0x3c)[0]
        n = struct.unpack_from('<H', header, nt + 6)[0]
        optional = struct.unpack_from('<H', header, nt + 20)[0]
        base = struct.unpack_from('<Q', header, nt + 48)[0]
        sections = [struct.unpack_from('<4I', header, nt + 24 + optional + i * 40 + 8)
                    for i in range(n)]

        def offset(address):
            matches = [raw + address - base - rva for _, rva, size, raw in sections
                       if base + rva <= address < base + rva + size]
            if len(matches) != 1:
                raise ValueError('Source pointer is not in one raw-backed section')
            return matches[0]

        def exact(at, size):
            source.seek(at)
            raw = source.read(size)
            if len(raw) != size:
                raise ValueError('Short StoreHot source metadata read')
            return raw

        def text(address):
            raw = exact(offset(address), 128).split(bytes(1), 1)[0]
            if not raw or any(b < 32 or b > 126 for b in raw):
                raise ValueError('Expected bounded original ASCII schema label')
            return raw.decode('ascii')

        params_raw = exact(PARAMS_OFFSET, 72)
        if hashlib.sha256(params_raw).hexdigest() != PARAMS_SHA:
            raise ValueError('StoreHot source registration changed')
        params = struct.unpack('<9Q', params_raw)
        if (text(params[3]), params[4], params[5], params[7] & 0xffffffff,
                params[7] >> 32, offset(params[6])) != ('StoreHotRecommendation', 392, 8, 28, 0x45, ARRAY_OFFSET):
            raise ValueError('StoreHot native struct owner/size/count changed')
        array_raw = exact(ARRAY_OFFSET, 28 * 8)
        descriptor_raw = exact(DESCRIPTORS_OFFSET, 28 * 24)
        if (hashlib.sha256(array_raw).hexdigest() != ARRAY_SHA
                or hashlib.sha256(descriptor_raw).hexdigest() != DESCRIPTORS_SHA):
            raise ValueError('StoreHot complete property/descriptor array changed')
        pointers = list(struct.unpack('<28Q', array_raw))[::-1]
        fields = []
        for index, pointer in enumerate(pointers):
            at = offset(pointer)
            raw = exact(at, 40)
            native = struct.unpack('<5Q', raw)
            desc = descriptor_raw[index * 24:(index + 1) * 24]
            name_pointer, kind_pointer, member = struct.unpack('<3Q', desc)
            name, kind = text(name_pointer), text(kind_pointer)
            if (text(native[0]) != name or native[4] >> 32 != member
                    or native[4] & 0xffffffff != 1):
                raise ValueError('StoreHot UHT owner/descriptor field mismatch')
            if name in IMAGE_FIELDS and (kind, member) != IMAGE_FIELDS[name]:
                raise ValueError('StoreHot image scalar/string type differs')
            fields.append({'name': name, 'kind': kind, 'member_offset': member,
                           'owned_uht_property_file_offset': at,
                           'uht_gen_flags': native[3] & 0xffffffff,
                           'uht_record_sha256': hashlib.sha256(raw).hexdigest(),
                           'typed_descriptor_file_offset': DESCRIPTORS_OFFSET + index * 24,
                           'typed_descriptor_sha256': hashlib.sha256(desc).hexdigest()})
    if len({f['name'] for f in fields}) != 28 or not IMAGE_FIELDS.keys() <= {f['name'] for f in fields}:
        raise ValueError('StoreHot image fields are not uniquely owned')
    return {'source_pe_sha256': EXPECTED_PE, 'native_struct_name': 'StoreHotRecommendation',
            'native_struct_size': 392, 'alignment': 8, 'field_count': 28,
            'params_file_offset': PARAMS_OFFSET, 'params_sha256': PARAMS_SHA,
            'property_array_file_offset': ARRAY_OFFSET, 'property_array_sha256': ARRAY_SHA,
            'typed_descriptor_array_file_offset': DESCRIPTORS_OFFSET,
            'typed_descriptor_array_sha256': DESCRIPTORS_SHA, 'fields': fields,
            'runtime_rowstruct_identity_verified': False, 'runtime_rows_read': False,
            'pc_cdn_field_in_this_native_schema': False,
            'limitation': 'Runtime table RowStruct identity must independently match before reading any row fields'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    installed, shadow = game_paths(args.source_game)
    output = args.output.resolve()
    if (output.is_relative_to(installed.resolve()) or output.is_relative_to(shadow.resolve())
            or not output.is_relative_to((ROOT / 'work/evidence').resolve()) or output.exists()):
        raise ValueError('Source game and existing reports must be preserved')
    report = verify_schema(installed / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
    with output.open('x', encoding='utf-8') as result:
        result.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'native_struct': report['native_struct_name'], 'fields': 28,
                      'runtime_rows_read': False, 'report': str(output)}))


if __name__ == '__main__':
    main()
