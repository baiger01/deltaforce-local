"""Extract bounded slot dimensions from the installed clear PropSlotConfig."""

import hashlib
import json
from pathlib import Path
import re
import struct

from extract_operator_avatar_catalog import tags, value

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'work/evidence/prop_slot_config'
TARGET = ROOT / 'outputs/df-local-server/protocol/deposit_slot_catalog.json'


def name_map(uasset):
    # This package uses the long UE4 summary form; the NameCount/NameOffset
    # pair is at byte 81 in the verified current-version PropSlotConfig asset.
    count, offset = struct.unpack_from('<ii', uasset, 81)
    if not 30 <= count <= 1000 or not 100 <= offset < len(uasset):
        raise ValueError('Unexpected PropSlotConfig name map')
    names = []
    for _ in range(count):
        length = struct.unpack_from('<i', uasset, offset)[0]
        offset += 4
        if length == 0 or abs(length) > 10000:
            raise ValueError('Invalid Unreal name length')
        raw_length = length if length > 0 else -length * 2
        raw = uasset[offset:offset + raw_length]
        if len(raw) != raw_length:
            raise ValueError('Truncated Unreal name')
        offset += raw_length + 4
        names.append(raw.rstrip(b'\0').decode('utf-8') if length > 0
                     else raw.decode('utf-16le').rstrip('\0'))
    return names


def main():
    uasset = (SOURCE / 'PropSlotConfig.uasset').read_bytes()
    uexp = (SOURCE / 'PropSlotConfig.uexp').read_bytes()
    names = name_map(uasset)
    page_id_index = names.index('PageId')
    rows = {}
    for index, row_id in enumerate(names):
        if not re.fullmatch(r'\d{1,9}', row_id):
            continue
        needle = struct.pack('<iiii', index, 0, page_id_index, 0)
        offset = uexp.find(needle)
        if offset < 0:
            continue
        row_tags, _ = tags(uexp, offset + 8, names, len(uexp))
        fields = {tag['name']: value(uexp, tag, names) for tag in row_tags}
        length = fields.get('PageLength')
        width = fields.get('PageWidth')
        if not isinstance(length, int) or not 0 <= length <= 1000:
            raise ValueError(f'Invalid length in slot {row_id}')
        if not isinstance(width, int) or not 0 <= width <= 1000:
            raise ValueError(f'Invalid width in slot {row_id}')
        rows[row_id] = {'grid_length': length, 'grid_width': width,
                        'capacity': fields.get('Capacity'),
                        'serialized_uexp_offset': offset}
    if rows.get('2', {}).get('grid_length') != 9 or rows['2']['grid_width'] != 40:
        raise ValueError('MainContainer dimensions did not match this client')
    report = {'source_table': '/Game/R13N/Common/Base/DataTables/PropSlotConfig',
              'source_pak': '1.101.37117.36.524_WindowsNoEditor_37641_P.pak',
              'source_uasset_sha256': hashlib.sha256(uasset).hexdigest(),
              'source_uexp_sha256': hashlib.sha256(uexp).hexdigest(),
              'main_container_slot_id': 2,
              'row_count': len(rows),
              'rows': dict(sorted(rows.items(), key=lambda item: int(item[0])))}
    TARGET.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n',
                      encoding='utf-8')
    print('slots', len(rows), 'main', rows['2'])


if __name__ == '__main__':
    main()
