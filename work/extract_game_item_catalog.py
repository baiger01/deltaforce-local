"""Build an ID/warehouse-metadata catalog from the installed GameItem table."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from explore_game_item import UASSET, UEXP, name_map
from extract_operator_avatar_catalog import fname, tags, value

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / 'outputs/df-local-server/protocol/game_item_catalog.json'


def scalar(data, tag, names):
    basic = value(data, tag, names)
    if basic is not None:
        return basic
    if tag['kind'] == 'BoolProperty':
        return bool(data[tag['value_start'] - 2])
    if tag['kind'] == 'FloatProperty' and tag['size'] == 4:
        return round(struct.unpack_from('<f', data, tag['value_start'])[0], 6)
    if tag['kind'] == 'UInt64Property' and tag['size'] == 8:
        return struct.unpack_from('<Q', data, tag['value_start'])[0]
    if tag['kind'] == 'TextProperty':
        raw = data[tag['value_start']:tag['end']]
        match = re.search(rb'([0-9]{8,14})_Name\0', raw)
        if match:
            return match.group(1).decode('ascii') + '_Name'
    if tag['kind'] == 'StrProperty':
        raw = data[tag['value_start']:tag['end']]
        if len(raw) >= 4:
            length = struct.unpack_from('<i', raw)[0]
            if 0 < length <= len(raw) - 4:
                return raw[4:4 + length].rstrip(b'\0').decode('utf-8', errors='replace')
    return None


def main():
    uasset, uexp = UASSET.read_bytes(), UEXP.read_bytes()
    names = name_map(uasset)
    header, offset = tags(uexp, 0, names, len(uexp))
    if not any(tag['name'] == 'RowStruct' for tag in header):
        raise ValueError('Missing GameItem RowStruct')
    if struct.unpack_from('<i', uexp, offset)[0] != 0:
        raise ValueError('Unexpected GameItem row prefix')
    row_count = struct.unpack_from('<i', uexp, offset + 4)[0]
    if not 10000 <= row_count <= 50000:
        raise ValueError('Unexpected GameItem row count')
    offset += 8
    keep = {
        'GameItemType': 'game_item_type', 'Quality': 'quality',
        'Material': 'material', 'MaxStackCount': 'max_stack_count',
        'Length': 'length', 'Width': 'width', 'Weight': 'weight',
        'CanStoreInSafeBox': 'can_store_in_safe_box',
        'IsCurrency': 'is_currency', 'IsModelOnly': 'is_model_only',
        'bValuableItem': 'valuable_item', 'bHighValueItemNeedInspection': 'high_value_needs_inspection',
        'RecycleMoney': 'recycle_currency_id', 'RecyclePrice': 'recycle_price',
        'InitialGuidePrice': 'initial_guide_price',
        'MallItemIcon': 'mall_item_icon',
    }
    rows = {}
    quality_counts = Counter()
    for index in range(row_count):
        row_offset = offset
        row_id = fname(uexp, offset, names)
        offset += 8
        properties, offset = tags(uexp, offset, names, len(uexp))
        fields = {tag['name']: tag for tag in properties}
        if scalar(uexp, fields['ItemID'], names) != row_id:
            raise ValueError(f'GameItem row {index} ID mismatch: {row_id}')
        if row_id in rows:
            raise ValueError(f'Duplicate GameItem ID: {row_id}')
        row = {'id': row_id, 'name_key': scalar(uexp, fields['Name'], names),
               'serialized_uexp_offset': row_offset}
        row.update({target: scalar(uexp, fields[source], names)
                    for source, target in keep.items() if source in fields})
        if not isinstance(row.get('length'), int) or not 0 <= row['length'] <= 100:
            raise ValueError(f'Invalid item length: {row_id}')
        if not isinstance(row.get('width'), int) or not 0 <= row['width'] <= 100:
            raise ValueError(f'Invalid item width: {row_id}')
        rows[row_id] = row
        quality_counts[row.get('quality')] += 1
    if offset + 4 != len(uexp) or uexp[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError(f'Unexpected GameItem trailing bytes: {len(uexp) - offset}')
    report = {
        'source_table': '/Game/R13N/Common/Base/DataTables/GameItem',
        'source_pak': '1.101.37117.36.10_WindowsNoEditor_37127_P.pak',
        'source_uasset_sha256': hashlib.sha256(uasset).hexdigest(),
        'source_uexp_sha256': hashlib.sha256(uexp).hexdigest(),
        'row_count': row_count,
        'quality_counts': dict(sorted(quality_counts.items())),
        'rows': rows,
    }
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False,
                                 separators=(',', ':')) + '\n', encoding='utf-8')
    print('rows', len(rows), 'quality_counts', dict(quality_counts),
          'output_bytes', OUTPUT.stat().st_size)
    for row_id in ('15080050006', '15080050001'):
        print(row_id, rows.get(row_id))


if __name__ == '__main__':
    main()
