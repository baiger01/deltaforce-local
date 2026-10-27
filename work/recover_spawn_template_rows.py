"""Decode the sealed cooked SOLStartSpotTemplateTable using structured tags."""
import hashlib
import json
import math
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname, name_map, property_tag, tags

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT / 'work/evidence/map-system-audit-20261018'
STEM = FOLDER / ('economy-decrypted-assets/pak-0-0-pakchunk2-WindowsClient/'
                 'DeltaForce/Content/DataTables/SOLStartSpotTemplateTable')
EXPECTED = {
    '.uasset': (9418, 'ac1482606941bb898b54cd9af5b038073bd034ddf1d7257f0919ceeefd1d5146'),
    '.uexp': (465055, '09b9fbd71da3e8c6b5eaca11edece9a26870dcbc75b5f8bc5eb105fc401eb254'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def derive():
    checked, pins = {}, []
    for suffix, (size, digest) in EXPECTED.items():
        path = STEM.with_suffix(suffix)
        raw = path.read_bytes()
        assert len(raw) == size and sha(raw) == digest
        checked[suffix] = raw
        pins.append(dict(relative_path=path.relative_to(ROOT).as_posix(), sha256=digest, bytes=size))
    header, payload = checked['.uasset'], checked['.uexp']
    names = name_map(header)
    assert names[0] == '/Game/DataTables/SOLStartSpotTemplateTable'
    custom_count = struct.unpack_from('<i', header, 20)[0]
    summary = 41 + custom_count * 20
    export_count, export_offset, import_count, import_offset = struct.unpack_from('<4i', header, summary + 16)
    assert (export_count, import_count) == (1, 5)
    assert export_offset - import_offset == import_count * 28
    imports = [dict(index=-i-1, class_name=fname(header, import_offset+i*28+8, names),
                    name=fname(header, import_offset+i*28+20, names)) for i in range(import_count)]
    class_index = struct.unpack_from('<i', header, export_offset)[0]
    export_name = fname(header, export_offset+16, names)
    export_bytes, export_absolute = struct.unpack_from('<qq', header, export_offset+28)
    assert export_name == 'SOLStartSpotTemplateTable'
    assert next(r for r in imports if r['index'] == class_index)['name'] == 'DataTable'
    assert export_absolute == len(header) and export_bytes == len(payload)-4
    assert payload[-4:] == bytes.fromhex('c1832a9e')

    def values(items, depth=0):
        assert depth <= 8
        result = {}
        for item in items:
            assert item['array_index'] == 0 and item['name'] not in result
            result[item['name']] = decode(item, depth)
        return result

    def decode(tag, depth):
        kind, first, end = tag['kind'], tag['value_start'], tag['end']
        raw = payload[first:end]
        if kind == 'NameProperty' and len(raw) == 8:
            return fname(payload, first, names)
        if kind == 'EnumProperty' and len(raw) == 8:
            assert len(tag['meta']) == 1
            return fname(payload, first, names)
        if kind == 'IntProperty' and len(raw) == 4:
            return struct.unpack('<i', raw)[0]
        if kind == 'FloatProperty' and len(raw) == 4:
            number = struct.unpack('<f', raw)[0]
            assert math.isfinite(number)
            return number
        if kind == 'BoolProperty' and not raw:
            number = payload[tag['start']+24]
            assert number in (0, 1)
            return bool(number)
        if kind == 'ObjectProperty' and len(raw) == 4:
            index = struct.unpack('<i', raw)[0]
            return next(r for r in imports if r['index'] == index)
        if kind == 'ArrayProperty':
            count = struct.unpack_from('<i', raw)[0]
            assert 0 <= count <= 4096 and len(tag['meta']) == 1
            at, children = first+4, []
            inner_type = tag['meta'][0]
            if inner_type == 'StructProperty':
                inner = property_tag(payload, at, names, end)
                assert inner['kind'] == 'StructProperty'
                at = inner['value_start']
                for _ in range(count):
                    children_tags, at = tags(payload, at, names, end)
                    children.append(values(children_tags, depth+1))
                assert at == end == inner['end']
            elif inner_type in ('IntProperty', 'NameProperty'):
                width = 4 if inner_type == 'IntProperty' else 8
                assert at + count * width == end
                for _ in range(count):
                    children.append(struct.unpack_from('<i', payload, at)[0]
                                    if width == 4 else fname(payload, at, names))
                    at += width
            else:
                raise ValueError('Unqualified array element type '+inner_type)
            return children
        raise ValueError('Unqualified property '+str(tag))

    object_tags, at = tags(payload, 0, names, export_bytes)
    obj = values(object_tags)
    assert list(obj) == ['RowStruct'] and obj['RowStruct']['name'] == 'SOLStartSpotTemplate'
    assert payload[at:at+4] == bytes(4)
    row_count = struct.unpack_from('<i', payload, at+4)[0]
    assert 0 < row_count <= 10000
    at += 8
    rows = []
    for index in range(row_count):
        start = at
        name = fname(payload, at, names)
        row_tags, at = tags(payload, at+8, names, export_bytes)
        rows.append(dict(name=name, serialized_index=index, uexp_offset=start,
                         serialized_bytes=at-start, serialized_sha256=sha(payload[start:at]),
                         fields=values(row_tags),
                         property_sources=[dict(name=t['name'], kind=t['kind'], meta=t['meta'],
                                                offset=t['start'], value_offset=t['value_start'], end=t['end'])
                                           for t in row_tags]))
    assert at == export_bytes and len({r['name'] for r in rows}) == row_count
    dam = [r for r in rows if r['fields']['SOLMapName'] == 'Dam_Iris_Level1']
    return dict(kind='static_client_SOL_spawn_template_rows', source_files=pins,
                source_package='/Game/DataTables/SOLStartSpotTemplateTable',
                row_struct=obj['RowStruct'], row_count=row_count,
                complete_export_consumed=True, row_order_is_serialized_asset_order=True,
                runtime_table_map_iteration_order_qualified=False,
                dam_map_name='Dam_Iris_Level1', dam_row_names=[r['name'] for r in dam],
                dam_positive_weight_rows=[r['name'] for r in dam if r['fields']['Weight'] > 0],
                rows=rows)


if __name__ == '__main__':
    result = derive()
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    target = FOLDER / 'native-spawn-template-table-rows.json'
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=target.relative_to(ROOT).as_posix(), sha256=sha(raw),
                          rows=result['row_count'], dam_rows=result['dam_row_names'],
                          dam_positive_weight_rows=result['dam_positive_weight_rows'])))
