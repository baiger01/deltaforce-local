"""Parse recovered installed tagged Unreal DataTables with explicit provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from extract_operator_avatar_catalog import name_map, fname, tags, property_tag
from recover_economy_pak_access import fstring, installed_name_map, installed_table_package_identity


STRUCT_FORMATS = {'Vector': ('<3f', ('X', 'Y', 'Z')), 'Vector2D': ('<2f', ('X', 'Y')),
                  'Rotator': ('<3f', ('Pitch', 'Yaw', 'Roll')), 'Quat': ('<4f', ('X', 'Y', 'Z', 'W')),
                  'LinearColor': ('<4f', ('R', 'G', 'B', 'A'))}


def tag_value(data, tag, names):
    kind, at, end = tag['kind'], tag['value_start'], tag['end']
    if kind == 'BoolProperty':
        return bool(data[at-2])
    formats = {'IntProperty': '<i', 'UInt32Property': '<I', 'Int64Property': '<q',
               'UInt64Property': '<Q', 'FloatProperty': '<f', 'DoubleProperty': '<d',
               'ObjectProperty': '<i'}
    if kind in formats and struct.calcsize(formats[kind]) == end-at:
        return struct.unpack_from(formats[kind], data, at)[0]
    if kind in ('NameProperty', 'EnumProperty', 'ByteProperty') and end-at == 8:
        return fname(data, at, names)
    if kind == 'ByteProperty' and end-at == 1:
        return data[at]
    if kind == 'StrProperty':
        result, cursor = fstring(data, at)
        if cursor != end:
            raise ValueError('String did not consume its tag')
        return result
    if kind == 'StructProperty':
        subtype = tag['meta'][0]
        if subtype == 'SoftObjectPath':
            subpath, cursor = fstring(data, at+8)
            if cursor != end:
                raise ValueError('SoftObjectPath did not consume its tag')
            return fname(data, at, names)+((':'+subpath) if subpath else '')
        if subtype in STRUCT_FORMATS:
            fmt, labels = STRUCT_FORMATS[subtype]
            if struct.calcsize(fmt) == end-at:
                return dict(zip(labels, struct.unpack_from(fmt, data, at)))
        child, cursor = tags(data, at, names, end)
        if cursor != end:
            raise ValueError('Struct did not consume its tag')
        return {field['name']: tag_value(data, field, names) for field in child}
    if kind == 'ArrayProperty':
        count = struct.unpack_from('<I', data, at)[0]
        at += 4
        if count > 100000:
            raise ValueError('Array count exceeds table bound')
        subtype = tag['meta'][0]
        result = []
        if subtype == 'StructProperty':
            inner = property_tag(data, at, names, end)
            if inner.get('kind') != 'StructProperty' or len(inner.get('meta', ())) != 1:
                raise ValueError('Expected an inline struct array declaration')
            at = inner['value_start']
            fixed = STRUCT_FORMATS.get(inner['meta'][0])
            if fixed is not None:
                fmt, labels = fixed
                stride = struct.calcsize(fmt)
                if inner['end'] != end or count * stride != end - at:
                    raise ValueError('Fixed-width struct array count does not match its payload')
                return [dict(zip(labels, struct.unpack_from(fmt, data, at + index * stride)))
                        for index in range(count)]
            for _ in range(count):
                if inner['meta'] == ['SoftObjectPath']:
                    text = fname(data, at, names)
                    subpath, at = fstring(data, at+8)
                    result.append(text+((':'+subpath) if subpath else ''))
                else:
                    child, at = tags(data, at, names, end)
                    result.append({field['name']: tag_value(data, field, names) for field in child})
        else:
            for _ in range(count):
                item, at = untagged_value(data, at, subtype, names, end)
                result.append(item)
        if at != end:
            raise ValueError('Array did not consume its tag')
        return result
    if kind == 'MapProperty':
        removed = struct.unpack_from('<I', data, at)[0]
        if removed:
            raise ValueError('Map contains unsupported removal entries')
        count = struct.unpack_from('<I', data, at+4)[0]
        at += 8
        if count > 100000:
            raise ValueError('Map count exceeds table bound')
        result = []
        for _ in range(count):
            key, at = untagged_value(data, at, tag['meta'][0], names, end)
            item, at = untagged_value(data, at, tag['meta'][1], names, end)
            result.append(dict(key=key, value=item))
        if at != end:
            raise ValueError('Map did not consume its tag')
        return result
    return dict(serialized_kind=kind, meta=tag['meta'], serialized_hex=data[at:end].hex())


def untagged_value(data, at, kind, names, end):
    if kind == 'StrProperty':
        return fstring(data, at)
    if kind in ('NameProperty', 'EnumProperty'):
        return fname(data, at, names), at+8
    if kind == 'StructProperty':
        possible_path = fname(data, at, names)
        if possible_path.startswith('/Game/') or possible_path == 'None':
            subpath, cursor = fstring(data, at+8)
            return possible_path+((':'+subpath) if subpath else ''), cursor
        fields, cursor = tags(data, at, names, end)
        return {field['name']: tag_value(data, field, names) for field in fields}, cursor
    formats = {'IntProperty': '<i', 'UInt32Property': '<I', 'Int64Property': '<q',
               'UInt64Property': '<Q', 'FloatProperty': '<f', 'DoubleProperty': '<d',
               'ByteProperty': '<B', 'BoolProperty': '<?', 'ObjectProperty': '<i'}
    if kind not in formats:
        raise ValueError('Unsupported untagged table field '+kind)
    fmt = formats[kind]
    return struct.unpack_from(fmt, data, at)[0], at+struct.calcsize(fmt)


def parse_table(uasset, uexp, pattern='.*'):
    asset, data = uasset.read_bytes(), uexp.read_bytes()
    names = installed_name_map(asset)
    header, at = tags(data, 0, names, len(data))
    if not any(tag['name'] == 'RowStruct' for tag in header):
        raise ValueError('Recovered asset is not a tagged DataTable')
    prefix, count = struct.unpack_from('<ii', data, at)
    if prefix != 0 or not 0 <= count <= 100000:
        raise ValueError('Unexpected DataTable row prefix or count')
    at += 8
    rows = {}
    all_names = []
    for _ in range(count):
        start = at
        row = fname(data, at, names)
        fields, at = tags(data, at+8, names, len(data))
        all_names.append(row)
        if re.search(pattern, row, re.IGNORECASE):
            if row in rows:
                raise ValueError('Duplicate serialized row name')
            rows[row] = dict(serialized_uexp_offset=start,
                            fields={field['name']: tag_value(data, field, names) for field in fields})
    if data[at:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('DataTable row coverage does not reach the package trailer')
    return dict(source_uasset=str(uasset), source_uexp=str(uexp),
                source_uasset_sha256=hashlib.sha256(asset).hexdigest(),
                source_uexp_sha256=hashlib.sha256(data).hexdigest(),
                source_table=installed_table_package_identity(asset)['package_path'],
                row_count=count, complete_row_coverage=True, selected_pattern=pattern,
                selected_row_count=len(rows), rows=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uasset', type=Path, required=True)
    parser.add_argument('--uexp', type=Path, required=True)
    parser.add_argument('--rows', default='.*')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.output.exists() or not args.output.resolve().is_relative_to(root/'work/evidence'):
        parser.error('A fresh evidence output is required')
    result = parse_table(args.uasset, args.uexp, args.rows)
    encoded = (json.dumps(result, ensure_ascii=False, indent=2)+'\n').encode('utf-8')
    with args.output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(encoded).hexdigest(),
                          row_count=result['row_count'], selected_row_count=result['selected_row_count'])))


if __name__ == '__main__':
    main()
