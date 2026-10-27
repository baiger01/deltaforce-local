"""Decode scalar recipe configuration from the qualified installed Parts table."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname, name_map, tags

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT/'work/evidence/map-system-audit-20261018'
REPORT = BASE/'native-owned-weapon-parts-config-cooked-sources-v1.json'
ASSET_SHA = '2e45f59cba4ad9ff8c3fd55d30fd7177403db2bbcb6f854f6581a634a0970cf9'


def scalar(data, tag, names):
    raw = data[tag['value_start']:tag['end']]
    formats = {'UInt64Property': '<Q', 'Int64Property': '<q', 'UInt32Property': '<I',
        'IntProperty': '<i', 'UInt16Property': '<H', 'Int16Property': '<h',
        'FloatProperty': '<f', 'DoubleProperty': '<d'}
    kind = tag['kind']
    if kind in formats:
        if len(raw) != struct.calcsize(formats[kind]):
            raise ValueError('The cooked recipe scalar width changed: '+tag['name'])
        return struct.unpack(formats[kind], raw)[0]
    if kind == 'BoolProperty':
        byte = data[tag['start']+24]
        if byte not in (0, 1) or raw:
            raise ValueError('Noncanonical cooked recipe bool')
        return bool(byte)
    if kind == 'ByteProperty' and len(raw) == 1:
        return raw[0]
    if kind in ('NameProperty', 'EnumProperty', 'ByteProperty') and len(raw) == 8:
        return fname(data, tag['value_start'], names)
    return dict(kind=kind, value_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        complete_value_decoded=False)


def derive():
    source = json.loads(REPORT.read_bytes())
    entries = source['paks'][0]['extracted_assets']
    selected = {}
    pins = {REPORT.relative_to(ROOT).as_posix(): hashlib.sha256(REPORT.read_bytes()).hexdigest()}
    for suffix in ('.uasset', '.uexp'):
        entry = next(e for e in entries if e['path'].endswith('/PartsDataTable'+suffix))
        path = ROOT/entry['output']
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry['decoded_sha256']:
            raise ValueError('The recovered cooked PartsDataTable changed')
        selected[suffix] = raw
        pins[path.relative_to(ROOT).as_posix()] = entry['decoded_sha256']
    if hashlib.sha256(selected['.uasset']).hexdigest() != ASSET_SHA:
        raise ValueError('Unexpected installed PartsDataTable package')
    names, data = name_map(selected['.uasset']), selected['.uexp']
    initial, offset = tags(data, 0, names, len(data))
    if [t['name'] for t in initial] != ['RowStruct']:
        raise ValueError('The installed Parts table RowStruct header changed')
    prefix, count = struct.unpack_from('<ii', data, offset)
    if prefix != 0 or not 1 <= count <= 10000:
        raise ValueError('The installed Parts table row count/header changed')
    offset += 8
    rows = {}
    for _ in range(count):
        start = offset
        key = fname(data, offset, names)
        fields, offset = tags(data, offset+8, names, len(data))
        if key in rows or len({f['name'] for f in fields}) != len(fields):
            raise ValueError('Duplicate installed Parts recipe row or field')
        values = {f['name']: scalar(data, f, names) for f in fields}
        if key != str(values.get('ItemId')):
            raise ValueError('The installed Parts recipe row key/ItemId differs')
        rows[key] = dict(values=values, uexp_offset=start, bytes=offset-start,
            row_sha256=hashlib.sha256(data[start:offset]).hexdigest())
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('The cooked Parts table has unparsed row/trailer bytes')
    return dict(kind='installed_weapon_parts_recipe_scalar_config_v1',
        source_table='/Game/R13N/Common/Base/DataTables/WeaponPart/PartsDataTable',
        row_count=count, rows=rows, sources=pins, client_launched=False,
        process_access=False, actor_recipe_or_gameplay_generated=False,
        non_scalar_values_only_hashed=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(BASE):
        parser.error('Use a fresh weapon evidence output')
    result = derive()
    raw = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)+'\n').encode('utf8')
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        rows=result['row_count'])))
