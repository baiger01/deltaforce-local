"""Inspect the installed client's clear PartsDataTable for pendant rows."""

import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname, name_map, tags, value


BASE = Path(__file__).resolve().parent / 'hero_custom_scan/evidence/matched_assets'
STEM = '1.101.37117.36.10_WindowsNoEditor_37127_P.pak'
header = (BASE / (STEM + '.entry-233.uasset')).read_bytes()
data = (BASE / (STEM + '.entry-234.uexp')).read_bytes()
names = name_map(header)
root, offset = tags(data, 0, names, len(data))
prefix, count = struct.unpack_from('<ii', data, offset)
assert prefix == 0
offset += 8
rows = []
for index in range(count):
    start = offset
    row_name = fname(data, offset, names)
    fields, offset = tags(data, offset + 8, names, len(data))
    if not row_name.startswith('1346'):
        continue
    decoded = {}
    for field in fields:
        kind, size = field['kind'], field['size']
        raw = data[field['value_start']:field['end']]
        if kind == 'UInt64Property' and size == 8:
            decoded[field['name']] = struct.unpack('<Q', raw)[0]
        elif kind == 'UInt32Property' and size == 4:
            decoded[field['name']] = struct.unpack('<I', raw)[0]
        elif kind == 'BoolProperty':
            decoded[field['name']] = bool(data[field['start'] + 24])
        elif kind == 'ArrayProperty' and field['meta'] == ['NameProperty']:
            decoded[field['name']] = [fname(raw, pos, names) for pos in range(4, len(raw), 8)]
        else:
            decoded[field['name']] = value(data, field, names)
    rows.append({'row': index, 'offset': start, 'row_name': row_name, 'fields': decoded})
assert data[offset:] == b'\xc1\x83\x2a\x9e'
print(json.dumps({'header_sha256': hashlib.sha256(header).hexdigest(),
                  'export_sha256': hashlib.sha256(data).hexdigest(),
                  'total_rows': count, 'pendant_rows': rows}, indent=2))
