"""Inspect numeric fields in the clear installed gun preset node export."""

from pathlib import Path
import struct

from extract_operator_avatar_catalog import tags


SOURCE = Path(__file__).with_name('evidence') / 'matched_assets/pak-0-0-pakchunk2-WindowsClient.pak.entry-4567.uexp'


def rows():
    data = SOURCE.read_bytes()
    names = [f'field_{index}' for index in range(40000)]
    types = {0x747f: 'None', 0x7480: 'ObjectProperty', 0x748b: 'UInt64Property',
        0x747a: 'UInt16Property', 0x747b: 'FloatProperty', 0x748a: 'IntProperty',
        0x746c: 'EnumProperty', 0x746a: 'BoolProperty', 0x7467: 'ArrayProperty',
        0x747d: 'NameProperty'}
    for index, kind in types.items():
        names[index] = kind
    _, offset = tags(data, 0, names, len(data))
    prefix, count = struct.unpack_from('<ii', data, offset)
    if prefix != 0:
        raise ValueError('Unexpected gun node table prefix')
    offset += 8
    for _ in range(count):
        row_offset = offset
        row_key = struct.unpack_from('<ii', data, offset)
        properties, offset = tags(data, offset + 8, names, len(data))
        values = {}
        for tag in properties:
            raw = data[tag['value_start']:tag['end']]
            if tag['kind'] == 'UInt64Property':
                val = struct.unpack('<Q', raw)[0]
            elif tag['kind'] == 'UInt16Property':
                val = struct.unpack('<H', raw)[0]
            elif tag['kind'] == 'IntProperty':
                val = struct.unpack('<i', raw)[0]
            elif tag['kind'] == 'ArrayProperty':
                val = {'count': struct.unpack_from('<i', raw)[0], 'hex': raw.hex()}
            else:
                val = raw.hex()
            values[int(tag['name'].removeprefix('field_'))] = val
        yield row_offset, row_key, values, properties
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unexpected gun node table trailer')


def main():
    count = 0
    for offset, key, values, _ in rows():
        if values[0x7471] == 10010000019:
            print(offset, key, {hex(k): v for k, v in values.items()})
        count += 1
    print('validated rows', count)


if __name__ == '__main__':
    main()
