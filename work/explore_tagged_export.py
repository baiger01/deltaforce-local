"""Inspect clear tagged exports whose encrypted name maps are unavailable.

This reports serialized indices only; it does not assign guessed field names.
"""

import argparse
from functools import lru_cache
from pathlib import Path
import struct


def read_row(data, start, none_index, maximum=None, known_types=None):
    maximum = maximum or none_index + 256
    @lru_cache(maxsize=None)
    def parse(offset, depth, type_layout):
        if depth > 500 or offset + 8 > len(data):
            return None
        field, instance = struct.unpack_from('<ii', data, offset)
        if field == none_index and instance == 0:
            return (), offset + 8, type_layout
        if not 0 <= field < maximum or instance != 0 or offset + 25 > len(data):
            return None
        kind, kind_instance, size, array_index = struct.unpack_from('<iiii', data, offset + 8)
        if not 0 <= kind < maximum or kind_instance != 0 or size < 0 or array_index != 0:
            return None
        inferred = dict(type_layout)
        candidates = (inferred[kind],) if kind in inferred else (
            (1, 0, 8, 24, 16) if size == 0 else (0, 8, 24, 16, 1))
        for metadata in candidates:
            flag = offset + 24 + metadata
            if flag >= len(data) or data[flag] not in (0, 1):
                continue
            value = flag + 1 + (16 if data[flag] else 0)
            end = value + size
            if end > len(data):
                continue
            following = parse(end, depth + 1, tuple(sorted({**inferred, kind: metadata}.items())))
            if following is not None:
                fields, row_end, layout = following
                tag = {'field': field, 'kind': kind, 'metadata_bytes': metadata,
                       'size': size, 'offset': offset, 'value_start': value, 'end': end}
                return (tag,) + fields, row_end, layout
        return None

    result = parse(start, 0, tuple(sorted((known_types or {}).items())))
    if result is None:
        raise ValueError(f'No consistent tagged row at {start}')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('entry', type=int)
    parser.add_argument('--row', type=int, default=0)
    args = parser.parse_args()
    path = Path(__file__).with_name('evidence') / 'matched_assets' / (
        f'pak-0-0-pakchunk2-WindowsClient.pak.entry-{args.entry}.bin')
    data = path.read_bytes()
    none_offset = 29
    if struct.unpack_from('<i', data, 37)[0] != 0:
        if struct.unpack_from('<ii', data, 45) != (0, 0):
            raise ValueError('Unrecognized root tags')
        none_offset = 55
    none_index = struct.unpack_from('<i', data, none_offset)[0]
    prefix, count = struct.unpack_from('<ii', data, none_offset + 8)
    if prefix != 0:
        raise ValueError('Export has additional root tags')
    offset = none_offset + 16
    print('none_index', none_index, 'rows', count)
    for index in range(args.row + 1):
        fields, end, _ = read_row(data, offset + 8, none_index)
        if index == args.row:
            print('row_offset', offset, 'row_fname', data[offset:offset + 8].hex())
            for field in fields:
                raw = data[field['value_start']:field['end']]
                value = struct.unpack('<Q', raw)[0] if len(raw) == 8 else None
                print(field, 'raw', raw[:32].hex(), 'u64', value)
        offset = end


if __name__ == '__main__':
    main()
