"""Inspect the already recovered GameItem package without modifying the game."""

from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
STEM = '1.101.37117.36.10_WindowsNoEditor_37127_P.pak'
SOURCE = HERE / 'evidence' / 'character_avatar_tables'
UASSET = SOURCE / (STEM + '.entry-227.uasset')
UEXP = SOURCE / (STEM + '.entry-228.uexp')


def name_map(data):
    count, position = struct.unpack_from('<ii', data, 81)
    if not 1000 < count < 100000 or not 100 < position < len(data):
        raise ValueError('Unexpected GameItem name map')
    names = []
    for _ in range(count):
        length = struct.unpack_from('<i', data, position)[0]
        position += 4
        if length == 0 or abs(length) > 10000:
            raise ValueError(f'Invalid name length at {position}')
        size = length if length > 0 else -length * 2
        raw = data[position:position + size]
        if len(raw) != size:
            raise ValueError('Truncated name map')
        position += size + 4
        names.append(raw.rstrip(b'\0').decode('utf-8') if length > 0
                     else raw.decode('utf-16le').rstrip('\0'))
    return names


def main():
    uasset = UASSET.read_bytes()
    uexp = UEXP.read_bytes()
    names = name_map(uasset)
    numeric = [(i, name) for i, name in enumerate(names)
               if re.fullmatch(r'\d{8,14}', name)]
    fields = [name for name in names if any(term in name.lower() for term in
              ('itemname', 'itemtype', 'rarity', 'itemid', 'grid', 'space',
               'weight', 'price', 'icon', 'quality', 'value', 'description'))]
    print('name_count', len(names), 'uexp_bytes', len(uexp),
          'numeric_name_count', len(numeric))
    print('numeric_sample', numeric[:20])
    print('field_sample', fields[:150])
    print('name_tail', names[-30:])
    for term in ('八音盒', '非洲之心', '海洋之泪'):
        print('chinese_term', term, 'utf8', uexp.find(term.encode('utf-8')),
              'utf16', uexp.find(term.encode('utf-16le')))


if __name__ == '__main__':
    main()
