"""Recover account cosmetic IDs/types from the read-only SocialAvatar export."""

import hashlib
import json
from pathlib import Path
import struct

from explore_tagged_export import read_row


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'work/profile_custom_scan/evidence/matched_assets' / (
    'pak-0-0-pakchunk2-WindowsClient.pak.entry-7110.bin')
OUTPUT = ROOT / 'outputs/df-local-server/protocol/profile_cosmetics_catalog.json'


def main():
    raw = SOURCE.read_bytes()
    none_offset = 29 if struct.unpack_from('<i', raw, 37)[0] == 0 else 55
    none, instance, prefix, count = struct.unpack_from('<iiii', raw, none_offset)
    if instance or prefix:
        raise ValueError('Unexpected account cosmetic export root')
    offset = none_offset + 16
    rows, layout = [], {}
    for index in range(count):
        start = offset
        fields, offset, kinds = read_row(raw, offset + 8, none, known_types=layout)
        layout = dict(kinds)
        fields = {field['field']: field for field in fields}
        item = fields[5213]
        category = fields[5215]
        if item['size'] != 8 or category['size'] != 4:
            raise ValueError('Unexpected SocialAvatar ID/type serialization')
        item_id = struct.unpack_from('<Q', raw, item['value_start'])[0]
        social_type = struct.unpack_from('<i', raw, category['value_start'])[0]
        if not 1 <= social_type <= 4 or str(item_id)[:4] != f'420{social_type}':
            raise ValueError('SocialAvatar row ID/type disagreement')
        rows.append({'item_id': item_id, 'social_type': social_type,
                     'row': index, 'offset': start})
    if raw[offset:] != b'\xc1\x83\x2a\x9e' or len({r['item_id'] for r in rows}) != count:
        raise ValueError('Incomplete or duplicate SocialAvatar export')
    report = {
        'source_table': 'SocialAvatarDataTable',
        'source_pak': 'pak-0-0-pakchunk2-WindowsClient.pak',
        'source_entry': 7110, 'source_sha256': hashlib.sha256(raw).hexdigest(),
        'row_count': count,
        'serialized_field_indices': {'item_id': 5213, 'social_type': 5215},
        'client_consumers': [
            'RoleInfoServer.lua 0.1 pc0287..0292 loads SocialAvatarDataTable',
            'RoleInfoServer.lua 0.20.0 pc0124..0141 AvatarID/AvatarType; props IDs determine ownership',
            'SocialChangeAvatar.lua 0.25/0.26 equips avatar/military',
        ],
        'ownership_policy': 'Only purchased or granted collection props are unlocked; no catalog-wide grant.',
        'limitations': 'Encrypted name map is unavailable; resource, visibility and timing fields remain in the native client table.',
        'rows': rows,
    }
    OUTPUT.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('source_sha256', report['source_sha256'], 'rows', count,
          'types', {kind: sum(r['social_type'] == kind for r in rows) for kind in range(1, 5)})


if __name__ == '__main__':
    main()
