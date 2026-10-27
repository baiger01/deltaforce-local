"""Read-only original action/account level table discovery with native schemas."""

import hashlib
import json
from pathlib import Path
import re
import struct

from extract_native_safehouse_catalog import source_structs
from inspect_department_tables import rows
from local_game_paths import game_paths
from scan_weapon_tables import decode_content, parse_entry


ROOT = Path(__file__).resolve().parent.parent
TABLES = {
    'action': (0, 0, 'SeasonLevel', 489442048, 413285552, 5),
    'account': (0, 0, 'AccountLevel', 489338512, 413331080, 2),
}


def main():
    reflected = source_structs(TABLES)
    path = game_paths()[0] / 'DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak'
    candidates = []
    examined = 0
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [value[:-1].decode('ascii') for value in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        position = number = 0
        while position < limit:
            try:
                try:
                    entry = parse_entry(handle, position, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(handle, position, limit, variant='observed_permutation')
            except (ValueError, struct.error):
                aligned = (position + 2047) // 2048 * 2048
                handle.seek(position)
                if aligned >= limit or handle.read(aligned - position) != bytes(aligned - position):
                    raise ValueError('Unexpected original archive boundary')
                position = aligned
                entry = parse_entry(handle, position, limit, variant='observed_permutation')
            number += 1
            if 64 < entry['uncompressed'] <= 2 * 1024 * 1024:
                raw = decode_content(handle, position, entry, methods)
                if raw is not None:
                    examined += 1
                    for group, native in reflected.items():
                        try:
                            recovered, fields = rows(raw, native['columns'])
                        except (ValueError, struct.error, KeyError, IndexError, UnicodeError):
                            continue
                        candidate = {'group': group, 'pak': path.name, 'entry': number,
                            'pak_offset': position, 'sha256': hashlib.sha256(raw).hexdigest(),
                            'size': len(raw), 'native': native, 'serialized_field_indices': fields,
                            'rows': recovered}
                        candidates.append(candidate)
                        print(group, number, position, len(recovered), recovered[:2], recovered[-2:], flush=True)
            position = entry['next_pos']
    output = ROOT / 'work/evidence/native-action-account-level-candidates-20261020.json'
    output.write_text(json.dumps({'status': 'typed_source_candidates_pending_package_binding',
        'archive': path.name, 'archive_entries': number, 'readable_exports_examined': examined,
        'scan_complete': position == limit, 'candidates': candidates}, ensure_ascii=True, indent=2) + '\n',
        encoding='utf-8')
    print('report', output, flush=True)


if __name__ == '__main__':
    main()
