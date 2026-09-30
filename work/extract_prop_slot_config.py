"""Extract the installed client's clear PropSlotConfig table for local analysis."""

import ast
import hashlib
from pathlib import Path
import re
import struct
import sys
import zlib

import lz4.block
import zstandard

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oodle_payload_reader import decode as decode_oodle
from local_game_paths import game_paths

root = Path(__file__).resolve().parent
namespace = {'struct': struct, 'hashlib': hashlib, 'decode_oodle': decode_oodle,
             'zlib': zlib, 'lz4': lz4, 'zstandard': zstandard}
for filename, name in [('probe_pak_payload_lua.py', 'parse_entry'),
                       ('probe_character_asset_rows.py', 'decode_content')]:
    tree = ast.parse((root / filename).read_text(encoding='utf-8'))
    fn = next(node for node in tree.body
              if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[fn], type_ignores=[]), '<local parser>', 'exec'), namespace)
parse_entry = namespace['parse_entry']
decode_content = namespace['decode_content']

name = '1.101.37117.36.524_WindowsNoEditor_37641_P.pak'
path = game_paths()[0] / 'DeltaForce/Saved/Dolphin/1.101.37117.36/Paks' / name
out = root / 'evidence' / 'prop_slot_config'
out.mkdir(parents=True, exist_ok=True)
target = b'/Game/R13N/Common/Base/DataTables/PropSlotConfig'

with path.open('rb') as handle:
    handle.seek(-512, 2)
    tail = handle.read(512)
    marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
    _, limit = struct.unpack_from('<IQ', tail, marker + 4)
    methods = [m[:-1].decode('ascii') for m in re.findall(
        rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
    position = 0
    count = 0
    found = False
    while position < limit:
        try:
            entry = parse_entry(handle, position, limit, variant='observed_permutation')
        except (ValueError, struct.error):
            try:
                entry = parse_entry(handle, position, limit)
            except (ValueError, struct.error):
                aligned = (position + 2047) // 2048 * 2048
                handle.seek(position)
                if aligned >= limit or handle.read(aligned - position) != bytes(aligned - position):
                    raise
                position = aligned
                entry = parse_entry(handle, position, limit, variant='observed_permutation')
        count += 1
        if not entry['flags'] & 1 and entry['uncompressed'] <= 4 * 1024 * 1024:
            content, _ = decode_content(handle, position, entry, methods,
                                        max_uncompressed=4 * 1024 * 1024)
            if content and content.startswith(b'\xc1\x83\x2a\x9e') and target in content:
                (out / 'PropSlotConfig.uasset').write_bytes(content)
                next_position = entry['next_pos']
                companion = parse_entry(handle, next_position, limit,
                                        variant='observed_permutation')
                payload, error = decode_content(handle, next_position, companion, methods,
                                                max_uncompressed=32 * 1024 * 1024)
                if not payload:
                    raise ValueError(f'Companion payload unavailable: {error}')
                (out / 'PropSlotConfig.uexp').write_bytes(payload)
                print('FOUND', name, 'entry', count, 'uasset', len(content),
                      'uexp', len(payload), flush=True)
                found = True
                break
        position = entry['next_pos']
print('DONE', 'found', found, 'entries_scanned', count, flush=True)
