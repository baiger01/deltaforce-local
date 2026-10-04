"""Read only the two migrated hotfix PAKs for map table name and row strings."""
import ast
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zlib

import lz4.block
import zstandard

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oodle_payload_reader import decode as decode_oodle

HERE = Path(__file__).resolve().parent
namespace = {'struct': struct, 'hashlib': hashlib, 'decode_oodle': decode_oodle,
             'zlib': zlib, 'lz4': lz4, 'zstandard': zstandard}
for filename, name in [('probe_pak_payload_lua.py', 'parse_entry'),
                       ('probe_character_asset_rows.py', 'decode_content')]:
    syntax = ast.parse((HERE / filename).read_text(encoding='utf-8'))
    function = next(node for node in syntax.body
                    if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[function], type_ignores=[]), filename, 'exec'), namespace)
parse_entry = namespace['parse_entry']
decode_content = namespace['decode_content']

terms = ('WorldEntranceConfig', 'MatchModeDataConfig', 'EntranceIdx',
         '零号大坝', '零号', 'MapName')
encodings = {term: (term.encode('utf-8'), term.encode('utf-16le')) for term in terms}
paths = [Path(value) for value in json.loads((HERE / 'pak_paths.json').read_text(encoding='utf-8'))]
summary = json.loads((HERE / 'evidence/config_field_candidates/scan_summary.json').read_text(
    encoding='utf-8'))
readable = {row['pak'] for row in summary if row.get('counts', {}).get('clear_uassets', 0)}
paths = [p for p in paths if p.exists() and p.name in readable]

for path in paths:
    hits = []
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [m[:-1].decode('ascii') for m in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        pos = 0
        count = 0
        while pos < limit:
            try:
                entry = parse_entry(handle, pos, limit)
            except (ValueError, struct.error):
                try:
                    entry = parse_entry(handle, pos, limit, variant='observed_permutation')
                except (ValueError, struct.error):
                    aligned = (pos + 2047) // 2048 * 2048
                    handle.seek(pos)
                    if aligned >= limit or handle.read(aligned - pos) != bytes(aligned - pos):
                        break
                    pos = aligned
                    entry = parse_entry(handle, pos, limit, variant='observed_permutation')
            count += 1
            try:
                content, error = decode_content(handle, pos, entry, methods,
                                                max_uncompressed=64 * 1024 * 1024)
            except Exception:
                content = None
            if content:
                found = [term for term, variants in encodings.items()
                         if any(value in content for value in variants)]
                if found:
                    hits.append({'entry': count, 'offset': pos, 'bytes': len(content),
                                 'prefix': content[:4].hex(), 'found': found})
            pos = entry['next_pos']
    print(json.dumps({'pak': path.name, 'entries': count, 'hits': hits},
                     ensure_ascii=False), flush=True)
