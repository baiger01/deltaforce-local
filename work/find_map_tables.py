"""Find map-related UE data tables in installed, readable package entries.

This is a bounded read-only scan.  It records candidate package locations and
the strings that matched, without copying the full game assets.
"""

import ast
import argparse
from collections import Counter
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
parser = argparse.ArgumentParser()
parser.add_argument('--archive-name')
parser.add_argument('--path-list', type=Path)
parser.add_argument('--unscanned-from', type=Path)
parser.add_argument('--report-name', default='map_table_candidates.json')
args = parser.parse_args()
if '/' in args.report_name or '\\' in args.report_name or not args.report_name.endswith('.json'):
    parser.error('report name must be a JSON basename')
namespace = {'struct': struct, 'hashlib': hashlib, 'decode_oodle': decode_oodle, 'zlib': zlib,
             'lz4': lz4, 'zstandard': zstandard}
for filename, name in [('probe_pak_payload_lua.py', 'parse_entry'),
                       ('probe_character_asset_rows.py', 'decode_content')]:
    syntax = ast.parse((HERE / filename).read_text(encoding='utf-8'))
    definition = next(node for node in syntax.body
                      if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[definition], type_ignores=[]), filename, 'exec'),
         namespace)
parse_entry = namespace['parse_entry']
decode_content = namespace['decode_content']

MARKERS = (
    b'WorldEntranceConfig\x00', b'MapConfig\x00', b'MatchModeDataConfig\x00',
    b'EntranceIdx\x00', b'SubModeList\x00', b'MapName\x00',
    b'MatchModeID\x00', b'MatchModeId\x00', b'MapID\x00',
)
out = HERE / 'evidence' / args.report_name
paths = [Path(p) for p in json.loads((args.path_list or HERE / 'pak_paths.json').read_text(encoding='utf-8'))]
if args.path_list:
    paths = [p for p in paths if p.exists()]
elif args.unscanned_from:
    prior = json.loads(args.unscanned_from.read_text(encoding='utf-8'))
    scanned = {row['pak'] for row in prior}
    paths = [p for p in paths if p.exists() and p.name not in scanned]
elif args.archive_name:
    paths = [p for p in paths if p.exists() and p.name == args.archive_name]
    if len(paths) != 1:
        parser.error('archive name must match one installed PAK')
else:
    summary = json.loads((HERE / 'evidence/commerce_tables_generic/scan_summary.json').read_text(
        encoding='utf-8'))
    readable = {row['pak'] for row in summary if row.get('counts', {}).get('clear_uassets', 0)}
    paths = [p for p in paths if p.exists() and p.name in readable]
paths.sort(key=lambda p: p.stat().st_size)
hits = []
skipped = []


def entry_at(handle, pos, limit):
    try:
        try:
            return parse_entry(handle, pos, limit), pos
        except (ValueError, struct.error):
            return parse_entry(handle, pos, limit, variant='observed_permutation'), pos
    except (ValueError, struct.error):
        aligned = (pos + 2047) // 2048 * 2048
        handle.seek(pos)
        if aligned >= limit or handle.read(aligned - pos) != bytes(aligned - pos):
            raise
        return parse_entry(handle, aligned, limit, variant='observed_permutation'), aligned


for index, path in enumerate(paths, 1):
    counts = Counter()
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        if marker < 0:
            skipped.append({'pak': path.name, 'reason': 'unknown_footer'})
            out.write_text(json.dumps({'searched_paks': index, 'total_paks': len(paths),
                                       'hits': hits, 'skipped': skipped}, indent=2),
                           encoding='utf-8')
            continue
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [m[:-1].decode('ascii') for m in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        pos = 0
        while pos < limit:
            try:
                entry, pos = entry_at(handle, pos, limit)
            except (ValueError, struct.error):
                counts['invalid_boundary'] += 1
                break
            counts['entries'] += 1
            if not entry['flags'] & 1 and 256 < entry['uncompressed'] < 8 * 1024 * 1024:
                try:
                    content, _ = decode_content(handle, pos, entry, methods,
                                                max_uncompressed=8 * 1024 * 1024)
                except Exception:
                    content = None
                if content and content.startswith(b'\xc1\x83\x2a\x9e'):
                    found = [m[:-1].decode('ascii') for m in MARKERS if m in content]
                    if ('WorldEntranceConfig' in found or 'MapConfig' in found
                            or 'MatchModeDataConfig' in found
                            or {'EntranceIdx', 'SubModeList', 'MapID'} <= set(found)
                            or {'MapName', 'MatchModeID', 'MapID'} <= set(found)):
                        hit = {'pak': path.name, 'entry': counts['entries'],
                               'offset': pos, 'size': len(content), 'markers': found}
                        hits.append(hit)
                        print('HIT', json.dumps(hit), flush=True)
            pos = entry['next_pos']
    print('PROGRESS', index, '/', len(paths), path.name, dict(counts), flush=True)
    out.write_text(json.dumps({'searched_paks': index, 'total_paks': len(paths),
                               'hits': hits, 'skipped': skipped}, indent=2), encoding='utf-8')
