"""Inspect bounded, clear map packages at previously observed Dam PAK entries.

No encrypted payload/index is decoded. Package names, typed scalar tags and
references are evidence; the scanner does not invent spawn/drop rules.
"""
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

import lz4.block
import zstandard
from oodle_payload_reader import decode as decode_oodle

HERE = Path(__file__).resolve().parent
OUT = HERE / 'evidence/dam_content_packages'
ARCHIVE = 'pak-0-1-pakchunk84-WindowsClient.pak'
RANGES = ((30255, 30270), (33845, 33870), (34250, 34420))
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_TOTAL = 96 * 1024 * 1024
TERMS = re.compile(r'(?i)spawn|born|loot|high.?value|mandel|brick|decod|player.?start|plunder|treasure|drop|area.?name|gameplay|location|rotation|weight|probab|random|select|pos|transform')

ns = {'struct': struct, 'hashlib': hashlib, 'decode_oodle': decode_oodle,
      'zlib': zlib, 'lz4': lz4, 'zstandard': zstandard}
for filename, method in [('probe_pak_payload_lua.py', 'parse_entry'),
                         ('probe_character_asset_rows.py', 'decode_content')]:
    definition = next(node for node in ast.parse((HERE / filename).read_text(encoding='utf-8')).body
                      if isinstance(node, ast.FunctionDef) and node.name == method)
    exec(compile(ast.Module(body=[definition], type_ignores=[]), filename, 'exec'), ns)


def entry_at(stream, offset, limit):
    for variant in ('standard', 'observed_permutation'):
        try:
            return ns['parse_entry'](stream, offset, limit, variant=variant), offset
        except (ValueError, struct.error):
            pass
    aligned = (offset + 2047) // 2048 * 2048
    stream.seek(offset)
    if aligned >= limit or stream.read(aligned - offset) != bytes(aligned - offset):
        raise ValueError('Invalid sequential boundary')
    return ns['parse_entry'](stream, aligned, limit, variant='observed_permutation'), aligned


def name_maps(data):
    candidates = []
    # Summary layouts differ in their custom-version container. Accept a map
    # only if every FString fits, terminates, and contains the None sentinel.
    for field in range(20, min(256, len(data) - 8)):
        count, offset = struct.unpack_from('<ii', data, field)
        if not 2 <= count <= 50000 or not 100 <= offset < len(data):
            continue
        at, names = offset, []
        try:
            for _ in range(count):
                length = struct.unpack_from('<i', data, at)[0]
                at += 4
                if not 0 < abs(length) <= 4096:
                    raise ValueError('Invalid name length')
                size = length if length > 0 else -length * 2
                raw = data[at:at + size]
                if len(raw) != size or not raw.endswith(b'\0' if length > 0 else b'\0\0'):
                    raise ValueError('Truncated/unterminated name')
                name = raw[:-1].decode('utf-8') if length > 0 else raw[:-2].decode('utf-16le')
                if '\0' in name:
                    raise ValueError('Embedded terminator')
                names.append(name)
                at += size + 4
                if at > len(data):
                    raise ValueError('Out of bounds name hashes')
            if 'None' in names:
                candidates.append((field, names))
        except (ValueError, UnicodeError, struct.error):
            continue
    if len(candidates) != 1:
        raise ValueError('Name map is missing or ambiguous')
    return candidates[0]


def main():
    paths = [Path(p) for p in json.loads((HERE / 'pak_paths.json').read_text(encoding='utf-8'))
             if Path(p).name == ARCHIVE and Path(p).exists()]
    if len(paths) != 1:
        raise ValueError('Expected one previously recorded Dam archive')
    path = paths[0]
    OUT.mkdir(parents=True, exist_ok=True)
    result = {'kind': 'bounded_clear_dam_package_inspection', 'archive': path.name,
              'archive_relative_path': 'DeltaForce/Content/Paks/' + path.name,
              'archive_size': path.stat().st_size, 'entry_ranges': RANGES,
              'encrypted_entries_decoded': False, 'game_modified': False,
              'spawn_selection_or_drop_rules_recovered': False, 'records': []}
    counts, copied, prior_names = Counter(), 0, None
    with path.open('rb') as stream:
        stream.seek(-512, 2)
        tail = stream.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        if marker < 0:
            raise ValueError('Unknown archive footer')
        version, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [x[:-1].decode('ascii') for x in re.findall(rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\0', tail)]
        offset, number = 0, 0
        while offset < limit and number < RANGES[-1][1]:
            entry, offset = entry_at(stream, offset, limit)
            number += 1
            if any(first <= number <= last for first, last in RANGES):
                row = {'entry': number, 'offset': offset, 'encrypted': bool(entry['flags'] & 1),
                       'uncompressed_bytes': entry['uncompressed']}
                if row['encrypted'] or entry['uncompressed'] > MAX_PAYLOAD:
                    prior_names = None
                else:
                    data, reason = ns['decode_content'](stream, offset, entry, methods, max_uncompressed=MAX_PAYLOAD)
                    if not data:
                        row['not_decoded'] = reason
                        prior_names = None
                    else:
                        copied += len(data)
                        if copied > MAX_TOTAL:
                            raise ValueError('Declared clear-payload budget exhausted')
                        counts['clear_payloads'] += 1
                        row['payload_sha256'] = hashlib.sha256(data).hexdigest()
                        row['entry_sha1_matches_payload'] = hashlib.sha1(data).digest() == entry['sha1']
                        is_header = data.startswith(b'\xc1\x83\x2a\x9e')
                        row['kind'] = 'uasset' if is_header else 'companion_candidate'
                        filename = f'entry-{number}.' + ('uasset' if is_header else 'uexp')
                        (OUT / filename).write_bytes(data)
                        row['evidence_file'] = filename
                        row['package_references'] = sorted(set(x.decode('ascii') for x in re.findall(rb'/Game/[A-Za-z0-9_/]+', data)))
                        if is_header:
                            try:
                                field, names = name_maps(data)
                                prior_names = (number, names)
                                row['name_map_summary_offset'] = field
                                row['name_count'] = len(names)
                                row['content_names'] = [name for name in names if TERMS.search(name)]
                                (OUT / f'entry-{number}.names.json').write_text(json.dumps(names, ensure_ascii=False, indent=2), encoding='utf-8')
                            except ValueError as exc:
                                row['name_map_error'] = str(exc)
                                prior_names = None
                        elif prior_names:
                            row['previous_uasset_entry'] = prior_names[0]
                            prior_names = None
                result['records'].append(row)
                print(json.dumps({key: row[key] for key in ('entry', 'kind', 'encrypted', 'uncompressed_bytes') if key in row}), flush=True)
            offset = entry['next_pos']
        result.update(entries_traversed=number, counts=dict(counts), clear_bytes_inspected=copied)
    (OUT / 'manifest.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'entries_traversed': number, 'records': len(result['records']), 'clear_bytes_inspected': copied}), flush=True)


if __name__ == '__main__':
    main()
