"""Read indexed original Lua chunks to narrow the separate board difficulty field."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
GAME = Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)')
INDEX = ROOT / 'outputs/df-local-server/protocol/pak_baseline_lua_probe.json'
sys.path.insert(0, str(ROOT / 'work'))

import oodle_payload_reader
from lua53_reader import Reader, walk, listing
from scan_weapon_tables import parse_entry, decode_content


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def original_chunks(rows):
    archive = None
    stream = None
    try:
        for row in rows:
            if row['archive'] != archive:
                if stream is not None:
                    stream.close()
                archive = row['archive']
                path = GAME / 'DeltaForce/Content/Paks' / archive
                stream = path.open('rb')
                stream.seek(-512, 2)
                tail = stream.read(512)
                marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
                if marker < 0:
                    raise ValueError('Original PAK footer marker missing')
                _, limit = struct.unpack_from('<IQ', tail, marker + 4)
                methods = [x[:-1].decode('ascii') for x in
                           re.findall(rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
            try:
                entry = parse_entry(stream, row['entry_offset'], limit)
            except (ValueError, struct.error):
                entry = parse_entry(stream, row['entry_offset'], limit,
                                    variant='observed_permutation')
            raw = decode_content(stream, row['entry_offset'], entry, methods)
            if raw is None:
                raise ValueError('Original Lua entry decode failed')
            if entry['method']:
                stored = []
                for first, last in entry['blocks']:
                    stream.seek(row['entry_offset'] + first)
                    stored.append(stream.read(last - first))
                stored_hash = hashlib.sha1(b''.join(stored)).digest()
            else:
                stored_hash = hashlib.sha1(raw).digest()
            if stored_hash != entry['sha1'] and hashlib.sha1(raw).digest() != entry['sha1']:
                raise ValueError('Original Lua entry SHA1 changed')
            chunk = raw[row['lua_offset']:row['lua_offset'] + row['length']]
            if digest(chunk) != row['sha256']:
                raise ValueError('Indexed original chunk SHA256 changed: ' + row['source_name'])
            yield row, chunk
    finally:
        if stream is not None:
            stream.close()


def collect(args):
    oodle_payload_reader.PATH = GAME / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    index_raw = INDEX.read_bytes()
    rows = [r for r in json.loads(index_raw)['recovered_lua_metadata'] if r.get('source_name')]
    if args.source:
        wanted = set(args.source)
        rows = [r for r in rows if r['source_name'] in wanted]
        if {r['source_name'] for r in rows} != wanted:
            raise ValueError('Requested source is not in the original index')
    expression = re.compile(args.terms, re.I)
    needle = re.compile(args.terms.encode('utf-8'), re.I)
    selected, scanned, total_bytes = [], 0, 0
    sources = []
    for row, chunk in original_chunks(rows):
        scanned += 1
        total_bytes += len(chunk)
        sources.append({k: row[k] for k in ('archive', 'entry_offset', 'lua_offset',
                                          'length', 'sha256', 'source_name')})
        if not needle.search(chunk):
            continue
        reader = Reader(chunk, allow_client_format1=True)
        tree = reader.function()
        if reader.at != len(chunk) or tree['source'] != row['source_name']:
            raise ValueError('Matching original proto source or EOF changed')
        functions = []
        for fn in walk(tree):
            hits = [v for v in fn['constants'] if isinstance(v, str) and expression.search(v)]
            if not hits or args.function and not re.search(args.function, fn['id']):
                continue
            item = dict(function_id=fn['id'], first_line=fn['first_line'],
                        last_line=fn['last_line'], matched_constants=hits,
                        instructions=len(fn['code']))
            if args.listing:
                item.update(listing=listing(fn).splitlines(), constants=fn['constants'],
                            upvalue_names=fn['upvalue_names'], locals=fn['locals'])
            functions.append(item)
        if functions:
            selected.append(dict(source=sources[-1], parsed_to_exact_eof=True,
                                 function_count=sum(1 for _ in walk(tree)), functions=functions))
    return dict(kind='original_lua_board_difficulty_consumer_research',
        as_of_utc=datetime.now(timezone.utc).isoformat(),
        terms=args.terms, selected_sources=args.source, function_pattern=args.function,
        listing_requested=args.listing, original_chunks_checked=scanned,
        original_chunk_bytes_checked=total_bytes,
        indexed_sources_sha256=digest(json.dumps(sources, sort_keys=True).encode()),
        scope=dict(game_started=False, game_written=False, peer_written=False,
                   process_access=False, network_access=False, database_access=False,
                   lua_executed=False, installed_compression_codec_only=True),
        source_pins={str(INDEX.relative_to(ROOT)).replace('\\', '/'): digest(index_raw),
            **{'work/' + name: digest((ROOT / 'work' / name).read_bytes()) for name in
               ('lua53_reader.py', 'scan_weapon_tables.py', 'oodle_payload_reader.py')},
            'compression_codec': digest(oodle_payload_reader.PATH.read_bytes())},
        helper_sha256=digest(Path(__file__).read_bytes()), matches=selected,
        limits=['bounded indexed original baseline, not all effective mounts',
                'constant matches locate candidates; listings require dataflow review',
                'not a live map board response or a production gameplay test'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', action='append', default=[])
    parser.add_argument('--terms', default='difficult|机密|绝密')
    parser.add_argument('--function')
    parser.add_argument('--listing', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    report = collect(args)
    if args.verify:
        saved = json.loads(args.verify.read_bytes())
        for key in report.keys() - {'as_of_utc'}:
            if report[key] != saved.get(key):
                raise ValueError('Replay mismatch: ' + key)
        print(json.dumps(dict(verified=True, chunks=report['original_chunks_checked'],
                              matching_sources=len(report['matches']))))
    elif args.output:
        path = args.output.resolve()
        if path.exists() or path.parent != (ROOT / 'work/evidence').resolve():
            raise ValueError('Use a fresh own work/evidence output')
        with path.open('xb') as stream:
            stream.write((json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode())
        print(json.dumps(dict(output=str(path), chunks=report['original_chunks_checked'],
                              matching_sources=len(report['matches']))))
    else:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
