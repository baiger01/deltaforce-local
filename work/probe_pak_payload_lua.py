"""Read bounded clear PAK entries without decrypting or modifying game data.

Entry layout reference: CUE4Parse's FPakEntry. This is a partial sequential
probe, not a replacement index reader. It stops on the first invalid boundary.
"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import re
import struct
import zlib
import io
import argparse
import lz4.block
import zstandard
from lua53_reader import Reader, walk
from oodle_payload_reader import decode as decode_oodle

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--baseline-only', action='store_true')
parser.add_argument('--hotfix-only', action='store_true')
parser.add_argument('--archive-name')
parser.add_argument('--baseline-entry-limit', type=int, default=2048)
parser.add_argument('--archive-entry-limit', type=int, default=128)
parser.add_argument('--clear-read-mib', type=int, default=128)
parser.add_argument('--max-entry-mib', type=int, default=1)
parser.add_argument('--report-name', default='pak_payload_probe.json')
args = parser.parse_args()
if not 1 <= args.baseline_entry_limit <= 100000 or not 1 <= args.clear_read_mib <= 1024:
    raise ValueError('Probe bounds exceed declared limits')
if not 1 <= args.archive_entry_limit <= 100000 or args.baseline_only and args.hotfix_only:
    raise ValueError('Invalid archive scope')
if not 1 <= args.max_entry_mib <= 8:
    raise ValueError('Entry limit exceeds declared bound')
if not re.fullmatch(r'[a-z_]+\.json', args.report_name):
    raise ValueError('Invalid report name')
PATHS = json.loads((ROOT / 'work/pak_paths.json').read_text(encoding='utf-8'))
BASELINE = 'pak-0-0-pakchunk1-WindowsClient.pak'
if args.baseline_only:
    PATHS = [name for name in PATHS if Path(name).name == BASELINE]
elif args.hotfix_only:
    PATHS = [name for name in PATHS if Path(name).name.startswith('1.101')]
if args.archive_name:
    PATHS = [name for name in PATHS if Path(name).name == args.archive_name]
    if len(PATHS) != 1:
        raise ValueError('Archive name must select exactly one known archive')
MAX_ENTRY = args.max_entry_mib * 1024 * 1024
MAX_ENTRIES = args.archive_entry_limit
MAX_CLEAR_READ = args.clear_read_mib * 1024 * 1024
MAGIC = b'\x1bLua\x53'
TARGET = re.compile(r'(?i)SDKInfoServer|ProtocolConnection|ServerConfig|dhkey|dh_key|EncryptKey|KeyMode|ProtocolConfig|AppSetting|ServerAddr|cs_account_pb|cs_deposit_pb|cs_quest_pb')
records, recovered = [], []
clear_read = 0

def parse_entry(handle, pos, limit, *, variant='standard'):
    handle.seek(pos)
    raw = handle.read(min(4096, limit - pos))
    if len(raw) < 53:
        raise ValueError('short header')
    if variant == 'standard':
        offset, compressed, uncompressed, method = struct.unpack_from('<qqqI', raw)
        at, digest = 48, raw[28:48]
    else:
        method, offset = struct.unpack_from('<Iq', raw)
        at, compressed, uncompressed, digest = 12, None, None, None
    if offset != 0 or method > 8 or method < 0:
        raise ValueError('unknown entry boundary or header layout')
    blocks = []
    if method:
        count = struct.unpack_from('<I', raw, at)[0]
        at += 4
        if not 1 <= count <= 2048:
            raise ValueError('invalid block table')
        needed = at + 16 * count + (41 if variant != 'standard' else 5)
        if needed > len(raw):
            handle.seek(pos)
            raw = handle.read(min(needed, limit - pos))
        if len(raw) < needed:
            raise ValueError('short block table')
        for index in range(count):
            start, end = struct.unpack_from('<qq', raw, at + 16 * index)
            if start < 0 or end <= start or end > limit - pos:
                raise ValueError('invalid compression block')
            blocks.append((start, end))
        at += 16 * count
    flags, block_size = struct.unpack_from('<BI', raw, at)
    at += 5
    if variant != 'standard':
        if len(raw) < at + 36:
            raise ValueError('short permuted header')
        uncompressed = struct.unpack_from('<q', raw, at)[0]
        digest = raw[at + 8:at + 28]
        compressed = struct.unpack_from('<q', raw, at + 28)[0]
        at += 36
    empty_entry = compressed == uncompressed == 0 and method == 0 and digest == hashlib.sha1(b'').digest()
    if not empty_entry and (not 0 < compressed <= limit - pos or not 0 < uncompressed < 1 << 34):
        raise ValueError('invalid entry sizes')
    if flags & ~3 or flags & 2:
        raise ValueError('unsupported entry flags')
    if blocks:
        if blocks[0][0] != at:
            raise ValueError('unsupported payload alignment')
        previous = at
        total = 0
        for start, end in blocks:
            if start != previous:
                raise ValueError('noncontiguous compression blocks')
            total += end - start
            previous = end + ((-end + start) % 16 if flags & 1 else 0)
        if total != compressed and not (flags & 1 and previous - at == compressed):
            raise ValueError('compressed size mismatch')
        next_pos = pos + previous
    else:
        if method or uncompressed != compressed:
            raise ValueError('unsupported uncompressed layout')
        next_pos = pos + at + compressed + ((-compressed) % 16 if flags & 1 else 0)
    if next_pos > limit or next_pos <= pos:
        raise ValueError('payload exceeds archive data region')
    return {'header_size': at, 'compressed': compressed, 'uncompressed': uncompressed,
            'method': method, 'flags': flags, 'blocks': blocks, 'block_size': block_size,
            'next_pos': next_pos, 'variant': variant, 'sha1': digest}

for name in sorted(PATHS, key=lambda value: (not Path(value).name.startswith('1.101'), Path(value).name)):
    path = Path(name)
    counts, reason, examples = Counter(), None, []
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        if marker < 0:
            records.append({'file': path.name, 'stop_reason': 'no supported footer'})
            continue
        version, limit = struct.unpack_from('<IQ', tail, marker + 4)
        compression_names = [value.decode('ascii') for value in
                             re.findall(rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)
                             for value in [value[:-1]]]
        if version < 9:
            records.append({'file': path.name, 'stop_reason': 'unsupported version', 'version': version})
            continue
        pos = 0
        entry_limit = args.baseline_entry_limit if path.name == BASELINE else MAX_ENTRIES
        for index in range(entry_limit):
            if pos == limit:
                break
            try:
                try:
                    entry = parse_entry(handle, pos, limit)
                except (ValueError, struct.error):
                    # Observed fixed-field permutation at this same boundary;
                    # no byte scanning or arbitrary boundary recovery is used.
                    entry = parse_entry(handle, pos, limit, variant='observed_permutation')
            except (ValueError, struct.error) as exc:
                aligned = (pos + 2047) // 2048 * 2048
                if aligned > pos and aligned < limit:
                    handle.seek(pos)
                    padding = handle.read(aligned - pos)
                    if padding == bytes(aligned - pos):
                        try:
                            entry = parse_entry(handle, aligned, limit, variant='observed_permutation')
                        except (ValueError, struct.error):
                            reason = str(exc)
                            break
                        counts['zero_padding_alignment_boundaries'] += 1
                        pos = aligned
                    else:
                        reason = str(exc)
                        break
                else:
                    reason = str(exc)
                    break
            counts['headers'] += 1
            counts['layout_' + entry['variant']] += 1
            counts['compression_method_' + str(entry['method'])] += 1
            counts['encrypted' if entry['flags'] & 1 else 'clear'] += 1
            if (not entry['flags'] & 1 and entry['compressed'] <= MAX_ENTRY
                    and entry['uncompressed'] <= MAX_ENTRY and clear_read + entry['compressed'] <= MAX_CLEAR_READ):
                if not entry['method']:
                    handle.seek(pos + entry['header_size'])
                    content = handle.read(entry['compressed'])
                    clear_read += len(content)
                else:
                    decoded, stored_blocks = [], []
                    try:
                        for start, end in entry['blocks']:
                            handle.seek(pos + start)
                            compressed = handle.read(end - start)
                            clear_read += len(compressed)
                            stored_blocks.append(compressed)
                            method_name = compression_names[entry['method'] - 1] if 0 < entry['method'] <= len(compression_names) else None
                            if method_name == 'Oodle':
                                expected = min(entry['block_size'], entry['uncompressed'] - sum(map(len, decoded)))
                                block = decode_oodle(compressed, expected)
                            elif compressed.startswith(b'\x28\xb5\x2f\xfd'):
                                with zstandard.ZstdDecompressor(max_window_size=4096).stream_reader(io.BytesIO(compressed)) as decoder:
                                    block = decoder.read(MAX_ENTRY + 1)
                                    if len(block) > MAX_ENTRY or decoder.read(1):
                                        raise ValueError('oversized Zstandard output')
                            else:
                                try:
                                    decoder = zlib.decompressobj(zlib.MAX_WBITS | 32)
                                    block = decoder.decompress(compressed, MAX_ENTRY + 1)
                                    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or len(block) > MAX_ENTRY:
                                        raise ValueError('not a bounded complete zlib block')
                                except (zlib.error, ValueError):
                                    block = lz4.block.decompress(compressed, uncompressed_size=MAX_ENTRY)
                            decoded.append(block)
                        content = b''.join(decoded)
                        if len(content) != entry['uncompressed']:
                            raise ValueError('decoded length mismatch')
                    except (zlib.error, ValueError, lz4.block.LZ4BlockError, zstandard.ZstdError):
                        counts['unsupported_compression'] += 1
                        content = b''
                if content:
                    counts['clear_payloads_read'] += 1
                    content_hash_matches = hashlib.sha1(content).digest() == entry['sha1']
                    stored_hash_matches = (hashlib.sha1(b''.join(stored_blocks)).digest() == entry['sha1']) if entry['method'] else content_hash_matches
                    verified = content_hash_matches or stored_hash_matches
                    counts['payload_sha1_matches' if verified else 'payload_sha1_mismatches'] += 1
                    if stored_hash_matches and not content_hash_matches:
                        counts['verified_hash_covers_compressed_bytes'] += 1
                    if not verified:
                        pos = entry['next_pos']
                        continue
                    hits = sorted({match[0] for match in TARGET.finditer(content.decode('latin1'))})
                    for keyword in ('DHKey', 'DhKey', 'EncryptKey', 'KeyMode', 'ProtocolConfig', 'AppSetting', 'ServerAddr'):
                        if keyword.encode('utf-16le') in content:
                            hits.append(keyword + ' (UTF-16LE)')
                    hits = sorted(set(hits))
                    if hits:
                        digest = hashlib.sha256(content).hexdigest()
                        target = ROOT / 'work/evidence/payload_candidates'
                        target.mkdir(exist_ok=True)
                        (target / (digest + '.bin')).write_bytes(content)
                        recovered.append({'archive': path.name, 'entry_offset': pos,
                                          'payload_sha256': digest, 'payload_size': len(content),
                                          'validated_stored_hash': True, 'related_identifier_names': hits,
                                          'lua_chunk_parsed': False})
                    for match in re.finditer(re.escape(MAGIC), content):
                        try:
                            reader = Reader(content[match.start():], allow_client_format1=True)
                            fn = reader.function()
                            if reader.at != len(content) - match.start():
                                raise ValueError('Unexpected trailing chunk data')
                        except ValueError:
                            counts['incomplete_lua_signatures'] += 1
                            continue
                        identifier_names = sorted({value for child in walk(fn) for value in child['constants']
                                                   if isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9.]*', value)
                                                   and TARGET.search(value)})
                        digest = hashlib.sha256(content[match.start():match.start() + reader.at]).hexdigest()
                        source_name = fn.get('source')
                        safe_source = source_name if isinstance(source_name, str) and re.fullmatch(r'@?[A-Za-z_][A-Za-z_0-9./\\-]*', source_name) else None
                        functions = list(walk(fn))
                        counts['complete_lua_chunks'] += 1
                        counts['complete_lua_functions'] += len(functions)
                        record = {'archive': path.name, 'entry_offset': pos, 'lua_offset': match.start(),
                                  'length': reader.at, 'sha256': digest, 'source_name': safe_source,
                                  'container_format': reader.container_format, 'functions': len(functions),
                                  'opcode_ids_outside_known_range': sum((word & 63) > 46 for child in functions for word in child['code']),
                                  'connection_or_schema_names': identifier_names,
                                  'opcode_semantics_verified': False}
                        recovered.append(record)
                        # Parsed original chunk code stays in scratch, never in deliverables.
                        target = ROOT / 'work/evidence/carved_lua'
                        target.mkdir(exist_ok=True)
                        (target / (digest + '.json')).write_text(json.dumps(fn, ensure_ascii=False), encoding='utf-8')
            pos = entry['next_pos']
        records.append({'file': path.name, 'version': version, 'counts': dict(counts),
                        'footer_compression_names': compression_names,
                        'last_boundary': pos, 'data_region_size': limit,
                        'data_region_fully_walked': pos == limit, 'stop_reason': reason})

result = {'scope': f'At most {MAX_ENTRIES} entries per archive ({args.baseline_entry_limit} in baseline chunk1), {args.max_entry_mib} MiB per decoded entry and {args.clear_read_mib} MiB of clear payload reads',
          'reference': 'https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Pak/Objects/FPakEntry.cs',
          'game_files_modified': False, 'encrypted_payloads_decrypted': False,
          'clear_payload_bytes_read': clear_read, 'archives': records, 'recovered_lua_metadata': recovered,
          'limitations': ['Only zero padding to the next 2048-byte boundary is skipped; invalid headers are not scanned past.',
                         'This bounded probe cannot exclude useful Lua elsewhere in the archives.']}
(ROOT / 'outputs/df-local-server/protocol' / args.report_name).write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
totals = Counter()
for row in records:
    totals.update(row.get('counts', {}))
print(json.dumps({'archives': len(records), 'totals': dict(totals), 'clear_read': clear_read,
                  'lua_chunks': sum('source_name' in row for row in recovered),
                  'connection_or_schema_modules': [row for row in recovered if row.get('connection_or_schema_names')],
                  'stop_reasons': dict(Counter(row.get('stop_reason') for row in records))},
                 ensure_ascii=False, indent=2))
