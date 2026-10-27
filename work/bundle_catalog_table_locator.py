"""Locate preserved store tables using bounded offline archive metadata reads."""

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'work/probe_pak_payload_lua.py'
definition = next(node for node in ast.parse(SOURCE.read_text(encoding='utf-8')).body
                  if isinstance(node, ast.FunctionDef) and node.name == 'parse_entry')
namespace = {'struct': struct, 'hashlib': hashlib}


class HeaderWindow(ast.NodeTransformer):
    def visit_Constant(self, node):
        return ast.copy_location(ast.Constant(128), node) if node.value == 4096 else node


definition = HeaderWindow().visit(definition)
exec(compile(ast.Module(body=[definition], type_ignores=[]), str(SOURCE), 'exec'), namespace)
parse_entry = namespace['parse_entry']
TARGETS = ('StoreHotRecommendation', 'DataTableAssetInfo')
MAGIC = bytes.fromhex('c1832a9e')
CODEC_PATH = None


class CountingReader:
    def __init__(self, handle):
        self.handle = handle
        self.count = 0

    def seek(self, *args):
        return self.handle.seek(*args)

    def read(self, size):
        data = self.handle.read(size)
        self.count += len(data)
        return data


def chunk(raw):
    if len(raw) < 48 or raw[:4] != MAGIC:
        return None
    tag, block, stored, output = struct.unpack_from('<4Q', raw)
    if tag != 0x9e2a83c1 or block != 131072 or not 0 < output <= 2 * 1024 * 1024:
        return None
    if not 0 < stored <= 256 * 1024:
        return None
    count = (output + block - 1) // block
    header = 32 + 16 * count
    if len(raw) != header + stored:
        return None
    parts, cursor, stored_sum = [], header, 0
    for index in range(count):
        size, expected = struct.unpack_from('<2Q', raw, 32 + index * 16)
        if not 0 < size <= stored or expected != min(block, output - index * block):
            raise ValueError('Invalid compressed-chunk block declaration')
        if cursor + size > len(raw):
            raise ValueError('Truncated compressed-chunk block')
        decoder = zlib.decompressobj()
        data = decoder.decompress(raw[cursor:cursor + size], expected + 1)
        if len(data) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('Invalid bounded compressed-chunk output')
        parts.append(data)
        cursor += size
        stored_sum += size
    if stored_sum != stored or cursor != len(raw):
        raise ValueError('Compressed-chunk total size mismatch')
    return b''.join(parts)


def first_block(reader, pos, entry, methods):
    if entry['flags'] & 1:
        return None
    if not entry['method']:
        reader.seek(pos + entry['header_size'])
        return reader.read(min(131072, entry['compressed']))
    if not 0 < entry['method'] <= len(methods) or not entry['blocks']:
        return None
    start, end = entry['blocks'][0]
    expected = min(entry['block_size'], entry['uncompressed'])
    if not 0 < expected <= 131072 or not 0 < end - start <= 196608:
        return None
    reader.seek(pos + start)
    raw = reader.read(end - start)
    method = methods[entry['method'] - 1]
    if method == 'Oodle':
        import oodle_payload_reader
        if CODEC_PATH is not None:
            oodle_payload_reader.PATH = CODEC_PATH
        return oodle_payload_reader.decode(raw, expected)
    if method == 'Zlib':
        decoder = zlib.decompressobj()
        data = decoder.decompress(raw, expected + 1)
        if len(data) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('Invalid bounded first block')
        return data
    return None


def scan(path, *, large_only, probe_large):
    stats, selected, hits, index, unknown_wrappers = Counter(), [], [], [], []
    with path.open('rb') as handle:
        reader = CountingReader(handle)
        file_size = reader.seek(0, 2)
        if file_size < 512:
            raise ValueError('Archive too short for bounded PAK footer')
        reader.seek(file_size - 512)
        footer = reader.read(512)
        marker = footer.rfind(struct.pack('<I', 0x5a6f12e1))
        if marker < 0 or marker + 16 > len(footer):
            raise ValueError('Missing or truncated PAK footer')
        _, limit = struct.unpack_from('<IQ', footer, marker + 4)
        if not 0 <= limit <= file_size - 512 + marker:
            raise ValueError('Invalid PAK data limit outside source data region')
        methods = [m[:-1].decode('ascii') for m in re.findall(rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', footer)]
        pos = number = 0
        while pos < limit:
            try:
                try:
                    entry = parse_entry(reader, pos, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(reader, pos, limit, variant='observed_permutation')
            except (ValueError, struct.error):
                aligned = (pos + 2047) // 2048 * 2048
                reader.seek(pos)
                if aligned <= pos or aligned >= limit or reader.read(aligned - pos) != bytes(aligned - pos):
                    raise ValueError(f'Invalid archive entry at {pos}')
                pos = aligned
                entry = parse_entry(reader, pos, limit, variant='observed_permutation')
            number += 1
            stats['headers'] += 1
            record = dict(entry=number, offset=pos,
                          **{k: entry[k] for k in ('compressed', 'uncompressed', 'method', 'flags', 'header_size', 'block_size', 'blocks', 'next_pos')})
            index.append(record)
            candidate = entry['uncompressed'] > 65536 if large_only else not entry['flags'] & 1
            if candidate:
                row = dict(pak=path.name, entry=number, offset=pos,
                           **{k: entry[k] for k in ('compressed', 'uncompressed', 'method', 'flags', 'header_size')})
                if not entry['flags'] & 1 and not entry['method']:
                    reader.seek(pos + entry['header_size'])
                    prefix = reader.read(min(48, entry['compressed']))
                    row['prefix48_sha256'] = hashlib.sha256(prefix).hexdigest()
                    row['prefix_magic'] = prefix[:4].hex()
                    stats['raw_prefix_bytes'] += len(prefix)
                    if prefix[:4] == MAGIC and len(prefix) == 48:
                        _, block, stored, output, block_stored, block_output = struct.unpack('<6Q', prefix)
                        row['compressed_chunk_sizes'] = [stored, output, block_stored, block_output]
                        blocks = (output + block - 1) // block if block else 0
                        chunk_header = 32 + 16 * blocks
                        if (block == 131072 and 0 < output <= 2 * 1024 * 1024
                                and 0 < stored <= 256 * 1024 and entry['compressed'] == chunk_header + stored):
                            raw = prefix + reader.read(chunk_header + stored - len(prefix))
                            try:
                                data = chunk(raw)
                            except (ValueError, zlib.error):
                                data = None
                            if data is None:
                                stats['nested_wrapper_decode_unknown'] += 1
                                unknown_wrappers.append({'entry': number, 'offset': pos,
                                    'status': 'unknown_invalid_or_unsupported_compressed_chunk'})
                            if data is not None:
                                stats['nested_zlib_chunks'] += 1
                                stats['nested_output_bytes'] += len(data)
                                row.update(payload_sha256=hashlib.sha256(raw).hexdigest(),
                                           inner_sha256=hashlib.sha256(data).hexdigest(),
                                           payload_sha1_matches=hashlib.sha1(raw).digest() == entry['sha1'])
                                terms = [term for term in TARGETS if term.encode() in data or term.encode('utf-16-le') in data]
                                if terms or not large_only and number in (7141, 7142):
                                    row.update(target_strings=terms, inner_prefix96_hex=data[:96].hex(),
                                               owner_status='unknown_target_string_is_not_package_ownership')
                                    hits.append(row)
                if probe_large and entry['uncompressed'] > 4194304:
                    before = reader.count
                    try:
                        data = first_block(reader, pos, entry, methods)
                    except (ValueError, OSError, zlib.error):
                        data = None
                        row['first_block_decode_status'] = 'unknown_decode_rejected_or_unavailable'
                    row['first_block_read_bytes'] = reader.count - before
                    if data is not None:
                        from bundle_asset_locations_package import package
                        row['first_block_sha256'] = hashlib.sha256(data).hexdigest()
                        row['first_block_size'] = len(data)
                        row['first_block_prefix16_hex'] = data[:16].hex()
                        row['first_block_target_strings'] = [term for term in TARGETS if term.encode() in data or term.encode('utf-16-le') in data]
                        try:
                            info = package(data)
                        except (ValueError, struct.error, UnicodeError):
                            info = None
                        row['first_block_package_status'] = 'parsed' if info else 'unknown_not_a_complete_supported_package_header'
                        if info:
                            row['owned_paths'] = info['own_paths']
                            row['root_exports'] = [e for e in info['exports'] if e['outer'] == 0]
                        stats['probed_large_entries'] += 1
                if large_only or not large_only and number in (7141, 7142):
                    selected.append(row)
            pos = entry['next_pos']
        return dict(pak=path.name, size=file_size, data_limit=limit,
                    scan_complete=pos == limit, read_bytes=reader.count,
                    footer_sha256=hashlib.sha256(footer).hexdigest(), stats=dict(stats),
                    large_entries=selected, entry_index=index, target_or_fixed_neighbor_hits=hits,
                    unknown_wrapper_entries=unknown_wrappers)


def main():
    global CODEC_PATH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--shadow-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--hotfix-first-blocks', action='store_true',
                        help='Read/decode only the first bounded block of the 52 hotfix entries above 4 MiB')
    args = parser.parse_args()
    CODEC_PATH = args.game_root / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    output = args.output.resolve()
    if any(output.is_relative_to(p.resolve()) for p in (args.game_root, args.shadow_root)):
        parser.error('Output must stay outside game trees')
    hotfix = args.shadow_root / 'DeltaForce/Saved/Dolphin/1.101.37117.36/Paks'
    paths = sorted(hotfix.glob('*.pak'))
    report = {'scope': 'Offline bounded FPakEntry metadata and selected raw compressed-chunk headers; no archive indexes, encrypted payloads, process access or game writes',
              'header_initial_window': 128,
              'hotfix': [scan(path, large_only=True, probe_large=args.hotfix_first_blocks) for path in paths],
              'base_pak2': scan(args.game_root / 'DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak', large_only=False, probe_large=False)}
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': output.as_posix(), 'hotfix_paks': len(paths),
                      'hotfix_entries_above_64k': sum(len(r['large_entries']) for r in report['hotfix']),
                      'hotfix_entries_above_4m': sum(e['uncompressed'] > 4194304
                          for r in report['hotfix'] for e in r['large_entries']),
                      'total_read_bytes': sum(r['read_bytes'] for r in report['hotfix']) + report['base_pak2']['read_bytes'],
                      'base_stats': report['base_pak2']['stats'],
                      'base_wrapper_hit_count': len(report['base_pak2']['target_or_fixed_neighbor_hits'])}, ensure_ascii=True))


if __name__ == '__main__':
    main()
