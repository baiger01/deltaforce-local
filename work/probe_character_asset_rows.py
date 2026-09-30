"""Scan only the two known hotfix PAKs for clear character-table entries.

The encrypted index is untouched. Entries are followed from offset zero using
the already validated local FPakEntry parser. Only metadata is printed.
"""

import ast
import hashlib
import io
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


source = Path(__file__).with_name('probe_pak_payload_lua.py').read_text(encoding='utf-8')
definition = next(node for node in ast.parse(source).body
                  if isinstance(node, ast.FunctionDef) and node.name == 'parse_entry')
namespace = {'struct': struct, 'hashlib': hashlib}
exec(compile(ast.Module(body=[definition], type_ignores=[]), '<local FPakEntry parser>', 'exec'),
     namespace)
parse_entry = namespace['parse_entry']

base = game_paths()[0] / 'DeltaForce/Saved/Dolphin/1.101.37117.36/Paks'
names = tuple(p.name for p in sorted(base.glob('1.101.37117.36.*_P.pak')))
terms = [b'HeroFashionData', b'HeroData', b'FashionSuitData', b'CharacterAvatarData',
         b'88000000025', b'88000000027', b'30000020003', b'30000010010']
encoded_terms = {term: (term, term.decode().encode('utf-16le')) for term in terms}
numeric_ids = (88000000025, 88000000027, 30000020003, 30000010010)


def decode_content(handle, pos, entry, compression_names, max_uncompressed=8 * 1024 * 1024):
    if entry['flags'] & 1:
        return None, 'encrypted'
    if entry['uncompressed'] > max_uncompressed:
        return None, 'too_large'
    if not entry['method']:
        handle.seek(pos + entry['header_size'])
        content = handle.read(entry['compressed'])
        return content, None
    blocks = []
    for start, end in entry['blocks']:
        handle.seek(pos + start)
        compressed = handle.read(end - start)
        method = compression_names[entry['method'] - 1]
        expected = min(entry['block_size'], entry['uncompressed'] - sum(map(len, blocks)))
        if method == 'Oodle':
            block = decode_oodle(compressed, expected)
        elif method == 'Zstd':
            block = zstandard.ZstdDecompressor().decompress(compressed,
                                                              max_output_size=expected)
        elif method in ('Zlib', 'Gzip'):
            block = zlib.decompress(compressed, zlib.MAX_WBITS | 32)
        elif method == 'LZ4':
            block = lz4.block.decompress(compressed, uncompressed_size=expected)
        else:
            return None, 'unsupported_' + method
        blocks.append(block)
    content = b''.join(blocks)
    if len(content) != entry['uncompressed']:
        return None, 'length_mismatch'
    return content, None


for filename in names:
    path = base / filename
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        compression_names = [m[:-1].decode('ascii') for m in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        pos = 0
        count = 0
        errors = {}
        previous_character_table = False
        while pos < limit:
            try:
                try:
                    entry = parse_entry(handle, pos, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(handle, pos, limit, variant='observed_permutation')
            except (ValueError, struct.error):
                aligned = (pos + 2047) // 2048 * 2048
                handle.seek(pos)
                if aligned >= limit or handle.read(aligned - pos) != bytes(aligned - pos):
                    errors['invalid_header'] = errors.get('invalid_header', 0) + 1
                    break
                pos = aligned
                try:
                    entry = parse_entry(handle, pos, limit, variant='observed_permutation')
                except (ValueError, struct.error):
                    errors['invalid_aligned_header'] = errors.get('invalid_aligned_header', 0) + 1
                    break
            count += 1
            try:
                content, error = decode_content(handle, pos, entry, compression_names,
                                                max_uncompressed=(40 * 1024 * 1024 if previous_character_table
                                                                  else 8 * 1024 * 1024))
            except Exception as exc:
                content, error = None, type(exc).__name__
            if error:
                errors[error] = errors.get(error, 0) + 1
            elif content:
                if previous_character_table:
                    target = Path(__file__).resolve().parent / 'evidence' / 'character_avatar_tables'
                    (target / (filename + '.next_entry')).write_bytes(content)
                    print('NEXT', filename, 'entry', count, 'offset', pos,
                          'uncompressed', len(content), 'prefix', content[:12].hex())
                previous_character_table = False
                hits = [term.decode() for term, encodings in encoded_terms.items()
                        if any(code in content for code in encodings)]
                binary_hits = [str(value) for value in numeric_ids
                               if struct.pack('<Q', value) in content]
                if hits or binary_hits:
                    target = Path(__file__).resolve().parent / 'evidence' / 'character_avatar_tables'
                    target.mkdir(parents=True, exist_ok=True)
                    suffix = '.uasset' if content.startswith(b'\xc1\x83\x2a\x9e') else '.uexp'
                    (target / (filename + f'.entry-{count}' + suffix)).write_bytes(content)
                    previous_character_table = any(path in content for path in (
                        b'/Game/DataTables/CharacterAvatarData',
                        b'/Game/R13N/Common/PC/DataTables/CharacterAvatarData',
                        b'/Game/R13N/Common/Base/DataTables/GameItem'))
                    print('HIT', filename, 'entry', count, 'offset', pos,
                          'uncompressed', len(content), 'strings', hits,
                          'uint64', binary_hits, 'prefix', content[:12].hex())
            pos = entry['next_pos']
        print('SUMMARY', filename, 'entries', count, 'stopped_at', pos,
              'data_end', limit, 'errors', errors)
