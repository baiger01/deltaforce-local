"""Re-read indexed installed Lua chunks for player initialization consumers."""
import argparse
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
from lua53_reader import Reader, walk, listing

ROOT = Path(__file__).resolve().parent.parent
TERMS = frozenset(('OnClientPlayerAvatarIDsChanged', 'currentCharacterHeroID',
    'SetCharacterSuitAvatar', 'SetCharacterSuitAvatarWithSequence',
    'GetCharacterFashionComponent', 'DFMCharacterFashionComponent',
    'SetCharacterAvatarWithSlot', 'SetCharacterAvatarWithSlotId',
    'GetControlRotation', 'AddMovementInput', 'MoveForward', 'MoveRight',
    'bIsFPPBaseRotationFromBone', 'MapDropConfig', 'DropPoolConfig', 'MapEconomyData'))


def scan(index_path, pak_root):
    namespace = dict(struct=struct, hashlib=hashlib, zlib=zlib, lz4=lz4,
                     zstandard=zstandard, decode_oodle=decode_oodle)
    for filename, function in (('probe_pak_payload_lua.py', 'parse_entry'),
                                ('probe_character_asset_rows.py', 'decode_content')):
        source = (ROOT / 'work' / filename).read_text(encoding='utf-8')
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == function)
        exec(compile(ast.Module(body=[node], type_ignores=[]), filename, 'exec'), namespace)
    raw_index = index_path.read_bytes()
    rows = [r for r in json.loads(raw_index)['recovered_lua_metadata']
            if type(r.get('length')) is int and type(r.get('lua_offset')) is int]
    if not 1 <= len(rows) <= 10000:
        raise ValueError('Indexed Lua count bound changed')
    counts, matches, failures = Counter(), [], []
    for archive in sorted({r['archive'] for r in rows}):
        path = pak_root / archive
        if path.name != archive:
            raise ValueError('Archive must be a basename inside the supplied PAK root')
        with path.open('rb') as handle:
            handle.seek(-512, 2)
            footer = handle.read(512)
            marker = footer.rfind(struct.pack('<I', 0x5a6f12e1))
            _, limit = struct.unpack_from('<IQ', footer, marker + 4)
            compression = [s.decode() for s in re.findall(rb'Zlib|Gzip|Oodle|LZ4|Zstd', footer)]
            for row in (r for r in rows if r['archive'] == archive):
                try:
                    entry = namespace['parse_entry'](handle, row['entry_offset'], limit,
                                                     variant='observed_permutation')
                    payload, error = namespace['decode_content'](handle, row['entry_offset'], entry, compression)
                    if error:
                        raise ValueError(error)
                    chunk = payload[row['lua_offset']:row['lua_offset'] + row['length']]
                    if hashlib.sha256(chunk).hexdigest() != row['sha256']:
                        raise ValueError('Indexed Lua hash changed')
                    reader = Reader(chunk, allow_client_format1=True)
                    tree = reader.function()
                    for function in walk(tree):
                        hits = sorted(TERMS.intersection(c for c in function['constants'] if isinstance(c, str)))
                        if hits:
                            matches.append(dict(source_name=row['source_name'], archive=archive,
                                entry_offset=row['entry_offset'], lua_sha256=row['sha256'],
                                function_id=function['id'], first_line=function['first_line'],
                                last_line=function['last_line'], matched_terms=hits,
                                constants=function['constants'], listing=listing(function)))
                    counts['parsed_and_hash_verified'] += 1
                except Exception as error:
                    failures.append(dict(source_name=row.get('source_name'), error_type=type(error).__name__, reason=str(error)))
    return dict(kind='readonly_current_installed_player_initialization_lua_consumers',
        source_index_sha256=hashlib.sha256(raw_index).hexdigest(), indexed_chunks=len(rows),
        counts=dict(counts), matches=matches, failures=failures, terms=sorted(TERMS),
        lua_executed=False, game_files_modified=False, final_behavior_inferred_from_constants=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--pak-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = scan(args.index, args.pak_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(dict(indexed=result['indexed_chunks'], counts=result['counts'],
                         matches=len(result['matches']), failures=len(result['failures']))))
