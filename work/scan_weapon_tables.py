"""Read-only scan of local hotfix PAK entries for weapon table candidates."""

import ast
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import struct
import zlib

import lz4.block
import zstandard

from extract_operator_avatar_catalog import name_map
from local_game_paths import game_paths
from lua53_reader import Reader
from oodle_payload_reader import decode as decode_oodle


SOURCE = Path(__file__).with_name('probe_pak_payload_lua.py')
MODULE = ast.parse(SOURCE.read_text(encoding='utf-8'))
definition = next(node for node in MODULE.body
                  if isinstance(node, ast.FunctionDef) and node.name == 'parse_entry')
namespace = {'struct': struct, 'hashlib': hashlib}
exec(compile(ast.Module(body=[definition], type_ignores=[]), str(SOURCE), 'exec'),
     namespace)
parse_entry = namespace['parse_entry']


def decode_content(handle, pos, entry, methods, max_uncompressed=16 * 1024 * 1024):
    if entry['flags'] & 1 or entry['uncompressed'] > max_uncompressed:
        return None
    if not entry['method']:
        handle.seek(pos + entry['header_size'])
        return handle.read(entry['compressed'])
    blocks = []
    for start, end in entry['blocks']:
        handle.seek(pos + start)
        compressed = handle.read(end - start)
        expected = min(entry['block_size'],
                       entry['uncompressed'] - sum(map(len, blocks)))
        method = methods[entry['method'] - 1]
        if method == 'Oodle':
            block = decode_oodle(compressed, expected)
        elif method == 'Zstd':
            block = zstandard.ZstdDecompressor().decompress(
                compressed, max_output_size=expected)
        elif method in ('Zlib', 'Gzip'):
            block = zlib.decompress(compressed, zlib.MAX_WBITS | 32)
        elif method == 'LZ4':
            block = lz4.block.decompress(compressed, uncompressed_size=expected)
        else:
            return None
        blocks.append(block)
    content = b''.join(blocks)
    return content if len(content) == entry['uncompressed'] else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--all-baseline', action='store_true')
    parser.add_argument('--pak-name', default='pak-0-0-pakchunk2-WindowsClient.pak')
    parser.add_argument('--max-entries', type=int, default=100000)
    parser.add_argument('--entry', type=int, nargs='+')
    parser.add_argument('--list-large', action='store_true')
    parser.add_argument('--max-uncompressed', type=int, default=16 * 1024 * 1024)
    parser.add_argument('--extract-lua', action='store_true')
    parser.add_argument('--lua-pattern')
    parser.add_argument('--asset-pattern', default=r'/Game/.*(?:DataTable|Config).*(?:weapon|gun|ammo|bullet|firearm|magazine)')
    parser.add_argument('--content-pattern')
    parser.add_argument('--item-id', type=int, nargs='+')
    parser.add_argument('--save-matches', action='store_true')
    parser.add_argument('--debug-errors', type=int, default=0)
    args = parser.parse_args()
    source = game_paths()[0]
    base = (source / 'DeltaForce/Content/Paks' if args.baseline or args.all_baseline else
            source / 'DeltaForce/Saved/Dolphin/1.101.37117.36/Paks')
    paths = ([base / args.pak_name] if args.baseline else
             sorted((p for p in base.glob('*.pak')
                     if 'optional' not in p.name and 'uhd' not in p.name),
                    key=lambda p: p.stat().st_size) if args.all_baseline else
             sorted(base.glob('*.pak')))
    asset_pattern = re.compile(args.asset_pattern, re.IGNORECASE)
    content_pattern = (re.compile(args.content_pattern.encode(), re.IGNORECASE)
                       if args.content_pattern else None)
    lua_pattern = re.compile(args.lua_pattern, re.IGNORECASE) if args.lua_pattern else None
    item_needles = [struct.pack('<Q', item_id) for item_id in (args.item_id or [])]
    for path in paths:
        with path.open('rb') as handle:
            handle.seek(-512, 2)
            tail = handle.read(512)
            marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
            if marker < 0:
                print('SKIP', path.name, 'no footer', flush=True)
                continue
            _, limit = struct.unpack_from('<IQ', tail, marker + 4)
            methods = [match[:-1].decode('ascii') for match in re.findall(
                rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
            pos = count = 0
            errors = Counter()
            save_next = False
            saved_index = 0
            while pos < limit and count < args.max_entries:
                try:
                    try:
                        entry = parse_entry(handle, pos, limit)
                    except (ValueError, struct.error):
                        entry = parse_entry(handle, pos, limit,
                                            variant='observed_permutation')
                except (ValueError, struct.error):
                    aligned = (pos + 2047) // 2048 * 2048
                    handle.seek(pos)
                    if aligned >= limit or handle.read(aligned - pos) != bytes(aligned - pos):
                        errors['invalid_header'] += 1
                        break
                    pos = aligned
                    try:
                        entry = parse_entry(handle, pos, limit,
                                            variant='observed_permutation')
                    except (ValueError, struct.error):
                        errors['invalid_aligned_header'] += 1
                        break
                count += 1
                if args.list_large:
                    if entry['uncompressed'] > 16 * 1024 * 1024:
                        print('LARGE_ENTRY', path.name, count, entry['uncompressed'],
                              entry['flags'], flush=True)
                    pos = entry['next_pos']
                    continue
                if args.entry and count not in args.entry:
                    pos = entry['next_pos']
                    continue
                if not entry['flags'] & 1:
                    try:
                        content = decode_content(handle, pos, entry, methods, args.max_uncompressed)
                        if args.entry and content:
                            output = Path(__file__).with_name('evidence') / 'matched_assets'
                            output.mkdir(parents=True, exist_ok=True)
                            suffix = '.uasset' if content.startswith(b'\xc1\x83\x2a\x9e') else '.uexp'
                            target = output / (path.name + f'.entry-{count}' + suffix)
                            target.write_bytes(content)
                            print('SAVED_ENTRY', target, len(content),
                                  hashlib.sha256(content).hexdigest(), flush=True)
                        if save_next and content:
                            output = Path(__file__).with_name('evidence') / 'matched_assets'
                            output.mkdir(parents=True, exist_ok=True)
                            target = output / (path.name + f'.entry-{saved_index}.uexp')
                            target.write_bytes(content)
                            print('SAVED', target, len(content), flush=True)
                        save_next = False
                        if content and ((content_pattern and content_pattern.search(content))
                                        or any(needle in content for needle in item_needles)):
                            print('CONTENT_HIT', path.name, count, pos,
                                  entry['uncompressed'], flush=True)
                            if args.save_matches:
                                output = Path(__file__).with_name('evidence') / 'matched_assets'
                                output.mkdir(parents=True, exist_ok=True)
                                target = output / (path.name + f'.entry-{count}.bin')
                                target.write_bytes(content)
                                print('SAVED', target, len(content), flush=True)
                        if (args.extract_lua or lua_pattern) and content and content.startswith(b'\x1bLua\x53'):
                            root = Reader(content, allow_client_format1=True).function()
                            source_name = (root['source'] or '').split('/')[-1].lstrip('@')
                            if lua_pattern and lua_pattern.search(source_name):
                                print('LUA_MATCH', path.name, count, source_name,
                                      len(content), flush=True)
                            if (lua_pattern and lua_pattern.search(source_name)) or (args.extract_lua and source_name in (
                                'WeaponAssemblyTool.lua',
                                'GunsmithAmmoLoadoutData.lua',
                                'WeaponFeature.lua',
                                'AssemblySelectionMain.lua',
                                'AssemblySelectionDataLogic.lua',
                                'AssemblyEquipAmmoCase.lua',
                                'QuickOperationDataBulletStruct.lua',
                                'EquipmentViewLogic.lua',
                                'BulletFeature.lua',
                                'GunsmithAmmoLogic.lua',
                                'WeaponHelperTool.lua',
                                'AuctionServer.lua',
                                'ShopServer.lua',
                            )):
                                output = Path(__file__).with_name('evidence') / 'weapon_lua'
                                output.mkdir(parents=True, exist_ok=True)
                                target = output / source_name
                                target.write_bytes(content)
                                print('LUA', path.name, count, source_name,
                                      len(content), flush=True)
                        if content and content.startswith(b'\xc1\x83\x2a\x9e'):
                            names = name_map(content)
                            matches = [name for name in names
                                       if asset_pattern.search(name)]
                            if matches:
                                print('HIT', path.name, count, pos,
                                      entry['uncompressed'], matches[:12], flush=True)
                                if args.save_matches:
                                    output = Path(__file__).with_name('evidence') / 'matched_assets'
                                    output.mkdir(parents=True, exist_ok=True)
                                    target = output / (path.name + f'.entry-{count}.uasset')
                                    target.write_bytes(content)
                                    print('SAVED', target, len(content), flush=True)
                                    save_next = True
                                    saved_index = count
                    except Exception as exc:
                        errors[type(exc).__name__] += 1
                        if errors[type(exc).__name__] <= args.debug_errors:
                            print('DECODE_ERROR', path.name, count, pos,
                                  entry['method'], entry['uncompressed'],
                                  type(exc).__name__, str(exc)[:200], flush=True)
                pos = entry['next_pos']
            print('SUMMARY', path.name, count, pos, limit, dict(errors),
                  flush=True)


if __name__ == '__main__':
    main()
