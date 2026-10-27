"""Read exact installed Game transition and inventory readiness Lua as data."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

import lz4.block
import zstandard
from lua53_reader import Reader, listing, walk
from oodle_payload_reader import decode as decode_oodle
import oodle_payload_reader
import inspect_economy_inventory_location_lua as installed
import inspect_economy_inventory_ready_lifecycle_lua as previous

TARGETS = {
    '@GameFlowState4Game.lua': '4d5a53ea49f0b429c22938f43864701918e87f61b48bc58bce273f2a47da97e8',
    '@GameFlowTransition4Game.lua': 'b3edb4ac3ff2215b7b2d92c8972fa7048065e1f72833c435c1089c56ea4666a1',
    '@GameFlowProcessor.lua': '294b3f37c28ba89274c11b17ae74abbb4dcbe899312ff8c288130ab3ac8cbb51',
    '@GameFlowState.lua': '17a074ac756879726a4ab507be0ae533e1407e87e4046b88260646948e9e9c65',
    '@GameFlowTransition.lua': 'd2cb8478c4ddf7716bba947cb1a0e8c6438326d5636c78eca2e8a4e480da318c',
    '@InGameController.lua': 'c944d3f0600f7bb990773776b93ab0db43ac1a13156a1ecf74af107c77e6ab36',
    '@MatchServer.lua': '4ec5c8287762a75c40be937d8588c03e2e0465e3735a274d86485ead38008be9',
    '@InventoryServer.lua': '6ee37eece339d7d501b5456170b7369426b02c37514f3cba1cec1858a2b0f147',
    '@LootingServer.lua': previous.TARGETS['@LootingServer.lua'],
    '@GameFlowManager.lua': previous.TARGETS['@GameFlowManager.lua'],
    '@LuaGameFlowEvent.lua': previous.TARGETS['@LuaGameFlowEvent.lua'],
}


def derive():
    oodle_payload_reader.PATH = installed.GAME.parents[2] / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    namespace = dict(struct=struct, hashlib=hashlib, zlib=zlib, lz4=lz4,
        zstandard=zstandard, decode_oodle=decode_oodle)
    helper_pins = {}
    for filename, function in (('probe_pak_payload_lua.py', 'parse_entry'),
            ('probe_character_asset_rows.py', 'decode_content')):
        path = installed.ROOT / 'work' / filename
        raw = path.read_bytes()
        helper_pins['work/' + filename] = hashlib.sha256(raw).hexdigest()
        node = next(node for node in ast.parse(raw.decode('utf8')).body
            if isinstance(node, ast.FunctionDef) and node.name == function)
        exec(compile(ast.Module(body=[node], type_ignores=[]), filename, 'exec'), namespace)
    index_raw = installed.INDEX.read_bytes()
    rows = [row for row in json.loads(index_raw)['recovered_lua_metadata']
        if row.get('source_name') in TARGETS]
    if len(rows) != len(TARGETS):
        raise ValueError('Missing or ambiguous exact installed Game-ready source')
    sources = []
    for row in rows:
        if row['sha256'] != TARGETS[row['source_name']] or row['archive'] != 'pak-0-0-pakchunk1-WindowsClient.pak':
            raise ValueError('Installed indexed Game-ready source changed')
        with (installed.GAME / row['archive']).open('rb') as stream:
            stream.seek(-512, 2)
            footer = stream.read(512)
            marker = footer.rfind(struct.pack('<I', 0x5a6f12e1))
            _, limit = struct.unpack_from('<IQ', footer, marker + 4)
            compression = [value.decode() for value in re.findall(rb'Zlib|Gzip|Oodle|LZ4|Zstd', footer)]
            entry = namespace['parse_entry'](stream, row['entry_offset'], limit, variant='observed_permutation')
            payload, error = namespace['decode_content'](stream, row['entry_offset'], entry, compression)
        if error:
            raise ValueError(error)
        chunk = payload[row['lua_offset']:row['lua_offset'] + row['length']]
        if hashlib.sha256(chunk).hexdigest() != TARGETS[row['source_name']]:
            raise ValueError('The actual installed Game-ready Lua changed')
        reader = Reader(chunk, allow_client_format1=True)
        tree = reader.function()
        if reader.at != len(chunk):
            raise ValueError('Unexpected trailing installed Lua bytes')
        functions = [dict(function_id=function['id'], first_line=function['first_line'],
            last_line=function['last_line'], constants=function['constants'],
            local_names=function['locals'], listing=listing(function).splitlines())
            for function in walk(tree)]
        sources.append(dict(source_name=row['source_name'], lua_sha256=row['sha256'],
            archive=row['archive'], entry_offset=row['entry_offset'], lua_offset=row['lua_offset'],
            lua_length=row['length'], functions=functions))
    return dict(kind='installed_game_ready_transition_and_inventory_lua_v4',
        source_index_sha256=hashlib.sha256(index_raw).hexdigest(), helper_source_pins=helper_pins,
        sources=sources, process_access=False, client_launched=False, production_modified=False,
        lua_executed=False, installed_baseline_verified=True, hotfix_override_absence_proven=False,
        server_wire_ready_signal_claimed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(installed.ROOT / 'work/evidence'):
        parser.error('Use a fresh audit-only evidence path')
    report = derive()
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        source_count=len(report['sources']), functions=sum(len(row['functions']) for row in report['sources']))))
