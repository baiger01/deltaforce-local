"""Inspect installed settlement consumers and generated business schemas offline."""
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
import oodle_payload_reader
from oodle_payload_reader import decode as decode_oodle
from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
INDEX = Path('E:/\u65b0\u5efa\u6587\u4ef6\u5939/DSH/deltaforce-local/outputs/df-local-server/protocol/pak_baseline_lua_probe.json')
PAKS = Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)/DeltaForce/Content/Paks')
SOURCES = {
    '@SettlementDefine.lua': 'e6ef5b94004625342a6a7c4977fb17a8282fbb68c0c28a9a43d6528944078065',
    '@SettlementServer.lua': '80bc6cefeb576b8f7d3b7199abe490bb91c80c9781de8c849cbb0a5909ee2322',
    '@GameFlowTransition4Game2Frontend.lua': 'b1288b1b53a13561bfc1300f1fb8ec6a66243ff96b18fec9dc3758a2a916554b',
}
MESSAGE_ROOTS = {
    'CSSettlementGetHasUnsettledMatchReq', 'CSSettlementGetHasUnsettledMatchRes',
    'CSSettlementGetNewSettlementInfoReq', 'CSSettlementGetNewSettlementInfoRes',
    'CSSettlementNewSettlementInfoNtf', 'CSStateClearSettlementReq', 'CSStateClearSettlementRes',
    'SettlementNtf', 'Ds2AnyMatchSettlementReq', 'Any2DsMatchSettlementRes',
}


def derive():
    oodle_payload_reader.PATH = PAKS.parents[2] / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    namespace = dict(struct=struct, hashlib=hashlib, zlib=zlib, lz4=lz4,
        zstandard=zstandard, decode_oodle=decode_oodle)
    pins = {}
    for filename, function in (('probe_pak_payload_lua.py', 'parse_entry'),
            ('probe_character_asset_rows.py', 'decode_content')):
        raw = (ROOT / 'work' / filename).read_bytes()
        node = next(n for n in ast.parse(raw.decode('utf8')).body
            if isinstance(n, ast.FunctionDef) and n.name == function)
        exec(compile(ast.Module(body=[node], type_ignores=[]), filename, 'exec'), namespace)
        pins['work/' + filename] = hashlib.sha256(raw).hexdigest()
    index_raw = INDEX.read_bytes()
    rows = [r for r in json.loads(index_raw)['recovered_lua_metadata']
        if r.get('source_name') in SOURCES]
    if len(rows) != len(SOURCES) or len({r['source_name'] for r in rows}) != len(SOURCES):
        raise ValueError('Exact installed settlement Lua entries are required')
    consumers = []
    for row in rows:
        digest = SOURCES[row['source_name']]
        if row['sha256'] != digest or row['archive'] != 'pak-0-0-pakchunk1-WindowsClient.pak':
            raise ValueError('Settlement Lua index identity changed')
        with (PAKS / row['archive']).open('rb') as stream:
            stream.seek(-512, 2)
            footer = stream.read(512)
            marker = footer.rfind(struct.pack('<I', 0x5a6f12e1))
            _, limit = struct.unpack_from('<IQ', footer, marker + 4)
            compression = [s.decode() for s in re.findall(rb'Zlib|Gzip|Oodle|LZ4|Zstd', footer)]
            entry = namespace['parse_entry'](stream, row['entry_offset'], limit, variant='observed_permutation')
            payload, error = namespace['decode_content'](stream, row['entry_offset'], entry, compression)
        if error:
            raise ValueError(error)
        chunk = payload[row['lua_offset']:row['lua_offset'] + row['length']]
        if hashlib.sha256(chunk).hexdigest() != digest:
            raise ValueError('Installed settlement Lua content changed')
        reader = Reader(chunk, allow_client_format1=True)
        tree = reader.function()
        if reader.at != len(chunk):
            raise ValueError('Unexpected trailing settlement Lua bytes')
        functions = [dict(function_id=f['id'], first_line=f['first_line'], last_line=f['last_line'],
            constants=f['constants'], local_names=f['locals'], listing=listing(f).splitlines()) for f in walk(tree)]
        consumers.append(dict(source=row['source_name'], lua_sha256=digest,
            archive=row['archive'], entry_offset=row['entry_offset'], lua_offset=row['lua_offset'],
            lua_bytes=row['length'], installed_bytes_verified=True, functions=functions))
    relative = 'outputs/df-local-server/protocol/generated_codec_fields.json'
    codec_raw = (ROOT / relative).read_bytes()
    pins[relative] = hashlib.sha256(codec_raw).hexdigest()
    by_name = {}
    for message in json.loads(codec_raw)['messages']:
        previous = by_name.get(message['name'])
        if previous is not None and previous != message:
            raise ValueError('Generated settlement message name is ambiguous')
        by_name[message['name']] = message
    if not MESSAGE_ROOTS <= by_name.keys():
        raise ValueError('A settlement root message is missing')
    selected, missing, pending = {}, set(), sorted(MESSAGE_ROOTS)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in by_name:
            missing.add(name)
            continue
        if len(selected) >= 256:
            raise ValueError('Settlement nested schema exceeds its fixed bound')
        selected[name] = by_name[name]
        pending.extend(f['nested_type'] for f in by_name[name]['fields'] if f.get('nested_type'))
    return dict(kind='offline_installed_settlement_consumer_and_schema_research',
        sources=pins, index_sha256=hashlib.sha256(index_raw).hexdigest(),
        installed_codec_sha256=hashlib.sha256(oodle_payload_reader.PATH.read_bytes()).hexdigest(),
        lua_consumers=consumers, message_roots=sorted(MESSAGE_ROOTS), messages=selected,
        schema_closure_complete=not missing, unqualified_nested_types=sorted(missing),
        lua_executed=False, client_launched=False, process_access=False,
        source_installation_written=False, message_wire_interoperability_claimed=False,
        generated_schema_is_not_native_match_end_receiver=True,
        completed_settlement_or_inventory_persistence_claimed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / 'work/evidence'):
        parser.error('Use a fresh evidence output inside this project')
    result = derive()
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        lua_sources=len(result['lua_consumers']), messages=len(result['messages']))))
