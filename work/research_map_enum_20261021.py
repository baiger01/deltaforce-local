"""Read actual ds_common_pb global enum assignments from the original PAK."""
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
EXPECTED = '6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / 'work'))
    import oodle_payload_reader
    from scan_weapon_tables import parse_entry, decode_content
    from lua53_reader import Reader, instruction, CLIENT_OPS, listing
    oodle_payload_reader.PATH = GAME / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    index_raw = INDEX.read_bytes()
    index = json.loads(index_raw)
    rows = [r for r in index['recovered_lua_metadata'] if r.get('source_name') == '@ds_common_pb.lua']
    if len(rows) != 1 or rows[0]['sha256'] != EXPECTED:
        raise ValueError('The original indexed enum chunk identity changed')
    row = rows[0]
    if row['archive'] != 'pak-0-0-pakchunk1-WindowsClient.pak' or row['entry_offset'] != 32942080:
        raise ValueError('The source enum PAK entry changed')
    pak = GAME / 'DeltaForce/Content/Paks' / row['archive']
    with pak.open('rb') as stream:
        stream.seek(-512, 2)
        tail = stream.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        version, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [x[:-1].decode('ascii') for x in re.findall(rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        try:
            entry = parse_entry(stream, row['entry_offset'], limit)
        except (ValueError, struct.error):
            entry = parse_entry(stream, row['entry_offset'], limit, variant='observed_permutation')
        raw = decode_content(stream, row['entry_offset'], entry, methods)
        if raw is None:
            raise ValueError('The source enum chunk could not be decoded')
        stored = []
        if entry['method']:
            for first, end in entry['blocks']:
                stream.seek(row['entry_offset'] + first)
                stored.append(stream.read(end - first))
        else:
            stored = [raw]
    if hashlib.sha1(b''.join(stored)).digest() != entry['sha1'] and hashlib.sha1(raw).digest() != entry['sha1']:
        raise ValueError('Original PAK entry SHA1 validation failed')
    chunk = raw[row['lua_offset']:row['lua_offset'] + row['length']]
    if digest(chunk) != EXPECTED:
        raise ValueError('Original enum chunk no longer matches the indexed bytes')
    reader = Reader(chunk, allow_client_format1=True)
    function = reader.function()
    if reader.at != len(chunk) or function['source'] != '@ds_common_pb.lua' or function['children']:
        raise ValueError('Expected one fully parsed original top-level proto')
    constants = function['constants']
    regs = {}
    tables = []
    exports = []

    def rk(value):
        return constants[value & 255] if value & 256 else regs.get(value)

    for pc, word in enumerate(function['code'], 1):
        ins = instruction(word)
        name = CLIENT_OPS[ins['op']]
        a, b, c = ins['a'], ins['b'], ins['c']
        if name == 'LOADK':
            regs[a] = constants[ins['bx']]
        elif name == 'MOVE':
            regs[a] = regs.get(b)
        elif name == 'NEWTABLE':
            value = dict(register=a, newtable_pc=pc, assignments=[])
            tables.append(value)
            regs[a] = value
        elif name == 'SETTABLE':
            value = regs.get(a)
            if isinstance(value, dict) and 'newtable_pc' in value:
                value['assignments'].append(dict(pc=pc, key=rk(b), value=rk(c), raw_word=hex(word)))
        elif name == 'SETTABUP':
            key, value = rk(b), rk(c)
            if isinstance(key, str) and (key == 'MatchSubMode' or re.search('difficult', key, re.I)):
                exports.append(dict(global_name=key, settabup_pc=pc, upvalue=a,
                                    table=value, raw_word=hex(word)))
        elif name not in ('JMP', 'RETURN', 'EQ', 'LT', 'LE', 'TEST', 'SETUPVAL', 'SETLIST'):
            if name == 'CALL':
                for register in list(regs):
                    if register >= a:
                        regs.pop(register)
            else:
                regs.pop(a, None)
    match = [x for x in exports if x['global_name'] == 'MatchSubMode']
    if len(match) != 1:
        raise ValueError('Expected exactly one lexical global MatchSubMode table assignment')
    match = match[0]
    expected = {'SOLPMC': 10, 'HighYieldSOLPMC': 11, 'ExtremeHighYieldSOLPMC': 12}
    values = {x['key']:x['value'] for x in match['table']['assignments']}
    if (match['table']['newtable_pc'], match['settabup_pc']) != (137, 194) or any(values.get(k) != v for k,v in expected.items()):
        raise ValueError('The exact source enum definition changed')
    if function['upvalue_names'][match['upvalue']] != '_ENV':
        raise ValueError('The table export does not target the source global environment')
    lines = listing(function).splitlines()
    for item in exports:
        table = item.get('table')
        if not isinstance(table, dict) or 'newtable_pc' not in table:
            item['definition_complete'] = False
            continue
        lo, hi = table['newtable_pc'], item['settabup_pc']
        item['definition_complete'] = all(CLIENT_OPS[instruction(w)['op']] in
            ('NEWTABLE', 'LOADK', 'SETTABLE', 'SETTABUP') for w in function['code'][lo-1:hi])
        item['listing'] = lines[lo-1:hi]
    dependencies = ('lua53_reader.py', 'scan_weapon_tables.py', 'probe_pak_payload_lua.py', 'oodle_payload_reader.py')
    pins = {str(INDEX.relative_to(ROOT)).replace('\\', '/'): digest(index_raw)}
    pins.update({'work/' + name:digest((ROOT / 'work' / name).read_bytes()) for name in dependencies})
    report = dict(kind='original_lua_match_submode_defining_assignments_20261021',
        as_of_utc=datetime.now(timezone.utc).isoformat(), game_launched=False,
        game_written=False, peer_written=False, database_opened=False,
        process_access=False, game_lua_executed=False,
        compression_only_installed_codec_loaded=True,
        source_pak=str(pak), source_index_entry=row, original_chunk_sha256=digest(chunk),
        source_pak_bytes=pak.stat().st_size, footer_sha256=digest(tail), pak_version=version,
        compression_codec_sha256=digest(oodle_payload_reader.PATH.read_bytes()),
        source_entry_sha1=entry['sha1'].hex(), source_entry_sha1_verified=True,
        complete_proto_parsed=True, proto_instruction_count=len(function['code']),
        enum_exports=exports, match_submode_values=expected,
        enum_is_protocol_field_index=False,
        difficulty_global_export_count=sum(x['global_name'] != 'MatchSubMode' for x in exports),
        board_difficulty_u32_field16_value_recovered=False,
        static_register_tracking_is_not_lua_execution=True,
        source_pins=pins, helper_sha256=digest(Path(__file__).read_bytes()))
    if args.verify:
        prior = json.loads(args.verify.read_bytes())
        for key in report.keys() - {'as_of_utc'}:
            if prior.get(key) != report[key]:
                raise ValueError('Replay mismatch: ' + key)
        print(json.dumps(dict(replay_matches=True, original_chunk_sha256=EXPECTED,
                              match_submode_values=expected, difficulty_global_export_count=report['difficulty_global_export_count'])))
    elif args.output:
        out = args.output.resolve()
        if out.exists() or out.parent != (ROOT / 'work/evidence').resolve():
            raise ValueError('A fresh own work/evidence output is required')
        data = (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode()
        with out.open('xb') as stream:
            stream.write(data)
        print(json.dumps(dict(path=str(out), sha256=digest(data), match_submode_values=expected,
                              difficulty_global_export_count=report['difficulty_global_export_count'])))
    else:
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
