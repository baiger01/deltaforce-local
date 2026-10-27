"""Recover board-difficulty labels and submode links from static Lua assignments."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

import research_map_difficulty_consumers_20261021 as source
from lua53_reader import CLIENT_OPS, Reader, instruction, listing, walk

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    '@ds_common_pb.lua': '6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b',
    '@RecruitConfig.lua': 'fb416d821d3db47055abf3ea2464cbd12cf454891beb9a5cb73cb0e6bd27a29c',
    '@ArmedForceConfig.lua': '099b45b57a4d1571e5b7888085130a0b3d4beee43a68c16cebe753c235f2bd58',
    '@RecruitLogic.lua': '1e6b53ce9a568d2b7174c9fcac13bb105c66cf87e0834266a727197b0968204f',
    '@GameModeServer.lua': 'c4ced93f1059d9cb8f91874a1d0084090d4263a95d443dcd7d9101548088e381',
}


def assignments(fn, low, high, parent_register, submodes):
    """Interpret only a straight assignment span; represent NSLOCTEXT symbolically."""
    root = {}
    regs = {parent_register: root}
    const = fn['constants']

    def rk(value):
        return const[value & 255] if value & 256 else regs[value]

    for pc, word in enumerate(fn['code'][low-1:high], low):
        ins = instruction(word)
        name = CLIENT_OPS[ins['op']]
        a, b, c = ins['a'], ins['b'], ins['c']
        if name == 'LOADK':
            regs[a] = const[ins['bx']]
        elif name == 'NEWTABLE':
            regs[a] = {}
        elif name == 'GETTABUP':
            if fn['upvalue_names'][b] != '_ENV':
                raise ValueError('Non-global value in source assignment span')
            regs[a] = ('global', rk(c))
        elif name == 'GETTABLE':
            if regs[b] != ('global', 'MatchSubMode'):
                raise ValueError('Unexpected table input in source assignment span')
            regs[a] = submodes[rk(c)]
        elif name == 'SETTABLE':
            if not isinstance(regs[a], dict):
                raise ValueError('Non-table assignment receiver')
            regs[a][rk(b)] = rk(c)
        elif name == 'CALL':
            if regs[a] != ('global', 'NSLOCTEXT') or (b, c) != (4, 2):
                raise ValueError('Only symbolic three-argument localization is supported')
            values = [regs[a+i] for i in (1, 2, 3)]
            if not all(isinstance(v, str) for v in values):
                raise ValueError('Unexpected localization arguments')
            regs[a] = dict(namespace=values[0], key=values[1], default_text=values[2])
        else:
            raise ValueError('Not a straight assignment span: ' + name + ' at ' + str(pc))
    return root


def collect():
    source.oodle_payload_reader.PATH = source.GAME / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    index_raw = source.INDEX.read_bytes()
    rows = [r for r in json.loads(index_raw)['recovered_lua_metadata'] if r.get('source_name') in EXPECTED]
    if len(rows) != len(EXPECTED):
        raise ValueError('Expected defining sources are not unique')
    parsed, pins = {}, {}
    for row, chunk in source.original_chunks(rows):
        name = row['source_name']
        if source.digest(chunk) != EXPECTED[name]:
            raise ValueError('Defining source changed')
        reader = Reader(chunk, allow_client_format1=True)
        fn = reader.function()
        if reader.at != len(chunk) or fn['source'] != name:
            raise ValueError('Defining source EOF or identity mismatch')
        parsed[name] = {f['id']: f for f in walk(fn)}
        pins[name] = {k: row[k] for k in ('archive', 'entry_offset', 'lua_offset', 'length', 'sha256')}
    enum = parsed['@ds_common_pb.lua']['0']
    submodes = {}
    for word in enum['code'][138:141]:
        ins = instruction(word)
        if CLIENT_OPS[ins['op']] != 'SETTABLE' or ins['a'] != 1 or not (ins['b'] & 256 and ins['c'] & 256):
            raise ValueError('Actual submode literal assignments changed')
        submodes[enum['constants'][ins['b'] & 255]] = enum['constants'][ins['c'] & 255]
    if submodes != {'SOLPMC': 10, 'HighYieldSOLPMC': 11, 'ExtremeHighYieldSOLPMC': 12}:
        raise ValueError('Source submode values changed')
    recruit = parsed['@RecruitConfig.lua']['0']
    armed = parsed['@ArmedForceConfig.lua']['0']
    targets = assignments(recruit, 691, 744, 3, submodes)
    labels = assignments(armed, 5355, 5396, 5, submodes)['ModeDifficulty']
    if targets['TargetId2SubMode'] != {1: 10, 2: 11, 3: 12}:
        raise ValueError('Source difficulty to submode assignments changed')
    if {k: v['default_text'] for k, v in labels.items()} != {-1: '无', 0: '默认', 1: '常规', 2: '机密', 3: '绝密'}:
        raise ValueError('Source localized difficulty values changed')
    selected = {'@RecruitLogic.lua': ['0.72', '0.89'],
                '@GameModeServer.lua': ['0.105', '0.106', '0.107', '0.143']}
    consumers = {name: [dict(function_id=fid, first_line=parsed[name][fid]['first_line'],
                       last_line=parsed[name][fid]['last_line'],
                       listing=listing(parsed[name][fid]).splitlines(),
                       constants=parsed[name][fid]['constants'], locals=parsed[name][fid]['locals'])
                       for fid in ids] for name, ids in selected.items()}
    spans = [dict(source='@RecruitConfig.lua', first_pc=691, last_pc=744,
                  listing=listing(recruit).splitlines()[690:744]),
             dict(source='@ArmedForceConfig.lua', first_pc=5355, last_pc=5396,
                  listing=listing(armed).splitlines()[5354:5396]),
             dict(source='@ds_common_pb.lua', first_pc=137, last_pc=194,
                  listing=listing(enum).splitlines()[136:194])]
    return dict(kind='static_original_board_difficulty_semantic_mapping',
        as_of_utc=datetime.now(timezone.utc).isoformat(),
        source_pins=pins, index_sha256=source.digest(index_raw),
        helper_sha256=source.digest(Path(__file__).read_bytes()),
        reader_sha256=source.digest((ROOT / 'work/lua53_reader.py').read_bytes()),
        source_reader_sha256=source.digest(Path(source.__file__).read_bytes()),
        localized_difficulty=labels, recruitment_targets=targets, submodes=submodes,
        defining_spans=spans, consumers=consumers,
        scope=dict(game_started=False, peer_written=False, game_written=False,
                   process_access=False, lua_executed=False, network_access=False,
                   database_access=False, localization_calls_symbolic_only=True),
        limits=['static original consumer contract, not a captured current official board',
                'dynamic per-map point/opening/level/fees/equipment rules are not inferred',
                'WorldEntranceConfig.Difficulty and AI difficulty are not substituted'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    result = collect()
    if args.verify:
        previous = json.loads(args.verify.read_bytes())
        for key in result.keys() - {'as_of_utc'}:
            if previous.get(key) != json.loads(json.dumps(result[key])):
                raise ValueError('Replay mismatch: ' + key)
        print(json.dumps(dict(verified=True, sources=len(EXPECTED), difficulty_to_submode={1: 10, 2: 11, 3: 12})))
    elif args.output:
        path = args.output.resolve()
        if path.exists() or path.parent != (ROOT / 'work/evidence').resolve():
            raise ValueError('Use a fresh own evidence path')
        with path.open('xb') as stream:
            stream.write((json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode())
        print(json.dumps(dict(output=str(path), sources=len(EXPECTED))))
    else:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
