"""Full indexed baseline Lua coverage for exact Game-ready callback/RPC names."""
import argparse
import hashlib
import json
from pathlib import Path

import oodle_payload_reader
import inspect_economy_inventory_location_lua as installed
import scan_map_runtime_lua_consumers as scanner

TERMS = frozenset(('evtGameFlowState4GameEnter', 'OnPostEnterGameFlow',
    'OnPostEnterGameFlowStage', 'ServerNotifyLoadingFinish', 'ServerHudViewsLoadedBroadcast',
    'ServerNotifyLoadedWorld', 'ServerMarkReadyForReceiving'))


def derive():
    oodle_payload_reader.PATH = installed.GAME.parents[2] / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    scanner.TERMS = TERMS
    result = scanner.scan(installed.INDEX, installed.GAME)
    result.update(kind='installed_game_ready_exact_callback_rpc_lua_xrefs_v4',
        process_access=False, client_launched=False, production_modified=False,
        installed_baseline_only=True, hotfix_override_absence_proven=False)
    result['helper_source_pins'] = {relative: hashlib.sha256((installed.ROOT / relative).read_bytes()).hexdigest()
        for relative in ('work/research_economy_game_ready_lua_xrefs_v4.py',
            'work/scan_map_runtime_lua_consumers.py')}
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(installed.ROOT / 'work/evidence'):
        parser.error('Use a fresh audit-only evidence path')
    result = derive()
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('ascii')
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        indexed=result['indexed_chunks'], counts=result['counts'], matches=len(result['matches']),
        failures=len(result['failures']))))
