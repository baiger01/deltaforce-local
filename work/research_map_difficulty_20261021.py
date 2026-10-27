"""Read original map/mode tables and consumers; compare current publication sources."""
import argparse
import ast
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import research_world_admission_20261020 as original

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT/'work/evidence/gameplay-map-difficulty-research-20261021.json'
FAMILIES = ('Forrest', 'Dam_Iris', 'SpaceCenter', 'Brakkesh', 'Tide', 'AZ-5')
EXPECTED_ROWS = {'MapConfig': 640, 'MatchModeDataConfig': 424,
                 'WorldEntranceConfig': 18, 'DT_SubWorldConfig_Iris_Entry': 81}
FUNCTIONS = {'GameModeServer': {'0.102', '0.103', '0.104', '0.105', '0.106', '0.107',
    '0.117', '0.118', '0.119', '0.120', '0.121', '0.131', '0.132', '0.140',
    '0.140.0', '0.141', '0.142', '0.143'}, 'cs_solo_editor_pb': {'0.40', '0.41'}}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def query_original():
    previous = sys.argv
    sys.argv = [str(original.__file__)]
    for name in [*EXPECTED_ROWS, *FUNCTIONS]:
        sys.argv += ['--name', name]
    sys.argv += ['--lua-terms', '.*', '--lua-listing', '--lua-function',
                r'^0\.(40|41|102|103|104|105|106|107|117|118|119|120|121|131|132|140|140\.0|141|142|143)$']
    captured = io.StringIO()
    try:
        with redirect_stdout(captured):
            original.main()
    finally:
        sys.argv = previous
    result = json.loads(captured.getvalue())
    tables = {}
    for table in result['tables']:
        name = Path(table['source_header']['indexed_path']).stem
        if name not in EXPECTED_ROWS or table['parse_status'] != 'parsed':
            raise ValueError('Unexpected or unparsed source table: '+name)
        assert len(table['result']['rows']) == EXPECTED_ROWS[name]
        tables[name] = table
    if set(tables) != set(EXPECTED_ROWS):
        raise ValueError('Expected original source tables were not all recovered')
    return result, tables


def lua_consumers(result):
    blocks = []
    for block in result['lua_blocks']:
        name = Path(block['source']['indexed_path']).stem
        if name not in FUNCTIONS:
            continue
        block['selected_functions'] = [f for f in block['selected_functions']
                                       if f['function_id'] in FUNCTIONS[name]]
        assert {f['function_id'] for f in block['selected_functions']} == FUNCTIONS[name]
        blocks.append(block)
    if len(blocks) != len(FUNCTIONS):
        raise ValueError('The original board consumer or protobuf module is missing')
    return blocks


def source_snapshot(path, functions=()):
    raw = path.read_bytes()
    result = dict(path=str(path), bytes=len(raw), sha256=digest(raw), symbols=[])
    if functions:
        tree = ast.parse(raw.decode('utf-8-sig'))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in functions:
                result['symbols'].append(dict(name=node.name, line=node.lineno, end_line=node.end_lineno))
        if {s['name'] for s in result['symbols']} != set(functions):
            raise ValueError('Publication function changed or moved')
    return result


def collect():
    source, tables = query_original()
    map_rows = tables['MapConfig']['result']['rows']
    subworlds = tables['DT_SubWorldConfig_Iris_Entry']['result']['rows']
    selected_maps = {}
    for key, row in map_rows.items():
        name = row['fields'].get('LevelName', '')
        family = next((f for f in FAMILIES if name.startswith(f+'_')), None)
        if family:
            selected_maps[key] = dict(family=family, **row)
    modes = []
    for key, row in tables['MatchModeDataConfig']['result']['rows'].items():
        fields = row['fields']
        map_row = selected_maps.get(str(fields.get('MapID')))
        if map_row is None:
            continue
        modes.append(dict(family=map_row['family'], match_mode_row=key,
            mode=row, map_row=str(fields['MapID']),
            map_serialized_uexp_offset=map_row['serialized_uexp_offset'],
            map_fields=map_row['fields'],
            baseline_sol_10_11_12=(fields.get('GameMode') == 1 and fields.get('GameRule') == 4
                                   and fields.get('MatchSubMode') in (10, 11, 12))))
    modes.sort(key=lambda m: (m['family'], int(m['match_mode_row'])))
    levels = {row['map_fields']['SubWorldName'] for row in modes}
    selected_subworlds = {key: row for key, row in subworlds.items() if key in levels}
    for name, table in tables.items():
        table['result']['rows'] = (
            selected_maps if name == 'MapConfig' else
            {m['match_mode_row']: m['mode'] for m in modes} if name == 'MatchModeDataConfig' else
            selected_subworlds if name == 'DT_SubWorldConfig_Iris_Entry' else table['result']['rows'])
        table['result']['research_filtered_row_count'] = len(table['result']['rows'])
    publication = original.PEER/'outputs/df-local-server/protocol/local_map_board_candidates.json'
    handshake = original.PEER/'outputs/df-local-server/dfserver/handshake_diagnostic.py'
    published = json.loads(publication.read_bytes())
    symbols = ('_candidate_local_map_board_catalog', '_candidate_local_prepare_map_response',
               '_candidate_local_board_tod_fields', '_candidate_valid_world_map_row')
    pin = source_snapshot(handshake, symbols)
    raw = handshake.read_text(encoding='utf-8-sig').splitlines()
    response = next(s for s in pin['symbols'] if s['name'] == '_candidate_local_prepare_map_response')
    response_text = '\n'.join(raw[response['line']-1:response['end_line']])
    generated = original.PEER/'outputs/df-local-server/protocol/generated_codec_fields.json'
    generated_data = json.loads(generated.read_bytes())
    proto = [m for m in generated_data['messages'] if m['name'] in
             ('MapBoardInfoDesc', 'CSPrepareMapBoardReq', 'CSPrepareMapBoardRes', 'MatchModeInfo')]
    assert len(proto) == 4
    board = next(m for m in proto if m['name'] == 'MapBoardInfoDesc')
    fields = {f['name']: (f['number'], f['codec_category']) for f in board['fields']}
    assert fields['difficulty'] == (16, 'u32') and fields['equip_price'] == (21, 'i64')
    current = dict(publication=source_snapshot(publication), operations=published['operations'],
        handshake=pin, board_response_source=response_text,
        explicitly_emits_difficulty=("'difficulty'" in response_text or '"difficulty"' in response_text),
        generated_schema=source_snapshot(generated), messages=proto,
        environment_override_observed=False, live_board_response_observed=False)
    return dict(kind='readonly_map_difficulty_source_research',
        reviewed_at_utc=datetime.now(timezone.utc).isoformat(),
        helper_sha256=digest(Path(__file__).read_bytes()),
        original_reader_sha256=digest(Path(original.__file__).read_bytes()),
        client_sha256=source['client_sha256'], cache_manifest_sha256=source['cache_manifest_sha256'],
        process_access=False, client_launched=False, packets_sent=False,
        account_database_accessed=False, original_or_peer_written=False,
        original_index_validation={k: source[k] for k in ('pak_count', 'directory_file_count',
            'all_primary_and_secondary_sha1_valid', 'matching_paks', 'source_pins', 'oodle_codec_sha256')},
        tables=tables, lua_consumers=lua_consumers(source), family_mode_matrix=modes,
        current_publication=current,
        limits=['original installation baseline, not proof of live effective overlays',
            'MatchSubMode numeric profiles are not an invented mapping to business difficulty values',
            'current official board difficulty, point IDs, admission thresholds and schedule require a source',
            'no map difficulty, gameplay authority or account transaction was installed by this research'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--compact', action='store_true')
    args = parser.parse_args()
    result = collect()
    if args.verify:
        previous = json.loads(OUTPUT.read_text(encoding='utf-8'))
        previous.pop('reviewed_at_utc')
        compare = dict(result)
        compare.pop('reviewed_at_utc')
        assert previous == compare, 'Original or current publication source changed'
    if args.compact:
        baseline = [m for m in result['family_mode_matrix'] if m['baseline_sol_10_11_12']]
        print(json.dumps(dict(status='verified', compared=args.verify,
            families={f: sorted({m['mode']['fields']['MatchSubMode'] for m in baseline
                                 if m['family'] == f}) for f in FAMILIES},
            baseline_mode_rows=len(baseline), total_family_mode_rows=len(result['family_mode_matrix']),
            published_rows=len(result['current_publication']['operations']),
            explicitly_emits_difficulty=result['current_publication']['explicitly_emits_difficulty'])))
    else:
        print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
