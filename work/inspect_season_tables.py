"""Match original season rows against complete native typed registrations."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from explore_tagged_export import read_row
from extract_native_safehouse_catalog import EXPECTED_PE, field_value, installed_export, source_structs
from local_game_paths import game_paths
from scan_weapon_tables import decode_content, parse_entry
from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
TABLES = {
    'ranking': (0, 0, 'RankingSeasonInfo', 489435952, 413704672, 19),
    'season': (0, 0, 'SeasonDataRow', 489441888, 413249728, 5),
    'tournament': (0, 0, 'TournamentSeason', 489454864, 413171296, 18),
}


def rows(raw, columns):
    root = 29 if struct.unpack_from('<i', raw, 37)[0] == 0 else 55
    none, instance, prefix, count = struct.unpack_from('<iiii', raw, root)
    if instance or prefix or not 1 <= count <= 256:
        raise ValueError('Not a bounded season table')
    offset, layout, signature, result = root + 16, {}, None, []
    for index in range(count):
        start = offset
        tags, offset, layout = read_row(raw, offset + 8, none, known_types=layout)
        layout = dict(layout)
        if len(tags) != len(columns) + 1:
            raise ValueError('Complete column count differs')
        current = [(tag['field'], tag['kind'], tag['metadata_bytes']) for tag in tags]
        if signature is not None and current != signature:
            raise ValueError('Column order differs')
        signature = current
        row = {'source_row': index, 'serialized_offset': start}
        for tag, column in zip(tags, columns):
            row[column['name']] = field_value(raw, tag, column['kind'])
        inherited = tags[-1]
        if inherited['size'] != 8 or inherited['metadata_bytes']:
            raise ValueError('Inherited row key differs')
        row['row_key_fname_hex'] = raw[inherited['value_start']:inherited['end']].hex()
        result.append(row)
    if raw[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Table trailer differs')
    return result, {column['name']: tag['field'] for tag, column in zip(tags, columns)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-catalog', action='store_true')
    args = parser.parse_args()
    reflected = source_structs(TABLES)
    path = game_paths()[0] / 'DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak'
    candidates = []
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        methods = [value[:-1].decode('ascii') for value in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        position = number = 0
        while position < limit and number < 15000:
            try:
                try:
                    entry = parse_entry(handle, position, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(handle, position, limit, variant='observed_permutation')
            except (ValueError, struct.error):
                aligned = (position + 2047) // 2048 * 2048
                handle.seek(position)
                if aligned >= limit or handle.read(aligned - position) != bytes(aligned - position):
                    raise ValueError('Unexpected original archive boundary')
                position = aligned
                entry = parse_entry(handle, position, limit, variant='observed_permutation')
            number += 1
            if 64 < entry['uncompressed'] <= 2 * 1024 * 1024:
                raw = decode_content(handle, position, entry, methods)
                if raw is not None:
                    for group, native in reflected.items():
                        try:
                            recovered, fields = rows(raw, native['columns'])
                        except (ValueError, struct.error, KeyError, IndexError, UnicodeError):
                            continue
                        record = {'group': group, 'pak': path.name, 'entry': number,
                                  'pak_offset': position, 'sha256': hashlib.sha256(raw).hexdigest(),
                                  'native': native, 'serialized_field_indices': fields,
                                  'rows': recovered}
                        candidates.append(record)
                        print(group, number, position, len(recovered), flush=True)
            position = entry['next_pos']
    output = ROOT / 'work/evidence/season-table-candidates-20261006.json'
    output.write_text(json.dumps({'candidates': candidates}, ensure_ascii=True, indent=2) + '\n',
                      encoding='utf-8')
    print('report', output, flush=True)
    if args.write_catalog:
        if sorted(row['group'] for row in candidates) != sorted(TABLES):
            raise ValueError('Original typed table matches must be unique and complete')
        by_group = {row['group']: row for row in candidates}
        ranking, seasons, tournament = (by_group[name]['rows'] for name in TABLES)
        indices = [row['Index'] for row in ranking]
        if indices != list(range(1, len(indices) + 1)):
            raise ValueError('Original rank serials are not contiguous')
        for rank, season, tour in zip(ranking, seasons, tournament, strict=True):
            if rank['Index'] != season['Index'] or rank['Index'] != tour['ID']:
                raise ValueError('Original season serials do not correspond')
            if any(rank[key] != season[key] or rank[key] != tour[key]
                   for key in ('StartTime', 'EndTime') if rank['Index'] >= 4):
                raise ValueError('Current source season schedules do not correspond')
        consumers = {}
        for name, offset, expected, required in (
                ('HallSeason.lua', 21645312,
                 'f01e9f6781a24505de1806b564bfac5602e25c233f73b0a515451117a0f1c16c',
                 {'0.9': ['GetRankSeasonConfigBySerial', 'SeasonName']}),
                ('RankingLogic.lua', 25544704,
                 '7e2083615f7141bbd1e5b41c892e406819c968b2605d1644bf87f530d0eed9e8',
                 {'0.27': ['RankingSeasonInfoTable', 'Index']}),
                ('RankingServer.lua', 34904064,
                 'e9fd084a84edf188cfe094a3ccc167349654b76d044c0a2ff6d97f2e17e9597a',
                 {'0.7.0': ['cur_serial', 'season_info', 'rank_summary', 'UIStartTime']}),
                ('ds_common_pb.lua', 32942080,
                 '6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b',
                 {'0': ['MatchGameType', 'SOLGameType', 'MPGameType']})):
            raw, source = installed_export(0, offset, pak='pak-0-0-pakchunk1-WindowsClient.pak')
            if source['sha256'] != expected:
                raise ValueError('Original consumer changed: ' + name)
            functions = {fn['id']: fn for fn in walk(Reader(raw, allow_client_format1=True).function())}
            if any(not all(term in functions[fn]['constants'] for term in terms)
                   for fn, terms in required.items()):
                raise ValueError('Original consumer function differs: ' + name)
            source.pop('entry')
            consumers[name] = {**source, 'functions': list(required)}
            if name == 'ds_common_pb.lua':
                lines = listing(functions['0']).splitlines()[129:136]
                if not any("'SOLGameType' K11=1" in line for line in lines) or not any(
                        "'MPGameType' K13=2" in line for line in lines):
                    raise ValueError('Original MatchGameType assignments differ')
                consumers[name]['mode_instructions'] = lines
        catalog = {'mapping_status': 'verified_by_native_reflection_and_serialization',
                   'native_pe_sha256': EXPECTED_PE,
                   'sources': {name: {key: value for key, value in row.items() if key != 'rows'}
                               for name, row in by_group.items()},
                   'client_consumers': consumers,
                   'modes': {'SOLGameType': 1, 'MPGameType': 2},
                   'ranking': ranking, 'season': seasons, 'tournament': tournament,
                   'date_timezone': 'UTC+08:00',
                   'limitations': ['Installed source schedules are not an official live-service schedule.',
                       'Rank results and historical attendance are not recovered by this metadata catalog.',
                       'FText and soft object paths retain their original opaque serialized bytes.']}
        target = ROOT / 'outputs/df-local-server/protocol/native_season_catalog.json'
        target.write_text(json.dumps(catalog, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
        print('catalog', target, flush=True)


if __name__ == '__main__':
    main()
