"""Record public primary warehouse evidence without changing runtime/account data."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / 'work/evidence/warehouse-primary-research-20261020'


def file_ref(path):
    return {'file': path.relative_to(ROOT).as_posix(),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    catalog_path = ROOT / 'outputs/df-local-server/protocol/native_safehouse_catalog.json'
    catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
    rows = sorted((row for row in catalog['upgrades'] if row['DeviceId'] == 1010),
                  key=lambda row: row['Level'])
    assert [row['Level'] for row in rows] == list(range(1, 11))
    levels, expansion_rows, crate_slots = [], 0, 0
    for row in rows:
        effects = dict(tuple(map(int, pair.split(':'))) for pair in row['UnlockSystemList'].split(';') if pair)
        expansion_rows = effects.get(2, expansion_rows)
        crate_slots = effects.get(3, crate_slots)
        levels.append({'level': row['Level'], 'source_row': row['source_row'],
                       'serialized_offset': row['serialized_offset'],
                       'UnlockSystemList': row['UnlockSystemList'],
                       'inherited_expansion_parameter': expansion_rows,
                       'expansion_grids_using_observed_factor9': expansion_rows * 9,
                       'crate_installation_cap': crate_slots,
                       'main_grids_if_inferred_base315': 315 + expansion_rows * 9})
    assert levels[-1]['expansion_grids_using_observed_factor9'] == 144
    assert levels[-2]['expansion_grids_using_observed_factor9'] == 108
    assert [row['main_grids_if_inferred_base315'] for row in levels] == [
        315, 333, 333, 360, 360, 387, 387, 423, 423, 459]
    total_metadata = json.loads((DIRECTORY / 'bilibili-kujinxi-459-source.json').read_text(encoding='utf-8'))
    assert '459' in total_metadata['headings'][0] and '10' in total_metadata['headings'][0]
    files = {path.name: file_ref(path) for path in sorted(DIRECTORY.iterdir())
             if path.suffix in ('.png', '.json') and path.name != 'report.json'}
    report = {
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Public normal browser viewing, original creator metadata and installed '
                 'already-recovered upgrade table only. No runtime modules, local account '
                 'or installed client were changed. Bilibili viewing stayed within its '
                 'public first30second preview.',
        'mapping_status': 'primary_native_ui_and_creator_report_with_explicit_arithmetic_inference',
        'client_catalog': file_ref(catalog_path),
        'primary_sources': [
            {'id': 'pc_native_upgrade', 'kind': 'primary_creator_recorded_native_ui',
             'url': 'https://www.bilibili.com/video/BV1zzc2edEP9/',
             'author': '\u6c2a\u4eca\u897f\u6e38\u620f\u89e3\u8bf4',
             'author_url': 'https://space.bilibili.com/385785606/',
             'published_local': '2025-01-13 18:35:26', 'video_time_seconds': 0,
             'platform': 'China PC UI, inferred from desktop inventory layout',
             'build': 'not displayed or recovered',
             'observation': 'Native Lv9 to Lv10 upgrade panel shows warehouse '
                 'space+108 to+144 and installable expansion crates+8 to+9.',
             'evidence': ['bilibili-kujinxi-lv9to10-0s.png', 'bilibili-kujinxi-source.json']},
            {'id': 'mobile_native_upgrade', 'kind': 'primary_player_posted_native_ui',
             'url': 'https://www.taptap.cn/moment/748923082684501437',
             'author': 'BOOM', 'author_url': 'https://www.taptap.cn/user/9168597',
             'published_local': '2025-12-13',
             'platform': 'China mobile UI; observed signal and touch-style panels',
             'build': 'not displayed or recovered',
             'image_url': 'https://img2-tc.tapimg.com/moment/etag/Fkx7Z3tb9bA9JY-6eMl-3ZyAeXbi_20251213151243.jpg',
             'observation': 'Own-player Lv9 to Lv10 upgrade screenshot independently '
                 'shows warehouse space+108 to+144 and crate installation+8 to+9.',
             'evidence': ['taptap-boom-lv9-to10-expansion.png', 'taptap-boom-source.json']},
            {'id': 'pc_level10_total_report', 'kind': 'primary_creator_explicit_title_report',
             'url': 'https://www.bilibili.com/video/BV1G882z5EF6/',
             'author': '\u6c2a\u4eca\u897f\u6e38\u620f\u89e3\u8bf4',
             'author_url': 'https://space.bilibili.com/385785606/',
             'published_local': '2025-07-31 18:15:30',
             'platform': 'China PC own gameplay; desktop UI visible in public preview',
             'build': 'not displayed or recovered',
             'title': total_metadata['headings'][0],
             'observation': 'Creator-authored title explicitly reports459grids for '
                 'a level10warehouse. It is a creator report, not a native counter '
                 'showing459 and not an official server response.',
             'evidence': ['bilibili-kujinxi-459-title.png', 'bilibili-kujinxi-459-source.json']},
        ],
        'conclusions': {
            'direct_native_observation': 'Level9 expansion is108grids; level10 '
                'expansion is144grids. Installation caps are8 and9. The source '
                'parameters12 and16 correspond to these numbers by a factor9.',
            'cumulative_effect': 'The native transition+108 to+144 supports an '
                'absolute expansion relative to the base, not addition of every '
                'historical expansion parameter.',
            'base_inference': {'formula': '459 - 144 = 315', 'grids': 315,
                'kind': 'arithmetic_inference_combining_primary_creator_report_and_native_ui',
                'assumptions': 'The creator title459 refers to the ordinary main '
                    'warehouse total, and the separate same-creator upgrade record '
                    '+144 is its total level10 gain. No differing build or '
                    'additional permanent capacity bonus is demonstrated.'},
            'first_crate_slot': 'Installed level2 row has3:1 and level1 has no '
                'crate unlock. Thus level2 first permits one expansion crate '
                'under the recovered installation-cap effect. Individual crate '
                'purchase/ownership and any specialized predicates are separate.',
            'qualified_level_mapping': levels,
        },
        'secondary_leads_not_used_as_primary_proof': [
            {'url': 'https://news.17173.com/content/08272025/110901723.shtml',
             'date': '2025-08-27', 'note': 'Reprint attributed to a public account, '
                 'with official-style author voice; underlying original not found. '
                 'Its18/45/72/108/144numbers agree with native parameters times9.'},
            {'url': 'https://delta-force.fandom.com/wiki/Stash',
             'note': 'Unsourced community table explicitly lists base9x35=315 and '
                 'level10total459; it corroborates but is not source proof.'},
        ],
        'limitations': ['No direct original level1 counter or full35row inventory '
            'observation was recovered.', 'No official Tencent/WeGame statement '
            'giving the initial base count was located.', 'Original server '
            'configuration was not recovered.', 'Build parity with the local '
            'installed executable is not established by public footage.',
            'No runtime change is authorized or made by this research report.'],
        'evidence_files': files,
    }
    output = DIRECTORY / 'report.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(),
                      'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                      'evidence_files': len(files),
                      'inferred_main_grid_counts': [row['main_grids_if_inferred_base315'] for row in levels]}, indent=2))


if __name__ == '__main__':
    main()
