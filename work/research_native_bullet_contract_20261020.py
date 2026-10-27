"""Record installed-client bullet operation evidence without changing the save."""

import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'work'))
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))

from lua53_reader import Reader, listing, walk
from dfserver import weapon_ammo
from extract_weapon_ammo_catalog import indexed_rows


FUNCTIONS = {
    'InventoryLogic.lua': ['0.5'],
    'ItemOperaTool.lua': ['0.49', '0.50', '0.51'],
    'GunsmithAmmoLogic.lua': ['0.0', '0.1', '0.2', '0.3'],
    'WeaponAssemblyTool.lua': ['0.63', '0.64', '0.67', '0.68', '0.69',
                               '0.71', '0.71.1', '0.72'],
    'QuickOperationLogic.lua': ['0.4', '0.4.1', '0.4.2', '0.4.3',
                               '0.7', '0.7.0', '0.7.1', '0.8', '0.8.0'],
    'GunsmithServer.lua': ['0.29', '0.29.0'],
}
GUNS = [(6400000000000000415, 18060000011),
        (6400000000000000059, 18010000006)]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    sources = []
    for name, ids in FUNCTIONS.items():
        path = ROOT / 'work/evidence/weapon_lua' / name
        functions = [dict(function=f['id'], offset=f['offset'],
                          original_source_lines=[f['first_line'], f['last_line']],
                          disassembly=listing(f).splitlines())
                     for f in walk(Reader(path.read_bytes(),
                                          allow_client_format1=True).function())
                     if f['id'] in ids]
        assert len(functions) == len(ids), name
        sources.append(dict(path=str(path.relative_to(ROOT)), sha256=digest(path),
                            functions=functions))

    database = ROOT / 'work/native-test-account/save.sqlite3'
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA query_only=ON')
    connection.execute('BEGIN')
    snapshot = []
    for gid, template_id in GUNS:
        gun = dict(connection.execute(
            'SELECT * FROM native_lobby_props WHERE gid=?', (gid,)).fetchone())
        assert gun['template_id'] == template_id
        parts = [dict(row) for row in connection.execute(
            'SELECT * FROM native_lobby_weapon_parts WHERE weapon_gid=? ORDER BY gid',
            (gid,))]
        loaded = [dict(row) for row in connection.execute(
            'SELECT * FROM native_lobby_weapon_bullets WHERE weapon_gid=? ORDER BY rowid',
            (gid,))]
        components = [{'prop_data': {'id': row['template_id'], 'components': []}}
                      for row in parts]
        capacity = weapon_ammo.magazine_capacity(components, template_id)
        snapshot.append(dict(gun=gun, parts=parts, loaded=loaded,
                             loaded_count=sum(row['quantity'] for row in loaded),
                             installed_capacity=capacity,
                             source_receiver=weapon_ammo.CATALOG['weapons'][str(template_id)],
                             source_magazines={str(row['template_id']):
                                 weapon_ammo.CATALOG['magazines'][str(row['template_id'])]
                                 for row in parts if str(row['template_id']) in
                                 weapon_ammo.CATALOG['magazines']}))
    loose_gids = (6400000000000000420, 6400000000000000421,
                  6400000000000000468, 6400000000000000255)
    loose = [dict(row) for row in connection.execute(
        'SELECT * FROM native_lobby_props WHERE gid IN (?,?,?,?) ORDER BY gid',
        loose_gids)]
    snapshot_utc = connection.execute("SELECT datetime('now')").fetchone()[0]
    connection.rollback()
    connection.close()

    weapons, weapon_source = indexed_rows(4489, 331, 177, 373)
    for row in snapshot:
        assert weapons[str(row['gun']['template_id'])] == row['source_receiver']

    log = ROOT / 'work/elevated-native-trials/1792475824236698400.log'
    requests = []
    for line_number, line in enumerate(log.read_text(encoding='utf-8').splitlines(), 1):
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if (event.get('request_name') == 'CSDepositOperateBulletReq' and
                event.get('phase') == 'processed'):
            requests.append(dict(line=line_number, event=event))

    report = {
        'status': 'installed_client_contract_and_read_only_save_observation',
        'official_server_algorithm_recovered': False,
        'database_read_only': True,
        'snapshot_utc': snapshot_utc,
        'scope': 'Live trial bullet failures; no runtime or save changes.',
        'observed_requests': requests,
        'observed_guns': snapshot,
        'observed_loose_stacks': loose,
        'source_weapon_attribute_table': weapon_source,
        'source_catalog': dict(
            path='outputs/df-local-server/protocol/weapon_ammo_catalog.json',
            sha256=digest(ROOT / 'outputs/df-local-server/protocol/weapon_ammo_catalog.json'),
            sources=weapon_ammo.CATALOG['sources']),
        'findings': [
            {
                'claim': 'Drag load transmits the dragged stack count, clamped to the whole magazine capacity.',
                'evidence': ['InventoryLogic.lua 0.5 PCs 45-54',
                             'ItemOperaTool.lua 0.49 PCs 10-21',
                             'GunsmithAmmoLogic.lua 0.2 PCs 155-158'],
                'qualification': 'The count is an attempted incremental load budget, not a verified target-final-count field. The client does not subtract already-loaded rounds here.',
            },
            {
                'claim': 'Client virtual batch counting adds load quantities and saturates at capacity.',
                'evidence': ['GunsmithAmmoLogic.lua 0.3 PCs 13-25'],
                'qualification': 'This proves client saturation bookkeeping. It does not recover how the official server handles excess requested rounds or full-magazine different-ammo drags.',
            },
            {
                'claim': 'Ordinary drag has no implicit unload command before its single load request.',
                'evidence': ['ItemOperaTool.lua 0.49', 'GunsmithAmmoLogic.lua 0.0',
                             'GunsmithServer.lua 0.29'],
                'qualification': 'No client-side ammo replacement is present in this path; official server-side replacement cannot be inferred from its absence.',
            },
            {
                'claim': 'Explicit unload-all iterates the native load_bullets array using ipairs and submits each entry id/gid/num as unload.',
                'evidence': ['ItemOperaTool.lua 0.50 PCs 16-50'],
                'qualification': 'Array order is retained; no reverse traversal. This does not establish in-match firing order.',
            },
            {
                'claim': 'Quick ammo configuration unloads player weapon rounds first and waits for a successful response before proceeding through move, buy/carry and load steps.',
                'evidence': ['QuickOperationLogic.lua 0.4 PCs 24-29',
                             'QuickOperationLogic.lua 0.7 and 0.7.0',
                             'QuickOperationLogic.lua 0.7.1 PCs 1-9',
                             'QuickOperationLogic.lua 0.4.3',
                             'QuickOperationLogic.lua 0.4.2',
                             'QuickOperationLogic.lua 0.4.1 PCs 11-22',
                             'QuickOperationLogic.lua 0.8.0'],
            },
            {
                'claim': 'The two installed capacities are 5 and 30, and current save rounds exactly fill them.',
                'evidence': ['WeaponAssemblyTool.lua 0.68 and 0.69',
                             'WeaponAttributeTable recId 18060000011: WeaponClipAmmoCount 5 at byte 238596',
                             'WeaponAttributeTable recId 18010000006: WeaponClipAmmoCount 30 at byte 65579',
                             'Magazine 13120000283: function 150283, row 3930, GMagCapacity 5',
                             'Magazine 13120000302: function 150302, row 3876, GMagCapacity 30',
                             'observed_guns'],
            },
        ],
        'current_service_mismatch': {
            'path': 'outputs/df-local-server/dfserver/core.py',
            'function': 'Backend.native_lobby_operate_bullets',
            'lines_at_observation': [1448, 1450],
            'behavior': 'Rejects the entire load when loaded_count + requested_count exceeds capacity.',
            'assessment': 'Stricter than the installed client drag request builder and its saturating virtual counter. This is the immediate cause of all five observed capacity failures.',
        },
        'minimal_qualified_local_policy_suggestion': {
            'load': 'Transfer min(requested_count, owned_stack_count, capacity - loaded_count), preserving existing round types and bindings. A full magazine is a no-transfer success with no inventory mutation.',
            'change_ammo': 'Use explicit unload-then-load, preserving the source unload order. Do not silently eject or destroy previously paid ammunition.',
            'qualification': 'Operational reconstruction consistent with observed client arithmetic, not a recovered official server algorithm. Full-magazine implicit ammo replacement remains unproven.',
            'related_validation': 'Validate ownership, weapon/ammo compatibility and verified capacity before no-op handling; transaction remains atomic across the command batch.',
        },
        'sources': sources,
    }
    destination = ROOT / 'work/evidence/native-bullet-contract-20261020.json'
    destination.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(destination), sha256=digest(destination),
                         snapshot_utc=snapshot_utc, requests=len(requests),
                         guns=[dict(gid=row['gun']['gid'], loaded=row['loaded_count'],
                                    capacity=row['installed_capacity']) for row in snapshot]),
                     indent=2))


if __name__ == '__main__':
    main()
