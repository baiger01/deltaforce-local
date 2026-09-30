"""Repair legacy preset roots using the installed default receiver catalog."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.local_commerce import installed_items
from dfserver.weapon_components import PRESETS, ROWS


def cells(row):
    return {(x, y) for x in range(row['x'], row['x'] + row['length'])
            for y in range(row['y'], row['y'] + row['width'])}


def plan_repairs(props, rotations, grid):
    catalog = installed_items()
    targets = [row for row in props if row['template_id'] in PRESETS]
    target_gids = {row['gid'] for row in targets}
    occupied = {cell for row in props
                if row['grid_page_id'] == 2 and row['gid'] not in target_gids
                for cell in cells(row)}
    repairs = []
    for row in targets:
        receiver = PRESETS[row['template_id']]
        definition = catalog[str(receiver)]
        length, width = definition['length'], definition['width']
        if rotations.get(row['gid']):
            length, width = width, length
        updated = {**row, 'template_id': receiver, 'length': length, 'width': width}
        if row['grid_page_id'] == 2:
            fits = (0 <= row['x'] <= grid['grid_length'] - length
                    and 0 <= row['y'] <= grid['grid_width'] - width
                    and not cells(updated) & occupied)
            if not fits:
                for y in range(grid['grid_width'] - width + 1):
                    for x in range(grid['grid_length'] - length + 1):
                        updated.update(x=x, y=y)
                        if not cells(updated) & occupied:
                            break
                    else:
                        continue
                    break
                else:
                    raise ValueError('Warehouse has no room for the verified receiver footprint')
            occupied.update(cells(updated))
        elif row['grid_page_id'] not in (111, 112, 114):
            raise ValueError('Legacy gun in a body container needs a separate placement review')
        repairs.append({'before': row, 'after': updated,
                        'receiver_item_offset': definition['serialized_uexp_offset'],
                        'preset_node_offsets': ROWS[str(receiver)]['node_offsets']})
    return repairs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    database = ROOT / 'work/native-test-account/save.sqlite3'
    protocol = ROOT / 'outputs/df-local-server/protocol'
    grid = json.loads((protocol / 'deposit_slot_catalog.json').read_text(encoding='utf-8'))['rows']['2']
    report = {'applied': args.apply, 'repairs': [], 'sources': {}}
    for name in ('weapon_component_catalog.json', 'game_item_catalog.json', 'deposit_slot_catalog.json'):
        source = protocol / name
        report['sources'][name] = hashlib.sha256(source.read_bytes()).hexdigest()
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('BEGIN IMMEDIATE')
        props = [dict(row) for row in connection.execute('SELECT * FROM native_lobby_props ORDER BY gid')]
        rotations = dict(connection.execute('SELECT gid,rotated FROM native_lobby_prop_rotations'))
        for player_id in {row['player_id'] for row in props}:
            report['repairs'].extend(plan_repairs(
                [row for row in props if row['player_id'] == player_id], rotations, grid))
        if args.apply and report['repairs']:
            backup = database.with_name(f'before-weapon-root-repair-{datetime.now():%Y%m%d-%H%M%S}.sqlite3')
            with sqlite3.connect(database) as source, sqlite3.connect(backup) as destination:
                source.backup(destination)
            report['backup'] = str(backup)
            for repair in report['repairs']:
                row = repair['after']
                connection.execute(
                    'UPDATE native_lobby_props SET template_id=?,length=?,width=?,x=?,y=? WHERE gid=?',
                    (row['template_id'], row['length'], row['width'], row['x'], row['y'], row['gid']))
        connection.commit()
    target = ROOT / 'work/evidence/native-weapon-root-repair.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
