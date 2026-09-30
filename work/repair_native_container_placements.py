"""Move invalid legacy placements into free warehouse cells without losing items."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import sqlite3
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.container_layouts import BACKPACK_LAYOUT, CHEST_RIG_LAYOUT


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    database = ROOT / 'work/native-test-account/save.sqlite3'
    report = {'moves': [], 'unknown_layouts': [], 'applied': args.apply}
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('BEGIN IMMEDIATE')
        for player in connection.execute('SELECT id FROM players'):
            player_id = player[0]
            props = [dict(row) for row in connection.execute(
                'SELECT * FROM native_lobby_props WHERE player_id=? ORDER BY gid', (player_id,))]
            occupied = {(x, y) for row in props if row['grid_page_id'] == 2
                        for x in range(row['x'], row['x'] + row['length'])
                        for y in range(row['y'], row['y'] + row['width'])}
            for slot, position, layouts in ((107, 107001, CHEST_RIG_LAYOUT),
                                            (108, 108001, BACKPACK_LAYOUT)):
                equipped = next((row for row in props if row['grid_page_id'] == slot), None)
                layout = layouts.get(equipped['template_id'] if equipped else None)
                if not layout:
                    report['unknown_layouts'].append(equipped['template_id'] if equipped else None)
                    continue
                used = {space: set() for space in range(1, len(layout) + 1)}
                for row in (row for row in props if row['grid_page_id'] == position):
                    valid = row['x'] in used
                    if valid:
                        width, height = layout[row['x'] - 1]
                        x, y = row['y'] % width, row['y'] // width
                        cells = {(cx, cy) for cx in range(x, x + row['width'])
                                 for cy in range(y, y + row['length'])}
                        valid = (x + row['width'] <= width and y + row['length'] <= height
                                 and not cells & used[row['x']])
                        if valid:
                            used[row['x']].update(cells)
                    if valid:
                        continue
                    length, width = row['width'], row['length']
                    cells = None
                    for y in range(41 - width):
                        for x in range(10 - length):
                            candidate = {(cx, cy) for cx in range(x, x + length)
                                         for cy in range(y, y + width)}
                            if not candidate & occupied:
                                cells = candidate
                                break
                        if cells is not None:
                            break
                    if cells is None:
                        raise ValueError('No free warehouse cells for legacy repair')
                    occupied.update(cells)
                    report['moves'].append({'gid': row['gid'], 'template_id': row['template_id'],
                        'quantity': row['quantity'], 'from': [position, row['x'], row['y']],
                        'to': [2, x, y], 'length': length, 'width': width})
        if args.apply:
            backup = database.with_name(f'before-container-repair-{datetime.now():%Y%m%d-%H%M%S}.sqlite3')
            with sqlite3.connect(database) as source, sqlite3.connect(backup) as destination:
                source.backup(destination)
            report['backup'] = str(backup)
            for move in report['moves']:
                connection.execute('UPDATE native_lobby_props SET grid_page_id=2,x=?,y=?,length=?,width=? WHERE gid=?',
                    (*move['to'][1:], move['length'], move['width'], move['gid']))
                connection.execute('DELETE FROM native_lobby_prop_rotations WHERE gid=?', (move['gid'],))
        connection.commit()
    target = ROOT / 'work/evidence/native-container-placement-repair.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
