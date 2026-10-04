"""Container dimensions recovered from installed client table exports."""

import json
from pathlib import Path


SOURCE = Path(__file__).resolve().parent.parent / 'protocol/container_layout_catalog.json'
ROWS = json.loads(SOURCE.read_text(encoding='utf-8'))['rows']
CHEST_RIG_LAYOUT = {int(item_id): tuple(map(tuple, row['layout']))
                    for item_id, row in ROWS.items() if row['kind'] == 'chest_rig'}
BACKPACK_LAYOUT = {int(item_id): tuple(map(tuple, row['layout']))
                  for item_id, row in ROWS.items() if row['kind'] == 'backpack'}


def capacity(item_id):
    return ROWS.get(str(item_id), {}).get('capacity', 0)


def position_changes(props, moves):
    affected = {row['grid_page_id'] for move in moves
                for row in (move.get('before'), move.get('after'))
                if row and row['grid_page_id'] in (107, 108)}
    equipped = {row['grid_page_id']: row['template_id'] for row in props
                if row['grid_page_id'] in affected}
    changes = []
    for slot in sorted(affected):
        item_id = equipped.get(slot, 0)
        layout = (CHEST_RIG_LAYOUT if slot == 107 else BACKPACK_LAYOUT).get(item_id, ())
        changes.append({'pos_id': slot * 1000 + 1, 'change_type': 3,
                        'src_prop_id': item_id,
                        'space': [{'id': index, 'length': x, 'width': y}
                                  for index, (x, y) in enumerate(layout, 1)]})
    return changes
