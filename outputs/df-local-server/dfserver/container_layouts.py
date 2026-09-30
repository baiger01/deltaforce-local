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
