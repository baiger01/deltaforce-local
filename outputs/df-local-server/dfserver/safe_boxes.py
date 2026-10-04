"""Verified square safety-box layouts and explicit local test permissions."""

import json
from pathlib import Path
from functools import lru_cache


EQUIPMENT_POSITION = 109
CONTENTS_POSITION = 109001
# Local account grants, not recovered official ownership or free entitlements.
LOCAL_BOX_IDS = (11090000002, 11090000004)


@lru_cache(maxsize=1)
def catalog():
    return json.loads((Path(__file__).resolve().parent.parent /
                       'protocol/safe_box_layout_catalog.json').read_text(encoding='utf-8'))


def layout(item_id):
    row = catalog()['rows'].get(str(item_id))
    if row is None or row['dimension_a'] != row['dimension_b']:
        return None
    return ((row['dimension_a'], row['dimension_b']),)


def can_store(item_id):
    from .local_commerce import installed_items
    item = installed_items().get(str(item_id))
    if item is None or not item['can_store_in_safe_box']:
        return False
    return not any(str(item_id).startswith(prefix)
                   for prefix in catalog()['contents_ignore_types'])


def permissions(connection, player_id):
    return [{'id': row['template_id'], 'gid': row['gid'], 'num': 1,
             'expire_timestamp': row['expire_timestamp']}
            for row in connection.execute(
                'SELECT * FROM native_lobby_safe_box_permissions WHERE player_id=? ORDER BY template_id',
                (player_id,))]


def position_change(item_id):
    spaces = layout(item_id)
    return {'pos_id': CONTENTS_POSITION, 'change_type': 3, 'src_prop_id': item_id,
            'space': [{'id': index, 'length': x, 'width': y}
                      for index, (x, y) in enumerate(spaces or (), 1)]}
