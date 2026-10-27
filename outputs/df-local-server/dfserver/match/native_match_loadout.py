"""Atomic account snapshot for a local match; no native inventory wire codec."""
from dfserver._paths import SERVER_ROOT
import hashlib
import json
from pathlib import Path

from dfserver.cosmetics.hero_customization import hero_record
from dfserver.weapons.melee_weapons import MELEE_POSITION, melee_prop

PROTOCOL = SERVER_ROOT/'protocol'
SLOT_RAW = (PROTOCOL/'deposit_slot_catalog.json').read_bytes()
SLOTS = json.loads(SLOT_RAW)['rows']
ITEM_RAW = (PROTOCOL/'game_item_catalog.json').read_bytes()
ITEMS = json.loads(ITEM_RAW)['rows']


def _validate_item(prop):
    item_id = prop.get('template_id', prop.get('id'))
    if type(item_id) is not int or str(item_id) not in ITEMS:
        raise ValueError('Carried prop has no installed GameItem definition')
    for child in prop.get('components', []):
        _validate_item(child['prop_data'])
    for bullet in prop.get('weapon', {}).get('load_bullets', []):
        _validate_item(bullet)


def snapshot(backend, token):
    from dfserver.app.core import CHEST_RIG_POSITION, BACKPACK_POSITION, SAFE_BOX_POSITION, POCKET_POSITION, KEYCHAIN_POSITION
    carried_positions = {int(k) for k, row in SLOTS.items()
        if 100 < int(k) < 139 and int(row['grid_length']) > 0 and int(row['grid_width']) > 0}
    carried_positions.update((CHEST_RIG_POSITION, BACKPACK_POSITION, SAFE_BOX_POSITION,
                              POCKET_POSITION, KEYCHAIN_POSITION))
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        backend._ensure_weapon_parts(connection, player_id)
        selected = connection.execute('SELECT hero_id FROM native_lobby_selected_heroes WHERE player_id=?',
                                      (player_id,)).fetchone()
        if selected is None:
            raise ValueError('A saved operator is required before freezing carried equipment')
        record = hero_record(connection, player_id, selected['hero_id'])
        suits = [r['id'] for r in record['fashion_equipped'] if r['slot'] == 0]
        if len(suits) != 1:
            raise ValueError('One actual equipped suit is required for the carried snapshot')
        rows = connection.execute(
            'SELECT p.gid,p.template_id,p.quantity,p.grid_page_id,p.x,p.y,p.length,p.width,'
            'COALESCE(r.rotated,0) AS rotated FROM native_lobby_props p '
            'LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
            'WHERE p.player_id=? ORDER BY p.gid', (player_id,)).fetchall()
        props = [backend._container_prop(connection, player_id, row)
                 for row in rows if row['grid_page_id'] in carried_positions]
        selected_melee = connection.execute('SELECT template_id,gid FROM native_lobby_melee_props '
                                            'WHERE player_id=?', (player_id,)).fetchone()
        selected_melee = melee_prop(dict(selected_melee), MELEE_POSITION) if selected_melee else None
        for prop in props + ([selected_melee] if selected_melee else []):
            _validate_item(prop)
        body_layouts = []
        for position in (CHEST_RIG_POSITION, BACKPACK_POSITION, SAFE_BOX_POSITION,
                         POCKET_POSITION, KEYCHAIN_POSITION):
            layout = backend._native_body_layout(connection, player_id, position)
            spaces = sorted(layout.items()) if isinstance(layout, dict) else enumerate(layout or (), 1)
            body_layouts.append(dict(business_position=position, spaces=[dict(
                business_space_id=space, width=dimensions[0], height=dimensions[1])
                for space, dimensions in spaces]))
        document = dict(kind='local_account_carried_loadout_v1',
            selected_hero_id=record['hero_id'], selected_fashion_id=suits[0], props=props,
            selected_melee=selected_melee, body_layouts=body_layouts,
            body_layout_origin='existing_verified_lobby_layout_provider',
            body_layouts_are_native_wire_values=False,
            source_slot_catalog_sha256=hashlib.sha256(SLOT_RAW).hexdigest(),
            source_item_catalog_sha256=hashlib.sha256(ITEM_RAW).hexdigest(),
            native_inventory_replication_verified=False)
        raw = (json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()
        if len(raw) > 1024*1024:
            raise ValueError('Carried equipment exceeds the bounded match snapshot size')
        connection.commit()
    return record['hero_id'], suits[0], raw
