"""Source-bound local production with durable materials, timing and claims."""
from dfserver._paths import SERVER_ROOT

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time

from dfserver.gateway.client_errors import error_code, inventory_error
from dfserver.app.core import DomainError, fail
from dfserver.commerce.premium_shop import ITEMS
from dfserver.weapons.weapon_components import PRESETS, ROWS
from dfserver.inventory import native_prop_bindings
from dfserver.progression import native_safehouse_progress


PROTOCOL = SERVER_ROOT / 'protocol'
CATALOG = json.loads((PROTOCOL / 'native_safehouse_catalog.json').read_text(encoding='utf-8'))
QUEST_WEAPON_PRESETS = json.loads((PROTOCOL / 'native_quest_weapon_presets_catalog.json').read_text(
    encoding='utf-8'))['presets']
FORMULAS = {row['Id']: row for row in CATALOG['formulas']}
DEVICE_IDS = frozenset(row['DeviceId'] for row in CATALOG['upgrades'])
SUPPORTED_REQUESTS = frozenset({'CSSafehouseProduceReq', 'CSSafehouseReceiveAwardReq',
                              'CSSafehouseGetInfoReq', 'CSSafehouseGetPlayerDeviceReq'}) | native_safehouse_progress.SUPPORTED_REQUESTS
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_safehouse_production (
 player_id TEXT NOT NULL, device_id INTEGER NOT NULL, formula_id INTEGER NOT NULL,
 start_time INTEGER NOT NULL, end_time INTEGER NOT NULL, products_json TEXT NOT NULL,
 materials_json TEXT NOT NULL, PRIMARY KEY(player_id,device_id),
 FOREIGN KEY(player_id,device_id) REFERENCES native_lobby_devices(player_id,device_id) ON DELETE CASCADE);
""" + native_safehouse_progress.SCHEMA


def _items(value):
    items = {}
    for part in value.split(';'):
        if not part:
            continue
        item, count = part.split(':')
        item, count = int(item), int(count)
        if item <= 0 or count <= 0 or str(item) not in ITEMS:
            fail('SafehouseInvalidFormula', 'Recipe references an unavailable native item')
        items[item] = items.get(item, 0) + count
    return [{'prop_id': item, 'num': count, 'bind_type': 0} for item, count in items.items()]


def _physical_product(item_id):
    # ItemBase.GetSize resolves presets to their receivers before reading size.
    quest_preset = QUEST_WEAPON_PRESETS.get(str(item_id))
    receiver_id = quest_preset['receiver_id'] if quest_preset else PRESETS.get(item_id, item_id)
    metadata = ITEMS[str(receiver_id)]
    if receiver_id != item_id:
        source = quest_preset or ROWS.get(str(receiver_id))
        if (source is None or source['preset_id'] != item_id or
                source['prop']['id'] != receiver_id or
                (source['prop']['length'], source['prop']['width']) !=
                (metadata['length'], metadata['width'])):
            fail('SafehouseInvalidFormula', 'Source preset has no verified physical component tree')
    if metadata['max_stack_count'] == 0:
        # ItemBase.lua 0.11 PCs 151-160; source witness in the quest preset catalog.
        metadata = {**metadata, 'max_stack_count': 1}
    if (metadata['length'] < 1 or metadata['width'] < 1 or
            not 1 <= metadata['max_stack_count'] <= 1000):
        fail('SafehouseInvalidFormula', 'Source product has no supported warehouse layout')
    return receiver_id, metadata


def _formula_timestamp(value):
    return int(datetime.strptime(value, '%Y-%m-%d %H:%M:%S').replace(
        tzinfo=timezone(timedelta(hours=8))).timestamp())


def _info(row):
    return {'formula_id': row['formula_id'], 'device_id': row['device_id'],
            'start_time': row['start_time'], 'end_time': row['end_time'],
            'pause_remain_time': 0, 'products': json.loads(row['products_json'])}


def device_infos(connection, player_id):
    return native_safehouse_progress.device_infos(connection, player_id)


def _snapshot(backend, connection, player_id):
    backend._ensure_weapon_parts(connection, player_id)
    rows = connection.execute('SELECT p.*,COALESCE(r.rotated,0) AS rotated '
        'FROM native_lobby_props p LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
        'WHERE p.player_id=? ORDER BY p.gid', (player_id,)).fetchall()
    return {row['gid']: backend._container_prop(connection, player_id, row) for row in rows}


def _device(connection, player_id, device_id):
    if device_id not in DEVICE_IDS:
        fail('SafehouseDeviceNotFound', 'Device is absent from the installed table')
    row = connection.execute('SELECT level FROM native_lobby_devices WHERE player_id=? AND device_id=?',
                             (player_id, device_id)).fetchone()
    if row is None:
        fail('SafehouseDeviceInfoNotFound', 'This local account does not own the device')
    return row


def _consume(connection, player_id, materials):
    """Consume source materials inside the caller transaction, retaining installed boxes."""
    from dfserver.inventory.native_warehouse_extensions import require_uninstalled_box
    plans = []
    for material in materials:
        rows = connection.execute('SELECT p.gid,p.quantity FROM native_lobby_props p '
            'WHERE p.player_id=? AND p.template_id=? AND NOT EXISTS '
            '(SELECT 1 FROM native_lobby_warehouse_extensions e WHERE e.box_gid=p.gid) '
            'ORDER BY p.gid', (player_id, material['prop_id'])).fetchall()
        if sum(row['quantity'] for row in rows) < material['num']:
            fail('SafehouseDelMaterialFail', 'Owned uninstalled material quantity is insufficient')
        plans.append((material, rows))
    for material, rows in plans:
        remaining = material['num']
        for row in rows:
            require_uninstalled_box(connection, player_id, row['gid'])
            take = min(remaining, row['quantity'])
            if take == row['quantity']:
                connection.execute('DELETE FROM native_lobby_props WHERE player_id=? AND gid=?',
                                   (player_id, row['gid']))
            else:
                connection.execute('UPDATE native_lobby_props SET quantity=quantity-? WHERE player_id=? AND gid=?',
                                   (take, player_id, row['gid']))
            remaining -= take
            if not remaining:
                break


def _produce(connection, player_id, fields, now):
    device_id, formula_id = int(fields.get('device_id') or 0), int(fields.get('formula_id') or 0)
    device = _device(connection, player_id, device_id)
    formula = FORMULAS.get(formula_id)
    if formula is None:
        fail('SafehouseFormulaNotFound', 'Formula is absent from the installed table')
    if formula['DeviceId'] != device_id:
        fail('SafehouseFormulaNotInDevice', 'Formula belongs to a different native device')
    if device['level'] < formula['Level']:
        fail('SafehouseDeviceConditionIneligible', 'Owned device level is below the source recipe requirement')
    if connection.execute('SELECT 1 FROM native_lobby_safehouse_production WHERE player_id=? AND device_id=?',
                          (player_id, device_id)).fetchone():
        fail('SafehouseProducingFormula', 'An existing production must be claimed first')
    for key, is_start in (('StartTime', True), ('EndTime', False)):
        if formula[key]:
            stamp = _formula_timestamp(formula[key])
            if (is_start and now < stamp) or (not is_start and now > stamp):
                fail('SafehouseFormulaNotInTime', 'The original recipe availability window is closed')
    if formula['UnlockSystemList']:
        fail('SafehouseBlueprintLocked', 'Recipe requires a separately verified blueprint/leader unlock')
    if (formula['WeightProductList'] or formula['MaxLoopTimes'] or formula['Type'] or
            formula['bDisassemble'] or formula['IsBind'] or formula['Time'] < 0):
        fail('SafehouseInvalidFormula', 'This recipe needs an additional source-bound production path')
    materials, products = _items(formula['MaterialList']), _items(formula['ProductList'])
    if not products:
        fail('SafehouseInvalidFormula', 'Source recipe has no deterministic product')
    for product in products:
        _physical_product(product['prop_id'])
    # InventoryServer.GetItemNumById defaults to the Player inventory group.
    _consume(connection, player_id, materials)
    end = now + formula['Time']
    connection.execute('INSERT INTO native_lobby_safehouse_production VALUES (?,?,?,?,?,?,?)',
        (player_id, device_id, formula_id, now, end, json.dumps(products), json.dumps(materials)))
    return {'result': 0, 'device_id': device_id, 'produce_info': {
        'formula_id': formula_id, 'device_id': device_id, 'start_time': now, 'end_time': end,
        'pause_remain_time': 0, 'products': products}}


def _grant_products(backend, connection, player_id, products, *, preserve_binding=False):
    from dfserver.inventory.native_warehouse_extensions import warehouse_grid
    grid_length, grid_width = warehouse_grid(connection, player_id, 2)
    granted = []
    for product in products:
        quest_preset = QUEST_WEAPON_PRESETS.get(str(product['prop_id']))
        item_id, metadata = _physical_product(product['prop_id'])
        product = {**product, 'prop_id': item_id}
        product_binding = (native_prop_bindings.validate_binding(product['bind_type'],
            product.get('bind_player', 0)) if preserve_binding else native_prop_bindings.OMITTED_BINDING)
        length, width, maximum = metadata['length'], metadata['width'], metadata['max_stack_count']
        remaining = product['num']
        for row in connection.execute('SELECT gid,quantity FROM native_lobby_props '
                'WHERE player_id=? AND template_id=? AND grid_page_id=2 ORDER BY gid',
                (player_id, product['prop_id'])).fetchall():
            if native_prop_bindings.binding(connection, row['gid']) != product_binding:
                continue
            added = min(remaining, maximum - row['quantity'])
            if added > 0:
                connection.execute('UPDATE native_lobby_props SET quantity=quantity+? WHERE gid=? AND player_id=?',
                                   (added, row['gid'], player_id))
                if preserve_binding:
                    native_prop_bindings.set_binding(connection, row['gid'], *product_binding)
                granted.append({**product, 'num': added, 'gid': row['gid']})
                remaining -= added
            if not remaining:
                break
        while remaining:
            occupied = set()
            for row in connection.execute('SELECT x,y,length,width FROM native_lobby_props '
                                          'WHERE player_id=? AND grid_page_id=2', (player_id,)):
                occupied.update((x, y) for x in range(row['x'], row['x'] + row['length'])
                                for y in range(row['y'], row['y'] + row['width']))
            location = next(((x, y) for y in range(grid_width - width + 1)
                for x in range(grid_length - length + 1)
                if not occupied.intersection((cx, cy) for cx in range(x, x + length)
                                             for cy in range(y, y + width))), None)
            if location is None:
                fail('WAREHOUSE_FULL', 'No room for the actual safehouse product')
            gid = backend._next_native_prop_gid(connection)
            if gid >= 2**63 - 1:
                fail('SafehouseSaveDBFail', 'Local physical prop ID range is exhausted')
            count = min(remaining, maximum)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (gid, player_id, product['prop_id'], count, 2, *location, length, width))
            if preserve_binding:
                native_prop_bindings.set_binding(connection, gid, *product_binding)
            if quest_preset:
                def insert_components(parent_gid, components):
                    for component in components:
                        part_gid = backend._next_native_prop_gid(connection)
                        child = component['prop_data']
                        connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)',
                            (part_gid, gid, parent_gid, component['slot'], child['id']))
                        insert_components(part_gid, child['components'])
                insert_components(gid, quest_preset['prop']['components'])
                connection.execute('INSERT INTO native_lobby_assembled_weapons VALUES (?)', (gid,))
            granted.append({**product, 'num': count, 'gid': gid})
            remaining -= count
    return granted


def _claim(backend, connection, player_id, fields, now):
    device_id = int(fields.get('device_id') or 0)
    _device(connection, player_id, device_id)
    row = connection.execute('SELECT * FROM native_lobby_safehouse_production WHERE player_id=? AND device_id=?',
                             (player_id, device_id)).fetchone()
    if row is None or now < row['end_time']:
        fail('SafehouseProduceNotFinish', 'No completed local production is ready')
    items = _grant_products(backend, connection, player_id, json.loads(row['products_json']))
    connection.execute('DELETE FROM native_lobby_safehouse_production WHERE player_id=? AND device_id=?',
                       (player_id, device_id))
    return {'result': 0, 'device_id': device_id, 'items': items, 'produce_list': [],
            'loop_produce_list': [], 'favorite_formula_ids': []}


def response_fields(request, backend, token, *, changes=None, curve=None, diagnostic=None):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    if request.name in native_safehouse_progress.SUPPORTED_REQUESTS:
        return native_safehouse_progress.response_fields(request, backend, token, changes=changes,
                                                         curve=curve, diagnostic=diagnostic)
    writing = request.name in ('CSSafehouseProduceReq', 'CSSafehouseReceiveAwardReq')
    try:
        with backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            if not writing:
                native_safehouse_progress.prepare_query(connection, player_id, int(time.time()))
                devices = device_infos(connection, player_id)
                device_id = int(request.fields.get('device_id') or 0)
                if device_id:
                    devices = [row for row in devices if row['device_id'] == device_id]
                connection.commit()
                if request.name == 'CSSafehouseGetInfoReq':
                    return {'result': 0, 'devices': devices,
                            'upgraded_device_list': [row['device_id'] for row in devices if row['level'] > 0],
                            'is_safehouse_unlocked': any(row['level'] > 0 for row in devices)}
                return {'result': 0, 'device_infos': devices}
            if CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization':
                fail('SafehouseLoadCfgFailed', 'Native formula bindings are unavailable')
            native_safehouse_progress.finish_due(connection, player_id, int(time.time()))
            before = _snapshot(backend, connection, player_id)
            now = int(time.time())
            result = (_produce(connection, player_id, request.fields, now)
                      if request.name == 'CSSafehouseProduceReq' else
                      _claim(backend, connection, player_id, request.fields, now))
            after = _snapshot(backend, connection, player_id)
            moves = [{'before': before.get(gid), 'after': after.get(gid)}
                     for gid in sorted(before.keys() | after.keys()) if before.get(gid) != after.get(gid)]
            connection.commit()
        if changes is not None:
            changes['inventory_moves'] = moves
        return result
    except DomainError as error:
        if diagnostic is not None:
            diagnostic['local_activity_error'] = {'code': error.code, 'message': error.message[:160]}
        return {'result': error_code(error.code) if error.code.startswith('Safehouse') else
                inventory_error(error) if error.code == 'WAREHOUSE_FULL' else error_code('SafehouseSaveDBFail')}
    except (sqlite3.Error, ValueError, TypeError, KeyError) as error:
        code = 'SafehouseSaveDBFail' if writing else 'SafehouseLoadDBFail'
        if diagnostic is not None:
            diagnostic['local_activity_error'] = {'code': code,
                'message': 'Safehouse transaction could not be completed', 'kind': type(error).__name__}
        return {'result': error_code(code)}
