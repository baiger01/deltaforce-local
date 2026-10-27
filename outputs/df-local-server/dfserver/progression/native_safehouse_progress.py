"""Original safehouse build costs, submitted materials and durable upgrade timers.

SafeHouseUpgrade: PAK entry 7072 at 50353481, SHA-256 a512e06581e890be
ccbc03d57fac4960d53647b0f2a0f14e1e5078f0a9a6def2. BlackSiteServer.lua
69389419f7b0fb5e3b993c2e65fa2b46f659e3e50c3cf2f375d94d519f6ae890:
0.10/0.11 submit physical props, then request an upgrade and update its device.
BlackSiteDevice.lua d1a05e46806f6498e8d680f4838d5b443b24cc821cf8337e591
ea73deec5aa1b: 0.4/0.28 enforce level, device, reputation and quest conditions;
0.63 separates the currency cost from partially submitted physical materials.
0.52 consumes UnlockSystemList as completed-level effects, not prerequisites.
BlackSiteConditions.lua 0.10 sets material bindType=-1, accepting either binding;
0.11.0 warns before an unbound submission without changing its eligibility.
BlackSiteLogic.lua 0714dac13ab758e14b4d63775d2f6f95fadacaf592a8262269f
82205817f8265: 0.21 examines effects from levels 1 through the completed level.
common_pb.lua 81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415
a0473b40350b: root PCs 2239-2279 binds SystemUnlockID, including repair ID 15.
InventoryServer_Network.lua d7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5
e459231b9eb6ec17dcb0dc: 0.8.0 unlocks repair from a matching response entry,
even when its inner params are empty. An unearned entry must be omitted.
"""
from dfserver._paths import SERVER_ROOT

import json
from pathlib import Path
import sqlite3
import time

from dfserver.gateway.client_errors import error_code
from dfserver.app.core import DomainError, fail
from dfserver.commerce.premium_shop import ITEMS, currency_change


CATALOG = json.loads((SERVER_ROOT /
                     'protocol/native_safehouse_catalog.json').read_text(encoding='utf-8'))
UPGRADES = {(row['DeviceId'], row['Level']): row for row in CATALOG['upgrades']}
DEVICE_IDS = frozenset(device_id for device_id, level in UPGRADES)
MAX_LEVELS = {device_id: max(level for ident, level in UPGRADES if ident == device_id)
              for device_id in DEVICE_IDS}
SUPPORTED_REQUESTS = frozenset({'CSSafehouseSubmitUpgradePropReq', 'CSSafehouseUpgradeReq',
                              'CSSafehouseFuncIsUnlockReq'})
# This is an old diagnostic fingerprint, not a client configuration or ID map.
LEGACY_MAX_SIGNATURE = {1001: 6, 1002: 3, 1003: 7, 1004: 7, 1005: 3,
                        1006: 3, 1007: 3, 1010: 10, 1014: 3, 1017: 2}
MIGRATION_ID = 'retire_candidate_safehouse_max_v1'
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_safehouse_accounts (
 player_id TEXT PRIMARY KEY REFERENCES players(id), initialized_at INTEGER NOT NULL,
 source_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS native_lobby_safehouse_materials (
 player_id TEXT NOT NULL REFERENCES players(id), device_id INTEGER NOT NULL,
 target_level INTEGER NOT NULL, prop_id INTEGER NOT NULL, curr_count INTEGER NOT NULL CHECK(curr_count>0),
 PRIMARY KEY(player_id,device_id,target_level,prop_id));
CREATE TABLE IF NOT EXISTS native_lobby_safehouse_upgrades (
 player_id TEXT NOT NULL REFERENCES players(id), device_id INTEGER NOT NULL,
 target_level INTEGER NOT NULL, start_time INTEGER NOT NULL, end_time INTEGER NOT NULL,
 PRIMARY KEY(player_id,device_id));
CREATE TABLE IF NOT EXISTS native_lobby_safehouse_upgrade_history (
 player_id TEXT NOT NULL REFERENCES players(id), device_id INTEGER NOT NULL,
 level INTEGER NOT NULL, start_time INTEGER NOT NULL, completed_at INTEGER NOT NULL,
 PRIMARY KEY(player_id,device_id,level));
CREATE TABLE IF NOT EXISTS native_lobby_safehouse_migrations (
 player_id TEXT NOT NULL REFERENCES players(id), migration_id TEXT NOT NULL,
 applied_at INTEGER NOT NULL, snapshot_json TEXT NOT NULL, source_sha256 TEXT NOT NULL,
 PRIMARY KEY(player_id,migration_id));
"""


def _pairs(value, separator=';'):
    result = {}
    for entry in value.split(separator):
        if not entry:
            continue
        ident, amount = map(int, entry.split(':'))
        if ident <= 0 or amount <= 0 or ident in result:
            fail('SafehouseLoadCfgFailed', 'Original safehouse requirement is invalid or duplicated')
        result[ident] = amount
    return result


def initial_levels():
    """Local bootstrap completes only free, immediate first builds in the source.

    An absent saved row means unbuilt level zero. The client server's official
    account initialization is unavailable; paid or timed first builds are never
    granted. No description text or guessed facility name controls these levels.
    """
    return {device_id: 1 for (device_id, level), row in UPGRADES.items()
            if level == 1 and not _pairs(row['ItemList']) and row['Time'] == 0
            and row['SeasonLevel'] <= 1 and not any(row[name] for name in
                ('TaskList', 'DeviceList', 'QualityList', 'SafeHouseDegree'))}


def _initialized(connection, player_id):
    return connection.execute('SELECT 1 FROM native_lobby_safehouse_accounts WHERE player_id=?',
                              (player_id,)).fetchone() is not None


def initialize(connection, player_id, now):
    if not _initialized(connection, player_id):
        _validate_catalog()
        connection.execute('INSERT INTO native_lobby_safehouse_accounts VALUES (?,?,?)',
            (player_id, now, CATALOG['sources']['upgrades']['sha256']))
        connection.executemany('INSERT OR IGNORE INTO native_lobby_devices VALUES (?,?,?)',
                               [(player_id, ident, level) for ident, level in initial_levels().items()])


def _validate_catalog():
    if (CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization'
            or len(UPGRADES) != len(CATALOG['upgrades'])):
        fail('SafehouseLoadCfgFailed', 'Original safehouse upgrade table is unavailable')


def _level(connection, player_id, device_id):
    row = connection.execute('SELECT level FROM native_lobby_devices WHERE player_id=? AND device_id=?',
                             (player_id, device_id)).fetchone()
    return row['level'] if row else 0


def _next_row(connection, player_id, device_id):
    _validate_catalog()
    if device_id not in DEVICE_IDS:
        fail('SafehouseDeviceNotFound', 'Device is absent from the installed upgrade table')
    level = _level(connection, player_id, device_id)
    if level == MAX_LEVELS[device_id]:
        fail('SafehouseDeviceMaxLevel', 'Device has reached its original maximum level')
    row = UPGRADES.get((device_id, level + 1))
    if row is None:
        fail('SafehouseLoadCfgFailed', 'Saved device level is outside the original upgrade sequence')
    return row


def finish_due(connection, player_id, now):
    for pending in connection.execute('SELECT * FROM native_lobby_safehouse_upgrades '
        'WHERE player_id=? AND end_time<=? ORDER BY device_id', (player_id, now)).fetchall():
        row = _next_row(connection, player_id, pending['device_id'])
        if row['Level'] != pending['target_level']:
            fail('SafehouseSaveDeviceLevelUpFail', 'Pending upgrade no longer matches its saved predecessor')
        connection.execute('INSERT INTO native_lobby_devices VALUES (?,?,?) '
            'ON CONFLICT(player_id,device_id) DO UPDATE SET level=excluded.level',
            (player_id, row['DeviceId'], row['Level']))
        connection.execute('INSERT INTO native_lobby_safehouse_upgrade_history VALUES (?,?,?,?,?)',
            (player_id, row['DeviceId'], row['Level'], pending['start_time'], pending['end_time']))
        connection.execute('DELETE FROM native_lobby_safehouse_upgrades WHERE player_id=? AND device_id=?',
                           (player_id, row['DeviceId']))
        connection.execute('DELETE FROM native_lobby_safehouse_materials WHERE player_id=? AND device_id=?',
                           (player_id, row['DeviceId']))


def material_infos(connection, player_id, device_id, level):
    row = UPGRADES.get((device_id, level + 1))
    if row is None:
        return []
    submitted = dict(connection.execute('SELECT prop_id,curr_count FROM native_lobby_safehouse_materials '
        'WHERE player_id=? AND device_id=? AND target_level=?', (player_id, device_id, level + 1)).fetchall())
    return [{'prop_id': ident, 'curr_count': submitted.get(ident, 0), 'require_count': count}
            for ident, count in _pairs(row['ItemList']).items()]


def device_infos(connection, player_id):
    from dfserver.progression.native_safehouse import _info
    owned = {row['device_id']: row['level'] for row in connection.execute(
        'SELECT device_id,level FROM native_lobby_devices WHERE player_id=? ORDER BY device_id', (player_id,))}
    identifiers = sorted(DEVICE_IDS | owned.keys()) if _initialized(connection, player_id) else list(owned)
    devices = []
    for device_id in identifiers:
        level = owned.get(device_id, 0)
        device = {'device_id': device_id, 'level': level, 'upgrade_end_time': 0, 'upgrade_level': 0,
                  'upgrade_prop_list': material_infos(connection, player_id, device_id, level)}
        pending = connection.execute('SELECT * FROM native_lobby_safehouse_upgrades '
            'WHERE player_id=? AND device_id=?', (player_id, device_id)).fetchone()
        if pending:
            device.update(upgrade_end_time=pending['end_time'], upgrade_level=pending['target_level'])
        line = connection.execute('SELECT * FROM native_lobby_safehouse_production '
            'WHERE player_id=? AND device_id=?', (player_id, device_id)).fetchone()
        if line is not None:
            device['produce_line'] = _info(line)
        devices.append(device)
    return devices


def prepare_query(connection, player_id, now):
    if not connection.execute('SELECT 1 FROM native_lobby_devices WHERE player_id=? LIMIT 1',
                              (player_id,)).fetchone():
        initialize(connection, player_id, now)
    finish_due(connection, player_id, now)


def _unlock_info(connection, player_id, fields):
    """Serialize earned source tuples without inventing effect aggregation.

    The remote aggregator is unavailable. This local policy preserves one entry
    per original effect, in source order, including every parameter after its
    unlock ID. Neither the latest value nor a sum is inferred. The actual repair
    consumer only needs the single 15:2 grant at device 1011 level 2 (row 14,
    serialized offset 8357). A zero or unknown query never grants a capability.
    """
    _validate_catalog()
    unlock_id = int(fields.get('unlock_id') or 0)
    levels = {row['device_id']: row['level'] for row in connection.execute(
        'SELECT device_id,level FROM native_lobby_devices WHERE player_id=?', (player_id,))}
    if any(level != 0 and (device_id, level) not in UPGRADES for device_id, level in levels.items()):
        fail('SafehouseLoadCfgFailed', 'Saved device level has no original unlock configuration')
    params = []
    for row in CATALOG['upgrades']:
        if row['Level'] > levels.get(row['DeviceId'], 0):
            continue
        for entry in row['UnlockSystemList'].split(';'):
            if not entry:
                continue
            values = [int(value) for value in entry.split(':')]
            if len(values) < 2 or any(value <= 0 for value in values):
                fail('SafehouseLoadCfgFailed', 'Original safehouse unlock tuple is invalid')
            if values[0] == unlock_id:
                params.append({'unlock_id': values[0], 'params': values[1:]})
    return {'result': 0, 'params': params}


def _conditions(connection, player_id, row, curve=None):
    from dfserver.progression import native_department_queries
    from dfserver.progression import native_departments
    from dfserver.progression import native_quests
    season = connection.execute('SELECT level FROM native_lobby_levels WHERE player_id=?',
                                (player_id,)).fetchone()
    if (season['level'] if season else 1) < row['SeasonLevel']:
        fail('SafehouseSeasonLevelConditionFail', 'Original action-level condition is not satisfied')
    for ident, level in _pairs(row['DeviceList']).items():
        if _level(connection, player_id, ident) < level:
            fail('SafehouseDeviceConditionIneligible', 'Original prerequisite facility level is not satisfied')
    qualities = _pairs(row['QualityList'])
    if qualities:
        try:
            verified_curve = (native_department_queries.reputation_curve() if curve is None else
                              curve if isinstance(curve, native_department_queries.RepLevelCurve) else
                              native_department_queries.RepLevelCurve(curve))
        except (OSError, ValueError, TypeError):
            fail('SafehousePlayerQualityConditionFail', 'A verified department reputation curve is required')
        for ident, level in qualities.items():
            if ident not in native_departments.DEPARTMENTS:
                fail('SafehousePlayerQualityConditionFail', 'Original department relation is unavailable')
            value = connection.execute('SELECT value FROM native_lobby_department_values '
                'WHERE player_id=? AND quality_id=?', (player_id, ident)).fetchone()
            if verified_curve.level_for(value['value'] if value else 0) < level:
                fail('SafehousePlayerQualityConditionFail', 'Original department reputation level is not satisfied')
    for entry in row['TaskList'].split(','):
        if entry:
            task = connection.execute('SELECT state FROM native_lobby_quest_progress '
                'WHERE player_id=? AND quest_id=?', (player_id, int(entry))).fetchone()
            if task is None or task['state'] < native_quests.COMPLETED:
                fail('SafehousePreTaskConditionFail', 'Original prerequisite quest is not completed')
    if row['SafeHouseDegree']:
        fail('SafehouseDegreeNotEnough', 'This source row needs a separately recovered degree predicate')


def _pending(connection, player_id, device_id):
    if connection.execute('SELECT 1 FROM native_lobby_safehouse_upgrades WHERE player_id=? AND device_id=?',
                          (player_id, device_id)).fetchone():
        fail('SafehouseDeviceIsUpgrading', 'An original upgrade timer is already running')


def _submit(connection, player_id, fields):
    device_id = int(fields.get('device_id') or 0)
    row = _next_row(connection, player_id, device_id)
    _pending(connection, player_id, device_id)
    required = _pairs(row['ItemList'])
    submitted = {item['prop_id']: item['curr_count'] for item in
                 material_infos(connection, player_id, device_id, row['Level'] - 1)}
    entries = fields.get('submit_prop_list', [])
    if not entries:
        fail('SafehouseSubmitInvalidProp', 'Submission has no physical material instances')
    seen = set()
    for entry in entries:
        ident, gid, count = (int(entry.get(key) or 0) for key in ('id', 'gid', 'num'))
        if (ident not in required or ITEMS.get(str(ident), {}).get('is_currency')
                or not 0 < gid < 2**63 or count <= 0 or gid in seen):
            fail('SafehouseSubmitInvalidProp', 'Submitted instance is duplicated or is not an original physical cost')
        seen.add(gid)
        if submitted.get(ident, 0) + count > required[ident]:
            fail('SafehouseSubmitOverCountProp', 'Submitted amount exceeds the remaining original cost')
        owned = connection.execute('SELECT * FROM native_lobby_props WHERE player_id=? AND gid=?',
                                   (player_id, gid)).fetchone()
        if owned is not None:
            from dfserver.inventory.native_warehouse_extensions import require_uninstalled_box
            require_uninstalled_box(connection, player_id, gid)
        if (owned is None or owned['template_id'] != ident or owned['quantity'] < count
                or int(entry.get('position') or 0) not in (0, owned['grid_page_id'])
                or owned['grid_page_id'] in (107, 108, 109, 116)):
            fail('SafehouseSubmitInvalidProp', 'Submitted instance differs from its actual owned inventory state')
        if count == owned['quantity']:
            connection.execute('DELETE FROM native_lobby_props WHERE player_id=? AND gid=?', (player_id, gid))
        else:
            connection.execute('UPDATE native_lobby_props SET quantity=quantity-? WHERE player_id=? AND gid=?',
                               (count, player_id, gid))
        submitted[ident] = submitted.get(ident, 0) + count
        connection.execute('INSERT INTO native_lobby_safehouse_materials VALUES (?,?,?,?,?) '
            'ON CONFLICT(player_id,device_id,target_level,prop_id) DO UPDATE SET curr_count=excluded.curr_count',
            (player_id, device_id, row['Level'], ident, submitted[ident]))
    return {'result': 0, 'device_id': device_id,
            'upgrade_prop_list': material_infos(connection, player_id, device_id, row['Level'] - 1)}


def _upgrade(connection, player_id, fields, now, changes, curve):
    device_id = int(fields.get('device_id') or 0)
    row = _next_row(connection, player_id, device_id)
    _pending(connection, player_id, device_id)
    _conditions(connection, player_id, row, curve)
    for material in material_infos(connection, player_id, device_id, row['Level'] - 1):
        ident, count = material['prop_id'], material['require_count']
        if ITEMS.get(str(ident), {}).get('is_currency'):
            changes['currency_changes'].append(currency_change(connection, player_id, ident, -count))
        elif material['curr_count'] != count:
            fail('SafehouseDelMaterialFail', 'Original physical costs have not been completely submitted')
    if row['Time'] < 0:
        fail('SafehouseLoadCfgFailed', 'Original upgrade duration is invalid')
    connection.execute('INSERT INTO native_lobby_safehouse_upgrades VALUES (?,?,?,?,?)',
                       (player_id, device_id, row['Level'], now, now + row['Time']))
    finish_due(connection, player_id, now)
    device = next(item for item in device_infos(connection, player_id) if item['device_id'] == device_id)
    return {'result': 0, 'device': device}


def response_fields(request, backend, token, *, changes=None, curve=None, diagnostic=None):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    from dfserver.progression.native_safehouse import _snapshot
    committed = {'currency_changes': []}
    try:
        with backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            now = int(time.time())
            if request.name == 'CSSafehouseFuncIsUnlockReq':
                prepare_query(connection, player_id, now)
                result = _unlock_info(connection, player_id, request.fields)
                connection.commit()
                return result
            initialize(connection, player_id, now)
            finish_due(connection, player_id, now)
            before = _snapshot(backend, connection, player_id)
            result = (_submit(connection, player_id, request.fields)
                      if request.name == 'CSSafehouseSubmitUpgradePropReq' else
                      _upgrade(connection, player_id, request.fields, now, committed, curve))
            after = _snapshot(backend, connection, player_id)
            committed['inventory_moves'] = [{'before': before.get(gid), 'after': after.get(gid)}
                for gid in sorted(before.keys() | after.keys()) if before.get(gid) != after.get(gid)]
            connection.commit()
        if changes is not None:
            changes.update(committed)
        return result
    except DomainError as error:
        if diagnostic is not None:
            diagnostic['local_activity_error'] = {'code': error.code, 'message': error.message[:160]}
        return {'result': error_code(error.code) if error.code.startswith('Safehouse') else
                error_code('SafehouseDelMaterialFail' if error.code == 'INSUFFICIENT_FUNDS' else 'SafehouseSaveDBFail')}
    except (sqlite3.Error, ValueError, TypeError, KeyError) as error:
        if diagnostic is not None:
            diagnostic['local_activity_error'] = {'code': 'SafehouseSaveDBFail',
                'message': 'Safehouse progress transaction could not be saved', 'kind': type(error).__name__}
        return {'result': error_code('SafehouseSaveDBFail')}


def migration_preview(connection, player_id):
    before = {row['device_id']: row['level'] for row in connection.execute(
        'SELECT device_id,level FROM native_lobby_devices WHERE player_id=? ORDER BY device_id', (player_id,))}
    if connection.execute('SELECT 1 FROM native_lobby_safehouse_migrations WHERE player_id=? AND migration_id=?',
                          (player_id, MIGRATION_ID)).fetchone():
        reason = 'already_migrated'
    elif before != LEGACY_MAX_SIGNATURE:
        reason = 'different_profile'
    elif any(connection.execute('SELECT 1 FROM ' + table + ' WHERE player_id=? LIMIT 1', (player_id,)).fetchone()
             for table in ('native_lobby_safehouse_production', 'native_lobby_safehouse_materials',
                           'native_lobby_safehouse_upgrades', 'native_lobby_safehouse_upgrade_history')):
        reason = 'preserve_saved_production_or_upgrade_progress'
    else:
        reason = 'exact_legacy_candidate_signature'
    return {'eligible': reason == 'exact_legacy_candidate_signature', 'reason': reason,
            'before': before, 'after': initial_levels()}


def migrate_legacy_max_profile(connection, player_id, now):
    """Explicit caller-owned transaction after a complete save backup and review.

    No startup or account query invokes this function. Inventory and currency are
    retained; active production or any real upgrade progress prevents migration.
    Warehouse geometry is an independent existing local policy and is untouched.
    """
    if not connection.in_transaction:
        raise ValueError('Legacy safehouse migration requires an explicit caller transaction')
    preview = migration_preview(connection, player_id)
    if not preview['eligible']:
        return preview
    _validate_catalog()
    source = CATALOG['sources']['upgrades']['sha256']
    connection.execute('INSERT INTO native_lobby_safehouse_migrations VALUES (?,?,?,?,?)',
                       (player_id, MIGRATION_ID, now, json.dumps(preview, sort_keys=True), source))
    connection.execute('DELETE FROM native_lobby_devices WHERE player_id=?', (player_id,))
    connection.execute('DELETE FROM native_lobby_safehouse_accounts WHERE player_id=?', (player_id,))
    initialize(connection, player_id, now)
    return preview
