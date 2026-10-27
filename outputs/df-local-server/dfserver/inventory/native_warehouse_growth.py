"""Qualified warehouse capacity, with explicit enrollment and legacy preservation.

Base315 is primary-creator arithmetic, not recovered official server data. Native
upgrade effects supply the latest completed expansion, never a sum. Read helpers
do not finish timers, change inventory/currency or enroll existing accounts.
"""
from dfserver._paths import SERVER_ROOT

from functools import lru_cache
import hashlib
import json
from pathlib import Path
import time

from dfserver.app.core import fail


PROTOCOL = SERVER_ROOT / 'protocol'
CATALOG_PATH = PROTOCOL / 'native_warehouse_growth_catalog.json'
CATALOG = json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
CATALOG_SHA256 = hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest()
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_warehouse_geometry (
 player_id TEXT PRIMARY KEY REFERENCES players(id), base_rows INTEGER NOT NULL CHECK(base_rows>0),
 provenance_json TEXT NOT NULL, migration_receipt_json TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS native_lobby_warehouse_geometry_migrations (
 player_id TEXT NOT NULL REFERENCES players(id), migration_id TEXT NOT NULL,
 before_json TEXT NOT NULL, after_json TEXT NOT NULL, backup_path TEXT NOT NULL,
 backup_sha256 TEXT NOT NULL, catalog_sha256 TEXT NOT NULL, applied_at INTEGER NOT NULL,
 PRIMARY KEY(player_id,migration_id));
"""


@lru_cache(maxsize=1)
def _validated_levels():
    source = json.loads((PROTOCOL / CATALOG['native_upgrade_source']['catalog']).read_text(encoding='utf-8'))
    if (CATALOG['mapping_status'] != 'native_upgrade_effects_and_primary_creator_arithmetic'
            or CATALOG['official_server_configuration_recovered'] is not False
            or CATALOG['base_provenance']['kind'] != 'primary_creator_arithmetic'
            or (CATALOG['grid_columns'], CATALOG['base_rows']) != (9, 35)
            or source['mapping_status'] != CATALOG['native_upgrade_source']['mapping_status']
            or source['sources']['upgrades']['sha256'] != CATALOG['native_upgrade_source']['sha256']):
        fail('DepositInvalidReq', 'Qualified warehouse growth provenance is unavailable')
    rows = {row['Level']: row for row in source['upgrades']
            if row['DeviceId'] == CATALOG['warehouse_device_id']}
    levels, expansion = {}, 0
    for configured in CATALOG['levels']:
        level = configured['level']
        row = rows.get(level)
        if row is None or any(row[key] != configured[key] for key in
                ('source_row', 'serialized_offset', 'UnlockSystemList')):
            fail('DepositInvalidReq', 'Warehouse effect differs from the original upgrade table')
        for pair in row['UnlockSystemList'].split(';'):
            if pair:
                kind, value = map(int, pair.split(':'))
                if kind == CATALOG['expansion_effect_id']:
                    expansion = value
        if expansion != configured['expansion_rows']:
            fail('DepositInvalidReq', 'Warehouse cumulative effect disagrees with its source')
        levels[level] = expansion
    if set(levels) != set(rows):
        fail('DepositInvalidReq', 'Warehouse growth levels are incomplete')
    return levels


def completed_level(connection, player_id):
    row = connection.execute('SELECT level FROM native_lobby_devices WHERE player_id=? AND device_id=?',
                             (player_id, CATALOG['warehouse_device_id'])).fetchone()
    level = row[0] if row else 1
    if type(level) is not int or level not in _validated_levels():
        fail('DepositInvalidReq', 'Saved completed warehouse level is outside the source table')
    return level


def reconstructed_size(connection, player_id):
    """Preview target dimensions independently of an account's legacy enrollment."""
    return CATALOG['grid_columns'], CATALOG['base_rows'] + _validated_levels()[completed_level(connection, player_id)]


def _stored(connection, player_id):
    if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                              "AND name='native_lobby_warehouse_geometry'").fetchone():
        return None
    row = connection.execute('SELECT base_rows,provenance_json,migration_receipt_json '
        'FROM native_lobby_warehouse_geometry WHERE player_id=?', (player_id,)).fetchone()
    return row


def main_size(connection, player_id):
    saved = _stored(connection, player_id)
    if saved is None:
        return CATALOG['grid_columns'], CATALOG['legacy_compatibility_rows']
    provenance, receipt = json.loads(saved[1]), json.loads(saved[2])
    if (saved[0] != CATALOG['base_rows'] or provenance.get('kind') != 'primary_creator_arithmetic'
            or provenance.get('policy_id') != CATALOG['policy_id']
            or receipt.get('kind') not in ('new_account_registration', 'explicit_geometry_migration')):
        fail('DepositInvalidReq', 'Saved warehouse geometry lacks explicit qualified enrollment')
    return reconstructed_size(connection, player_id)


def register_geometry(connection, player_id, receipt, *, now=None):
    """Persist metadata only; callers must own a new-account or migration transaction."""
    _validated_levels()
    if receipt.get('kind') not in ('new_account_registration', 'explicit_geometry_migration'):
        fail('DepositInvalidReq', 'Warehouse enrollment requires an explicit registration receipt')
    provenance = {**CATALOG['base_provenance'], 'policy_id': CATALOG['policy_id'],
                  'catalog_sha256': CATALOG_SHA256}
    connection.execute('INSERT INTO native_lobby_warehouse_geometry VALUES (?,?,?,?,?)',
        (player_id, CATALOG['base_rows'], json.dumps(provenance, sort_keys=True),
         json.dumps(receipt, sort_keys=True), int(time.time()) if now is None else now))


def initialize_new_player(connection, player_id):
    """Call only during creation of a genuinely new player, never a login/bootstrap."""
    if _stored(connection, player_id) is None:
        register_geometry(connection, player_id, {'kind': 'new_account_registration',
                                               'policy_id': CATALOG['policy_id']})
