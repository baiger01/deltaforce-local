"""Preview explicit legacy warehouse enrollment; --apply backs up and repacks atomically."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.core import DomainError, fail
from dfserver.deposit_sort import pack_items
from dfserver import native_warehouse_growth as growth


GEOMETRY_TABLES = frozenset({'native_lobby_warehouse_geometry',
                           'native_lobby_warehouse_geometry_migrations'})
POSITION_KEYS = ('x', 'y', 'length', 'width', 'rotated')


def _open(path, *, readonly):
    mode = 'ro' if readonly else 'rw'
    connection = sqlite3.connect(path.resolve().as_uri() + '?mode=' + mode, uri=True, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    if readonly:
        connection.execute('PRAGMA query_only=ON')
    return connection


def _integrity(connection):
    if [tuple(row) for row in connection.execute('PRAGMA integrity_check')] != [('ok',)]:
        raise RuntimeError('Database integrity check failed')
    if connection.execute('PRAGMA foreign_key_check').fetchone() is not None:
        raise RuntimeError('Database contains a foreign key violation')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        default=lambda item: {'sqlite_blob_hex': item.hex()}).encode('utf-8')).hexdigest()


def _protected_state(connection):
    result = {}
    excluded = GEOMETRY_TABLES | {'native_lobby_props', 'native_lobby_prop_rotations'}
    for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        name = row[0]
        if name not in excluded and not name.startswith('sqlite_'):
            quoted = '"' + name.replace('"', '""') + '"'
            rows = sorted((tuple(item) for item in connection.execute('SELECT * FROM ' + quoted)), key=repr)
            result[name] = {'rows': len(rows), 'sha256': _digest(rows)}
    return result


def _inventory_state(connection):
    return ({row['gid']: dict(row) for row in connection.execute('SELECT * FROM native_lobby_props')},
            {row['gid']: row['rotated'] for row in connection.execute('SELECT * FROM native_lobby_prop_rotations')})


def _plan(connection, player_id):
    current = growth.main_size(connection, player_id)
    target = growth.reconstructed_size(connection, player_id)
    rows = [dict(row) for row in connection.execute(
        'SELECT p.*,COALESCE(r.rotated,0) AS rotated FROM native_lobby_props p '
        'LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
        'WHERE p.player_id=? AND p.grid_page_id=? ORDER BY p.gid',
        (player_id, growth.CATALOG['main_page_id']))]
    registered = growth._stored(connection, player_id) is not None
    result = {'player_id': player_id, 'migration_needed': not registered,
              'from_grid': list(current), 'to_grid': list(target),
              'completed_warehouse_level': growth.completed_level(connection, player_id),
              'item_count': len(rows), 'occupied_cells': sum(row['length'] * row['width'] for row in rows),
              'can_apply': True, 'before': rows, 'after': rows, 'moved_items': 0}
    if registered:
        result['status'] = 'already_explicitly_registered'
        return result
    try:
        packed = pack_items(rows, {'sort_style': 0}, grid=target)
    except DomainError as error:
        if error.code != 'WAREHOUSE_FULL':
            raise
        result.update(can_apply=False, status='packing_refused',
                      error={'code': error.code, 'message': error.message})
        return result
    after = sorted(({**row, 'rotated': int(row['rotated'])} for row in packed), key=lambda row: row['gid'])
    result.update(after=after, status='ready_for_explicit_migration', moved_items=sum(
        any(old[key] != new[key] for key in POSITION_KEYS) for old, new in zip(rows, after)))
    return result


def _plans(connection, player_ids):
    available = {row[0] for row in connection.execute('SELECT id FROM players')}
    selected = available if player_ids is None else set(player_ids)
    if not selected <= available:
        raise ValueError('Selected player does not exist in this database')
    return [_plan(connection, player_id) for player_id in sorted(selected)]


def _backup(database, backup_path):
    if backup_path is None:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup_path = database.parent / 'backups' / (
            'warehouse-before-' + stamp + '-' + uuid.uuid4().hex[:8] + '.sqlite3')
    backup_path = Path(backup_path).resolve()
    if backup_path == database.resolve():
        raise ValueError('Backup path must differ from the live database')
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    with backup_path.open('xb'):
        pass
    # A separate reader includes committed WAL data while our writer reservation
    # prevents another transaction from changing the pre-migration snapshot.
    with closing(_open(database, readonly=True)) as source:
        with closing(sqlite3.connect(backup_path)) as destination:
            source.backup(destination)
            _integrity(destination)
    with backup_path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(backup_path), 'sha256': digest, 'integrity': 'ok'}


def _apply_account(connection, plan, backup, now):
    before, after = plan['before'], plan['after']
    previous = {row['gid']: row for row in before}
    if before:
        parking_x = min(row['x'] for row in before) - len(before) - 1
        for index, row in enumerate(before):
            connection.execute('UPDATE native_lobby_props SET x=?,y=0 WHERE gid=? AND player_id=? AND grid_page_id=?',
                (parking_x - index, row['gid'], plan['player_id'], growth.CATALOG['main_page_id']))
    for row in after:
        connection.execute('UPDATE native_lobby_props SET x=?,y=?,length=?,width=? '
            'WHERE gid=? AND player_id=? AND grid_page_id=?', (row['x'], row['y'], row['length'],
            row['width'], row['gid'], plan['player_id'], growth.CATALOG['main_page_id']))
        old = previous[row['gid']]
        if row['rotated'] != old['rotated']:
            connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (?,?) '
                'ON CONFLICT(gid) DO UPDATE SET rotated=excluded.rotated', (row['gid'], row['rotated']))
    receipt = {'kind': 'explicit_geometry_migration', 'migration_id': growth.CATALOG['policy_id'],
               'backup_sha256': backup['sha256'], 'from_grid': plan['from_grid'],
               'to_grid': plan['to_grid'], 'item_count': plan['item_count'],
               'before_sha256': _digest(before), 'after_sha256': _digest(after)}
    growth.register_geometry(connection, plan['player_id'], receipt, now=now)
    connection.execute('INSERT INTO native_lobby_warehouse_geometry_migrations VALUES (?,?,?,?,?,?,?,?)',
        (plan['player_id'], growth.CATALOG['policy_id'],
         json.dumps({'grid': plan['from_grid'], 'items': before}, sort_keys=True),
         json.dumps({'grid': plan['to_grid'], 'items': after}, sort_keys=True),
         backup['path'], backup['sha256'], growth.CATALOG_SHA256, now))


def _verify_inventory(connection, initial, plans):
    old_props, old_rotations = initial
    new_props, new_rotations = _inventory_state(connection)
    allowed = {row['gid'] for plan in plans if plan['migration_needed'] for row in plan['before']}
    expected = {row['gid']: row for plan in plans if plan['migration_needed'] for row in plan['after']}
    if set(old_props) != set(new_props):
        raise RuntimeError('Migration changed the saved physical item identities')
    for gid, old in old_props.items():
        new = new_props[gid]
        if gid not in allowed:
            if old != new or old_rotations.get(gid) != new_rotations.get(gid):
                raise RuntimeError('Migration changed an item outside the selected main warehouses')
            continue
        if any(old[key] != new[key] for key in old if key not in POSITION_KEYS):
            raise RuntimeError('Migration changed item ownership, template, quantity or page')
        old_shape = (old['length'], old['width'])
        new_shape = (new['length'], new['width'])
        if old_rotations.get(gid, 0):
            old_shape = old_shape[::-1]
        if new_rotations.get(gid, 0):
            new_shape = new_shape[::-1]
        if (old_shape != new_shape or new_rotations.get(gid, 0) != expected[gid]['rotated']
                or any(new[key] != expected[gid][key] for key in POSITION_KEYS[:-1])):
            raise RuntimeError('Migration changed an item shape or diverged from its preview')
    if set(new_rotations) - set(old_rotations) - allowed:
        raise RuntimeError('Migration created an unrelated rotation record')


def migrate(database, *, apply=False, player_ids=None, backup_path=None):
    database = Path(database).resolve()
    if not database.is_file():
        raise ValueError('Database must be an existing saved-account file')
    backup = None
    with closing(_open(database, readonly=not apply)) as connection:
        try:
            connection.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
            _integrity(connection)
            plans = _plans(connection, player_ids)
            can_apply = all(plan['can_apply'] for plan in plans)
            report = {'mode': 'read_only_preview', 'database': str(database), 'can_apply': can_apply,
                      'policy_id': growth.CATALOG['policy_id'],
                      'provenance_kind': 'primary_creator_arithmetic_not_official_server_recovery',
                      'accounts': plans}
            if not apply:
                return report
            if not can_apply:
                fail('WAREHOUSE_FULL', 'At least one selected main warehouse cannot fit; no accounts migrated')
            pending = [plan for plan in plans if plan['migration_needed']]
            if not pending:
                return {**report, 'mode': 'applied', 'backup': None, 'invariants_verified': True}
            backup = _backup(database, backup_path)
            protected, inventory = _protected_state(connection), _inventory_state(connection)
            # executescript would commit the reserved transaction before schema DDL.
            for statement in growth.SCHEMA.split(';'):
                if statement.strip():
                    connection.execute(statement)
            now = int(time.time())
            for plan in pending:
                _apply_account(connection, plan, backup, now)
            _verify_inventory(connection, inventory, pending)
            if _protected_state(connection) != protected:
                raise RuntimeError('Migration changed components, currencies, quests or another protected table')
            _integrity(connection)
            connection.commit()
            return {**report, 'mode': 'applied', 'backup': backup, 'invariants_verified': True}
        except BaseException as error:
            connection.rollback()
            if backup is not None:
                error.warehouse_backup = backup
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', nargs='?', type=Path,
                        default=ROOT / 'work/native-test-account/save.sqlite3')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--player-id', action='append', dest='player_ids')
    parser.add_argument('--backup-path', type=Path)
    args = parser.parse_args()
    try:
        result = migrate(args.database, apply=args.apply, player_ids=args.player_ids, backup_path=args.backup_path)
    except (DomainError, sqlite3.Error, ValueError, TypeError, KeyError, RuntimeError, OSError, OverflowError) as error:
        result = {'mode': 'refused', 'error': {'code': getattr(error, 'code', type(error).__name__),
                                             'message': str(error)}}
        if getattr(error, 'warehouse_backup', None):
            result['backup'] = error.warehouse_backup
        print(json.dumps(result, indent=2))
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
