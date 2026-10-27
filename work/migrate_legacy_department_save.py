"""Preview or archive and retire the exact deprecated forced-maximum profile."""

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
from dfserver import native_safehouse, native_safehouse_progress as progress


def open_readonly(path):
    connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def previews(connection):
    return [{'player_id': row['id'], **progress.migration_preview(connection, row['id'])}
            for row in connection.execute('SELECT id FROM players ORDER BY id')]


def protected_state(connection):
    allowed = {'native_lobby_devices', 'native_lobby_safehouse_accounts',
               'native_lobby_safehouse_migrations'}
    result = {}
    for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        name = row['name']
        if name not in allowed and not name.startswith('sqlite_'):
            quoted = '"' + name.replace('"', '""') + '"'
            result[name] = sorted((tuple(item) for item in connection.execute('SELECT * FROM ' + quoted)),
                                  key=repr)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup-directory', type=Path)
    args = parser.parse_args()
    if not args.database.is_file():
        parser.error('database must be an existing saved account database')
    with closing(open_readonly(args.database)) as source:
        if not args.apply:
            with sqlite3.connect(':memory:') as copy:
                source.backup(copy)
                copy.row_factory = sqlite3.Row
                copy.executescript(native_safehouse.SCHEMA)
                print(json.dumps({'mode': 'read_only_preview', 'profiles': previews(copy)}, indent=2))
            return
        folder = args.backup_directory or args.database.parent / 'backups'
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup = folder / f'department-before-migration-{stamp}-{uuid.uuid4().hex[:8]}.sqlite3'
        with sqlite3.connect(backup) as destination:
            source.backup(destination)
            if destination.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('The complete account backup failed its integrity check')
    with backup.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    with sqlite3.connect(args.database, timeout=15) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
        connection.executescript(native_safehouse.SCHEMA)
        connection.execute('BEGIN IMMEDIATE')
        protected = protected_state(connection)
        foreign_keys = list(connection.execute('PRAGMA foreign_key_check'))
        results = []
        for row in connection.execute('SELECT id FROM players ORDER BY id').fetchall():
            results.append({'player_id': row['id'], **progress.migrate_legacy_max_profile(
                connection, row['id'], int(time.time()))})
        if protected_state(connection) != protected:
            raise RuntimeError('Migration changed saved state outside facility levels and migration audit')
        if list(connection.execute('PRAGMA foreign_key_check')) != foreign_keys:
            raise RuntimeError('Migration changed foreign key integrity')
        connection.commit()
    print(json.dumps({'mode': 'applied_exact_signature_only', 'backup': str(backup.resolve()),
                      'backup_sha256': digest, 'profiles': results}, indent=2))


if __name__ == '__main__':
    main()
