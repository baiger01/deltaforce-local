"""Recover contents only with the former equipment IDs recorded in the trial."""

import argparse
from contextlib import closing
from datetime import datetime
import json
from pathlib import Path
import sqlite3
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.core import Backend


def recover(database, templates):
    backend = Backend(database, ROOT / 'outputs/df-local-server/definitions.json')
    with backend.connection() as connection:
        accounts = connection.execute('SELECT player_id FROM accounts').fetchall()
        if len(accounts) != 1:
            raise ValueError('Recovery requires exactly one preserved local test account')
        session = backend._new_session(connection, accounts[0]['player_id'])['session']
        connection.commit()
    try:
        moves = backend.native_lobby_recover_orphaned_containers(
            session, original_templates=templates)
        return [{'gid': move['after']['gid'], 'id': move['after']['template_id'],
                 'num': move['after']['quantity'],
                 'from': move['before']['grid_page_id'], 'to': move['after']['grid_page_id']}
                for move in moves]
    finally:
        backend.logout(session)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--chest-template', type=int, required=True)
    parser.add_argument('--backpack-template', type=int, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    database = ROOT / 'work/native-test-account/save.sqlite3'
    templates = {107: args.chest_template, 108: args.backpack_template}
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    with tempfile.TemporaryDirectory() as temporary:
        preview = Path(temporary) / 'preview.sqlite3'
        with closing(sqlite3.connect(database)) as source, closing(sqlite3.connect(preview)) as destination:
            source.backup(destination)
        moves = recover(preview, templates)
    report = {'applied': False, 'former_templates': templates, 'moves': moves}
    if args.apply:
        backup = ROOT / f'work/evidence/before-orphan-recovery-{stamp}.sqlite3'
        with closing(sqlite3.connect(database)) as source, closing(sqlite3.connect(backup)) as destination:
            source.backup(destination)
        report['moves'] = recover(database, templates)
        report.update(applied=True, backup=str(backup))
    target = ROOT / f'work/evidence/orphan-recovery-{stamp}.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'applied': report['applied'], 'moved_stacks': len(report['moves']),
                      'report': str(target)}))


if __name__ == '__main__':
    main()
