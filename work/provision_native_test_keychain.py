"""Back up and explicitly provide a verified keychain to the preserved test account."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.core import Backend
from dfserver import native_keycards


def verify_native_response(backend, token, template_id):
    from dfserver.gcp_data import decode_data_frame
    from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_deposit_response
    codec, key = _candidate_codec(), b'0123456789abcdef'
    request = b'ABCD' + codec.encode('CSDepositGetPropsReq', {}, sequence=71)
    frame = _candidate_local_deposit_response(request, backend, token, key,
                                             header_word4=1, header_word9=71)
    fields = codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                            compression_method=1).messages[0]).fields
    slots = {row['position']: row for row in fields['equiped_props']}
    expected = native_keycards.grid_spaces(template_id)
    if (fields['result'] != 0 or int(slots[116]['load_props'][0]['id']) != template_id or
            slots[116001]['grid_space'] != expected or
            slots[116001]['capacity'] != sum(space['base_cnt'] for space in expected)):
        raise ValueError('Actual native inventory response does not match the persisted source keychain')
    return {'native_response_verified': True, 'map_ids': [space['id'] for space in expected]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--template-id', type=int, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    database = ROOT / 'work/native-test-account/save.sqlite3'
    if not database.is_file():
        raise ValueError('The preserved local test database is missing')
    spaces = native_keycards.grid_spaces(args.template_id)
    with sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True) as source:
        accounts = source.execute('SELECT player_id FROM accounts').fetchall()
        if len(accounts) != 1:
            raise ValueError('This tool requires exactly one preserved local test account')
        selected = source.execute('SELECT template_id FROM native_lobby_props '
            'WHERE player_id=? AND grid_page_id=116', (accounts[0][0],)).fetchall()
        if selected and selected != [(args.template_id,)]:
            raise ValueError('An existing different keychain must be changed through the native equip transaction')
        summary = {'template_id': args.template_id, 'spaces': len(spaces),
                   'base_slots': sum(space['base_cnt'] for space in spaces), 'applied': False}
        if not args.apply:
            print(json.dumps(summary))
            return
        backups = ROOT / 'work/native-test-account/backups'
        backups.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup = backups / ('before-keychain-' + stamp + '.sqlite3')
        with sqlite3.connect(backup) as destination:
            source.backup(destination)
    backend = Backend(database, ROOT / 'outputs/df-local-server/definitions.json')
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        token = backend._new_session(connection, accounts[0][0])['session']
        connection.commit()
    try:
        backend.ensure_native_lobby_keychains(token, template_ids=[args.template_id],
                                             selected_template_id=args.template_id)
        profile = backend.native_lobby_profile(token)
        if (len([row for row in profile['props'] if row['grid_page_id'] == 116]) != 1 or
                not profile.get('keychain_permissions')):
            raise ValueError('Persisted keychain permission/equipment verification failed')
        summary.update(verify_native_response(backend, token, args.template_id))
        summary.update(applied=True, backup=backup.relative_to(ROOT).as_posix())
        print(json.dumps(summary))
    finally:
        backend.logout(token)


if __name__ == '__main__':
    main()
