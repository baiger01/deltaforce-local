"""Collection read receipts from CollectionServer.lua 0.138 and its load callbacks.

Read acknowledgements never grant props. Pattern IDs are challenge identities,
not skin or appearance IDs; unrecovered challenge ownership is not synthesized.
"""

import sqlite3

from dfserver.gateway.client_errors import error_code
from dfserver.app.core import DomainError, fail


SUPPORTED_REQUESTS = frozenset(('CSCollectionUpdateRedPointReq',))
LOAD_FIELDS = {
    'CSCollectionLoadPropsReq': ('weapon_skin_props', 'mystical_skin_props',
                                'weapon_pendant_props', 'common_props'),
    'CSCollectionLoadMysticalSkinPropsReq': ('mystical_skin_props',),
    'CSCollectionLoadMysticalPendantPropsReq': ('mystical_pendant_props',),
    'CSCollectionUnlockAvatarsReq': ('props',),
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_collection_reads (
 player_id TEXT NOT NULL REFERENCES players(id),
 kind TEXT NOT NULL CHECK(kind IN ('prop','pattern')),
 item_id TEXT NOT NULL, item_gid TEXT NOT NULL,
 PRIMARY KEY(player_id,kind,item_id,item_gid));
CREATE TRIGGER IF NOT EXISTS native_collection_stack_arrived
AFTER INSERT ON native_lobby_collection_props BEGIN
 DELETE FROM native_lobby_collection_reads WHERE player_id=NEW.player_id
 AND kind='prop' AND item_id=CAST(NEW.template_id AS TEXT) AND item_gid='0';
END;
CREATE TRIGGER IF NOT EXISTS native_collection_stack_increased
AFTER UPDATE OF quantity ON native_lobby_collection_props WHEN NEW.quantity>OLD.quantity BEGIN
 DELETE FROM native_lobby_collection_reads WHERE player_id=NEW.player_id
 AND kind='prop' AND item_id=CAST(NEW.template_id AS TEXT) AND item_gid='0';
END;
CREATE TRIGGER IF NOT EXISTS native_collection_stack_removed
AFTER DELETE ON native_lobby_collection_props BEGIN
 DELETE FROM native_lobby_collection_reads WHERE player_id=OLD.player_id
 AND kind='prop' AND item_id=CAST(OLD.template_id AS TEXT) AND item_gid='0';
END;
CREATE TRIGGER IF NOT EXISTS native_collection_skin_arrived
AFTER INSERT ON native_lobby_gun_skins BEGIN
 DELETE FROM native_lobby_collection_reads WHERE player_id=NEW.player_id AND kind='prop'
 AND item_id=CAST(NEW.skin_id AS TEXT) AND item_gid=CAST(NEW.gid AS TEXT);
END;
CREATE TRIGGER IF NOT EXISTS native_collection_skin_removed
AFTER DELETE ON native_lobby_gun_skins BEGIN
 DELETE FROM native_lobby_collection_reads WHERE player_id=OLD.player_id AND kind='prop'
 AND item_id=CAST(OLD.skin_id AS TEXT) AND item_gid=CAST(OLD.gid AS TEXT);
END;
CREATE TRIGGER IF NOT EXISTS native_collection_pendant_arrived
AFTER INSERT ON native_lobby_pendant_instances BEGIN
 DELETE FROM native_lobby_collection_reads WHERE player_id=NEW.player_id AND kind='prop'
 AND item_id=CAST(NEW.template_id AS TEXT) AND item_gid=CAST(NEW.gid AS TEXT);
END;
CREATE TRIGGER IF NOT EXISTS native_collection_pendant_removed
AFTER DELETE ON native_lobby_pendant_instances BEGIN
 DELETE FROM native_lobby_collection_reads WHERE player_id=OLD.player_id AND kind='prop'
 AND item_id=CAST(OLD.template_id AS TEXT) AND item_gid=CAST(OLD.gid AS TEXT);
END;
"""


def _uint64(value, *, positive=False):
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        value = int(value)
    if type(value) is not int or not int(positive) <= value < 2**64:
        fail('INVALID_ARGUMENT', 'Collection identity is not a uint64')
    return value


def _owned(connection, player_id):
    from dfserver.weapons.melee_weapons import WEAPONS

    owned = {(row['template_id'], 0) for row in connection.execute(
        'SELECT template_id FROM native_lobby_collection_props '
        'WHERE player_id=? AND quantity>0', (player_id,))}
    owned.update((row['skin_id'], row['gid']) for row in connection.execute(
        'SELECT skin_id,gid FROM native_lobby_gun_skins WHERE player_id=?', (player_id,)))
    owned.update((row['template_id'], row['gid']) for row in connection.execute(
        'SELECT template_id,gid FROM native_lobby_pendant_instances WHERE player_id=?',
        (player_id,)))
    # CollectionServer receives melee skins at gid 0; deposit receiver gids differ.
    owned.update((WEAPONS[row['template_id']], 0) for row in connection.execute(
        'SELECT template_id FROM native_lobby_melee_items WHERE player_id=?', (player_id,))
        if row['template_id'] in WEAPONS)
    return owned


def update(backend, token, fields):
    props = fields.get('props', [])
    legacy = fields.get('prop_ids', [])
    patterns = fields.get('gun_skin_pattern_id', [])
    if (not all(isinstance(rows, list) for rows in (props, legacy, patterns))
            or fields.get('mystical_pendant_suit_ids')):
        fail('INVALID_ARGUMENT', 'Unsupported collection read receipt')
    requested = set()
    for prop in props:
        if not isinstance(prop, dict):
            fail('INVALID_ARGUMENT', 'Invalid collection prop identity')
        item_id = _uint64(prop.get('id', 0))
        gid = _uint64(prop.get('gid', 0))
        # The original read helper sends empty entries; its callback skips them.
        if item_id == 0 and gid == 0:
            continue
        if item_id == 0:
            fail('INVALID_ARGUMENT', 'Collection instance has no template identity')
        requested.add((item_id, gid))
    legacy_ids = {_uint64(value, positive=True) for value in legacy}
    pattern_ids = {_uint64(value, positive=True) for value in patterns}
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        owned = _owned(connection, player_id)
        if requested - owned or legacy_ids - {item_id for item_id, _ in owned}:
            fail('PROP_NOT_FOUND', 'Collection read receipt is not owned by this account')
        requested.update(pair for pair in owned if pair[0] in legacy_ids)
        connection.executemany('INSERT OR IGNORE INTO native_lobby_collection_reads '
            'VALUES (?,?,?,?)',
            ((player_id, 'prop', str(item_id), str(gid)) for item_id, gid in requested))
        # The source callback independently removes challenge-task redpoints.
        # Persist the receipt only; no pattern catalog or reward is created here.
        connection.executemany('INSERT OR IGNORE INTO native_lobby_collection_reads '
            'VALUES (?,?,?,?)',
            ((player_id, 'pattern', str(item_id), '0') for item_id in pattern_ids))
        connection.commit()
    return {'result': 0}


def with_redpoints(request_name, fields, backend, token):
    prop_fields = LOAD_FIELDS.get(request_name)
    if prop_fields is None or fields.get('result') != 0:
        return fields
    with backend.connection() as connection:
        connection.execute('BEGIN')
        player_id = backend._authorize(connection, token)
        owned = _owned(connection, player_id)
        read = {(row['kind'], int(row['item_id']), int(row['item_gid']))
                for row in connection.execute('SELECT kind,item_id,item_gid '
                    'FROM native_lobby_collection_reads WHERE player_id=?', (player_id,))}
    redpoints = {}
    for field in prop_fields:
        for prop in fields.get(field, []):
            item_id = int(prop['id'])
            gid = int(prop.get('gid') or 0)
            if (item_id, gid) in owned and ('prop', item_id, gid) not in read:
                redpoints[(item_id, gid)] = {'prop_id': item_id, 'prop_gid': gid,
                                            'num': int(prop.get('num') or 1)}
    # Keep only already supplied source-backed pattern redpoints. No guessed IDs.
    for redpoint in fields.get('redpoint_list', []):
        pattern_id = int(redpoint.get('gun_skin_pattern_id') or 0)
        if (not int(redpoint.get('prop_id') or 0) and pattern_id
                and ('pattern', pattern_id, 0) not in read):
            redpoints[('pattern', pattern_id)] = redpoint
    return {**fields, 'redpoint_list': list(redpoints.values())}


def response_fields(request, backend, token):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    try:
        return update(backend, token, request.fields)
    except sqlite3.Error:
        return {'result': error_code('CollectionSaveDBFailed')}
    except DomainError as error:
        names = {'INVALID_ARGUMENT': 'CollectionParamWorng',
                 'PROP_NOT_FOUND': 'CollectionPropNotFound'}
        if error.code not in names:
            raise
        return {'result': error_code(names[error.code])}
