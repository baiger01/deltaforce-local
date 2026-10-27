"""Persist explicit native PropInfo binding without rewriting legacy defaults.

native_quest_objectives.json records common_pb.lua 0, PCs 512-520:
BindingBinded=0, BindingNotBind=1, BindingTeammate=2. ItemBase.lua 0.2,
PCs 13-14 and SetRawPropInfo 0.12, PCs 28-37 establish the omitted (1, 0)
default. Source hashes and extracted instructions remain in that catalog.
"""


SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_prop_bindings (
 gid INTEGER PRIMARY KEY REFERENCES native_lobby_props(gid) ON DELETE CASCADE,
 bind_type INTEGER NOT NULL CHECK(bind_type IN (0,1,2)),
 bind_player INTEGER NOT NULL CHECK(bind_player>=0));
CREATE TABLE IF NOT EXISTS native_lobby_loaded_bullet_bindings (
 gid INTEGER PRIMARY KEY REFERENCES native_lobby_weapon_bullets(gid) ON DELETE CASCADE,
 bind_type INTEGER NOT NULL CHECK(bind_type IN (0,1,2)),
 bind_player INTEGER NOT NULL CHECK(bind_player>=0));
"""

OMITTED_BINDING = (1, 0)


def snapshot_binding(prop):
    """Keep the same native binding pair when freezing a match loadout."""
    present = {'bind_type', 'bind_player'} & prop.keys()
    if not present:
        return OMITTED_BINDING
    if present != {'bind_type', 'bind_player'}:
        raise ValueError('An explicit snapshot binding requires both fields')
    kind, player = prop['bind_type'], prop['bind_player']
    if type(kind) is not int or kind not in (0, 1, 2):
        raise ValueError('Invalid snapshot binding type')
    if type(player) is not int or not 0 <= player < 1 << 63:
        raise ValueError('Invalid snapshot binding player')
    return kind, player


def validate_binding(bind_type, bind_player=0):
    from dfserver.app.core import integer
    return (integer(bind_type, 'bind_type', 0, 2),
            integer(bind_player, 'bind_player', 0, 2**63 - 1))


def _table(loaded):
    return 'native_lobby_loaded_bullet_bindings' if loaded else 'native_lobby_prop_bindings'


def persisted_fields(connection, gid, *, loaded=False):
    from dfserver.app.core import integer
    integer(gid, 'gid', 1, 2**63 - 1)
    row = connection.execute(f'SELECT bind_type,bind_player FROM {_table(loaded)} WHERE gid=?',
                             (gid,)).fetchone()
    return {} if row is None else {'bind_type': row[0], 'bind_player': row[1]}


def binding(connection, gid, *, loaded=False):
    fields = persisted_fields(connection, gid, loaded=loaded)
    return (fields['bind_type'], fields['bind_player']) if fields else OMITTED_BINDING


def set_binding(connection, gid, bind_type, bind_player=0, *, loaded=False):
    from dfserver.app.core import integer
    integer(gid, 'gid', 1, 2**63 - 1)
    values = validate_binding(bind_type, bind_player)
    connection.execute(f'INSERT INTO {_table(loaded)} VALUES (?,?,?) '
        'ON CONFLICT(gid) DO UPDATE SET bind_type=excluded.bind_type,bind_player=excluded.bind_player',
        (gid, *values))
