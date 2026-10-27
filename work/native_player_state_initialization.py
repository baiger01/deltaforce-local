"""Build local PlayerState references from rechecked same-build field metadata.

The official snapshot supplies the class identity, never account values, Actor
GUIDs or its private flags. GUIDs below come only from the current local manifests.
"""
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_manifest import CLIENT_SHA256
from dfserver.legacy_ds_rep_layout_refs import ObjectReference

SPEC_PATH = 'work/evidence/map-entry-next-20261006/initial-player-state-reference-profiles.json'
SPEC_SHA256 = '0e4a85eaa197b830ca66adf7648df91147332be0e29a0476a007ae29e831d520'
PLAYER_STATE_PATH = '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C'
FIELDS = (('BP_DFMPlayerController_C', 0x378), ('BP_DFMCharacter_C', 0x390))


def _read(root, relative, expected):
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('PlayerState source is missing or outside its bound')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('PlayerState source SHA256 mismatch')
    return raw


def _spec(raw):
    document = json.loads(raw)
    if (document.get('kind') != 'source_qualified_pc_pawn_player_state_reference_profiles' or
            document.get('client_sha256') != CLIENT_SHA256 or
            type(document.get('profiles')) is not list or len(document['profiles']) != 2):
        raise ValueError('PlayerState field specification does not match the client')
    for row, (name, offset) in zip(document['profiles'], FIELDS):
        prefix = row.get('prefix_commands')
        index = row.get('command_index')
        if (row.get('class_name') != name or row.get('field_name') != 'PlayerState' or
                row.get('data_offset') != offset or row.get('dispatch_opcode') != 8 or
                row.get('serializer_hook_rva') != '0x10e8ed20' or type(index) is not int or
                row.get('wire_handle') != index + 1 or not 0 <= index < 65535 or
                type(prefix) is not list or len(prefix) != index + 1 or
                any(c.get('command_index') != i or c.get('dispatch_opcode') == 0
                    for i, c in enumerate(prefix)) or prefix[-1].get('descriptor_name') != 'PlayerState'):
            raise ValueError('PlayerState field is not a qualified ordinary scalar handle')
    return document


def qualified_player_state_source_pins(root):
    root = Path(root).resolve(strict=True)
    document = _spec(_read(root, SPEC_PATH, SPEC_SHA256))
    pins = {SPEC_PATH: SPEC_SHA256}
    for stem in ('metadata_source', 'ordinary_consumer_spec', 'official_after_spawn_source'):
        relative, digest = document[stem + '_relative_path'], document[stem + '_sha256']
        _read(root, relative, digest)
        pins[relative] = digest
    relative = 'work/native_player_state_initialization.py'
    data = (root / relative).read_bytes()
    pins[relative] = hashlib.sha256(data).hexdigest()
    if data != Path(__file__).read_bytes():
        raise ValueError('PlayerState reference helper was imported from another checkout')
    return pins


def build_player_state_references(root, manifests, source_pins):
    root = Path(root).resolve(strict=True)
    pins = qualified_player_state_source_pins(root)
    if any(source_pins.get(path) != digest for path, digest in pins.items()):
        raise ValueError('PlayerState reference sources are outside the association seal')
    document = _spec(_read(root, SPEC_PATH, SPEC_SHA256))
    states = [m for m in manifests if m.class_path == PLAYER_STATE_PATH]
    if len(states) != 1:
        raise ValueError('Exactly one current local PlayerState Actor is required')
    target = states[0]
    if target.actor_guid < 2 or target.actor_guid & 1:
        raise ValueError('PlayerState references require a dynamic local Actor GUID')
    updates, summary = {}, []
    for row in document['profiles']:
        matches = [m for m in manifests if m.class_path == row['asset_path']]
        if len(matches) != 1:
            raise ValueError('PlayerState reference source must have one current local Actor')
        actor = matches[0]
        updates[actor.actor_guid] = ObjectReference(row['wire_handle'], target.actor_guid)
        summary.append(dict(class_path=actor.class_path, field_name='PlayerState',
            ordinary_handle=row['wire_handle'], actor_guid=actor.actor_guid,
            referenced_actor_guid=target.actor_guid, channel_index=actor.channel_index))
    if qualified_player_state_source_pins(root) != pins:
        raise ValueError('PlayerState reference sources changed during preparation')
    return updates, summary
