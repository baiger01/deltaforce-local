"""Source-sealed existing WorldSettings channel for the Dam entry experiment.

This allocates only a local GUID/channel. It never writes native MapType or
constructs a WorldSettings; the client must resolve its existing Level Actor.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath

from dfserver.legacy_ds_actor_manifest import ActorManifest, GuidPathBinding, CLIENT_SHA256, preflight_actor_manifest
from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest
from dfserver.legacy_ds_guid_exports import GuidExportNode

SOURCE_PATH = 'work/evidence/map-entry-next-20261007/static-world-settings-actor-gap.json'
SOURCE_SHA256 = 'cf0b95f6ac1d82fde9065533e1d205ae912fd85ec40b48ea3d5fac74a811c03e'
CLASS_PATH = '/Script/DFMGameplay.DFMWorldSettings'
ACTOR_PATH = '/Game/Maps/Iris_Entry/Iris_Entry.Iris_Entry:PersistentLevel.DFMWorldSettings'
LOCAL_GUID = 39
LOCAL_CHANNEL = 7
DEPENDENCIES = {
    'work/evidence/map-entry-next-20261007/world-settings-channel-open-hook.code':
        '28f844b5972c241e804231b0e41b93e13696e59b98dde74f19029386db5da0c5',
    'work/evidence/map-entry-next-20261007/world-settings-writer.cf19df0.asm.txt':
        'bd56bc95afe027e37621a6931841130ddcc8d05a130ecbd7164389adafaa581c',
    'work/evidence/native-post-join-serialize-new-actor-full-roots.12bcb060.dfcode':
        '41f16f35e0f066044b68e156b478cd6064b15492a77469e7ab167b28606fedc2',
    'work/evidence/native-post-join-serialize-new-actor-full-roots.12bccde9.dfcode':
        '51f69dce28483c9b2f44ecfdfb4a28c4c04a6b4bbb5805d851b0e5d0362ba337',
}


def _read(root, relative, expected=None):
    if (not isinstance(relative, str) or '\\' in relative or ':' in relative or
            PurePosixPath(relative).is_absolute() or
            any(part in ('', '.', '..') for part in relative.split('/'))):
        raise ValueError('WorldSettings source requires a plain relative path')
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file() or not 0 < path.stat().st_size <= 1024 * 1024:
        raise ValueError('WorldSettings source is outside its local bound')
    raw = path.read_bytes(); digest = hashlib.sha256(raw).hexdigest()
    if expected is not None and digest != expected:
        raise ValueError('WorldSettings source SHA256 mismatch')
    return raw, digest


def qualified_static_world_settings_source_pins(root):
    root = Path(root).resolve(strict=True)
    raw, digest = _read(root, SOURCE_PATH, SOURCE_SHA256)
    record = json.loads(raw)
    header, hook = record.get('native_header_source', {}), record.get('native_class_hook_source', {})
    if (record.get('kind') != 'source_backed_static_world_settings_actor_gap' or
            record.get('client_sha256') != CLIENT_SHA256 or record.get('actor_class') != CLASS_PATH or
            record.get('observed_existing_actor_path') != ACTOR_PATH or
            record.get('observed_guid_kind') != 'static odd GUID' or
            header.get('dynamic_archetype_level_and_transform_fields_skipped') is not True or
            header.get('static_branch_destination') != '0x12bcd575' or
            hook.get('actor_channel_open_target') != '0xd5f350' or
            hook.get('extra_header_fields_read') is not False):
        raise ValueError('WorldSettings path and static header are not source-qualified')
    pins = {SOURCE_PATH: digest}
    for relative, expected in DEPENDENCIES.items():
        data, actual = _read(root, relative, expected)
        if relative.endswith('world-settings-channel-open-hook.code') and data[:3] != b'\xc2\x00\x00':
            raise ValueError('WorldSettings channel hook is not the qualified empty return')
        pins[relative] = actual
    for relative in ('work/native_static_world_settings.py',
                     'outputs/df-local-server/dfserver/legacy_ds_static_actor_manifest.py'):
        _, actual = _read(root, relative); pins[relative] = actual
    if pins['work/native_static_world_settings.py'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('WorldSettings factory was imported from another checkout')
    return pins


def build_static_world_settings_manifest(root, source_pins, dynamic_manifests):
    pins = qualified_static_world_settings_source_pins(root)
    if any(source_pins.get(relative) != digest for relative, digest in pins.items()):
        raise ValueError('WorldSettings source is outside the launch seal')
    if (type(dynamic_manifests) is not tuple or not dynamic_manifests or
            any(type(row) is not ActorManifest for row in dynamic_manifests)):
        raise ValueError('Existing WorldSettings needs the exact qualified dynamic Actor set')
    level_path = ACTOR_PATH.rsplit('.', 1)[0]
    levels = []
    used_guids = set()
    for row in dynamic_manifests:
        preflight_actor_manifest(row, channel_sequence=1023, max_packet_bytes=1492)
        if row.level_path != level_path or row.channel_index == LOCAL_CHANNEL:
            raise ValueError('WorldSettings Level or locally allocated channel conflicts')
        used_guids.add(row.actor_guid)
        for exported in row.exports:
            node = exported
            while node is not None:
                used_guids.add(node.guid)
                if node.guid == row.level_guid:
                    levels.append(node)
                node = node.outer
    if LOCAL_GUID in used_guids or not levels or any(level != levels[0] for level in levels):
        raise ValueError('WorldSettings local GUID or existing Level graph conflicts')
    level = levels[0]
    if level.outer is None or level.outer.outer is None:
        raise ValueError('WorldSettings requires its qualified persistent Level export')
    actor = GuidExportNode(LOCAL_GUID, ACTOR_PATH.rsplit('.', 1)[1], level)
    world, package = level.outer, level.outer.outer
    bindings = (
        GuidPathBinding(package.guid, package.path),
        GuidPathBinding(world.guid, package.path + '.' + world.path, '.'),
        GuidPathBinding(level.guid, level_path, ':'),
        GuidPathBinding(LOCAL_GUID, ACTOR_PATH, '.'),
    )
    manifest = StaticActorManifest(CLIENT_SHA256, SOURCE_PATH, SOURCE_SHA256, CLASS_PATH,
        ACTOR_PATH, LOCAL_GUID, level.guid, level_path, bindings, (actor,), LOCAL_CHANNEL, True, True)
    if qualified_static_world_settings_source_pins(root) != pins:
        raise ValueError('WorldSettings source changed during preparation')
    return manifest
