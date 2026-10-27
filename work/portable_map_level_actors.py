"""Source-pinned existing level Actor opens and empty RepLayout plans.

The caller supplies its complete reserved GUID/channel namespace. Observed Outer
paths qualify this static subset; they do not prove world membership or loading
in a later client. No dynamic Actor, gameplay property or native call is made.
"""
import argparse
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_manifest import CLIENT_SHA256, GuidPathBinding, _full_path
from dfserver.legacy_ds_bit_archive import UINT32_MAX
from dfserver.legacy_ds_control_connection import (MAX_INITIAL_ACTOR_CHANNELS,
    preflight_actor_content_plans)
from dfserver.legacy_ds_guid_exports import GuidExportNode
from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content
from dfserver.legacy_ds_static_actor_manifest import (StaticActorManifest,
    preflight_static_actor_manifest)

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_RELATIVE_PATH = 'outputs/df-local-server/protocol/portable-map-spawn/level-actors-schema.json'
SCHEMA_SHA256 = '322d3c79d316e1c4bd854da12e6ef9faf9364d29df1968c3a64397e2dc6fc12b'
SOURCE_REPORT = 'work/native-client-tests/1792297548603201600/economy-loaded-interactors-with-hooks.json'
NOOP_REPORT = 'work/evidence/map-system-audit-20261018/native-economy-box-actor-channel-open-noop.json'
SOURCE_PINS = {
    SOURCE_REPORT: 'acae343448b8f42ccaa5f67aeff3b26e6fd5155413f8d4307b6971740b783911',
    NOOP_REPORT: '3db5677b10afc0ae8b5e35ff9888904a1fbc6abb6026d38889e3ef8426f741c5',
}
CACHE_MANIFEST_SHA256 = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
MAX_NAMESPACE_ENTRIES = 4096
CHANNEL_SOURCE = 'work/evidence/map-system-audit-20261018/native-reserved-voice-channel-one.json'
CHANNEL_SOURCE_SHA256 = 'abd5a73a073d6d44fcdace7a73f30a9dcdc5967888019bdaa4eb6229a9f0d721'


def _source_reports(root):
    reports = {}
    for relative, expected in SOURCE_PINS.items():
        raw = (Path(root) / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('The pinned existing level Actor source changed: ' + relative)
        reports[relative] = json.loads(raw)
    observation, native = reports[SOURCE_REPORT], reports[NOOP_REPORT]
    if (observation.get('kind') != 'owned_current_exact_dam_interactor_metadata_observation' or
            observation.get('status') != 'observed' or observation.get('client_sha256') != CLIENT_SHA256 or
            observation.get('source_identity_rechecked') is not True or
            any(observation.get(k) is not False for k in ('process_memory_written', 'native_methods_invoked',
                'native_layouts_constructed', 'packets_sent', 'code_sampled', 'historical_process_pointers_reused')) or
            native.get('kind') != 'qualified_portable_offline_native_analysis' or
            native.get('client_sha256') != CLIENT_SHA256 or
            native.get('cache_manifest_sha256') != CACHE_MANIFEST_SHA256 or
            native.get('process_access') is not False or native.get('client_launched') is not False):
        raise ValueError('The existing Actor source qualification changed')
    functions = [f for f in native.get('functions', []) if f.get('requested_rva') == '0xd5f350']
    if (len(functions) != 1 or not functions[0].get('instructions') or
            functions[0]['instructions'][0] !=
            dict(rva='0xd5f350', bytes='c20000', mnemonic='ret', operands='0')):
        raise ValueError('The exact source Actor open hook no-op is required')
    return observation


def level_actor_source_pins(root):
    _source_reports(root)
    raw = (Path(root)/CHANNEL_SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CHANNEL_SOURCE_SHA256:
        raise ValueError('The native reserved Voice channel observation changed')
    reservation = json.loads(raw)
    if (reservation.get('kind') != 'current_native_reserved_voice_channel_observation' or
            reservation.get('client_sha256') != CLIENT_SHA256 or
            reservation.get('observed_channel_index') != 1 or
            reservation.get('existing_channel_type') != 'Voice' or
            reservation.get('incoming_channel_type') != 'Actor'):
        raise ValueError('The current client channel reservation is not qualified')
    return dict(SOURCE_PINS, **{CHANNEL_SOURCE: CHANNEL_SOURCE_SHA256})


def derive_schema(root):
    observation = _source_reports(root)
    actors = observation.get('actors')
    if type(actors) is not list or len(actors) != 4:
        raise ValueError('The four exact source existing Actors are required')
    rows, paths = [], set()
    for actor in actors:
        level, world, package = (actor[k] for k in ('level', 'world', 'package'))
        hook = actor.get('actor_open_hook', {})
        membership = actor.get('current_world_membership_beyond_observed_outer_chain_verified')
        if (hook.get('slot') != 0x3d8 or hook.get('target_rva') != 0xd5f350 or
                hook.get('inside_pinned_image') is not True or
                hook.get('source_qualified_no_extra_fields') is not True or
                hook.get('native_method_invoked') is not False or membership is not False):
            raise ValueError('The exact existing Actor open hook and membership limit are required')
        chain = ((actor, level, 'Actor'), (level, world, 'Level'), (world, package, 'World'))
        for child, outer, expected in chain:
            if (expected not in child['identity']['class_ancestry'] or
                    int(child['identity']['outer_address'], 16) != int(outer['identity']['address'], 16)):
                raise ValueError('The observed existing Actor Outer chain changed')
        if ('Package' not in package['identity']['class_ancestry'] or
                int(package['identity']['outer_address'], 16) != 0):
            raise ValueError('An observed root package is required')
        package_path = package['object_path']
        world_path = package_path + '.' + world['identity']['name']
        level_path = world_path + ':' + level['identity']['name']
        actor_path = level_path + '.' + actor['identity']['name']
        if (world['object_path'] != world_path or level['object_path'] != level_path or
                actor['object_path'] != actor_path or actor_path in paths or
                not package_path.startswith('/Game/Maps/Dam_Iris_Long3/InterActors/')):
            raise ValueError('The exact source full object paths are inconsistent')
        for path in (package_path, world_path, level_path, actor_path, actor['class_path']):
            _full_path(path)
        paths.add(actor_path)
        rows.append(dict(package_path=package_path, world_path=world_path, level_path=level_path,
            actor_path=actor_path, class_path=actor['class_path'],
            actor_open_hook=dict(slot='0x3d8', target_rva='0xd5f350', has_extra_fields=False)))
    return dict(kind='client_derived_existing_level_actors_schema', version=1,
        client_sha256=CLIENT_SHA256, sources=[dict(relative_path=p, sha256=s) for p, s in SOURCE_PINS.items()],
        actors=rows, property_content=dict(kind='ordinary_empty_rep_layout', payload_bits=9),
        current_world_membership_beyond_observed_outer_chain_verified=False,
        process_pointers_reused=False, dynamic_actors_spawned=False, native_resolution_verified=False,
        actor_interaction_or_loot_verified=False)


def _namespace(values, label):
    if type(values) not in (tuple, list, set, frozenset) or len(values) > MAX_NAMESPACE_ENTRIES:
        raise ValueError('A complete bounded ' + label + ' namespace is required')
    if any(type(v) is not int or not 0 <= v <= UINT32_MAX for v in values):
        raise ValueError('The complete ' + label + ' namespace must contain uint32 integers')
    return set(values)


def level_actor_plans(root, raw_schema, *, used_guids, used_channels, channel_sequence,
                      max_packet_bytes, maximum_channel_index=64):
    """Return immutable manifests and ordinary post-open plans without reserving state."""
    if (type(raw_schema) is not bytes or hashlib.sha256(raw_schema).hexdigest() != SCHEMA_SHA256 or
            json.loads(raw_schema) != derive_schema(root)):
        raise ValueError('The sealed source existing level Actor schema is required')
    schema = json.loads(raw_schema)
    level_actor_source_pins(root)
    guids, channels = _namespace(used_guids, 'GUID'), _namespace(used_channels, 'channel')
    if (type(maximum_channel_index) is not int or not 1 <= maximum_channel_index <= 1024 or
            len(channels - {0}) + len(schema['actors']) > MAX_INITIAL_ACTOR_CHANNELS):
        raise ValueError('The bounded initial Actor channel capacity is insufficient')
    # Native Control is 0 and the current client's pre-opened Voice channel is 1.
    free_channels = [c for c in range(2, maximum_channel_index + 1) if c not in channels]
    if len(free_channels) < len(schema['actors']):
        raise ValueError('The bounded existing Actor channel allocation is exhausted')
    # At most four unique nodes per Actor. A prefix larger than the occupied
    # namespace plus this demand necessarily contains enough free odd GUIDs.
    free_guids = iter(g for g in range(3, 2 * (len(guids) + 4 * len(schema['actors'])) + 5, 2)
                      if g not in guids)
    allocated, manifests, plans, opens = {}, [], [], []

    def node(path, leaf, outer=None):
        if path not in allocated:
            allocated[path] = GuidExportNode(next(free_guids), leaf, outer)
        value = allocated[path]
        if value.path != leaf or value.outer != outer:
            raise ValueError('A source path has inconsistent exported Outer definitions')
        return value

    for row, channel in zip(schema['actors'], free_channels):
        package = node(row['package_path'], row['package_path'])
        world = node(row['world_path'], row['world_path'][len(row['package_path']) + 1:], package)
        level = node(row['level_path'], row['level_path'][len(row['world_path']) + 1:], world)
        actor = node(row['actor_path'], row['actor_path'][len(row['level_path']) + 1:], level)
        bindings = tuple(GuidPathBinding(n.guid, row[k], sep) for n, k, sep in (
            (package, 'package_path', None), (world, 'world_path', '.'),
            (level, 'level_path', ':'), (actor, 'actor_path', '.')))
        manifest = StaticActorManifest(CLIENT_SHA256, SOURCE_REPORT, SOURCE_PINS[SOURCE_REPORT],
            row['class_path'], row['actor_path'], actor.guid, level.guid, row['level_path'], bindings,
            (actor,), channel, True, True, any(ord(c) > 127 for c in row['actor_path']))
        opening = preflight_static_actor_manifest(manifest, channel_sequence=channel_sequence,
            max_packet_bytes=max_packet_bytes)
        manifests.append(manifest)
        opens.append(dict(opening.actor_fields))
        plans.append(dict(channel_index=channel, actor_guid=actor.guid,
            static_content_source_sha256=SCHEMA_SHA256,
            content_blocks=(build_empty_rep_layout_content(),)))
    plans = tuple(plans)
    preflight_actor_content_plans(tuple(opens), plans, initial_channel_sequence=channel_sequence,
        max_packet_bytes=max_packet_bytes)
    return tuple(manifests), plans


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export-schema', action='store_true', required=True)
    opts = parser.parse_args()
    raw = (json.dumps(derive_schema(ROOT), ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8')
    path = ROOT / SCHEMA_RELATIVE_PATH
    with path.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest())))
