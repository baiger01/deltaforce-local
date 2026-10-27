"""Current-source entry Actors, with a separate live receiver guard.

This is the minimum entry diagnostic. Inventory, HUD, FSM, randomized spawn,
world loot and Mandel state need their own current schemas before activation.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

from build_updated_minimum_actor_profile import (
    ROOT, CURRENT_CLIENT_SHA256, source_blobs, compile_sources, rpc_profiles, _read,
)
from updated_map_scene import scene_context
from updated_player_appearance import appearance_context, avatar_ids

PROFILE_PATH = 'work/evidence/updated-minimum-actor-profile-79fb7b10.json'
PROFILE_SHA256 = '64e5979c79b0876f62c6e03a9ad0407a88aaff3d7b9b81ed9961c920e4c2399a'


def property_content(actor, values):
    """Encode only caller-selected leaves in this exact current source subset."""
    from dfserver.legacy_ds_bit_archive import BitWriter
    from dfserver.legacy_ds_actor_content import ActorContentBlock
    selected = [(actor['properties'][name], value) for name, value in values.items()]
    writer = BitWriter(maximum_bits=4096)
    writer.write_bool(False)
    for field, value in sorted(selected, key=lambda r: r[0]['relative_handle']):
        writer.write_packed_int(field['relative_handle'])
        family = field['family']
        if family == 'FObjectProperty':
            if type(value) is not int or not 0 <= value <= 0xffffffff or value == 1:
                raise ValueError('Explicit ordinary local object GUID required')
            writer.write_packed_int(value)
        elif family == 'FBoolProperty':
            if type(value) is not bool:
                raise ValueError('An explicit native boolean is required')
            writer.write_bool(value)
        elif family in ('FUInt64Property', 'FInt64Property'):
            signed = family == 'FInt64Property'
            lower, upper = (-(1 << 63), 1 << 63) if signed else (0, 1 << 64)
            if type(value) is not int or not lower <= value < upper:
                raise ValueError('Explicit current 64-bit scalar required')
            writer.write_payload(struct.pack('<q' if signed else '<Q', value), 64)
        elif family in ('FByteProperty', 'FEnumProperty'):
            bits = field['enum_serialized_bit_width']
            if type(bits) is not int or type(value) is not int or not 0 <= value < 1 << bits:
                raise ValueError('Explicit source-qualified enum value required')
            writer.write_bits(value, bits)
        else:
            raise ValueError('Leaf outside the qualified current minimum subset')
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


@dataclass
class UpdatedMapPlan:
    sources: dict
    profile: dict
    actors: dict
    contents: tuple
    rpc: dict
    start: object
    appearance: dict

    def summary(self):
        return dict(kind='current_source_minimum_entry_plan', client_sha256=CURRENT_CLIENT_SHA256,
            map_id=2201, actor_count=len(self.actors), source_pins=self.sources,
            diagnostic_only=True, runtime_receiver_check_required=True,
            runtime_native_cache_observed=False, native_gameplay_acceptance=False,
            random_spawn_activated=False, loot_or_mandel_activated=False,
            inventory_hud_fsm_activated=False)

    def install(self, probe, *, receiver_guard=None):
        if not callable(receiver_guard) or receiver_guard() is not True:
            raise ValueError('A current live receiver identity/context guard is required')
        from portable_source_guard import SourceGuard, qualification_scope
        guard = SourceGuard(ROOT, self.sources)
        pc, pawn, state = (self.actors[role] for role in ('PlayerController', 'Pawn', 'GameState'))

        def resolve(ticket, fields):
            if not guard() or receiver_guard() is not True:
                raise ValueError('The current live receiver context or source lease expired')
            if ticket.map_id != 2201:
                raise ValueError('Current minimum bootstrap serves its qualified Dam map only')
            return tuple(dict(field) for field in fields)

        def admission(player_id, hero_id, fashion_id, plans):
            if not guard() or receiver_guard() is not True:
                raise ValueError('The current live receiver context or source lease expired')
            if any(type(value) is not int or not 0 < value < 1 << 63 for value in (player_id, hero_id)):
                raise ValueError('Explicit admitted identity and selected operator are required')
            ps = self.actors['PlayerState']
            hero, same_team, diff_team = avatar_ids(self.appearance, hero_id, fashion_id)
            block = property_content(self.profile['actors']['PlayerState'],
                dict(Uin=player_id, HeroID=hero, CurrSameTeamAvatarId=same_team,
                     CurrDiffTeamAvatarId=diff_team))
            return plans + (dict(channel_index=ps.channel_index, actor_guid=ps.actor_guid,
                content_blocks=(block,)),)

        try:
            probe.set_pc_ping_profile(2201, pc, self.rpc['ping'])
            probe.set_pc_startup_profile(2201, pc, self.rpc['startup'])
            probe.set_game_state_start_profile(2201, state, self.start)
            probe.set_pc_restart_profile(2201, pc, pawn, self.rpc['restart'])
            probe.set_pc_view_target_profile(2201, pc, pawn, self.rpc['view'])
            probe.set_initial_actor_manifests(2201, tuple(self.actors.values()), resolver=resolve,
                post_open_actor_contents=self.contents, admission_content_factory=admission,
                admission_qualification_scope=qualification_scope)
        except BaseException:
            guard.close()
            raise
        # The caller must retain this lease through probe shutdown.
        return guard


def load_plan(root=ROOT):
    from dfserver.replication.legacy_ds_current_actor_profile import (
        qualify_current_actor_sources, CURRENT_ARCHETYPE_QUALIFICATION)
    from dfserver.replication.legacy_ds_current_movement_actor import (
        qualify_current_movement_actor_sources, MOVEMENT_PROFILE_PATH,
        MOVEMENT_PROFILE_SHA256, MOVEMENT_ARCHETYPE_QUALIFICATION)
    from dfserver.legacy_ds_actor_manifest import ActorManifest, GuidPathBinding, preflight_actor_manifest
    from dfserver.legacy_ds_guid_exports import GuidExportNode
    from dfserver.legacy_ds_game_state_start import GameStateStartProfile
    from updated_enabled_header_context import PROOF, PROOF_SHA256
    root = Path(root).resolve(strict=True)
    if root != ROOT.resolve(strict=True):
        raise ValueError('The current map plan requires its canonical source root')
    blobs = source_blobs(root)
    profile = compile_sources(blobs)
    raw = _read(root, PROFILE_PATH)
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256 or json.loads(raw) != profile:
        raise ValueError('Exact compiled current minimum source profile required')
    receiver_source = _read(root, PROOF)
    if hashlib.sha256(receiver_source).hexdigest() != PROOF_SHA256:
        raise ValueError('The current enabled receiver contract changed')
    blobs[PROOF] = receiver_source
    qualification = qualify_current_actor_sources(raw, source_blobs=blobs)
    movement_raw = _read(root, MOVEMENT_PROFILE_PATH)
    movement = json.loads(movement_raw)
    movement_blobs = {path: _read(root, path) for path in movement['source_pins']}
    movement_qualification = qualify_current_movement_actor_sources(movement_raw,
        source_blobs=movement_blobs, entry_qualification=qualification)
    scene = scene_context(root)
    appearance = appearance_context(root)
    source_pins = {**profile['source_pins'], **scene['source_pins'], **appearance['source_pins'],
        PROFILE_PATH: PROFILE_SHA256,
        PROOF: PROOF_SHA256, **dict(movement_qualification.source_pins)}
    for path in ('work/build_updated_minimum_actor_profile.py', 'work/updated_map_scene.py',
                 'work/updated_map_bootstrap.py'):
        source_pins[path] = hashlib.sha256(_read(root, path)).hexdigest()
    world, level = scene['world_export']['name'], scene['level_export']['name']
    level_package = GuidExportNode(25, scene['package_path'])
    world_node = GuidExportNode(9, world, level_package)
    level_node = GuidExportNode(11, level, world_node)
    # All GUIDs and channels below belong to our local sender namespace.
    allocations = {'PlayerController': (13, 15, 17, 4, 2), 'GameState': (19, 21, 23, 6, 3),
                   'Pawn': (3, 5, 7, 2, 4), 'PlayerState': (27, 29, 31, 8, 5),
                   'MovementReplicationActor': (33, 35, 37, 10, 6)}
    actors = {}
    for role, (package_guid, class_guid, cdo_guid, actor_guid, channel) in allocations.items():
        native_movement = role == 'MovementReplicationActor'
        source = movement if native_movement else profile['actors'][role]
        package = GuidExportNode(package_guid, source['package_path'])
        klass = GuidExportNode(class_guid, source['class_path'].rsplit('.', 1)[-1], package)
        cdo = GuidExportNode(cdo_guid, source['archetype_path'].rsplit('.', 1)[-1], package)
        manifest = ActorManifest(client_sha256=CURRENT_CLIENT_SHA256,
            source_relative_path=MOVEMENT_PROFILE_PATH if native_movement else PROFILE_PATH,
            source_sha256=MOVEMENT_PROFILE_SHA256 if native_movement else PROFILE_SHA256,
            class_guid=class_guid, class_path=source['class_path'], archetype_guid=cdo_guid,
            archetype_path=source['archetype_path'],
            archetype_qualification=MOVEMENT_ARCHETYPE_QUALIFICATION if native_movement else CURRENT_ARCHETYPE_QUALIFICATION,
            level_guid=11, level_path=scene['level_path'],
            path_bindings=(GuidPathBinding(package_guid, source['package_path']),
                GuidPathBinding(class_guid, source['class_path'], '.'),
                GuidPathBinding(cdo_guid, source['archetype_path'], '.'),
                GuidPathBinding(25, scene['package_path']),
                GuidPathBinding(9, scene['package_path']+'.'+world, '.'),
                GuidPathBinding(11, scene['level_path'], ':')),
            exports=(klass, cdo, level_node), actor_guid=actor_guid,
            connection_network_version=13, archive_network_version=13,
            references_resolvable=True, channel_index=channel,
            location=None, scale=None, velocity=None, local_player_index=0 if role == 'PlayerController' else None,
            game_replication_flags=0 if role == 'Pawn' else None,
            must_be_mapped_guids=(class_guid, cdo_guid, 11),
            current_qualification=movement_qualification if native_movement else qualification)
        preflight_actor_manifest(manifest, channel_sequence=1023, max_packet_bytes=1024)
        actors[role] = manifest
    leaf_doc = next(json.loads(raw) for path, raw in blobs.items() if 'minimum_leaf_bindings_' in path)
    enums = {e['name']: {v['name']: v['value'] for v in e['enumerators']} for e in leaf_doc['enum_registrations']}
    selections = {'PlayerController': dict(Pawn=2, PlayerState=8),
        'Pawn': dict(RemoteRole=enums['ENetRole']['ROLE_AutonomousProxy'], PlayerState=8, Controller=4),
        'GameState': dict(DFMGamePlayerMode=enums['EDFMGamePlayMode']['EDFMGamePlayMode::GamePlayMode_SOL'])}
    contents = tuple(dict(channel_index=actors[role].channel_index, actor_guid=actors[role].actor_guid,
        content_blocks=(property_content(profile['actors'][role], values),)) for role, values in selections.items())
    gs = profile['actors']['GameState']['properties']
    handle = lambda name: gs[name]['relative_handle']
    start = GameStateStartProfile(class_path=actors['GameState'].class_path,
        begin_play_handle=handle('bReplicatedHasBegunPlay'), client_sha256=CURRENT_CLIENT_SHA256,
        source_sha256=PROFILE_SHA256, all_ready_handle=handle('bStartMathWithAllPlayerReady'),
        abseil_handle=handle('bCanSwitchToAbseil'), map_id_handle=handle('MapId'),
        room_id_handle=handle('RoomId'), real_start_handle=handle('bMatchRealStart'),
        current_qualification=qualification)
    return UpdatedMapPlan(source_pins, profile, actors, contents, rpc_profiles(root), start, appearance)
