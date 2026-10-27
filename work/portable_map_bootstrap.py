"""Rebuild a local bootstrap from explicit, available same-build sources.

Archived metadata supplies schema, never live process pointers. Fresh template
reports supply observed class identities and the Pawn native interface. Missing
roles remain absent. This is an opt-in diagnostic plan, not gameplay proof.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from native_actor_bootstrap import (CLIENT_SHA256, ROLE_CLASSES, QualifiedPCTailProfile,
    QualifiedGameSpawnProfile, build_initial_actor_bootstrap)
from native_game_state_start_profile import qualify_outer_handle
from dfserver.legacy_ds_rep_layout_refs import (ObjectReference, build_object_reference_content,
                                               build_empty_rep_layout_content)
from dfserver.legacy_ds_pc_startup_rpc import PCStartupField, PCStartupProfile
from dfserver.legacy_ds_pc_ping_receiver import PCPingProfile
from dfserver.legacy_ds_pc_restart_rpc import PCRestartProfile
from dfserver.legacy_ds_pc_view_target_rpc import PCViewTargetProfile
from dfserver.legacy_ds_game_state_start import GameStateStartProfile
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding
from dfserver.legacy_ds_match_admission import LocalMatchTicket
from dfserver.legacy_ds_rotator import CompressedRotator16

ARCHIVE_PATH = '\u8fdb\u56fe\u8c03\u7814/\u5b57\u6bb5\u5143\u6570\u636e/\u8fdb\u573a\u540e\u5b57\u6bb5.json'
PC = ROLE_CLASSES['PlayerController']
GS = ROLE_CLASSES['GameState']


def sealed_read(root, source):
    relative, expected = source['relative_path'], source['sha256']
    if (type(relative) is not str or ':' in relative or '\\' in relative or
            PurePosixPath(relative).is_absolute() or
            any(p in ('', '.', '..') for p in relative.split('/'))):
        raise ValueError('A project-relative portable source is required')
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not 0 < path.stat().st_size <= 32 * 1024 * 1024:
        raise ValueError('Portable source exceeds its project bound')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Portable source SHA256 changed: ' + relative)
    return raw


def class_export(document, name, *, layout=False, cache=False):
    records = [r for r in document['driver_class_exports'] if r.get('class_name') == name
               and (not layout or 'layout' in r) and (not cache or 'cache_nodes' in r)]
    if len(records) != 1:
        raise ValueError('Exactly one available class schema is required: ' + name)
    return records[0]


def property_handle(record, name, *, opcode, serializer, parent=None):
    commands = record['layout']['commands']
    matches = [c for c in commands if c.get('descriptor_name') == name and
               (parent is None or c.get('parent_index') == parent)]
    if len(matches) != 1:
        raise ValueError('Property must have one qualified declaration: ' + name)
    command = matches[0]
    hook = command.get('property_serializer_hook', {})
    if (command['dispatch_opcode'] != opcode or hook.get('target_rva') != serializer or
            hook.get('target_module_sha256') != CLIENT_SHA256 or
            hook.get('identity_rechecked') is not True or hook.get('inside_pinned_image') is not True):
        raise ValueError('Property serializer changed: ' + name)
    prefix = [dict(c, index=c['command_index'])
              for c in commands[:command['command_index'] + 1]]
    return qualify_outer_handle(prefix, dict(name=name, dispatch_opcode=opcode,
        command_index=command['command_index'], ordinary_handle=command['relative_handle']))


def rpc_index(record, name):
    fields = [f for node in record['cache_nodes'] for f in node['fields']
              if f.get('descriptor_name') == name]
    if (len(fields) != 1 or fields[0].get('incompatible') is not False or
            fields[0].get('descriptor_representation') != 1 or
            type(fields[0].get('rep_index')) is not int or
            not 0 <= fields[0]['rep_index'] < record['exclusive_index_maximum']):
        raise ValueError('One compatible native RPC declaration is required: ' + name)
    return fields[0]['rep_index']


@dataclass
class PortableMapPlan:
    sources: dict
    control: dict
    actors: dict
    resolver: object
    contents: tuple
    startup: PCStartupProfile
    ping: PCPingProfile
    start: GameStateStartProfile
    restart: PCRestartProfile
    view: PCViewTargetProfile
    spawn_summary: dict | None = None
    player_state_schema: dict | None = None
    admission_content_factory: object = None
    fashion_component_configured: bool = False
    gameplay_mode_sync_configured: bool = False
    rotation: object = None
    spawn_selector: object = None
    local_rule_profile: tuple | None = None
    hud: object = None
    hud_class_guid: int | None = None
    gameplay_metadata_probe_configured: bool = False
    additional_manifests: tuple = ()
    inventory_content_factory: object = None
    vitals_metadata_probe_configured: bool = False
    map_marker_metadata_probe_configured: bool = False
    ticket_content_factory: object = None
    weapon_owner_initialization_configured: bool = False
    skill_detail_initialization_configured: bool = False
    admission_actor_factory: object = None
    skill_entity_initialization_configured: bool = False
    modular_weapon_recipe_configured: bool = False
    room_content_factory: object = None
    owned_weapon_switch_timeline_configured: bool = False
    skill_game_state_component_creation_configured: bool = False
    weapon_equipment_positions_configured: bool = False
    fsm_metadata_probe_configured: bool = False
    admission_owned_actor_channels_factory: object = None
    fsm_instance_creation: dict | None = None
    fsm_replica_initialization_configured: bool = False
    admission_inventory_refresh_factory: object = None
    admission_owner_switch_factory: object = None
    admission_movement_factory: object = None
    skill_template_authority_configured: bool = False
    level_visibility_profile: object = None
    admission_character_initialization_factory: object = None
    admission_static_box_runtime_factory: object = None
    profile_relative_path: str | None = None

    @property
    def manifests(self):
        return tuple(item.manifest for item in self.actors.values()) + self.additional_manifests

    def summary(self):
        return dict(kind='portable_local_map_bootstrap', map_id=2201,
            roles=list(self.actors), unavailable_roles=[r for r in ROLE_CLASSES if r not in self.actors],
            source_pins=self.sources, profile_relative_path=self.profile_relative_path,
            archived_metadata_is_schema_only=True,
            old_machine_original_reports_reconstructed=False,
            spawn_selection=self.spawn_summary,
            player_control_content_configured=self.player_state_schema is not None,
            per_admission_appearance_configured=self.admission_content_factory is not None,
            gameplay_metadata_probe_configured=self.gameplay_metadata_probe_configured,
            default_fashion_component_sync_configured=self.fashion_component_configured,
            gameplay_mode_sync_configured=self.gameplay_mode_sync_configured,
            controller_spawn_rotation_configured=self.rotation is not None,
            native_hud_creation_configured=self.hud is not None,
            existing_level_actor_metadata_channels=sum(type(m).__name__ == 'StaticActorManifest'
                                                       for m in self.additional_manifests),
            native_inventory_content_configured=self.inventory_content_factory is not None,
            inventory_optional_features_complete=False,
            vitals_metadata_probe_configured=self.vitals_metadata_probe_configured,
            map_marker_metadata_probe_configured=self.map_marker_metadata_probe_configured,
            native_weapon_owner_initialization_configured=self.weapon_owner_initialization_configured,
            native_skill_detail_initialization_configured=self.skill_detail_initialization_configured,
            native_skill_entity_initialization_configured=self.skill_entity_initialization_configured,
            native_modular_weapon_recipe_configured=self.modular_weapon_recipe_configured,
            native_owned_weapon_switch_timeline_configured=self.owned_weapon_switch_timeline_configured,
            native_skill_game_state_component_creation_configured=self.skill_game_state_component_creation_configured,
            native_weapon_equipment_positions_configured=self.weapon_equipment_positions_configured,
            fsm_default_component_metadata_probe_configured=self.fsm_metadata_probe_configured,
            admitted_actor_reliable_receipts_configured=self.admission_owned_actor_channels_factory is not None,
            fsm_instance_creation=self.fsm_instance_creation or None,
            native_fsm_replica_initialization_configured=self.fsm_replica_initialization_configured,
            native_character_fsm_initialization_configured=self.admission_character_initialization_factory is not None,
            native_inventory_ready_refresh_configured=self.admission_inventory_refresh_factory is not None,
            native_high_value_markers_configured=self.room_content_factory is not None,
            native_carried_weapon_actor_probe_configured=self.admission_actor_factory is not None,
            native_owner_switch_runtime_configured=self.admission_owner_switch_factory is not None,
            native_movement_runtime_configured=self.admission_movement_factory is not None,
            native_skill_template_authority_configured=self.skill_template_authority_configured,
            native_owner_level_visibility_configured=self.level_visibility_profile is not None,
            static_box_reference_runtime_configured=self.admission_static_box_runtime_factory is not None,
            box_gameplay_implemented=False,
            configurable_local_map_rules_configured=self.local_rule_profile is not None,
            historical_process_pointers_reused=False,
            connection_network_version=13, runtime_connection_version_verified=False,
            native_spawn_verified=False, playable_map_verified=False)

    def install(self, probe):
        from portable_source_guard import qualification_scope
        pc, pawn, state = (self.actors[r].manifest for r in ('PlayerController', 'Pawn', 'GameState'))
        probe.set_pc_ping_profile(2201, pc, self.ping)
        probe.set_pc_startup_profile(2201, pc, self.startup)
        probe.set_game_state_start_profile(2201, state, self.start)
        probe.set_pc_restart_profile(2201, pc, pawn, self.restart)
        probe.set_pc_view_target_profile(2201, pc, pawn, self.view)
        if self.rotation is not None:
            probe.set_pc_rotation_profile(2201, pc, pawn, self.rotation)
        if self.hud is not None:
            probe.set_pc_hud_profile(2201, pc, pawn, self.hud, self.hud_class_guid)
        probe.set_initial_actor_manifests(2201, self.manifests, resolver=self.resolver,
            post_open_actor_contents=self.contents, admission_content_factory=self.admission_content_factory,
            admission_loadout_content_factory=self.inventory_content_factory,
            admission_ticket_content_factory=self.ticket_content_factory,
            admission_ticket_actor_factory=self.admission_actor_factory,
            admission_room_content_factory=self.room_content_factory,
            admission_character_initialization_factory=self.admission_character_initialization_factory,
            admission_owned_actor_channels_factory=self.admission_owned_actor_channels_factory,
            admission_inventory_refresh_factory=self.admission_inventory_refresh_factory,
            admission_owner_switch_factory=self.admission_owner_switch_factory,
            admission_movement_factory=self.admission_movement_factory,
            admission_static_box_runtime_factory=self.admission_static_box_runtime_factory,
            admission_qualification_scope=qualification_scope,
            level_visibility_profile=self.level_visibility_profile,
            room_capacity=1 if self.spawn_selector is not None else None)
        if self.local_rule_profile is not None:
            probe.set_local_map_rules(2201, *self.local_rule_profile[:3], match_mode_ids=self.local_rule_profile[3])
        return self.summary()


def load_plan(root, profile_path, *, skill_id_ledger=None, skill_template_store=None,
              character_initialization_store=None):
    root = Path(root).resolve(strict=True)
    profile_path = Path(profile_path).resolve(strict=True)
    if not profile_path.is_relative_to(root) or profile_path.stat().st_size > 65536:
        raise ValueError('Portable profile must be inside the bounded project')
    profile_raw = profile_path.read_bytes()
    config = json.loads(profile_raw)
    if (config.get('kind') != 'portable_local_map_bootstrap_profile' or
            config.get('client_sha256') != CLIENT_SHA256 or config.get('map_id') != 2201 or
            config.get('diagnostic_only') is not True or
            config.get('network_version_origin') != 'explicit_same_build_reference_trial_setting' or
            config.get('connection_network_version') != 13):
        raise ValueError('Unsupported portable bootstrap profile')
    sources = config['sources']
    if set(sources) != {'archive', 'templates', 'scene', 'pc_tail'}:
        raise ValueError('Portable bootstrap needs its four explicit source documents')
    raws = {name: sealed_read(root, value) for name, value in sources.items()}
    documents = {name: json.loads(raw) for name, raw in raws.items()}
    if any(doc.get('client_sha256') != CLIENT_SHA256 for doc in documents.values()):
        raise ValueError('Portable source build mismatch')
    scene, tail = documents['scene'], documents['pc_tail']
    if (scene.get('kind') != 'official_spawn_scene_context_reference' or
            scene['controller_world_settings']['owning_world_name'] != 'Iris_Entry' or
            scene['controller_world_settings']['owning_level_name'] != 'PersistentLevel' or
            tail.get('kind') != 'source_backed_base_player_controller_open_tail_profile' or
            tail.get('hook_target_rva') != '0x12d4ddb0' or
            tail.get('hook_slot') != '0x3d8' or tail.get('tail_encoding') != 'unaligned_raw_u8' or
            tail.get('local_player_index') != 0):
        raise ValueError('Scene or base PlayerController tail qualification changed')
    world = scene['controller_world_settings']['owning_world_name']
    level = '/Game/Maps/' + world + '/' + world + '.' + world + ':' + scene['controller_world_settings']['owning_level_name']
    common = dict(level_path=level, level_source_relative_path=sources['scene']['relative_path'],
        level_source_sha256=sources['scene']['sha256'], level_package_guid=25,
        level_outer_guid=9, level_guid=11, channel_sequence=1023,
        connection_network_version=13, archive_network_version=13,
        max_packet_bytes=1024, references_resolvable=True)
    spawn_vector, spawn_summary = None, None
    if config.get('spawn') is not None:
        from portable_spawn_point import qualify_spawn_point
        spawn = config['spawn']
        spawn_vector, spawn_summary = qualify_spawn_point(
            json.loads(sealed_read(root, spawn['source'])),
            json.loads(sealed_read(root, spawn['catalog'])), spawn['selected_actor_path'])
    allocations = {'PlayerController': (13, 15, 17, 4, 2), 'GameState': (19, 21, 23, 6, 3),
                   'Pawn': (3, 5, 7, 2, 4), 'PlayerState': (27, 29, 31, 8, 5),
                   'MovementReplicationActor': (33, 35, 37, 10, 6)}
    actors, actor_arguments, actor_raws = {}, {}, {}
    for role, (package, klass, archetype, actor, channel) in allocations.items():
        # Prefer the current machine observation. Only PC/GS may use the
        # explicit same-build archive when not yet loaded in this lobby.
        fresh = documents['templates']['roots']
        present = any(r.get('name') == ROLE_CLASSES[role] for r in fresh['classes'])
        source_name = 'templates' if present else 'archive'
        if not present and role not in ('PlayerController', 'GameState'):
            continue
        source = sources[source_name]
        arguments = dict(common, role=role, source_relative_path=source['relative_path'],
            source_sha256=source['sha256'], package_guid=package, class_guid=klass,
            archetype_guid=archetype, actor_guid=actor, channel_index=channel)
        if role == 'PlayerController':
            arguments.update(local_player_index=0, pc_tail_profile=QualifiedPCTailProfile(
                CLIENT_SHA256, sources['pc_tail']['relative_path'], sources['pc_tail']['sha256'], 0x12d4ddb0))
        if role == 'Pawn':
            if spawn_vector is not None:
                arguments['location'] = spawn_vector
                arguments['rotation'] = CompressedRotator16(tuple(spawn_summary['rotation_steps']))
            arguments['game_spawn_profile'] = QualifiedGameSpawnProfile(
                raws['templates'], sources['templates']['relative_path'], sources['templates']['sha256'],
                original_state_u8=2, actor_byte93_mask20=True, owner_connection_match=True,
                connection_present=True, actor_is_connection_actor=False,
                actor_in_connection_actor_array=False)
        actors[role] = build_initial_actor_bootstrap(raws[source_name], **arguments)
        actor_arguments[role], actor_raws[role] = arguments, raws[source_name]
    if not {'PlayerController', 'GameState', 'Pawn'} <= set(actors):
        raise ValueError('The minimal controller, state and Pawn sources are required')
    if actors['Pawn'].game_spawn_result.flags_u8 != 0:
        raise ValueError('The explicit local autonomous Pawn state changed')

    qualified_mode_ids = None
    select_spawn = None
    random_spawn = config.get('random_spawn')
    if random_spawn is not None:
        from portable_map_spawn_selection import spawn_selector
        if config.get('world_state') is None or config.get('controller_rotation') is None:
            raise ValueError('Random spawn requires mode qualification and controller rotation synchronization')
        if spawn_vector is None:
            raise ValueError('Random spawn requires the corroborated coordinate convention')
        select_spawn = spawn_selector(sealed_read(root, random_spawn['schema']),
            json.loads(sealed_read(root, config['spawn']['source'])), random_spawn['local_room_policy'])
        spawn_summary = dict(kind='source_derived_native_MS23_single_human_allocation',
            schema_sha256=random_spawn['schema']['sha256'], room_capacity=1,
            coordinate_convention_reference=spawn_summary,
            seed_origin=random_spawn['local_room_policy']['seed_policy'],
            world_origin_rechecked=True, native_collision_adjustment_applied=False,
            official_server_map_level_recovered=False, native_spawn_position_verified=False,
            movement_direction_verified=False, playable_map_verified=False)

    def resolver(ticket, fields):
        if type(ticket) is not LocalMatchTicket or ticket.map_id != 2201:
            raise ValueError('Portable bootstrap requires its admitted local Dam ticket')
        if qualified_mode_ids is not None and ticket.match_mode_id not in qualified_mode_ids:
            raise ValueError('The admitted mode does not match the qualified SOL map context')
        pawn_fields = dict(actors['Pawn'].preflight.actor_fields)
        matches = [f for f in fields if f.get('actor_guid') == pawn_fields['actor_guid']]
        if len(matches) != 1 or matches[0] != pawn_fields:
            raise ValueError('Joined Pawn differs from its prepared local state')
        if select_spawn is not None:
            from dfserver.legacy_ds_quantized_vector import QuantizedVector10
            selected = select_spawn(ticket)
            from dfserver.legacy_ds_actor_manifest import preflight_actor_manifest
            manifest = replace(actors['Pawn'].manifest,
                location=QuantizedVector10(tuple(selected['quantized_steps'])),
                rotation=CompressedRotator16(tuple(selected['rotation_steps'])))
            pawn = preflight_actor_manifest(manifest, channel_sequence=actors['Pawn'].channel_sequence,
                max_packet_bytes=actors['Pawn'].max_packet_bytes)
            return tuple(dict(pawn.actor_fields) if f is matches[0] else dict(f) for f in fields)
        return tuple(dict(f) for f in fields)

    archive = documents['archive']
    pc_record = class_export(archive, PC, layout=True, cache=True)
    hud, hud_class_guid = None, None
    hud_source = config.get('controller_hud')
    if hud_source is not None:
        from portable_map_hud import hud_profile, add_hud_class_export
        hud = hud_profile(sealed_read(root, hud_source), pc_record, sources['archive']['sha256'])
        actors['PlayerController'], hud_class_guid = add_hud_class_export(actors, hud)
    pawn_record = class_export(archive, ROLE_CLASSES['Pawn'], layout=True)
    state_record = class_export(archive, GS, layout=True)
    world_sources, state_content = {}, build_empty_rep_layout_content()
    if config.get('world_state') is not None:
        from portable_map_world_state import mode_content
        world_sources = config['world_state']
        if set(world_sources) != {'schema', 'map_modes'}:
            raise ValueError('World state requires its native schema and observed map modes')
        world_documents = {k: json.loads(sealed_read(root, source)) for k, source in world_sources.items()}
        state_content, qualified_mode_ids = mode_content(world_documents['schema'], state_record,
            world_documents['map_modes'], config['map_id'])
    pc_path, pawn_path, gs_path = (actors[r].manifest.class_path for r in ('PlayerController', 'Pawn', 'GameState'))
    pc_refs = [ObjectReference(property_handle(pc_record, 'Pawn', opcode=8, serializer=0x10e8ed20), 2)]
    pawn_refs = [ObjectReference(property_handle(pawn_record, 'Controller', opcode=8, serializer=0x10e8ed20), 4)]
    if 'PlayerState' in actors:
        pc_refs.append(ObjectReference(property_handle(pc_record, 'PlayerState', opcode=8, serializer=0x10e8ed20), 8))
        pawn_refs.append(ObjectReference(property_handle(pawn_record, 'PlayerState', opcode=8, serializer=0x10e8ed20), 8))
    player_schema, admission_factory, player_sources = None, None, {}
    fashion_source, fashion_schema, component_guid = None, None, None
    if config.get('fashion_component') is not None:
        from portable_map_fashion import qualify_schema as qualify_fashion_schema
        fashion_source = config['fashion_component']
        fashion_schema = json.loads(sealed_read(root, fashion_source))
        qualify_fashion_schema(fashion_schema)
        allocated = {m.actor_guid for m in (a.manifest for a in actors.values())}
        allocated.update(b.guid for a in actors.values() for b in a.manifest.path_bindings)
        component_guid = next(g for g in range(2, 2*len(allocated)+4, 2) if g not in allocated)
    pawn_content = build_object_reference_content(tuple(sorted(pawn_refs, key=lambda f: f.handle)))
    if config.get('player_state') is not None:
        from portable_map_player_state import qualify_schema, appearance_content, identity_content
        from dfserver.legacy_ds_byte_scalar import build_byte_reference_content
        if 'PlayerState' not in actors:
            raise ValueError('The admitted appearance profile requires an observed PlayerState')
        player_sources = config['player_state']
        if set(player_sources) != {'schema', 'heroes', 'avatars'}:
            raise ValueError('The receiver schema and both native avatar catalogs are required')
        player_documents = {k: json.loads(sealed_read(root, source)) for k, source in player_sources.items()}
        player_schema = player_documents['schema']
        control_field, _ = qualify_schema(player_schema)
        pawn_content = build_byte_reference_content((control_field,),
            tuple(sorted(pawn_refs, key=lambda field: field.handle)))
        ps = actors['PlayerState'].manifest

        def admission_factory(player_id, hero_id, fashion_id, plans):
            if any(p['channel_index'] == ps.channel_index for p in plans):
                raise ValueError('Per-admission appearance cannot replace existing PlayerState content')
            content = appearance_content(player_schema, hero_id, fashion_id,
                player_documents['heroes'], player_documents['avatars'])
            if fashion_schema is not None:
                from portable_map_fashion import fashion_update
                pawn = actors['Pawn'].manifest
                matches = [p for p in plans if p['actor_guid'] == pawn.actor_guid]
                if len(matches) != 1 or 'default_subobject' in matches[0]:
                    raise ValueError('One unchanged Pawn content plan is required for default Fashion')
                update = fashion_update(fashion_schema, hero_id, fashion_id,
                    player_documents['heroes'], player_documents['avatars'],
                    actor_guid=pawn.actor_guid, component_guid=component_guid)
                prerequisites = (actors['PlayerController'].manifest.channel_index, ps.channel_index)
                plans = tuple(dict(p, default_subobject=update, after_content=prerequisites)
                              if p is matches[0] else dict(p) for p in plans)
            return plans + (dict(channel_index=ps.channel_index, actor_guid=ps.actor_guid,
                                 content_blocks=(identity_content(player_schema, player_id), content)),)

    if fashion_schema is not None and admission_factory is None:
        raise ValueError('Default Fashion requires per-admission player appearance')

    contents = tuple(dict(channel_index=actors[role].manifest.channel_index,
        actor_guid=actors[role].manifest.actor_guid,
        content_blocks=((pawn_content if role == 'Pawn' else
            build_object_reference_content(tuple(sorted(refs, key=lambda f: f.handle)))),))
        for role, refs in (('PlayerController', pc_refs), ('Pawn', pawn_refs)))
    contents += (dict(channel_index=actors['GameState'].manifest.channel_index,
        actor_guid=actors['GameState'].manifest.actor_guid,
        content_blocks=(state_content,)),)
    additional_manifests, gameplay_actor_sources = (), {}

    def current_namespace():
        manifests = tuple(a.manifest for a in actors.values()) + additional_manifests
        guids = {m.actor_guid for m in manifests}
        guids.update(b.guid for m in manifests for b in m.path_bindings)
        if component_guid is not None:
            guids.add(component_guid)
        return guids, {m.channel_index for m in manifests}

    def content_namespace(plans):
        used, _ = current_namespace()
        for plan in plans:
            updates = plan.get('default_subobjects', ())
            if 'default_subobject' in plan:
                updates += (plan['default_subobject'],)
            used.update(update.guid for update in updates)
            for group in plan.get('continuations', ()):
                used.update(update.guid for update in group if hasattr(update, 'guid'))
        return tuple(sorted(used))

    level_actor_source = config.get('level_actor_metadata_probe')
    if level_actor_source is not None:
        from portable_map_level_actors import level_actor_plans, level_actor_source_pins
        guids, channels = current_namespace()
        additional_manifests, extra_contents = level_actor_plans(root,
            sealed_read(root, level_actor_source), used_guids=guids, used_channels=channels,
            channel_sequence=1023, max_packet_bytes=1024)
        contents += extra_contents
        gameplay_actor_sources.update(level_actor_source_pins(root))
        gameplay_actor_sources[level_actor_source['relative_path']] = level_actor_source['sha256']
    weapon = None
    weapon_actor_source = config.get('owned_weapon_metadata_probe')
    if weapon_actor_source is not None:
        from portable_map_owned_weapon import empty_hand_actor_manifest
        from owned_weapon_values_codec import schema_binding
        weapon_schema = json.loads(sealed_read(root, weapon_actor_source))
        if weapon_schema != schema_binding():
            raise ValueError('The current weapon native source schema is required')
        guids, channels = current_namespace()
        asset_guids = tuple(g for g in range(3, 2*len(guids)+11, 2) if g not in guids)[:3]
        actor_guid = next(g for g in range(2, 2*len(guids)+6, 2) if g not in guids)
        pawn = actors['Pawn'].manifest
        weapon = empty_hand_actor_manifest(weapon_schema, parent_manifest=pawn,
            package_guid=asset_guids[0], class_guid=asset_guids[1], archetype_guid=asset_guids[2],
            actor_guid=actor_guid, channel_index=next(c for c in range(2, 65) if c not in channels),
            allocated_guids=tuple(sorted(guids)), allocated_channels=tuple(sorted(channels)),
            location=pawn.location, rotation=pawn.rotation, scale=pawn.scale, velocity=pawn.velocity)
        additional_manifests += (weapon,)
        contents += (dict(channel_index=weapon.channel_index, actor_guid=weapon.actor_guid,
                          content_blocks=(build_empty_rep_layout_content(),)),)
        gameplay_actor_sources.update(weapon_schema['sources'])
        gameplay_actor_sources[weapon_actor_source['relative_path']] = weapon_actor_source['sha256']
    component_probe_sources = {}
    component_probe = config.get('default_component_metadata_probe')
    if component_probe is not None:
        from portable_map_gameplay_probe import qualify_schema as qualify_probe, empty_updates
        if admission_factory is None:
            raise ValueError('Component metadata sampling requires the per-admission Pawn owner')
        probe_schema = json.loads(sealed_read(root, component_probe))
        qualify_probe(probe_schema)
        component_probe_sources[component_probe['relative_path']] = component_probe['sha256']
        for relative, expected in probe_schema['sources'].items():
            sealed_read(root, dict(relative_path=relative, sha256=expected))
            component_probe_sources[relative] = expected
        for source in probe_schema['cooked_sources']:
            sealed_read(root, source)
            component_probe_sources[source['relative_path']] = source['sha256']
        allocated, _ = current_namespace()
        allocated.discard(component_guid)
        allocated = tuple(sorted(allocated))
        appearance_factory = admission_factory

        def admission_factory(player_id, hero_id, fashion_id, plans):
            plans = appearance_factory(player_id, hero_id, fashion_id, plans)
            pawn = actors['Pawn'].manifest
            entries = [p for p in plans if p['actor_guid'] == pawn.actor_guid]
            if len(entries) != 1 or 'default_subobjects' in entries[0]:
                raise ValueError('Component sampling requires one unchanged Pawn content plan')
            entry = dict(entries[0])
            existing = (entry.pop('default_subobject'),) if 'default_subobject' in entry else ()
            current_allocated = current_namespace()[0]
            current_allocated.discard(component_guid)
            entry['default_subobjects'] = empty_updates(probe_schema, actor_guid=pawn.actor_guid,
                allocated_guids=tuple(sorted(current_allocated)), existing_updates=existing)
            return tuple(entry if p is entries[0] else dict(p) for p in plans)
    vitals_probe = config.get('vitals_component_metadata_probe')
    if vitals_probe is not None:
        from portable_map_vitals_probe import qualify_schema as qualify_vitals, empty_vitals_updates
        if component_probe is None or admission_factory is None:
            raise ValueError('Vitals metadata sampling requires the ordinary owned component profile')
        vitals_schema = json.loads(sealed_read(root, vitals_probe))
        qualify_vitals(vitals_schema)
        component_probe_sources[vitals_probe['relative_path']] = vitals_probe['sha256']
        for relative, expected in vitals_schema['sources'].items():
            sealed_read(root, dict(relative_path=relative, sha256=expected))
            component_probe_sources[relative] = expected
        for source in vitals_schema['cooked_sources']:
            sealed_read(root, source)
            component_probe_sources[source['relative_path']] = source['sha256']
        before_vitals = admission_factory

        def vitals_factory(player_id, hero_id, fashion_id, plans):
            plans = before_vitals(player_id, hero_id, fashion_id, plans)
            pawn = actors['Pawn'].manifest
            entries = [p for p in plans if p['actor_guid'] == pawn.actor_guid]
            if len(entries) != 1:
                raise ValueError('Vitals sampling requires one unchanged Pawn content plan')
            entry = dict(entries[0])
            group = empty_vitals_updates(vitals_schema, actor_guid=pawn.actor_guid,
                                        allocated_guids=content_namespace(plans))
            entry['continuations'] = entry.get('continuations', ()) + (group,)
            return tuple(entry if p is entries[0] else dict(p) for p in plans)

        admission_factory = vitals_factory
    marker_probe = config.get('map_marker_component_metadata_probe')
    if marker_probe is not None:
        from portable_map_marker_probe import empty_map_marker_updates, map_marker_probe_source_pins
        if admission_factory is None or 'PlayerState' not in actors:
            raise ValueError('Map component sampling requires the admitted native PlayerState profile')
        marker_schema = json.loads(sealed_read(root, marker_probe))
        component_probe_sources.update(map_marker_probe_source_pins(root, marker_schema))
        component_probe_sources[marker_probe['relative_path']] = marker_probe['sha256']
        before_markers = admission_factory

        def marker_factory(player_id, hero_id, fashion_id, plans):
            plans = before_markers(player_id, hero_id, fashion_id, plans)
            updates = empty_map_marker_updates(marker_schema,
                game_state_guid=actors['GameState'].manifest.actor_guid,
                player_state_guid=actors['PlayerState'].manifest.actor_guid,
                allocated_guids=content_namespace(plans))
            for update in updates:
                entries = [p for p in plans if p['actor_guid'] == update.actor_guid]
                if len(entries) != 1 or 'default_subobject' in entries[0] or 'default_subobjects' in entries[0]:
                    raise ValueError('Map component sampling requires one unchanged parent content plan')
                entry = dict(entries[0], default_subobject=update)
                plans = tuple(entry if p is entries[0] else dict(p) for p in plans)
            return plans

        admission_factory = marker_factory
    fsm_probe = config.get('fsm_default_component_metadata_probe')
    fsm_creation = config.get('fsm_empty_instance_creation')
    fsm_replica = config.get('fsm_replica_initialization', False)
    if type(fsm_replica) is not bool or fsm_replica and fsm_creation is None:
        raise ValueError('FSM replica initialization requires explicit enablement and qualified instance creation')
    if fsm_replica:
        from portable_fsm_replica_initialization import (project_updates as project_fsm_updates,
            source_pins as fsm_replica_sources)
        component_probe_sources.update(fsm_replica_sources())
    fsm_allocation = {}
    if fsm_creation is not None and fsm_probe is None:
        raise ValueError('Dynamic FSM creation requires its preceding default-component metadata stage')
    if fsm_probe is not None:
        from portable_map_fsm_kickoff import (schema_binding as fsm_schema_binding,
            source_pins as fsm_source_pins, project_fsm_kickoff_update)
        if admission_factory is None or component_probe is None:
            raise ValueError('FSM metadata requires the current admitted Pawn component profile')
        if json.loads(sealed_read(root, fsm_probe)) != fsm_schema_binding():
            raise ValueError('FSM metadata requires its exact qualified default-component schema')
        component_probe_sources.update(fsm_source_pins())
        if fsm_creation is not None:
            from portable_map_fsm_instance import (project_instance_class_export,
                project_instance_creation, source_pins as instance_sources, CLASS_PATH as FSM_CLASS_PATH)
            from qualify_fsm_creation_scope_1792385022786009500 import (
                derive as current_fsm_proof, PINS as fsm_proof_pins, SNAPSHOTS as fsm_proof_snapshots)
            from dfserver.legacy_ds_actor_manifest import GuidPathBinding, preflight_actor_manifest
            if json.loads(sealed_read(root, fsm_creation)) != current_fsm_proof():
                raise ValueError('The current main FSM class/CDO creation proof changed')
            component_probe_sources.update(instance_sources())
            component_probe_sources.update(fsm_proof_pins)
            for relative in ('work/qualify_fsm_creation_scope_1792385022786009500.py',
                             *fsm_proof_snapshots.values()):
                component_probe_sources[relative] = hashlib.sha256((root/relative).read_bytes()).hexdigest()
            component_probe_sources[fsm_creation['relative_path']] = fsm_creation['sha256']
            used, _ = current_namespace()
            static = tuple(g for g in range(3, 2 * len(used) + 9, 2) if g not in used)[:2]
            fsm_export = project_instance_class_export(package_guid=static[0], class_guid=static[1],
                allocated_guids=tuple(sorted(used)))
            bootstrap = actors['Pawn']
            manifest = replace(bootstrap.manifest, exports=bootstrap.manifest.exports+(fsm_export,),
                path_bindings=bootstrap.manifest.path_bindings + (
                    GuidPathBinding(static[0], fsm_export.outer.path),
                    GuidPathBinding(static[1], FSM_CLASS_PATH, '.')))
            preflight = preflight_actor_manifest(manifest, channel_sequence=bootstrap.channel_sequence,
                max_packet_bytes=bootstrap.max_packet_bytes)
            actors['Pawn'] = replace(bootstrap, manifest=manifest, preflight=preflight)
        before_fsm = admission_factory

        def fsm_factory(player_id, hero_id, fashion_id, plans):
            plans = before_fsm(player_id, hero_id, fashion_id, plans)
            pawn = actors['Pawn'].manifest
            entry, = [p for p in plans if p['actor_guid'] == pawn.actor_guid]
            allocated = content_namespace(plans)
            fresh = next(g for g in range(2, 2 * len(allocated) + 4, 2) if g not in allocated)
            update = project_fsm_kickoff_update(pawn_guid=pawn.actor_guid,
                component_guid=fresh, allocated_guids=allocated)
            parent = dict(entry)
            tails = parent.get('continuations', ())
            parent['continuations'] = tails + ((update,),)
            if 'continuation_after_content_stages' in parent:
                parent['continuation_after_content_stages'] += ((),)
            if fsm_creation is not None:
                used = tuple(sorted((*allocated, fresh)))
                instance_guid = next(g for g in range(2, 2 * len(used) + 4, 2) if g not in used)
                instance = project_instance_creation(pawn_guid=pawn.actor_guid, class_guid=fsm_export.guid,
                    instance_guid=instance_guid, allocated_guids=used)
                parent['continuations'] += ((instance,),)
                if 'continuation_after_content_stages' in parent:
                    parent['continuation_after_content_stages'] += ((),)
                fsm_allocation.clear()
                fsm_allocation.update(actor_guid=pawn.actor_guid, guid=instance_guid,
                    class_guid=fsm_export.guid, class_path=instance.class_path,
                    source_sha256=instance.source_sha256, allocated_guids=list(used))
                if fsm_replica:
                    updates = project_fsm_updates(pawn_guid=pawn.actor_guid, component_guid=fresh,
                        instance_guid=instance_guid, class_guid=fsm_export.guid,
                        allocated_guids=tuple(sorted((*used, instance_guid))))
                    parent['continuations'] += tuple((item,) for item in updates)
                    if 'continuation_after_content_stages' in parent:
                        parent['continuation_after_content_stages'] += tuple(() for _ in updates)
            return tuple(parent if p is entry else dict(p) for p in plans)

        admission_factory = fsm_factory
    inventory_factory, inventory_sources = None, {}
    inventory_config = config.get('native_inventory_content')
    if inventory_config is not None:
        from portable_map_inventory_content import build_content_groups, source_pins as inventory_source_pins
        if component_probe is None or admission_factory is None:
            raise ValueError('Native inventory requires the qualified owned InventoryManager profile')
        if set(inventory_config) != {'schema', 'valuation_policy'}:
            raise ValueError('Inventory schema and explicit local valuation policy are required')
        inventory_raw_schema = sealed_read(root, inventory_config['schema'])
        policy = inventory_config['valuation_policy']
        if (type(policy) is not dict or set(policy) != {'kind', 'values'} or
                policy['kind'] != 'explicit_local_fixed_values' or type(policy['values']) is not list or
                len(policy['values']) != 7 or any(type(v) is not int or v != 0 for v in policy['values'])):
            raise ValueError('Seven explicit local zero inventory valuation values are required')
        value_fields = tuple(policy['values'])
        inventory_sources.update(inventory_source_pins())
        source = inventory_config['schema']
        inventory_sources[source['relative_path']] = source['sha256']

        def inventory_factory(player_id, hero_id, fashion_id, raw_snapshot, plans):
            if type(raw_snapshot) is not bytes or not 0 < len(raw_snapshot) <= 1024*1024:
                raise ValueError('The immutable admitted carried loadout is required')
            snapshot = json.loads(raw_snapshot)
            if (snapshot.get('selected_hero_id') != hero_id or
                    snapshot.get('selected_fashion_id') != fashion_id):
                raise ValueError('Carried inventory and admitted appearance must share one snapshot')
            pawn = actors['Pawn'].manifest
            entries = [p for p in plans if p['actor_guid'] == pawn.actor_guid]
            if len(entries) != 1:
                raise ValueError('Native inventory requires one qualified Pawn content plan')
            entry = dict(entries[0])
            components = [u for u in entry.get('default_subobjects', ()) if u.name == 'InventoryManager']
            if len(components) != 1 or components[0].actor_guid != pawn.actor_guid:
                raise ValueError('Native inventory requires the exact current default component binding')
            groups = build_content_groups(raw_snapshot, pawn_guid=pawn.actor_guid,
                component_guid=components[0].guid, value_fields=value_fields,
                owner_player_id=player_id, schema=inventory_raw_schema)
            entry['continuations'] = entry.get('continuations', ()) + groups
            return tuple(entry if p is entries[0] else dict(p) for p in plans)
    ticket_factory = None
    skill_init = config.get('skill_detail_initialization')
    skill_context_init = config.get('skill_context_initialization')
    skill_entities_init = config.get('skill_entity_initialization')
    skill_gs_creation = config.get('skill_game_state_component_creation')
    skill_template_authority = config.get('skill_template_authority', False)
    if (type(skill_template_authority) is not bool or skill_template_authority and
            (skill_entities_init is None or skill_gs_creation is None)):
        raise ValueError('Skill template authority requires the actual entity grant and GS component creation')
    if skill_template_authority:
        from skill_template_authority import (SkillTemplateAuthorityStore, source_pins as authority_sources,
            template_support_for_hero)
        from skill_template_replication import (source_schema as template_schema,
            project_update as template_update, source_pins as template_sources)
        if skill_template_store is None:
            skill_template_store = SkillTemplateAuthorityStore(root/'work/local-state/skill-templates.sqlite3')
        if type(skill_template_store) is not SkillTemplateAuthorityStore:
            raise ValueError('A persistent skill template authority store is required')
        component_probe_sources.update(authority_sources())
        component_probe_sources.update(template_sources())
    if skill_gs_creation is not None:
        if skill_context_init is None or skill_entities_init is None:
            raise ValueError('Dynamic GS ability creation requires the qualified owner context and entity stages')
        from current_skill_gs_dynamic_component import (schema_binding as gs_creation_binding,
            component_manifest as gs_component_manifest, projected_creation_update)
        from dfserver.legacy_ds_ability_component_creation import AbilityComponentCreation, SOURCE_SHA256
        gs_creation_schema = gs_creation_binding(root)
        if (skill_gs_creation['sha256'] != SOURCE_SHA256 or
                json.loads(sealed_read(root, skill_gs_creation)) != gs_creation_schema):
            raise ValueError('The dynamic GS ability profile differs from the actual native creation source')
        component_probe_sources.update({row['relative_path']: row['sha256']
                                        for row in gs_creation_schema['sources']})
        component_probe_sources[skill_gs_creation['relative_path']] = skill_gs_creation['sha256']
    if skill_context_init is not None and skill_init is None:
        raise ValueError('Combined skill context requires its qualified detail schema')
    if skill_entities_init is not None and skill_context_init is None:
        raise ValueError('Skill entities require their preceding qualified owner context')
    if skill_init is not None:
        if vitals_probe is None:
            raise ValueError('Skill detail requires the acknowledged actual default skill component')
        from portable_map_skill_detail import schema_binding, skill_detail_update
        skill_schema = schema_binding(root)
        if json.loads(sealed_read(root, skill_init)) != skill_schema:
            raise ValueError('Skill detail profile differs from the qualified receiver')
        component_probe_sources.update(skill_schema['sources'])
        component_probe_sources[skill_init['relative_path']] = skill_init['sha256']
        skill_index_schema = None
        if skill_context_init is not None:
            from portable_map_skill_context import schema_binding as context_binding, skill_context_update
            from portable_map_skill_player_index import schema_binding as index_binding, initial_assignment
            if select_spawn is None:
                raise ValueError('Initial skill index requires the qualified one-participant room policy')
            context_schema = context_binding(root)
            if json.loads(sealed_read(root, skill_context_init)) != context_schema:
                raise ValueError('The combined skill context profile differs from its receiver')
            skill_index_schema = index_binding(root)
            component_probe_sources.update(context_schema['sources'])
            component_probe_sources[skill_context_init['relative_path']] = skill_context_init['sha256']
        if skill_entities_init is not None:
            from skill_initial_state_values import schema_binding as entity_binding, owner_initial_update
            from portable_skill_entity_admission import prepare_grant
            from skill_entity_id_ledger import SkillEntityIdLedger
            entity_schema = entity_binding(root)
            if json.loads(sealed_read(root, skill_entities_init)) != entity_schema:
                raise ValueError('The skill entity profile differs from its qualified receiver')
            if skill_id_ledger is None:
                skill_id_ledger = SkillEntityIdLedger(root/'work/local-state/skill-entity-ids.sqlite3')
            if type(skill_id_ledger) is not SkillEntityIdLedger:
                raise ValueError('A persistent local skill instance ledger is required')
            component_probe_sources.update(entity_schema['sources'])
            component_probe_sources[skill_entities_init['relative_path']] = skill_entities_init['sha256']

        def initialize_skill(ticket, plans):
            pawn = actors['Pawn'].manifest
            entries = [p for p in plans if p['actor_guid'] == pawn.actor_guid]
            if len(entries) != 1:
                raise ValueError('Skill initialization requires the exact admitted Pawn')
            parent = dict(entries[0])
            tails = parent.get('continuations', ())
            bindings = [(index, update) for index, group in enumerate(tails, 1)
                        for update in group if update.name == skill_schema['component']['name']]
            if len(bindings) != 1:
                raise ValueError('Skill initialization requires one preceding component metadata stage')
            metadata_stage, component = bindings[0]
            if not 1 <= metadata_stage <= len(tails):
                raise ValueError('Skill component metadata must precede its values')
            if skill_index_schema is None:
                update = skill_detail_update(skill_schema, hero_id=ticket.selected_hero_id,
                    pawn_guid=pawn.actor_guid, component_guid=component.guid,
                    pawn_open_acknowledged=True, component_metadata_acknowledged=True)
            else:
                assignment = initial_assignment(skill_index_schema, room_id=str(ticket.room_id),
                    participant_uids=(ticket.player_id,), existing_native_slots=())
                update = skill_context_update(skill_schema, skill_index_schema, assignment=assignment,
                    hero_id=ticket.selected_hero_id, room_id=str(ticket.room_id), participant_uid=ticket.player_id,
                    pawn_guid=pawn.actor_guid, component_guid=component.guid,
                    pawn_open_acknowledged=True, component_metadata_acknowledged=True)
            updates = ((update,),)
            if skill_entities_init is not None:
                grant = prepare_grant(entity_schema, ticket=ticket, assignment=assignment,
                                      ledger=skill_id_ledger)
                entities = owner_initial_update(entity_schema, grant=grant, room_id=str(ticket.room_id),
                    participant_uid=ticket.player_id, hero_id=ticket.selected_hero_id,
                    pawn_guid=pawn.actor_guid, component_guid=component.guid,
                    pawn_open_acknowledged=True, component_metadata_acknowledged=True,
                    skill_context_acknowledged=True)
                updates += ((entities,),)
            dependencies = parent.get('continuation_after_content_stages', tuple(() for _ in tails))
            entity_dependencies = ()
            if skill_gs_creation is not None:
                gs = actors['GameState'].manifest
                stages = [(index, update) for plan in plans if plan['actor_guid'] == gs.actor_guid
                    for index, group in enumerate(plan.get('continuations', ()), 1)
                    for update in group if type(update) is AbilityComponentCreation]
                if len(stages) != 1:
                    raise ValueError('Owner skills require one preceding dynamic GS ability creation stage')
                entity_dependencies = ((gs.channel_index, stages[0][0]),)
                if skill_template_authority and template_support_for_hero(ticket.selected_hero_id).supported:
                    materialized = skill_template_store.materialize(ticket=ticket, grant=grant)
                    creation = stages[0][1]
                    namespace = tuple(sorted(set(content_namespace(plans)) | {creation.class_guid}))
                    template = template_update(template_schema(), plan=materialized.plan,
                        actor_guid=gs.actor_guid, component_guid=creation.guid,
                        class_guid=creation.class_guid, allocated_guids=namespace)
                    state_entry, = [p for p in plans if p['actor_guid'] == gs.actor_guid]
                    state = dict(state_entry)
                    state_tails = state.get('continuations', ())
                    state_deps = state.get('continuation_after_content_stages', tuple(() for _ in state_tails))
                    state['continuations'] = state_tails + ((template,),)
                    state['continuation_after_content_stages'] = state_deps + ((),)
                    plans = tuple(state if p is state_entry else p for p in plans)
                    entity_dependencies = ((gs.channel_index, len(state_tails)+1),)
            parent['continuations'] = tails + updates
            # Earlier stages on this reliable channel are implicit ACK prerequisites.
            parent['continuation_after_content_stages'] = dependencies + tuple(entity_dependencies for _ in updates)
            return tuple(parent if p is entries[0] else dict(p) for p in plans)

        ticket_factory = initialize_skill
    weapon_init = config.get('owned_weapon_initialization')
    modular_init = config.get('modular_weapon_initialization')
    modular_recipe = config.get('modular_weapon_recipe')
    weapon_timeline = config.get('owned_weapon_switch_timeline')
    equipment_positions = config.get('owned_weapon_equipment_positions', False)
    if type(equipment_positions) is not bool or equipment_positions and modular_recipe is None:
        raise ValueError('Equipment positions require an explicit boolean and complete Modular recipes')
    if modular_recipe is not None and modular_init is None:
        raise ValueError('A Modular recipe requires its qualified Actor identity and owner initialization')
    initial_weapon_policy = config.get('initial_weapon_policy')
    if weapon_timeline is not None:
        policy = weapon_timeline.get('policy') if type(weapon_timeline) is dict else None
        if (modular_recipe is None or initial_weapon_policy is None or
                type(weapon_timeline) is not dict or set(weapon_timeline) != {'schema', 'policy'} or
                type(policy) is not dict or set(policy) != {'kind', 'frame_no', 'world_time', 'clock_origin'} or
                policy['kind'] != 'fresh_local_initial_instant_switch' or
                type(policy['frame_no']) is not int or policy['frame_no'] != 1 or
                type(policy['world_time']) not in (int, float) or policy['world_time'] != 0.0 or
                policy['clock_origin'] != 'local_match_initial_epoch'):
            raise ValueError('The initial owner timeline requires complete recipes, selection and an explicit fresh local epoch')
    if initial_weapon_policy is not None and (modular_init is None or initial_weapon_policy != dict(
            kind='explicit_local_initial_equipped_weapon', priority=['MainWeaponLeft','MainWeaponRight'],
            manager_slot='source_native_constructor_default')):
        raise ValueError('An explicit source-qualified initial equipped weapon policy is required')
    if modular_init is not None and weapon_init is None:
        raise ValueError('Modular initialization requires its exact EmptyHand and manager baseline')
    if weapon_init is not None:
        if weapon is None or component_probe is None or inventory_factory is None:
            raise ValueError('Weapon initialization requires its actual Actor and frozen owned inventory')
        from portable_map_owned_weapon import empty_hand_initialization, owned_weapon_actor_source_pins
        from owned_weapon_values_codec import qualify_actor_schema
        actor_schema = qualify_actor_schema(json.loads(sealed_read(root, weapon_init)))
        gameplay_actor_sources.update(owned_weapon_actor_source_pins())
        gameplay_actor_sources[weapon_init['relative_path']] = weapon_init['sha256']
        if modular_init is not None:
            from portable_modular_weapon_initialization import (initialize as initialize_modular,
                schema_binding as modular_binding, source_pins as modular_sources)
            if (config.get('carried_weapon_actor_metadata_probe') is None or
                    json.loads(sealed_read(root, modular_init)) != modular_binding()):
                raise ValueError('Modular initialization requires its actual equipped Actor receiver')
            gameplay_actor_sources.update(modular_sources())
            if initial_weapon_policy is not None:
                from weapon_native_default_slot import native_default_slot_policy, source_pins as slot_sources
                gameplay_actor_sources.update(slot_sources())
        if modular_recipe is not None:
            from modular_weapon_recipe_codec import schema_binding as recipe_binding
            from portable_modular_weapon_recipe import build as build_recipes, source_pins as recipe_sources
            if json.loads(sealed_read(root, modular_recipe)) != recipe_binding():
                raise ValueError('The physical Modular recipe differs from its actual receiver schema')
            gameplay_actor_sources.update(recipe_sources())
        if equipment_positions:
            from portable_weapon_equipment_position import (
                project_equipment_positions, source_pins as equipment_position_sources)
            gameplay_actor_sources.update(equipment_position_sources())
        if weapon_timeline is not None:
            from weapon_switch_timeline_codec import (schema_binding as timeline_binding,
                LocalInitialSwitchClock)
            from portable_weapon_switch_timeline import build as build_timeline, source_pins as timeline_sources
            if json.loads(sealed_read(root, weapon_timeline['schema'])) != timeline_binding():
                raise ValueError('The owner-switch timeline differs from its source-qualified native receiver')
            gameplay_actor_sources.update(timeline_sources())
        before_weapon_initialization = ticket_factory

        def initialize_weapons(ticket, plans):
            if before_weapon_initialization is not None:
                plans = before_weapon_initialization(ticket, plans)
            pawn = actors['Pawn'].manifest
            entries = [p for p in plans if p['actor_guid'] == pawn.actor_guid]
            weapon_entries = [p for p in plans if p['actor_guid'] == weapon.actor_guid]
            if len(entries) != 1 or len(weapon_entries) != 1:
                raise ValueError('Owned weapon stages need their exact admitted Pawn and Actor')
            parent = dict(entries[0])
            by_name = {u.name: u for u in parent.get('default_subobjects', ())}
            if not {'WeaponManager', 'WeaponReplicate'} <= by_name.keys():
                raise ValueError('Owned weapon stages require the actual default-component GUIDs')
            if modular_init is None:
                initialized = empty_hand_initialization(ticket, pawn_guid=pawn.actor_guid,
                    weapon_guid=weapon.actor_guid, manager_component_guid=by_name['WeaponManager'].guid,
                    replicate_component_guid=by_name['WeaponReplicate'].guid,
                    pawn_open_acknowledged=True, weapon_open_acknowledged=True,
                    initial_state_is_fresh=True, manager_binding_snapshot_complete=True,
                    actor_schema=actor_schema)
            else:
                from portable_carried_weapon_selection import select, binding as selection_binding
                from portable_melee_weapon import select as select_melee
                guns = select(ticket).guns
                melee = select_melee(ticket)
                base_guids = {m.actor_guid for m in (
                    *(a.manifest for a in actors.values()), *additional_manifests)}
                gun_entries = [p for p in plans if p['actor_guid'] not in base_guids]
                if len(gun_entries) != len(guns)+int(melee is not None):
                    raise ValueError('The complete current equipped gun Actor set is required')
                melee_entry = gun_entries[-1] if melee is not None else None
                gun_entries = gun_entries[:len(guns)]
                policy_arguments = {}
                if initial_weapon_policy is not None:
                    slots = selection_binding()['business_slots']
                    initial = next((gun for name in initial_weapon_policy['priority'] for gun in guns
                                    if gun.business_position == slots[name]), None)
                    policy_arguments = dict(native_slot_policy=native_default_slot_policy(),
                        initial_active_inventory_gid=None if initial is None else initial.inventory_gid)
                initialized = initialize_modular(ticket, pawn_guid=pawn.actor_guid,
                    empty_hand_guid=weapon.actor_guid,
                    gun_allocations=tuple((gun.inventory_gid, entry['actor_guid'])
                        for gun,entry in zip(guns,gun_entries)),
                    manager_component_guid=by_name['WeaponManager'].guid,
                    replicate_component_guid=by_name['WeaponReplicate'].guid,
                    pawn_open_acknowledged=True, weapon_opens_acknowledged=True,
                    initial_state_is_fresh=True, manager_binding_snapshot_complete=True,
                    melee_actor_guid=None if melee_entry is None else melee_entry['actor_guid'], **policy_arguments)
            recipes = {}
            if modular_recipe is not None:
                recipes = {value.actor_guid: value for value in build_recipes(ticket,
                    gun_allocations=tuple((gun.inventory_gid, entry['actor_guid'])
                        for gun,entry in zip(guns,gun_entries)),
                    known_actor_guids=tuple(p['actor_guid'] for p in plans),
                    actor_opens_acknowledged=True, identity_and_owner_acknowledged=True,
                    initial_state_is_fresh=True, max_packet_bytes=1024)}
            positions = {}
            recipe_coordinates = {actor_guid: (next(p['channel_index'] for p in plans
                if p['actor_guid'] == actor_guid), 1) for actor_guid in recipes}
            if equipment_positions:
                positions = {value.actor_guid: value for value in project_equipment_positions(ticket,
                    initialization=initialized, recipe_updates=tuple(recipes.values()),
                    known_actor_guids=tuple(p['actor_guid'] for p in plans))}
            position_coordinates = tuple((channel, 2) for channel, _ in recipe_coordinates.values())
            replacements, updates = {}, []
            coordinates = {}
            tail_dependencies = []
            tails = parent.get('continuations', ())
            for index, stage in enumerate(initialized.stages):
                previous = ((pawn.channel_index,0) if stage.after_stage is None else
                            coordinates.get(stage.after_stage))
                if previous is None:
                    raise ValueError('Weapon stages require a completed preceding initialization stage')
                if stage.actor_content is not None:
                    matching = [p for p in plans if p['actor_guid']==stage.actor_guid]
                    if len(matching)!=1:
                        raise ValueError('Weapon Actor content requires its exact current channel')
                    entry = dict(matching[0], content_blocks=(stage.actor_content,))
                    entry['after_content_stages'] = tuple(dict.fromkeys(
                        entry.get('after_content_stages',())+(previous,)))
                    if stage.actor_guid in recipes:
                        if entry.get('continuations'):
                            raise ValueError('A fresh Modular identity must precede its complete initial recipe')
                        entry['continuations'] = ((recipes[stage.actor_guid].actor_content,),)
                        entry['continuation_after_content_stages'] = ((),)
                        if stage.actor_guid in positions:
                            entry['continuations'] += ((positions[stage.actor_guid].actor_content,),)
                            entry['continuation_after_content_stages'] += (tuple(
                                coordinate for guid, coordinate in recipe_coordinates.items()
                                if guid != stage.actor_guid),)
                    replacements[stage.actor_guid] = entry
                    coordinates[index] = (entry['channel_index'],
                                          1 if stage.actor_guid in recipes else 0)
                else:
                    updates.append(stage.updates)
                    coordinates[index] = (pawn.channel_index,len(tails)+len(updates))
                    needs = (previous,) if previous[0] != pawn.channel_index else ()
                    # The manager's constructor slot precedes gun identities;
                    # only later manager updates can wait on gun positions.
                    if equipment_positions and stage.name != 'manager_slot':
                        needs += position_coordinates
                    by_channel = {}
                    for channel, required_stage in needs:
                        by_channel[channel] = max(required_stage, by_channel.get(channel, -1))
                    tail_dependencies.append(tuple(by_channel.items()))
            if weapon_timeline is not None:
                switch = build_timeline(ticket, pawn_guid=pawn.actor_guid,
                    manager_component_guid=by_name['WeaponManager'].guid,
                    replicate_component_guid=by_name['WeaponReplicate'].guid,
                    initialization=initialized, known_actor_guids=tuple(p['actor_guid'] for p in plans),
                    recipe_updates=tuple(recipes.values()),
                    clock=LocalInitialSwitchClock(weapon_timeline['policy']['frame_no'],
                                                 weapon_timeline['policy']['world_time']),
                    actor_opens_acknowledged=True, all_initialization_stages_acknowledged=True,
                    complete_recipes_acknowledged=True, initial_state_is_fresh=True,
                    max_packet_bytes=1024)
                updates.append((switch.update,))
                # The same channel's preceding Active stage must receive its
                # own full-send ACK before the normal owner timeline is sent.
                tail_dependencies.append(())
            dependencies = parent.get('continuation_after_content_stages', tuple(() for _ in tails))
            parent['continuations'] = tails + tuple(updates)
            parent['continuation_after_content_stages'] = dependencies + tuple(tail_dependencies)
            return tuple(parent if p is entries[0] else replacements.get(p['actor_guid'],dict(p)) for p in plans)
        ticket_factory = initialize_weapons
    admission_actor_factory = None
    carried_probe = config.get('carried_weapon_actor_metadata_probe')
    if carried_probe is not None:
        if inventory_factory is None:
            raise ValueError('Carried weapon Actors require the exact frozen native inventory')
        from portable_carried_weapon_actor import actor_probes, source_pins as carried_actor_sources
        from portable_carried_weapon_selection import binding as carried_binding, select as carried_selection
        from portable_melee_weapon import (select as melee_selection,
            actor_probe as melee_actor_probe, source_pins as melee_sources)
        if json.loads(sealed_read(root, carried_probe)) != carried_binding():
            raise ValueError('Carried weapon Actor profile differs from its installed class sources')
        gameplay_actor_sources.update(carried_actor_sources())
        gameplay_actor_sources.update(melee_sources())

        def allocate_carried_actors(ticket, manifests, plans):
            guns = carried_selection(ticket).guns
            melee = melee_selection(ticket)
            if not guns and melee is None:
                return manifests, plans
            if len(manifests)+len(guns)+int(melee is not None) > 16:
                raise ValueError('The exact equipped gun set exceeds the initial Actor bound')
            used = set(content_namespace(plans))
            used.update(m.actor_guid for m in manifests)
            used.update(b.guid for m in manifests for b in m.path_bindings)
            channels = {m.channel_index for m in manifests}
            static = tuple(g for g in range(3, 2*len(used)+15, 2) if g not in used)[:3]
            dynamic = tuple(g for g in range(2, 2*len(used)+10, 2) if g not in used)[:len(guns)]
            free_channels = tuple(c for c in range(2,65) if c not in channels)[:len(guns)]
            if len(static)!=3 or len(dynamic)!=len(guns) or len(free_channels)!=len(guns):
                raise ValueError('No distinct bounded GUID/channel allocation for the equipped gun set')
            pawn = actors['Pawn'].manifest
            location, rotation = pawn.location, pawn.rotation
            if select_spawn is not None:
                from dfserver.legacy_ds_quantized_vector import QuantizedVector10
                selected = select_spawn(ticket)
                location = QuantizedVector10(tuple(selected['quantized_steps']))
                rotation = CompressedRotator16(tuple(selected['rotation_steps']))
            probes = () if not guns else actor_probes(ticket, allocations=tuple(
                (gun.inventory_gid, guid, channel) for gun,guid,channel in zip(guns,dynamic,free_channels)),
                parent_manifest=pawn, package_guid=static[0], class_guid=static[1], archetype_guid=static[2],
                allocated_guids=tuple(sorted(used)), allocated_channels=tuple(sorted(channels)),
                location=location, rotation=rotation, scale=pawn.scale, velocity=pawn.velocity)
            manifests = manifests+tuple(p.manifest for p in probes)
            plans = plans+tuple(dict(
                channel_index=p.manifest.channel_index, actor_guid=p.manifest.actor_guid,
                content_blocks=(p.initial_content,), after_content_stages=((pawn.channel_index,0),))
                for p in probes)
            if melee is not None:
                used = set(content_namespace(plans))
                used.update(m.actor_guid for m in manifests)
                used.update(b.guid for m in manifests for b in m.path_bindings)
                channels = {m.channel_index for m in manifests}
                static = tuple(g for g in range(3, 2*len(used)+15, 2) if g not in used)[:3]
                guid = next(g for g in range(2, 2*len(used)+10, 2) if g not in used)
                channel = next(c for c in range(2,65) if c not in channels)
                manifest, block = melee_actor_probe(ticket, parent_manifest=pawn,
                    package_guid=static[0], class_guid=static[1], archetype_guid=static[2],
                    actor_guid=guid, channel_index=channel, allocated_guids=tuple(sorted(used)),
                    allocated_channels=tuple(sorted(channels)), location=location,
                    rotation=rotation, scale=pawn.scale, velocity=pawn.velocity)
                manifests += (manifest,)
                plans += (dict(channel_index=channel, actor_guid=guid, content_blocks=(block,),
                    after_content_stages=((pawn.channel_index,0),)),)
            return manifests, plans

        admission_actor_factory = allocate_carried_actors
    if skill_gs_creation is not None:
        before_gs_creation = admission_actor_factory

        def allocate_gs_ability(ticket, manifests, plans):
            if before_gs_creation is not None:
                manifests, plans = before_gs_creation(ticket, manifests, plans)
            gs = actors['GameState'].manifest
            parents = [manifest for manifest in manifests if manifest.actor_guid == gs.actor_guid]
            entries = [plan for plan in plans if plan['actor_guid'] == gs.actor_guid]
            if len(parents) != 1 or len(entries) != 1:
                raise ValueError('Dynamic ability creation requires the exact current GS Actor and content')
            used = set(content_namespace(plans))
            used.update(m.actor_guid for m in manifests)
            used.update(binding.guid for m in manifests for binding in m.path_bindings)
            assets = tuple(g for g in range(3, 2*len(used)+11, 2) if g not in used)[:2]
            component_guid = next(g for g in range(2, 2*len(used)+6, 2) if g not in used)
            projection = gs_component_manifest(gs_creation_schema, parent_manifest=parents[0],
                package_guid=assets[0], class_guid=assets[1], component_guid=component_guid,
                allocated_guids=tuple(sorted(used)))
            update = projected_creation_update(gs_creation_schema, projection,
                game_state_open_acknowledged=True, class_export_acknowledged=True)
            creation = AbilityComponentCreation(update.actor_guid, update.guid, update.class_guid,
                                                update.source_sha256)
            parent = dict(entries[0])
            tails = parent.get('continuations', ())
            dependencies = parent.get('continuation_after_content_stages', tuple(() for _ in tails))
            parent['continuations'] = tails + ((creation,),)
            parent['continuation_after_content_stages'] = dependencies + ((),)
            return (tuple(projection.parent_manifest if m is parents[0] else m for m in manifests),
                    tuple(parent if plan is entries[0] else dict(plan) for plan in plans))

        admission_actor_factory = allocate_gs_ability
    digest = sources['archive']['sha256']
    maximum = pc_record['exclusive_index_maximum']
    startup = PCStartupProfile(pc_path, maximum,
        tuple(PCStartupField(name, rpc_index(pc_record, name), kind) for name, kind in (
            ('ServerShortTimeout', 'empty'), ('Server_RcvACWorldTime', 'float32'),
            ('ServerFieldOfView', 'float32'), ('NotifySeamlessLoginReady', 'bool'))),
        rpc_index(pc_record, 'ClientAckSeamlessLoginReady'), digest)
    ping = PCPingProfile(pc_path, maximum, rpc_index(pc_record, 'ServerBouncePing'),
                         rpc_index(pc_record, 'ClientReturnPing'), digest)
    start = GameStateStartProfile(gs_path,
        property_handle(state_record, 'bReplicatedHasBegunPlay', opcode=21, serializer=0x10e8ebe0),
        CLIENT_SHA256, digest,
        property_handle(state_record, 'bStartMathWithAllPlayerReady', opcode=21, serializer=0x10e8ebe0),
        property_handle(state_record, 'bCanSwitchToAbseil', opcode=21, serializer=0x10e8ebe0),
        property_handle(state_record, 'MapID', opcode=20, serializer=0x10e5ce20, parent=31),
        property_handle(state_record, 'RoomId', opcode=20, serializer=0x10e5ce20, parent=31),
        real_start_handle=(property_handle(state_record, 'bMatchRealStart', opcode=21,
            serializer=0x10e8ebe0) if qualified_mode_ids is not None else None))
    binding = NativeScalarBinding(CLIENT_SHA256, 0x10e8ed20, None, 0x15a86b80)
    restart = PCRestartProfile(pc_path, maximum, rpc_index(pc_record, 'ClientRestart'),
        rpc_index(pc_record, 'ServerAcknowledgePossession'), 0x01020cc0, 0x80220cc0, digest, binding)
    view = PCViewTargetProfile(pc_path, maximum, rpc_index(pc_record, 'ClientSetViewTarget'),
        rpc_index(pc_record, 'ServerVerifyViewTarget'), 0x01020cc0, 0x80220cc0, digest, binding)
    rotation = None
    rotation_source = config.get('controller_rotation')
    if rotation_source is not None:
        from portable_map_rotation import rotation_profile
        if actors['Pawn'].manifest.rotation is None:
            raise ValueError('Controller rotation requires a source-qualified Pawn spawn rotation')
        rotation = rotation_profile(json.loads(sealed_read(root, rotation_source)), pc_record, digest)
    pins = {s['relative_path']: s['sha256'] for s in sources.values()}
    pins.update(gameplay_actor_sources)
    pins.update(component_probe_sources)
    pins.update(inventory_sources)
    pins.update({s['relative_path']: s['sha256'] for s in player_sources.values()})
    pins.update({s['relative_path']: s['sha256'] for s in world_sources.values()})
    if fashion_source is not None:
        pins[fashion_source['relative_path']] = fashion_source['sha256']
    if rotation_source is not None:
        pins[rotation_source['relative_path']] = rotation_source['sha256']
    if hud_source is not None:
        pins[hud_source['relative_path']] = hud_source['sha256']
        from portable_map_hud import required_guid_source_pins
        pins.update(required_guid_source_pins(root))
    if random_spawn is not None:
        source = random_spawn['schema']
        pins[source['relative_path']] = source['sha256']
    if config.get('spawn') is not None:
        pins.update({s['relative_path']: s['sha256'] for s in
            (config['spawn']['source'], config['spawn']['catalog'])})
    pins[profile_path.relative_to(root).as_posix()] = hashlib.sha256(profile_raw).hexdigest()
    dependencies = [root / 'work/portable_map_bootstrap.py', root / 'work/native_actor_bootstrap.py',
        root / 'work/watch_client_log.py',
        root / 'work/native_game_state_start_profile.py', root / 'outputs/df-local-server/dfserver/game_server_probe.py',
        root / 'work/observe_portable_map_runtime.py', root / 'work/native_gp_first_player_state.py',
        root / 'work/native_world_settings_context.py', root / 'work/native_metadata_objects.py',
        root / 'work/native_metadata_names.py', root / 'work/native_metadata_paths.py',
        root / 'work/native_spawn_default_state.py', root / 'work/native_connection_binding.py',
        root / 'work/native_replication_metadata_core.py', root / 'work/export_native_replication_metadata.py']
    if spawn_vector is not None:
        dependencies.append(root / 'work/portable_spawn_point.py')
    if player_schema is not None:
        dependencies.extend(root / p for p in ('work/portable_map_player_state.py',
            'work/portable_player_appearance.py', 'outputs/df-local-server/dfserver/hero_customization.py',
            'outputs/df-local-server/dfserver/handshake_diagnostic.py',
            'outputs/df-local-server/dfserver/native_match_loadout.py'))
    if fashion_schema is not None:
        dependencies.append(root / 'work/portable_map_fashion.py')
    if component_probe is not None:
        dependencies.append(root / 'work/portable_map_gameplay_probe.py')
    if vitals_probe is not None:
        dependencies.append(root / 'work/portable_map_vitals_probe.py')
    if marker_probe is not None:
        dependencies.append(root / 'work/portable_map_marker_probe.py')
    if skill_init is not None:
        dependencies.append(root / 'work/portable_map_skill_detail.py')
    if skill_context_init is not None:
        dependencies.extend(root/p for p in ('work/portable_map_skill_context.py',
                                            'work/portable_map_skill_player_index.py'))
    if skill_entities_init is not None:
        dependencies.extend(root/p for p in ('work/skill_initial_state_values.py',
            'work/portable_skill_entity_admission.py', 'work/skill_entity_id_ledger.py'))
    if inventory_config is not None:
        from portable_gameplay_observers import extended_source_pins
        for relative, digest in extended_source_pins().items():
            if relative in pins and pins[relative] != digest:
                raise ValueError('An extended gameplay observer source conflicts: ' + relative)
            pins[relative] = digest
    if skill_gs_creation is not None:
        dependencies.extend(root/p for p in ('work/current_skill_gs_dynamic_component.py',
            'work/export_current_skill_gs_dynamic_schema.py'))
    if inventory_config is not None:
        dependencies.extend(root / p for p in ('work/portable_map_inventory.py',
            'work/portable_map_inventory_content.py', 'work/portable_gameplay_observers.py',
            'work/observe_economy_inventory_receive.py', 'work/observe_economy_inventory_gun_receive.py',
            'work/observe_economy_inventory_spaces.py',
            'work/observe_owned_vitals_metadata.py',
            'work/vitals_readonly_field_scope.py', 'work/observe_owned_map_marker_metadata.py',
            'work/observe_economy_loaded_interactors.py', 'work/observe_owned_weapon_state.py'))
    if level_actor_source is not None:
        dependencies.append(root / 'work/portable_map_level_actors.py')
    if weapon_actor_source is not None:
        dependencies.extend(root / p for p in ('work/portable_map_owned_weapon.py',
            'work/owned_weapon_values_codec.py', 'work/owned_weapon_fast_array_codec.py'))
    if modular_recipe is not None:
        dependencies.extend(root/p for p in ('work/modular_weapon_recipe_codec.py',
            'work/portable_modular_weapon_recipe.py'))
    if weapon_timeline is not None:
        dependencies.extend(root/p for p in ('work/weapon_switch_timeline_codec.py',
            'work/portable_weapon_switch_timeline.py'))
    if qualified_mode_ids is not None:
        dependencies.append(root / 'work/portable_map_world_state.py')
    if rotation is not None:
        dependencies.append(root / 'work/portable_map_rotation.py')
    if hud is not None:
        dependencies.append(root / 'work/portable_map_hud.py')
        dependencies.extend(root / path for path in ('work/observe_owned_gameplay_metadata.py',
            'work/observe_map_component_sources.py'))
    if select_spawn is not None:
        dependencies.append(root / 'work/portable_map_spawn_selection.py')
    local_rule_profile = None
    if config.get('local_map_rules') is not None:
        from dfserver.legacy_ds_local_map_rules import simulate_local_map_rules
        rule = config['local_map_rules']
        if select_spawn is None or qualified_mode_ids is None:
            raise ValueError('Local map rules require the qualified single-human SOL allocation')
        sources_raw, items_raw = (sealed_read(root, rule[key]) for key in ('sources', 'items'))
        relative = rule['config_relative_path']
        if (type(relative) is not str or ':' in relative or '\\' in relative or
                PurePosixPath(relative).is_absolute() or any(p in ('', '.', '..') for p in relative.split('/'))):
            raise ValueError('Local rules need a bounded project-relative config')
        config_path = (root / relative).resolve(strict=True)
        if not config_path.is_relative_to(root) or not 0 < config_path.stat().st_size <= 65536:
            raise ValueError('Local rule config exceeds its project bound')
        config_raw = config_path.read_bytes()
        simulate_local_map_rules(sources_raw, items_raw, config_raw, seed=0)
        local_rule_profile = (sources_raw, items_raw, config_raw, frozenset(qualified_mode_ids))
        spawn_summary = dict(spawn_summary, seed_origin='prepared_local_room_seed')
        pins.update({rule[k]['relative_path']: rule[k]['sha256'] for k in ('sources', 'items')})
        pins[relative] = hashlib.sha256(config_raw).hexdigest()
    room_factory = None
    high_value_init = config.get('high_value_initialization')
    if high_value_init is not None:
        if local_rule_profile is None or marker_probe is None:
            raise ValueError('High-value markers require the frozen local room and actual MapInfo component')
        from highvalue_initial_state_values import (schema_binding as high_value_binding,
            freeze_high_value_markers, high_value_initial_updates)
        high_value_schema = high_value_binding(root)
        if json.loads(sealed_read(root, high_value_init)) != high_value_schema:
            raise ValueError('The high-value profile differs from its source-qualified receiver')
        pins.update(high_value_schema['sources'])
        pins[high_value_init['relative_path']] = high_value_init['sha256']
        dependencies.extend(root/p for p in ('work/highvalue_initial_state_values.py',
            'work/normal_map_archive_values.py'))

        def room_factory(ticket, world_state, plans):
            state = actors['GameState'].manifest
            entries = [p for p in plans if p['actor_guid'] == state.actor_guid]
            if len(entries) != 1:
                raise ValueError('Initial markers require this admission\'s exact GameState')
            parent = dict(entries[0])
            component = parent.get('default_subobject')
            tails = parent.get('continuations', ())
            from dfserver.legacy_ds_skill_template import SkillTemplateUpdate
            preceding_creation = (skill_gs_creation is not None and
                len(tails) in ((1, 2) if skill_template_authority else (1,)) and
                len(tails[0]) == 1 and type(tails[0][0]) is AbilityComponentCreation and
                (len(tails) == 1 or len(tails[1]) == 1 and
                 type(tails[1][0]) is SkillTemplateUpdate))
            if (component is None or component.actor_guid != state.actor_guid or
                    component.name != high_value_schema['component']['name'] or
                    tails and not preceding_creation):
                raise ValueError('Initial markers require one fresh qualified MapInfo metadata stage')
            selection = freeze_high_value_markers(high_value_schema, room_id=str(ticket.room_id),
                participant_uid=ticket.player_id, local_world_state=world_state, existing_native_count=0)
            updates = high_value_initial_updates(high_value_schema, selection=selection,
                room_id=str(ticket.room_id), participant_uid=ticket.player_id,
                game_state_guid=state.actor_guid, component_guid=component.guid,
                game_state_open_acknowledged=True, component_metadata_acknowledged=True,
                ack_ordered_continuations=True)
            dependencies = parent.get('continuation_after_content_stages', tuple(() for _ in tails))
            parent['continuations'] = tails + tuple((update,) for update in updates)
            parent['continuation_after_content_stages'] = dependencies + tuple(() for _ in updates)
            return tuple(parent if p is entries[0] else dict(p) for p in plans)

    dependencies += list((root / 'outputs/df-local-server/dfserver').glob('legacy_ds_*.py'))
    from server_source_layout import expand_server_sources
    dependencies = [root / relative for relative in expand_server_sources(
        root, (path.relative_to(root).as_posix() for path in dependencies))]
    for path in dependencies:
        pins[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    control = dict(client_sha256=CLIENT_SHA256, hello_net_version=1077088301,
        maximum_packet_bytes=1024, control_welcome_maps={'2201': dict(
            level=world, game='', redirect='SubWorld=Dam_Iris_Level1')})
    reliable_receipts = config.get('admitted_actor_reliable_receipts', False)
    if type(reliable_receipts) is not bool:
        raise ValueError('Admitted Actor reliable receipts require an explicit boolean')
    owned_actor_channels_factory = None
    if reliable_receipts:
        if 'PlayerState' not in actors or admission_actor_factory is None:
            raise ValueError('Owned reliable receipts require qualified PlayerState and carried Actor producers')

        def owned_actor_channels_factory(ticket, manifests, plans):
            from portable_carried_weapon_selection import select
            from portable_melee_weapon import select as select_melee
            base = {m.actor_guid for m in (*[a.manifest for a in actors.values()], *additional_manifests)}
            guns = tuple(m for m in manifests if m.actor_guid not in base)
            if len(guns) != len(select(ticket).guns)+int(select_melee(ticket) is not None):
                raise ValueError('Owned receipt channels must match the complete frozen equipped gun set')
            ps = actors['PlayerState'].manifest
            if len([m for m in manifests if m == ps]) != 1:
                raise ValueError('Owned receipts require this profile\'s exact PlayerState manifest')
            # The owned EmptyHand is a base manifest. Once its one-node recipe
            # lets the client initialize it, the client sends reliable traffic
            # on its channel; omitting it rejects every packet that bundles it.
            hands = tuple(m for m in manifests if m.actor_guid in base and
                          m.class_path.endswith('.BP_EmptyHand_C'))
            if len(hands) > 1:
                raise ValueError('One owned EmptyHand Actor is expected')
            return (ps.channel_index, *(m.channel_index for m in hands),
                    *(m.channel_index for m in guns))

    inventory_refresh = config.get('inventory_ready_refresh', False)
    if (type(inventory_refresh) is not bool or
            inventory_refresh and (inventory_factory is None or not reliable_receipts)):
        raise ValueError('Inventory ready refresh requires explicit enablement, carried content and owning receipts')
    inventory_refresh_factory = None
    if inventory_refresh:
        from portable_inventory_refresh_runtime import make_profile, source_pins as refresh_sources
        inventory_refresh_factory = make_profile
        pins.update(refresh_sources())

    owner_switch_runtime = config.get('owner_switch_runtime', False)
    if (type(owner_switch_runtime) is not bool or owner_switch_runtime and
            (not reliable_receipts or not equipment_positions or weapon_timeline is None)):
        raise ValueError('Owner switch authority requires the complete acknowledged weapon graph and owning receipts')
    owner_switch_factory = None
    if owner_switch_runtime:
        from portable_owner_switch_profile import make_profile as make_owner_profile, source_pins as owner_sources
        pins.update(owner_sources())

        def owner_switch_factory(ticket, manifests, plans):
            return make_owner_profile(ticket, manifests, plans,
                pawn_guid=actors['Pawn'].manifest.actor_guid, empty_hand_guid=weapon.actor_guid,
                initial_policy=initial_weapon_policy, clock_policy=weapon_timeline['policy'])

    movement_policy = config.get('movement_runtime')
    movement_factory = None
    if movement_policy is not None:
        if not reliable_receipts or vitals_probe is None:
            raise ValueError('Movement authority requires the actual owning receipt policy and component metadata')
        from portable_movement_runtime import make_profile as make_movement_profile, source_pins as movement_sources
        pins.update(movement_sources())

        def movement_factory(ticket, manifests, plans):
            from dfserver.legacy_ds_actor_manifest import preflight_actor_manifest
            fields = tuple(dict(preflight_actor_manifest(m, channel_sequence=1023,
                max_packet_bytes=1024).actor_fields) for m in manifests)
            current = resolver(ticket, fields)
            pawn, = [row for row in current if row['actor_guid'] == actors['Pawn'].manifest.actor_guid]
            return make_movement_profile(ticket, manifests, plans,
                spawn_location=pawn['location'], policy=movement_policy)

    visibility_runtime = config.get('level_visibility_runtime', False)
    if type(visibility_runtime) is not bool or visibility_runtime and not reliable_receipts:
        raise ValueError('Level visibility requires the actual admitted owning receipt policy')
    visibility_profile = None
    if visibility_runtime:
        from native_level_visibility_string_profile import qualified_sources, loadProfile
        visibility_sources = qualified_sources(root)
        visibility_profile = loadProfile(root, visibility_sources)
        pins.update(visibility_sources)

    character_initialization = config.get('character_fsm_initialization', False)
    if (type(character_initialization) is not bool or
            character_initialization and not fsm_replica):
        raise ValueError('Character initialization requires its qualified context/bind/start stages')
    character_factory = None
    if character_initialization:
        from portable_character_initialization import CharacterInitializationStore, source_pins as character_sources
        from portable_fsm_replica_initialization import initialize_admitted_character
        if character_initialization_store is None:
            character_initialization_store = CharacterInitializationStore(
                root/'work/local-state/character-initializations.sqlite3')
        if type(character_initialization_store) is not CharacterInitializationStore:
            raise ValueError('The owning persistent character initialization store is required')
        pins.update(character_sources())

        def character_factory(ticket, manifests, plans):
            return initialize_admitted_character(character_initialization_store, ticket, manifests, plans)

    static_box_factory = None
    if reliable_receipts and additional_manifests:
        from portable_durable_world_runtime import make_static_box_profile, static_box_source_pins
        from portable_loot_box_codec import qualified_bindings
        box_paths = {binding.object_path for binding in qualified_bindings()}
        if any(getattr(manifest, 'actor_path', None) in box_paths for manifest in additional_manifests):
            static_box_factory = make_static_box_profile
            pins.update(static_box_source_pins())

    canonical_pins = {}
    for relative, digest in pins.items():
        normalized = relative.replace('\\', '/')
        if normalized in canonical_pins and canonical_pins[normalized] != digest:
            raise ValueError('Portable source aliases have conflicting hashes: ' + normalized)
        canonical_pins[normalized] = digest
    return PortableMapPlan(canonical_pins, control, actors, resolver, contents, startup, ping, start, restart, view,
                           spawn_summary, player_schema, admission_factory, fashion_schema is not None,
                           qualified_mode_ids is not None, rotation, select_spawn, local_rule_profile, hud, hud_class_guid,
                           component_probe is not None, additional_manifests, inventory_factory,
                           vitals_probe is not None, marker_probe is not None, ticket_factory,
                           weapon_init is not None, skill_init is not None, admission_actor_factory,
                           skill_entities_init is not None, modular_recipe is not None, room_factory,
                           weapon_timeline is not None, skill_gs_creation is not None,
                           equipment_positions, fsm_probe is not None, owned_actor_channels_factory,
                           fsm_allocation, fsm_replica, inventory_refresh_factory, owner_switch_factory,
                           movement_factory, skill_template_authority, visibility_profile, character_factory,
                           static_box_factory, profile_relative_path=profile_path.relative_to(root).as_posix())


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('profile', type=Path)
    opts = parser.parse_args()
    print(json.dumps(load_plan(ROOT, opts.profile).summary(), indent=2))
