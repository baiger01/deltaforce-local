"""Pure EmptyHand Actor and existing default-component update producers.

No current object pointer, game method, process or transport is used. Local
GUIDs, channels, transforms and opaque UniqueIds are supplied by the service.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_manifest import ActorManifest, GuidPathBinding
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_guid_exports import GuidExportNode
from dfserver.legacy_ds_match_admission import LocalMatchTicket
from owned_weapon_values_codec import (CLIENT_SHA, SCHEMA_PATH, SCHEMA_SHA256, WeaponPair,
    qualify_schema, build_weapon_info_content, build_active_weapon_content,
    manager_empty_hand_update, replicate_owner_update, actor_schema_binding,
    qualify_actor_schema, build_weapon_actor_initial_content, ACTOR_SCHEMA_PATH, ACTOR_SCHEMA_SHA256,
    schema_binding, manager_weapon_bindings_update)


def empty_hand_actor_manifest(schema, *, parent_manifest, package_guid, class_guid,
        archetype_guid, actor_guid, channel_index, allocated_guids, allocated_channels,
        location, rotation, scale, velocity):
    """Use the actual CDO and the admitted Pawn's already qualified Level chain.

    allocated_guids/channels must contain the connection's entire namespace.
    This factory only verifies the supplied namespace and chooses no IDs. Send
    the normal empty ordinary Actor content after Open to obtain its RepLayout.
    """
    qualify_schema(schema)
    if (type(parent_manifest) is not ActorManifest or parent_manifest.client_sha256 != CLIENT_SHA
            or parent_manifest.connection_network_version != 13 or parent_manifest.archive_network_version != 13
            or parent_manifest.references_resolvable is not True or parent_manifest.level_guid is None
            or not parent_manifest.class_path.endswith('.BP_DFMCharacter_C')):
        raise ValueError('The current admitted source-qualified Pawn manifest is required')
    if (type(allocated_guids) is not tuple or len(set(allocated_guids)) != len(allocated_guids)
            or any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids)
            or type(allocated_channels) is not tuple or len(set(allocated_channels)) != len(allocated_channels)
            or any(type(c) is not int or not 1 <= c <= 65535 for c in allocated_channels)
            or parent_manifest.channel_index not in allocated_channels
            or not ({parent_manifest.actor_guid} | {b.guid for b in parent_manifest.path_bindings}) <= set(allocated_guids)):
        raise ValueError('The complete explicit current GUID and channel namespace is required')
    fresh = (package_guid, class_guid, archetype_guid, actor_guid)
    if (any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in fresh)
            or len(set(fresh)) != 4 or set(fresh) & set(allocated_guids)
            or any(not g & 1 for g in fresh[:3]) or actor_guid & 1
            or type(channel_index) is not int or not 2 <= channel_index <= 65535
            or channel_index in allocated_channels):
        raise ValueError('Three fresh odd asset GUIDs and one fresh even Actor/channel are required')
    definitions = {}
    for node in parent_manifest.exports:
        while node is not None:
            definitions[node.guid] = node
            node = node.outer
    level = definitions.get(parent_manifest.level_guid)
    if level is None or level.outer is None or level.outer.outer is None or level.outer.outer.outer is not None:
        raise ValueError('The current Pawn Level has no qualified package/world chain')
    level_ids = {level.guid, level.outer.guid, level.outer.outer.guid}
    level_bindings = tuple(b for b in parent_manifest.path_bindings if b.guid in level_ids)
    # Preserve Package.World:Level ordering independently of the input tuple.
    level_bindings = tuple(next(b for b in level_bindings if b.guid == guid)
        for guid in (level.outer.outer.guid, level.outer.guid, level.guid))
    source = schema['empty_hand_actor']
    package_path, class_leaf = source['class_path'].rsplit('.', 1)
    cdo_leaf = source['cdo_path'].rsplit('.', 1)[1]
    if (source['net_rep_actor_interface_present'] is not False or source['custom_open_payload_bits'] != 0
            or source['interface_layout_native_proof_rebuilt'] is not True
            or source['actor_channel_open_handler_rva'] != '0xd5f350'
            or not int(source['cdo_flags'], 16) & 0x10):
        raise ValueError('EmptyHand class/CDO and zero-tail native source are required')
    package = GuidExportNode(package_guid, package_path)
    klass = GuidExportNode(class_guid, class_leaf, package)
    cdo = GuidExportNode(archetype_guid, cdo_leaf, package)
    return ActorManifest(client_sha256=CLIENT_SHA, source_relative_path=SCHEMA_PATH,
        source_sha256=SCHEMA_SHA256, class_guid=class_guid, class_path=source['class_path'],
        archetype_guid=archetype_guid, archetype_path=source['cdo_path'],
        archetype_qualification='explicit_template', level_guid=level.guid,
        level_path=parent_manifest.level_path,
        path_bindings=(GuidPathBinding(package_guid, package_path),
            GuidPathBinding(class_guid, source['class_path'], '.'),
            GuidPathBinding(archetype_guid, source['cdo_path'], '.'))+level_bindings,
        exports=(klass, cdo, level), actor_guid=actor_guid,
        connection_network_version=13, archive_network_version=13,
        references_resolvable=True, channel_index=channel_index, location=location,
        scale=scale, velocity=velocity, rotation=rotation,
        local_player_index=None, game_replication_flags=None)


def weapon_info_update(schema, *, pawn_guid, component_guid, changed_pairs,
                       array_key, base_key, deleted_ids):
    block = build_weapon_info_content(changed_pairs, array_key=array_key,
        base_key=base_key, deleted_ids=deleted_ids, schema=schema)
    update = DefaultSubobjectUpdate(pawn_guid, component_guid, 'WeaponReplicate',
        SCHEMA_SHA256, block.payload, block.payload_bit_count, has_rep_layout=False)
    update.__post_init__()
    return update


def active_weapon_update(schema, *, pawn_guid, component_guid, pair):
    block = build_active_weapon_content((pair,), schema=schema)
    update = DefaultSubobjectUpdate(pawn_guid, component_guid, 'WeaponReplicate',
        SCHEMA_SHA256, block.payload, block.payload_bit_count, has_rep_layout=True)
    update.__post_init__()
    return update


def empty_hand_component_stages(schema, *, pawn_guid, manager_component_guid,
        replicate_component_guid, weapon_guid, actor_open_acknowledged, pair,
        replication_id, array_key, base_key):
    """Four distinct reliable stages; each preceding stage requires a true ACK.

    The generated bytes are reviewable wire input, not a claim that the client's
    FPP/owner initialization has succeeded. Actor native init fields still need
    its real RepLayout before claiming full weapon gameplay functionality.
    """
    qualify_schema(schema)
    if type(pair) is not WeaponPair or pair.common_class_id != 1:
        raise ValueError('EmptyHand requires its source-declared Type1 ClassId1')
    if len({pawn_guid, manager_component_guid, replicate_component_guid, weapon_guid}) != 4:
        raise ValueError('The Actor and two actual components need distinct current GUIDs')
    owner = replicate_owner_update(schema, pawn_guid=pawn_guid, component_guid=replicate_component_guid,
        pawn_open_acknowledged=actor_open_acknowledged)
    info = weapon_info_update(schema, pawn_guid=pawn_guid, component_guid=replicate_component_guid,
        changed_pairs=((replication_id, pair),), array_key=array_key, base_key=base_key, deleted_ids=())
    reference = manager_empty_hand_update(schema, pawn_guid=pawn_guid, component_guid=manager_component_guid,
        weapon_guid=weapon_guid, actor_open_acknowledged=actor_open_acknowledged)
    active = active_weapon_update(schema, pawn_guid=pawn_guid, component_guid=replicate_component_guid, pair=pair)
    return ((owner,), (info,), (reference,), (active,))


@dataclass(frozen=True)
class OwnedWeaponStage:
    name: str
    actor_guid: int
    actor_content: ActorContentBlock | None
    updates: tuple[DefaultSubobjectUpdate, ...]
    after_stage: int | None
    required_open_guids: tuple[int, ...]
    requires_initial_actor_contents: bool = True


@dataclass(frozen=True)
class OwnedWeaponInitialization:
    unique_id: int
    pair: WeaponPair | None
    weapon_rec_id: int
    stages: tuple[OwnedWeaponStage, ...]
    qualification: dict


def owned_weapon_actor_source_pins():
    schema = actor_schema_binding()
    root = Path(__file__).resolve().parent.parent
    pins = dict(schema['sources'], **{ACTOR_SCHEMA_PATH: ACTOR_SCHEMA_SHA256})
    from weapon_actor_network_role import source_pins as role_pins
    pins.update(role_pins())
    for relative in ('work/portable_map_owned_weapon.py', 'work/owned_weapon_values_codec.py',
            'work/owned_weapon_fast_array_codec.py', 'work/export_owned_weapon_actor_schema.py'):
        pins[relative] = hashlib.sha256((root/relative).read_bytes()).hexdigest()
    return pins


def _admitted_loadout(ticket):
    if (type(ticket) is not LocalMatchTicket or type(ticket.cookie) is not str or not ticket.cookie or
            any(type(v) is not int or not 1 <= v < 1 << 64 for v in
                (ticket.player_id, ticket.room_id, ticket.map_id, ticket.match_mode_id,
                 ticket.selected_hero_id, ticket.selected_fashion_id)) or
            type(ticket.loadout_snapshot) is not bytes or not 0 < len(ticket.loadout_snapshot) <= 1024*1024):
        raise ValueError('One exact admission with its bounded frozen loadout is required')
    document = json.loads(ticket.loadout_snapshot)
    if (type(document) is not dict or document.get('kind') != 'local_account_carried_loadout_v1' or
            document.get('selected_hero_id') != ticket.selected_hero_id or
            document.get('selected_fashion_id') != ticket.selected_fashion_id or
            type(document.get('props')) is not list or len(document['props']) > 2048 or
            any(type(p) is not dict for p in document['props'])):
        raise ValueError('Weapon initialization and appearance must use the exact same frozen admission')
    return document


def empty_hand_initialization(ticket, *, pawn_guid, weapon_guid, manager_component_guid,
        replicate_component_guid, pawn_open_acknowledged, weapon_open_acknowledged, weapon_slot=None,
        initial_state_is_fresh=False, manager_binding_snapshot_complete=False,
        used_unique_ids=(), activate_empty_hand=False, actor_schema=None):
    """Initialize the source-default EmptyHand baseline without selecting carried guns.

    Send stage zero only after the exact admission's base PC/Pawn/PS content and
    both Actor opens have actual receipts. Each later stage additionally waits
    for the previous stage's actual receipt. The caller owns these journal gates.
    This initial subset requires a fresh manager and replicate array, with
    EmptyHand as the entire current weapon Actor binding set. Call the separate
    complete-list codec when qualified carried weapon Actors are available.
    Omit weapon_slot until its business mapping is qualified; Actor/manager
    initialization then remains usable without creating or activating a pair.
    """
    actual = actor_schema_binding() if actor_schema is None else qualify_actor_schema(actor_schema)
    sources = owned_weapon_actor_source_pins()
    document = _admitted_loadout(ticket)
    guids = (pawn_guid, weapon_guid, manager_component_guid, replicate_component_guid)
    if (any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1 for g in guids) or
            len(set(guids)) != 4 or pawn_open_acknowledged is not True or
            weapon_open_acknowledged is not True or initial_state_is_fresh is not True or
            manager_binding_snapshot_complete is not True or
            (weapon_slot is not None and (type(weapon_slot) is not int or not 0 <= weapon_slot <= 255)) or
            type(activate_empty_hand) is not bool or
            type(used_unique_ids) is not tuple or len(used_unique_ids) > 4096 or
            len(set(used_unique_ids)) != len(used_unique_ids) or
            any(type(i) is not int or not 1 <= i <= UINT32_MAX for i in used_unique_ids)):
        raise ValueError('Distinct current acknowledged Actors/components and explicit local weapon policy are required')
    carried = [p for p in document['props'] if p.get('weapon')]
    if activate_empty_hand and weapon_slot is None:
        raise ValueError('Active EmptyHand requires a separately qualified business slot')
    if activate_empty_hand and (carried or document.get('selected_melee') is not None):
        raise ValueError('A carried gun/melee active selection needs its separately qualified native mapping')
    snapshot_sha = hashlib.sha256(ticket.loadout_snapshot).hexdigest()
    seed = json.dumps(['portable_empty_hand_identity_v1', ticket.cookie, ticket.player_id,
        ticket.room_id, ticket.map_id, ticket.match_mode_id, snapshot_sha], separators=(',', ':')).encode()
    used = set(used_unique_ids)
    for counter in range(len(used)+2):
        # A local 31-bit subset keeps int32 FastArray tooling independent of GIDs.
        identity = int.from_bytes(hashlib.sha256(seed+counter.to_bytes(4, 'little')).digest()[:4], 'little') & 0x7fffffff
        if identity and identity not in used:
            break
    else:
        raise ValueError('No bounded unused local weapon identity was found')
    baseline = schema_binding()
    switch = next(e['value'] for e in baseline['switch_type']['entries']
        if e['name'] == 'EWeaponSwitchType::Default')
    pair = (None if weapon_slot is None else
        WeaponPair(False, switch, identity, actual['empty_hand']['common_class_id'], 0, weapon_slot))
    body = build_weapon_actor_initial_content(actual, pawn_guid=pawn_guid, unique_id=identity,
        weapon_rec_id=actual['empty_hand']['rec_id'], weapon_slot=weapon_slot,
        pawn_open_acknowledged=pawn_open_acknowledged, root_recipe=True)
    opens = (pawn_guid, weapon_guid)
    stages = [OwnedWeaponStage('weapon_actor', weapon_guid, body, (), None, opens)]
    owner = replicate_owner_update(baseline, pawn_guid=pawn_guid, component_guid=replicate_component_guid,
        pawn_open_acknowledged=pawn_open_acknowledged)
    reference = manager_weapon_bindings_update(actual, pawn_guid=pawn_guid,
        component_guid=manager_component_guid,
        bindings=((weapon_guid, identity, actual['empty_hand']['rec_id']),), empty_hand_guid=weapon_guid,
        actor_opens_acknowledged=weapon_open_acknowledged)
    updates = [('replicate_owner', owner), ('manager_bindings', reference)]
    if pair is not None:
        info = weapon_info_update(baseline, pawn_guid=pawn_guid, component_guid=replicate_component_guid,
            changed_pairs=((1, pair),), array_key=1, base_key=-1, deleted_ids=())
        updates.append(('weapon_info', info))
    for name, update in updates:
        stages.append(OwnedWeaponStage(name, pawn_guid, None, (update,), len(stages)-1, opens))
    if activate_empty_hand:
        update = active_weapon_update(baseline, pawn_guid=pawn_guid,
            component_guid=replicate_component_guid, pair=pair)
        stages.append(OwnedWeaponStage('active_empty_hand', pawn_guid, None, (update,), len(stages)-1, opens))
    return OwnedWeaponInitialization(identity, pair, actual['empty_hand']['rec_id'], tuple(stages),
        dict(kind='source_qualified_ticket_empty_hand_initialization_v1', source_pins=sources,
            snapshot_sha256=snapshot_sha, ticket_appearance_consistent=True,
            identity_origin=actual['local_policy']['identity_origin'], identity_is_inventory_gid=False,
            empty_hand_rec_id_origin=actual['empty_hand']['rec_id_origin'],
            weapon_slot_origin=(None if weapon_slot is None else
                'explicit_caller_local_policy_not_recovered_business_mapping'),
            inventory_gid_assigned=False, active_weapon_overridden=activate_empty_hand,
            carried_gun_count=len(carried), carried_weapon_actor_selection_qualified=False,
            weapon_info_created=pair is not None, requires_fresh_weapon_replicate_array=pair is not None,
            array_key=1 if pair is not None else None, base_key=-1 if pair is not None else None,
            replication_id=1 if pair is not None else None,
            manager_complete_lists_replaced=True, manager_binding_count=1,
            required_gate='Fresh manager/replicate state; actual opens and base actor contents; ACK every prior stage',
            native_gameplay_verified=False, packets_sent=False, process_access=False))
