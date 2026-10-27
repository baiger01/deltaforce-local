"""Fresh owner-switch plan projected from the exact admitted initialization."""
from dataclasses import dataclass
import hashlib

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate, write_default_subobject_followup
from dfserver.legacy_ds_wire_codec import WireBunch, WirePacket, ChannelName, encode_observed_application
from portable_carried_weapon_selection import select
from portable_modular_weapon_initialization import (ModularWeaponInitialization, WeaponBinding, initialize,
    source_pins as initialization_source_pins)
from portable_modular_weapon_recipe import build as build_recipes, source_pins as recipe_source_pins
from weapon_native_default_slot import native_default_slot_policy
from weapon_switch_timeline_codec import (LocalInitialSwitchClock, InitialSwitchTimeline,
    initial_timeline, encode, source_pins as codec_source_pins, SCHEMA_SHA256, ROOT)


@dataclass(frozen=True)
class WeaponSwitchTimelineUpdate:
    update: DefaultSubobjectUpdate
    timeline: InitialSwitchTimeline
    selected_inventory_gid: int | None
    selected_actor_guid: int
    selected_unique_id: int
    snapshot_sha256: str
    maximum_packet_bytes: int

    @property
    def qualification(self):
        return dict(schema_sha256=SCHEMA_SHA256,
            local_initialization_policy='explicit_local_server_fresh_initial_instant_switch',
            current_native_timeline_observed=False, official_current_frame_claimed=False,
            native_held_weapon_verified=False, internal_state_or_role_emitted=False,
            inventory_ui_readiness_repaired=False, complete_fresh_ring=True,
            zero_initial_epoch_not_expired_by_this_receive_path=True,
            existing_unacknowledged_local_prediction_can_be_replayed=True,
            required_gate='All exact Actor recipe, manager bindings, WeaponInfo and final Active full-send ACK; then this own positive ACK',
            partial_frame_splitting=False, actual_current_ack_measured=False)


def source_pins():
    pins = {}
    for group in (codec_source_pins(), initialization_source_pins(), recipe_source_pins()):
        for relative, digest in group.items():
            if relative in pins and pins[relative] != digest:
                raise ValueError('Switch timeline source groups disagree: ' + relative)
            pins[relative] = digest
    for relative in ('work/portable_weapon_switch_timeline.py',
            'outputs/df-local-server/dfserver/legacy_ds_default_subobject.py',
            'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def _packet_preflight(update, actor_guids, maximum):
    writer = BitWriter(maximum_bits=maximum*8)
    write_default_subobject_followup(writer, update, (ActorContentBlock(True, b'\0\0', 9),), actor_guids)
    bunch = WireBunch(UINT32_MAX, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=1023, channel_name=ChannelName(hardcoded_index=102), package_exports=True)
    return encode_observed_application(WirePacket(16383, 16383, (0xffffffff,),
        False, 255, None, (bunch,), 0), max_packet_bytes=maximum, received_by_server=False)


def build(ticket, *, pawn_guid, manager_component_guid, replicate_component_guid,
        initialization, known_actor_guids, recipe_updates, clock,
        actor_opens_acknowledged, all_initialization_stages_acknowledged,
        complete_recipes_acknowledged, initial_state_is_fresh, max_packet_bytes=1024,
        used_unique_ids=()):
    """Plan one independent manager component message after the whole weapon DAG.

    True gates declare required scheduler receipts; they do not measure runtime
    ACKs. This fresh-only policy cannot replace an established local timeline.
    The caller must wait for this message's own ACK before its next dependent
    lifecycle stage. The whole ring either fits one real packet or is refused.
    WorldTime zero is an explicit local epoch: the remote import copies it and
    ApplyCurrentFrame uses the identity/switch values, without a time-window
    rejection. Existing unacknowledged local predictions can still be replayed.
    """
    if (actor_opens_acknowledged is not True or all_initialization_stages_acknowledged is not True or
            complete_recipes_acknowledged is not True or initial_state_is_fresh is not True):
        raise ValueError('Fresh exact weapon initialization and complete recipe receipts are required')
    if type(max_packet_bytes) is not int or not 1 <= max_packet_bytes <= 1024:
        raise ValueError('The complete packet budget must be bounded by the current 1024-byte profile')
    if (type(known_actor_guids) is not tuple or not 1 <= len(known_actor_guids) <= 16 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in known_actor_guids) or
            len(set(known_actor_guids)) != len(known_actor_guids) or pawn_guid not in known_actor_guids or
            manager_component_guid in known_actor_guids or replicate_component_guid in known_actor_guids):
        raise ValueError('The complete distinct Actor namespace must exclude the two default components')
    if (type(used_unique_ids) is not tuple or len(set(used_unique_ids)) != len(used_unique_ids) or
            any(type(v) is not int or not 1 <= v <= UINT32_MAX for v in used_unique_ids)):
        raise ValueError('Exact prior local weapon identities are required')
    if (type(initialization) is not ModularWeaponInitialization or
            type(initialization.bindings) is not tuple or not 1 <= len(initialization.bindings) <= 4 or
            any(type(b) is not WeaponBinding for b in initialization.bindings) or
            type(initialization.qualification) is not dict):
        raise ValueError('The exact frozen-ticket Modular initialization is required')
    selected_gid = initialization.qualification.get('initial_active_inventory_gid')
    melee_guid = initialization.qualification.get('melee_actor_guid')
    allocations = tuple((b.inventory_gid, b.actor_guid) for b in initialization.bindings[1:]
        if b.actor_guid != melee_guid)
    rebuilt = initialize(ticket, pawn_guid=pawn_guid,
        empty_hand_guid=initialization.bindings[0].actor_guid, gun_allocations=allocations,
        manager_component_guid=manager_component_guid, replicate_component_guid=replicate_component_guid,
        pawn_open_acknowledged=True, weapon_opens_acknowledged=True, initial_state_is_fresh=True,
        manager_binding_snapshot_complete=True, native_slot_policy=native_default_slot_policy(),
        initial_active_inventory_gid=selected_gid, used_unique_ids=used_unique_ids,
        melee_actor_guid=melee_guid)
    if rebuilt != initialization or any(b.actor_guid not in known_actor_guids for b in rebuilt.bindings):
        raise ValueError('The timeline must use the exact admitted Actor, identity and active choice')
    guns = select(ticket).guns
    if {b.inventory_gid for b in rebuilt.bindings[1:] if b.actor_guid != melee_guid} != {g.inventory_gid for g in guns}:
        raise ValueError('The complete frozen equipped weapon set changed')
    exact_recipes = build_recipes(ticket, gun_allocations=allocations,
        known_actor_guids=known_actor_guids, actor_opens_acknowledged=True,
        identity_and_owner_acknowledged=True, initial_state_is_fresh=True, max_packet_bytes=1024)
    if type(recipe_updates) is not tuple or recipe_updates != exact_recipes:
        raise ValueError('Every exact admitted Actor recipe must precede the owner-switch timeline')
    selected = next(b for b in rebuilt.bindings if b.actor_guid ==
                    rebuilt.qualification['initial_active_actor_guid'])
    timeline = initial_timeline(selected.unique_id, clock)
    block = encode(timeline, maximum_bits=max_packet_bytes*8)
    update = DefaultSubobjectUpdate(pawn_guid, manager_component_guid, 'WeaponManager',
        SCHEMA_SHA256, block.payload, block.payload_bit_count, has_rep_layout=True)
    packet = _packet_preflight(update, known_actor_guids, max_packet_bytes)
    return WeaponSwitchTimelineUpdate(update, timeline, selected.inventory_gid, selected.actor_guid,
        selected.unique_id, hashlib.sha256(ticket.loadout_snapshot).hexdigest(), len(packet))
