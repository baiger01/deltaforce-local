"""Pure complete-ticket physical recipe updates; no namespace allocation or IO transport."""
from dataclasses import dataclass
import hashlib

from dfserver.legacy_ds_actor_content import ActorContentBlock, write_actor_content_blocks
from dfserver.legacy_ds_bit_archive import BitWriter, MAX_BITS, UINT32_MAX
from dfserver.transport.native.legacy_ds_reliable_fragmentation import fragment_content_bunch
from dfserver.legacy_ds_wire_codec import (WireBunch, WirePacket, ChannelName,
    encode_observed_application)
from modular_weapon_recipe_codec import (project, encode, source_pins as codec_source_pins,
    SCHEMA_SHA256, ROOT)
from portable_carried_weapon_selection import select, source_pins as selection_source_pins


@dataclass(frozen=True)
class RecipeActorUpdate:
    inventory_gid: int
    actor_guid: int
    actor_content: ActorContentBlock
    snapshot_sha256: str
    schema_sha256: str = SCHEMA_SHA256

    @property
    def qualification(self):
        return dict(snapshot_sha256=self.snapshot_sha256, recipe_schema_sha256=self.schema_sha256,
            native_held_weapon_verified=False, internal_ready_flags_emitted=False,
            actual_current_ack_measured=False, complete_initial_recipe=True,
            required_gate='Current Modular Actor open and identity/owner full-send positive ACK; then recipe ACK before Active',
            existing_actor_property_handles=(36, 37, 38), namespace_allocated=False,
            equip_position_emitted=False, selected_melee_actor_created=False,
            nonzero_durability_business_semantics_verified=False)


def source_pins():
    pins = codec_source_pins()
    for relative, digest in selection_source_pins().items():
        if relative in pins and pins[relative] != digest:
            raise ValueError('Recipe and frozen selection source groups disagree: '+relative)
        pins[relative] = digest
    for relative in ('work/portable_modular_weapon_recipe.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
            'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py',
            'outputs/df-local-server/dfserver/transport/native/legacy_ds_reliable_fragmentation.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def _packet_preflight(block, max_packet_bytes):
    # Use the largest allowed channel index and reliable sequence. The current
    # control sender sends one PacketNotify history word on these content paths.
    writer = BitWriter(maximum_bits=MAX_BITS)
    write_actor_content_blocks(writer, (block,))
    bunch = WireBunch(UINT32_MAX, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=1023, channel_name=ChannelName(hardcoded_index=102))
    return tuple(encode_observed_application(WirePacket(16383, 16383, (0xffffffff,),
        False, 255, None, (piece,), 0), max_packet_bytes=max_packet_bytes,
        received_by_server=False) for piece in fragment_content_bunch(bunch,max_packet_bytes=max_packet_bytes))


def build(ticket, *, gun_allocations, known_actor_guids, actor_opens_acknowledged,
        identity_and_owner_acknowledged, initial_state_is_fresh, max_packet_bytes=1024):
    """Return one ordinary Actor block per exact frozen equipped gun, or none.

    This is a planning API. True gate arguments declare the scheduler's required
    receipt boundaries, never report runtime receipts. No plan is returned unless
    every complete recipe fits the bounded reliable fragment path. Root must
    insert each block after that Actor's identity/owner stage and make
    manager/WeaponInfo/Active wait for all fragments of the recipe stage.
    """
    if (actor_opens_acknowledged is not True or identity_and_owner_acknowledged is not True or
            initial_state_is_fresh is not True):
        raise ValueError('Fresh acknowledged Actor opens and source identity/owner stages are required')
    if type(max_packet_bytes) is not int or not 1 <= max_packet_bytes <= 1492:
        raise ValueError('An explicit bounded complete packet budget is required')
    if (type(known_actor_guids) is not tuple or not 1 <= len(known_actor_guids) <= 16 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in known_actor_guids) or
            len(set(known_actor_guids)) != len(known_actor_guids)):
        raise ValueError('The complete distinct existing Actor GUID namespace is required')
    guns = select(ticket).guns
    if (type(gun_allocations) is not tuple or len(gun_allocations) != len(guns) or len(guns) > 2 or
            any(type(pair) is not tuple or len(pair) != 2 or
                any(type(value) is not int for value in pair) for pair in gun_allocations)):
        raise ValueError('The exact complete frozen equipped gun allocation is required')
    by_gid = dict(gun_allocations)
    if (len(by_gid) != len(gun_allocations) or set(by_gid) != {g.inventory_gid for g in guns} or
            len(set(by_gid.values())) != len(by_gid) or any(
                guid not in known_actor_guids or guid & 1 for guid in by_gid.values())):
        raise ValueError('Distinct current Modular Actor references must match all frozen inventory GIDs')
    digest = hashlib.sha256(ticket.loadout_snapshot).hexdigest()
    result = []
    for gun in guns:
        recipe = project(gun.description)
        if recipe.nodes[0].gid != gun.inventory_gid or recipe.nodes[0].item_id != gun.weapon_rec_id:
            raise ValueError('The actual frozen receiver identity differs from its Actor recipe root')
        block = encode(recipe, maximum_bits=MAX_BITS)
        _packet_preflight(block, max_packet_bytes)
        result.append(RecipeActorUpdate(gun.inventory_gid, by_gid[gun.inventory_gid], block, digest))
    return tuple(result)
