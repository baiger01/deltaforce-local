"""Source-closed modular Actor-open/empty-content probes from frozen tickets."""
from dataclasses import dataclass, replace
import hashlib

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_actor_manifest import ActorManifest, GuidPathBinding
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_guid_exports import GuidExportNode
from owned_weapon_values_codec import (schema_binding, SCHEMA_PATH as OWNED_SCHEMA_PATH,
    SCHEMA_SHA256 as OWNED_SCHEMA_SHA256)
from portable_map_owned_weapon import empty_hand_actor_manifest
from export_portable_carried_weapon_schema import ROOT, OUTPUT
from portable_carried_weapon_selection import (CarriedGunSelection, select, binding,
    source_pins as selection_source_pins, SCHEMA_SHA256)


@dataclass(frozen=True)
class CarriedGunActorProbe:
    selection: CarriedGunSelection
    manifest: ActorManifest
    initial_content: ActorContentBlock
    qualification: dict


def source_pins():
    pins = selection_source_pins()
    old = schema_binding()
    for path, digest in old['sources'].items():
        if path in pins and pins[path] != digest:
            raise ValueError('Weapon source pin groups disagree: '+path)
        pins[path] = digest
    pins[OWNED_SCHEMA_PATH] = OWNED_SCHEMA_SHA256
    # The namespace/Level validator is inherited from the already qualified helper.
    for path in ('work/portable_carried_weapon_actor.py', 'work/owned_weapon_values_codec.py'):
        pins[path] = hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
    return pins


def actor_probe(ticket, *, inventory_gid, parent_manifest, package_guid, class_guid,
        archetype_guid, actor_guid, channel_index, allocated_guids, allocated_channels,
        location, rotation, scale, velocity):
    schema = binding()
    source = schema['modular_actor']
    if source['actor_open_probe_qualified'] is not True or source['custom_open_payload_bits'] != 0:
        raise ValueError('The actual modular native ActorOpen source is required')
    choices = [g for g in select(ticket).guns if g.inventory_gid == inventory_gid]
    if type(inventory_gid) is not int or len(choices) != 1:
        raise ValueError('Only one exact equipped gun from this frozen ticket may open')
    gun = choices[0]
    # Reuse complete namespace and Level qualification without editing that helper.
    parent = empty_hand_actor_manifest(schema_binding(), parent_manifest=parent_manifest,
        package_guid=package_guid, class_guid=class_guid, archetype_guid=archetype_guid,
        actor_guid=actor_guid, channel_index=channel_index, allocated_guids=allocated_guids,
        allocated_channels=allocated_channels, location=location, rotation=rotation, scale=scale, velocity=velocity)
    package_path, class_leaf = gun.class_path.rsplit('.', 1)
    package = GuidExportNode(package_guid, package_path)
    klass = GuidExportNode(class_guid, class_leaf, package)
    cdo = GuidExportNode(archetype_guid, gun.cdo_path.rsplit('.', 1)[1], package)
    manifest = replace(parent, source_relative_path=OUTPUT.relative_to(ROOT).as_posix(),
        source_sha256=SCHEMA_SHA256, class_path=gun.class_path, archetype_path=gun.cdo_path,
        exports=(klass, cdo, parent.exports[-1]),
        path_bindings=(GuidPathBinding(package_guid, package_path),
            GuidPathBinding(class_guid, gun.class_path, '.'),
            GuidPathBinding(archetype_guid, gun.cdo_path, '.'))+parent.path_bindings[3:])
    writer = BitWriter()
    writer.write_bool(False)
    writer.write_packed_int(0)
    return CarriedGunActorProbe(gun, manifest,
        ActorContentBlock(True, writer.to_bytes(), writer.bit_count),
        dict(snapshot_sha256=hashlib.sha256(ticket.loadout_snapshot).hexdigest(),
            actual_modular_layout_available=False, actor_initialization_sent_or_verified=False,
            native_gameplay_verified=False, required_sequence='ActorOpen then actual ACK then this empty ordinary content',
            next_stage='observe existing passive modular cache/layout before any property content'))


def actor_probes(ticket, *, allocations, **fields):
    """Use one static package/class/CDO GUID graph for the whole equipped gun set.

    allocations is the complete tuple of (inventory_gid, actor_guid, channel).
    This returns immutable plans and performs no queue/send or allocation mutation.
    """
    guns = select(ticket).guns
    if (type(allocations) is not tuple or len(allocations) != len(guns) or
            not allocations or len(allocations) > 2 or
            any(type(row) is not tuple or len(row) != 3 or
                any(type(value) is not int for value in row) for row in allocations)):
        raise ValueError('A complete bounded explicit equipped-gun allocation set is required')
    gids, actors, channels = zip(*allocations)
    if (set(gids) != {g.inventory_gid for g in guns} or len(set(gids)) != len(gids) or
            len(set(actors)) != len(actors) or len(set(channels)) != len(channels)):
        raise ValueError('Equipped gun GIDs, dynamic Actors and channels cannot alias')
    return tuple(actor_probe(ticket, inventory_gid=gid, actor_guid=actor, channel_index=channel,
        **fields) for gid, actor, channel in allocations)
