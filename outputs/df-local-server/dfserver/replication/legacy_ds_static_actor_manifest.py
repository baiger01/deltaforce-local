"""Explicit source-pinned existing Level Actor, with no replicated content.

The complete path and class hook are producer observations. Preflight checks
their consistency; it does not load an asset or prove native resolution.
"""
from dataclasses import dataclass
from types import MappingProxyType

from dfserver.replication.legacy_ds_actor_bunch import build_static_actor_bunch
from dfserver.replication.legacy_ds_actor_manifest import ActorManifestPreflight, GuidPathBinding, _source, _clone_exports, _full_path, _static_guid
from dfserver.transport.native.legacy_ds_bit_archive import UINT32_MAX
from dfserver.replication.legacy_ds_guid_exports import GuidExportNode
from dfserver.transport.native.legacy_ds_wire_codec import SEQUENCE_MASK, WirePacket, encode_observed_application


@dataclass(frozen=True)
class StaticActorManifest:
    client_sha256: str
    source_relative_path: str
    source_sha256: str
    class_path: str
    actor_path: str
    actor_guid: int
    level_guid: int
    level_path: str
    path_bindings: tuple[GuidPathBinding, ...]
    exports: tuple[GuidExportNode, ...]
    channel_index: int
    references_resolvable: bool
    actor_open_hook_has_no_extra_fields: bool
    force_unicode: bool = False


def preflight_static_actor_manifest(manifest, *, channel_sequence, max_packet_bytes):
    if type(manifest) is not StaticActorManifest:
        raise ValueError('An exact immutable StaticActorManifest is required')
    _source(manifest)
    for path in (manifest.class_path, manifest.actor_path, manifest.level_path):
        _full_path(path)
    for guid in (manifest.actor_guid, manifest.level_guid):
        _static_guid(guid)
    if type(manifest.force_unicode) is not bool:
        raise ValueError('An explicit Boolean Unicode policy is required')
    exports = _clone_exports(manifest)
    # This supported subset is exactly Package.World:Level.Actor.
    if len(exports) != 1:
        raise ValueError('An existing Actor requires one explicit export chain')
    actor = exports[0]
    level = actor.outer
    world = None if level is None else level.outer
    package = None if world is None else world.outer
    if (package is None or package.outer is not None or
            actor.guid != manifest.actor_guid or level.guid != manifest.level_guid):
        raise ValueError('An existing Actor requires its exact Package.World:Level.Actor chain')
    if type(manifest.path_bindings) is not tuple or len(manifest.path_bindings) != 4:
        raise ValueError('Four exact existing Actor path bindings are required')
    expected = (
        GuidPathBinding(package.guid, package.path),
        GuidPathBinding(world.guid, package.path + '.' + world.path, '.'),
        GuidPathBinding(level.guid, package.path + '.' + world.path + ':' + level.path, ':'),
        GuidPathBinding(actor.guid, package.path + '.' + world.path + ':' + level.path + '.' + actor.path, '.'),
    )
    if (any(type(binding) is not GuidPathBinding for binding in manifest.path_bindings) or
            manifest.path_bindings != expected or
            len({row.guid for row in expected}) != 4 or
            expected[2].full_path != manifest.level_path or
            expected[3].full_path != manifest.actor_path or
            any(c in package.path for c in '.:') or
            any(not node.path or any(c in node.path for c in '/.:\\') for node in (world, level, actor))):
        raise ValueError('Existing Actor export leaves and full path bindings disagree')
    fields = dict(actor_kind='static', exports=exports, actor_guid=manifest.actor_guid,
        references_resolvable=manifest.references_resolvable,
        actor_open_hook_has_no_extra_fields=manifest.actor_open_hook_has_no_extra_fields,
        channel_index=manifest.channel_index, force_unicode=manifest.force_unicode)
    bunch = build_static_actor_bunch(channel_sequence=channel_sequence,
        max_packet_bytes=max_packet_bytes, **{key: value for key, value in fields.items() if key != 'actor_kind'})
    packet = WirePacket(SEQUENCE_MASK, SEQUENCE_MASK, (UINT32_MAX,), False, 0, None, (bunch,), 0)
    envelope = encode_observed_application(packet, max_packet_bytes=max_packet_bytes,
                                          received_by_server=False)
    return ActorManifestPreflight(bunch, MappingProxyType(fields), len(envelope))
