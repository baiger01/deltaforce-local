"""Pure preflight of explicitly described, property-free initial Actor opens.

Paths and source pins are caller observations, not asset existence proofs. A
generated UClass is not an Actor archetype. Named default-object candidates
remain candidates: RF_ClassDefaultObject and native acceptance are not checked.
This module performs no I/O, GUID allocation, queue mutation or native calls.
"""

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from types import MappingProxyType
import re

from .legacy_ds_actor_bunch import build_actor_bunch
from .legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from .legacy_ds_guid_exports import (
    DEFAULT_LIMITS, GuidExportNode, read_guid_exports, write_guid_exports,
)
from .legacy_ds_quantized_vector import QuantizedVector10
from .legacy_ds_wire_codec import (
    SEQUENCE_MASK, WireBunch, WirePacket, encode_observed_application,
)


CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'


@dataclass(frozen=True)
class GuidPathBinding:
    guid: int
    full_path: str
    # None for a package/root; child separators must be observed explicitly.
    separator_from_outer: str | None = None


@dataclass(frozen=True)
class ActorManifest:
    client_sha256: str
    source_relative_path: str
    source_sha256: str
    class_guid: int
    class_path: str
    archetype_guid: int
    archetype_path: str
    archetype_qualification: str
    level_guid: int | None
    level_path: str | None
    path_bindings: tuple[GuidPathBinding, ...]
    exports: tuple[GuidExportNode, ...]
    actor_guid: int
    connection_network_version: int
    archive_network_version: int
    references_resolvable: bool
    channel_index: int
    location: QuantizedVector10 | None
    scale: QuantizedVector10 | None
    velocity: QuantizedVector10 | None
    local_player_index: int | None = None
    force_unicode: bool = False
    game_replication_flags: int | None = None


@dataclass(frozen=True)
class ActorManifestPreflight:
    bunch: WireBunch
    actor_fields: MappingProxyType
    conservative_packet_bytes: int
    native_acceptance: bool = field(default=False, init=False)


def _static_guid(value):
    if type(value) is not int or not 3 <= value <= UINT32_MAX or not value & 1:
        raise ValueError('A caller-supplied static odd GUID is required')


def _full_path(value):
    if (type(value) is not str or not value.startswith('/') or
            len(value) > 4096 or any(c.isspace() or ord(c) < 32 for c in value) or
            '\\' in value or any(part == '' for part in re.split(r'[/.:]', value[1:]))):
        raise ValueError('An explicit complete UE object or package path is required')


def _source(manifest):
    if type(manifest.client_sha256) is not str or manifest.client_sha256 != CLIENT_SHA256:
        raise ValueError('This manifest requires the recovered client build SHA')
    if type(manifest.source_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', manifest.source_sha256):
        raise ValueError('An explicit lowercase source SHA256 is required')
    path = manifest.source_relative_path
    if (type(path) is not str or not path or '\\' in path or ':' in path or
            PurePosixPath(path).is_absolute() or
            any(part in ('', '.', '..') for part in path.split('/'))):
        raise ValueError('The source pin must use a plain relative path')


def _clone_exports(manifest):
    """Bound the original graph first, then detach via the existing codec."""
    if type(manifest.exports) is not tuple or len(manifest.exports) > DEFAULT_LIMITS.max_exports:
        raise ValueError('An immutable export tuple is required')
    occurrences = 0
    for root in manifest.exports:
        node, depth = root, 0
        while node is not None:
            occurrences += 1
            if depth > DEFAULT_LIMITS.max_depth or occurrences > DEFAULT_LIMITS.max_nodes:
                raise ValueError('Export graph depth or total-node limit exceeded')
            if type(node) is not GuidExportNode or type(node.path) is not str:
                raise ValueError('Only exact immutable GUID export nodes are supported')
            node, depth = node.outer, depth + 1
    writer = BitWriter(maximum_bits=DEFAULT_LIMITS.max_bytes * 8)
    write_guid_exports(writer, manifest.exports, force_unicode=manifest.force_unicode)
    reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
    result = read_guid_exports(reader)
    if reader.remaining:
        raise ValueError('The staged export graph has unread data')
    return result


def _paths(manifest, exports):
    if (type(manifest.path_bindings) is not tuple or
            not 1 <= len(manifest.path_bindings) <= DEFAULT_LIMITS.max_nodes):
        raise ValueError('A bounded immutable path-binding tuple is required')
    bindings, full_paths = {}, set()
    for binding in manifest.path_bindings:
        if type(binding) is not GuidPathBinding:
            raise ValueError('An exact immutable GUID path binding is required')
        _static_guid(binding.guid)
        _full_path(binding.full_path)
        if binding.guid in bindings or binding.full_path in full_paths:
            raise ValueError('Duplicate GUID or complete path binding')
        if binding.separator_from_outer not in (None, '.', ':'):
            raise ValueError('An observed dot or colon outer separator is required')
        bindings[binding.guid] = binding
        full_paths.add(binding.full_path)
    definitions = {}
    for root in exports:
        node = root
        while node is not None:
            definitions[node.guid] = node
            node = node.outer
    if set(bindings) != set(definitions):
        raise ValueError('Path bindings must exactly cover the exported graph')
    for guid, node in definitions.items():
        binding = bindings[guid]
        if node.outer is None:
            if binding.separator_from_outer is not None or binding.full_path != node.path:
                raise ValueError('Root export and observed complete path disagree')
            if '.' in node.path or ':' in node.path:
                raise ValueError('A null-Outer root export must identify a package, not an object')
        else:
            if (not node.path or any(c in node.path for c in '/.:\\') or
                    binding.separator_from_outer is None or
                    binding.full_path != bindings[node.outer.guid].full_path +
                    binding.separator_from_outer + node.path):
                raise ValueError('Export outer/leaf and observed complete path disagree')
    for guid, path, label in ((manifest.class_guid, manifest.class_path, 'class'),
                              (manifest.archetype_guid, manifest.archetype_path, 'archetype')):
        _static_guid(guid)
        _full_path(path)
        if guid not in bindings or bindings[guid].full_path != path:
            raise ValueError('The explicit ' + label + ' path is absent or mismatched')
    if manifest.class_guid == manifest.archetype_guid or manifest.class_path == manifest.archetype_path:
        raise ValueError('A generated UClass cannot substitute for the Actor archetype')
    if manifest.level_guid is None:
        if manifest.level_path is not None:
            raise ValueError('An omitted Level GUID requires an omitted path')
    else:
        _static_guid(manifest.level_guid)
        _full_path(manifest.level_path)
        if (manifest.level_guid in (manifest.class_guid, manifest.archetype_guid) or
                manifest.level_guid not in bindings or
                bindings[manifest.level_guid].full_path != manifest.level_path):
            raise ValueError('The explicit Level path is absent or mismatched')
        level = definitions[manifest.level_guid]
        world = level.outer
        package = None if world is None else world.outer
        if (world is None or package is None or package.outer is not None or
                bindings[level.guid].separator_from_outer != ':' or
                bindings[world.guid].separator_from_outer != '.'):
            raise ValueError('A Level requires the explicit Package.World:Level export chain')
    qualification = manifest.archetype_qualification
    if type(qualification) is not str or qualification not in ('explicit_template', 'named_default_object_candidate'):
        raise ValueError('An explicit archetype qualification is required')
    if qualification == 'named_default_object_candidate':
        cls, template = definitions[manifest.class_guid], definitions[manifest.archetype_guid]
        class_leaf = re.split(r'[/.:]', manifest.class_path)[-1]
        outers = {cls.guid}
        if cls.outer is not None:
            outers.add(cls.outer.guid)
        if (template.path != 'Default__' + class_leaf or template.outer is None or
                template.outer.guid not in outers):
            raise ValueError('The named candidate must match the observed Class and allowed Outer')


def preflight_actor_manifest(manifest, *, channel_sequence, max_packet_bytes):
    """Return a detached empty-content bunch plus fields owned by its producer.

    SHA formatting/path consistency is checked; source-file contents, template
    flags, actual client resolution, derived headers and possession are not.
    Sequence and byte limits belong to the connection, never the manifest.
    """
    if type(manifest) is not ActorManifest:
        raise ValueError('An exact immutable ActorManifest is required')
    _source(manifest)
    if type(manifest.force_unicode) is not bool:
        raise ValueError('An explicit Boolean Unicode policy is required')
    exports = _clone_exports(manifest)
    _paths(manifest, exports)
    vectors = {}
    for name in ('location', 'scale', 'velocity'):
        value = getattr(manifest, name)
        if value is not None and (type(value) is not QuantizedVector10 or type(value.steps) is not tuple):
            raise ValueError('Only exact integer quantized vectors are supported')
        vectors[name] = None if value is None else QuantizedVector10(tuple(value.steps))
    actor_fields = dict(exports=exports, actor_guid=manifest.actor_guid,
        archetype_guid=manifest.archetype_guid, level_guid=manifest.level_guid,
        connection_network_version=manifest.connection_network_version,
        archive_network_version=manifest.archive_network_version,
        references_resolvable=manifest.references_resolvable, channel_index=manifest.channel_index,
        **vectors, local_player_index=manifest.local_player_index,
        game_replication_flags=manifest.game_replication_flags,
        force_unicode=manifest.force_unicode, content_blocks=())
    bunch = build_actor_bunch(channel_sequence=channel_sequence,
                             max_packet_bytes=max_packet_bytes, **actor_fields)
    packet = WirePacket(SEQUENCE_MASK, SEQUENCE_MASK, (UINT32_MAX,), False, 0, None, (bunch,), 0)
    envelope = encode_observed_application(packet, max_packet_bytes=max_packet_bytes,
                                            received_by_server=False)
    return ActorManifestPreflight(bunch, MappingProxyType(actor_fields), len(envelope))
