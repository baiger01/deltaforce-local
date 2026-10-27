"""Pure normal-client dynamic GS ability component creation subset.

This creates only reviewable bytes. The service exports the real class first,
then sends after its ACK and the existing GS Actor Open ACK. No guessed native
property handles, stable default-subobject name, RPC or gameplay completion.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_manifest import ActorManifest, GuidPathBinding
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_guid_exports import GuidExportNode
from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = 'work/evidence/model-init-chain-20261018/native-current-skill-gs-dynamic-component-schema-v2.json'
SCHEMA_SHA256 = '3893210b7c72243bed6d358faaca21ad5bbab984848e88dfbd8194049f499109'
GAME_STATE_CLASS = '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C'
GAME_STATE_CDO = '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.Default__BP_GameState_PVPVE_C'


@dataclass(frozen=True)
class DynamicComponentUpdate:
    actor_guid: int
    guid: int
    class_guid: int
    class_path: str
    source_sha256: str
    payload: bytes
    payload_bit_count: int
    stably_named: bool = False
    has_rep_layout: bool = True


@dataclass(frozen=True)
class DynamicComponentContent:
    payload: bytes
    payload_bit_count: int


@dataclass(frozen=True)
class DynamicComponentManifest:
    parent_manifest: ActorManifest
    component_guid: int
    class_guid: int
    source_sha256: str
    allocated_guids: tuple[int, ...]


def qualify_schema(schema):
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256 or
            schema.get('kind') != 'source_qualified_gs_ability_dynamic_component_creation_v1' or
            schema.get('connection_network_version') != 13 or schema.get('archive_network_version') != 13):
        raise ValueError('The pinned current GS ability creation schema is required')
    return schema['component']


def schema_binding(root=ROOT):
    raw = (root/SCHEMA_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The current GS ability schema file changed')
    schema = json.loads(raw)
    qualify_schema(schema)
    for source in schema['sources']:
        if hashlib.sha256((root/source['relative_path']).read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('The current GS ability creation native source changed')
    return schema


def _namespace(allocated_guids):
    if (type(allocated_guids) is not tuple or not allocated_guids or
            len(allocated_guids) > 4096 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            len(set(allocated_guids)) != len(allocated_guids)):
        raise ValueError('The complete explicit current GUID namespace is required')
    return set(allocated_guids)


def _dynamic(value):
    return type(value) is int and 2 <= value <= UINT32_MAX and not value & 1


def _static(value):
    return type(value) is int and 3 <= value <= UINT32_MAX and bool(value & 1)


def component_manifest(schema, *, parent_manifest, package_guid, class_guid,
                       component_guid, allocated_guids):
    """Add only real package/class exports; the component has no path export.

    The normal receiver creates an unnamed instance with channel-GS Outer.
    Its identity is the fresh dynamic GUID and typed class, not the server name.
    """
    source = qualify_schema(schema)
    used = _namespace(allocated_guids)
    parent = parent_manifest
    if (type(parent) is not ActorManifest or parent.class_path != GAME_STATE_CLASS or
            parent.archetype_path != GAME_STATE_CDO or parent.client_sha256 != schema['client_sha256'] or
            parent.connection_network_version != 13 or parent.archive_network_version != 13 or
            parent.references_resolvable is not True or not _dynamic(parent.actor_guid) or
            not ({parent.actor_guid,parent.class_guid,parent.archetype_guid} |
                {b.guid for b in parent.path_bindings}) <= used):
        raise ValueError('The current source-qualified normal GS manifest is required')
    for export in parent.exports:
        seen = set()
        while export is not None:
            if (type(export) is not GuidExportNode or export.guid not in used or
                    id(export) in seen or len(seen) >= 32):
                raise ValueError('The complete parent export graph namespace is required')
            seen.add(id(export))
            export = export.outer
    fresh = (package_guid,class_guid,component_guid)
    if (not _static(package_guid) or not _static(class_guid) or not _dynamic(component_guid) or
            len(set(fresh)) != 3 or set(fresh) & used):
        raise ValueError('Two fresh odd class asset GUIDs and a fresh even component GUID are required')
    package_path, name = source['class_path'].rsplit('.',1)
    package = GuidExportNode(package_guid,package_path)
    klass = GuidExportNode(class_guid,name,package)
    parent = replace(parent, exports=parent.exports+(klass,), path_bindings=parent.path_bindings+(
        GuidPathBinding(package_guid,package_path), GuidPathBinding(class_guid,source['class_path'],'.')))
    return DynamicComponentManifest(parent,component_guid,class_guid,SCHEMA_SHA256,allocated_guids+fresh)


def projected_creation_update(schema, projection, *, game_state_open_acknowledged,
                              class_export_acknowledged):
    """Preferred integration API retaining the qualified GS projection binding."""
    source = qualify_schema(schema)
    if (type(projection) is not DynamicComponentManifest or projection.source_sha256 != SCHEMA_SHA256 or
            projection.parent_manifest.class_path != GAME_STATE_CLASS or
            projection.parent_manifest.client_sha256 != schema['client_sha256'] or
            not any(b.guid == projection.class_guid and b.full_path == source['class_path']
                for b in projection.parent_manifest.path_bindings) or
            projection.component_guid not in _namespace(projection.allocated_guids)):
        raise ValueError('The actual source-qualified GS class projection is required')
    return empty_component_update(schema, actor_guid=projection.parent_manifest.actor_guid,
        component_guid=projection.component_guid, class_guid=projection.class_guid,
        allocated_guids=tuple(g for g in projection.allocated_guids if g != projection.component_guid),
        game_state_open_acknowledged=game_state_open_acknowledged,
        class_export_acknowledged=class_export_acknowledged)


def empty_component_update(schema, *, actor_guid, component_guid, class_guid,
        allocated_guids, game_state_open_acknowledged, class_export_acknowledged):
    """A low-level empty creation update for the caller's qualified GS channel.

    Use component_manifest first. The namespace here is the state immediately
    before reserving this dynamic component; both static class exports exist.
    """
    source = qualify_schema(schema)
    used = _namespace(allocated_guids)
    if (not _dynamic(actor_guid) or not _dynamic(component_guid) or not _static(class_guid) or
            actor_guid not in used or class_guid not in used or component_guid in used or
            game_state_open_acknowledged is not True or class_export_acknowledged is not True):
        raise ValueError('ACKed current GS/class exports and one collision-free dynamic component are required')
    body = build_empty_rep_layout_content()
    return DynamicComponentUpdate(actor_guid,component_guid,class_guid,source['class_path'],SCHEMA_SHA256,
        body.payload,body.payload_bit_count)


def _update(update,schema):
    source = qualify_schema(schema)
    if (type(update) is not DynamicComponentUpdate or not _dynamic(update.actor_guid) or
            not _dynamic(update.guid) or update.actor_guid == update.guid or
            not _static(update.class_guid) or update.source_sha256 != SCHEMA_SHA256 or
            update.class_path != source['class_path'] or update.stably_named is not False or
            update.has_rep_layout is not True or type(update.payload) is not bytes or
            type(update.payload_bit_count) is not int or update.payload_bit_count != 9 or
            update.payload != b'\0\0'):
        raise ValueError('Only the source-qualified empty GS ability dynamic component is supported')


def build_dynamic_component_content(update, *, schema):
    """One content block, without alignment or any Actor/bunch wrapper."""
    _update(update,schema)
    writer = BitWriter(maximum_bits=256)
    writer.write_bool(True)
    writer.write_bool(False)
    writer.write_packed_int(update.guid)
    writer.write_bool(False)
    writer.write_packed_int(update.class_guid)
    writer.write_packed_int(update.payload_bit_count)
    writer.write_payload(update.payload,update.payload_bit_count)
    return DynamicComponentContent(writer.to_bytes(),writer.bit_count)


def read_dynamic_component_content(reader, *, expected_update, schema):
    """Strict atomic decode of only this explicitly qualified creation subset."""
    _update(expected_update,schema)
    if type(reader) is not BitReader:
        raise ValueError('A bounded native bit reader is required')
    start = reader.position
    try:
        if (reader.read_bool() is not True or reader.read_bool() is not False or
                reader.read_packed_int() != expected_update.guid or reader.read_bool() is not False or
                reader.read_packed_int() != expected_update.class_guid or reader.read_packed_int() != 9 or
                reader.read_payload(9) != b'\0\0'):
            raise ValueError('The source-qualified GS dynamic component content differs')
        return build_dynamic_component_content(expected_update,schema=schema)
    except Exception:
        reader.position = start
        raise
