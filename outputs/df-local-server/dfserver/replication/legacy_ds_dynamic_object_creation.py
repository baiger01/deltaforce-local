"""Bounded ordinary dynamic UObject creation, with no ActorComponent semantics.

The currently admitted class is the source main Pawn FSM. Its schema digest is
derived from immutable native creation/receive evidence by the work helper.
The receiver chooses NAME_None and the current Actor channel's Pawn as Outer.
Only the ordinary nine zero-bit no-field RepLayout body is admitted here.
"""
from dataclasses import dataclass

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.replication.legacy_ds_guid_exports import GuidExportNode, DEFAULT_LIMITS


CLASS_PATH = '/Game/BluePrints/Characters/CharacterFSM/DFMCharacterFSM_Main.DFMCharacterFSM_Main_C'
SOURCE_SHA256 = 'b7225cc8fc3a3ca6bcc1b568b526278b1ab4f954c288dbb49efd0def9693c4c4'


@dataclass(frozen=True)
class DynamicObjectCreation:
    actor_guid: int
    guid: int
    class_guid: int
    class_path: str
    source_sha256: str
    payload: bytes = b'\0\0'
    payload_bit_count: int = 9

    @property
    def outer_guid(self):
        return self.actor_guid

    @property
    def name(self):
        return None


def _namespace(values, label, maximum=65536):
    if (type(values) is not tuple or not 1 <= len(values) <= maximum or
            any(type(value) is not int or not 2 <= value <= UINT32_MAX for value in values) or
            len(set(values)) != len(values)):
        raise ValueError('A distinct bounded '+label+' GUID namespace is required')
    return set(values)


def qualified_class_exports(exports):
    """Select only exact two-node static package/class bindings from the exports."""
    if type(exports) is not tuple or len(exports) > DEFAULT_LIMITS.max_exports:
        raise ValueError('A bounded dynamic UObject class export tuple is required')
    package, name = CLASS_PATH.rsplit('.', 1)
    result, definitions, nodes = set(), {}, 0
    for root in exports:
        if type(root) is not GuidExportNode:
            raise ValueError('The dynamic UObject export root must be an exact export node')
        node, depth = root, 0
        while node is not None:
            nodes += 1
            if (type(node) is not GuidExportNode or depth > DEFAULT_LIMITS.max_depth or
                    nodes > DEFAULT_LIMITS.max_nodes or type(node.guid) is not int or
                    not 3 <= node.guid <= UINT32_MAX or not node.guid & 1 or
                    type(node.path) is not str or not node.path or
                    len(node.path) > DEFAULT_LIMITS.max_path_units or
                    node.outer is not None and type(node.outer) is not GuidExportNode or
                    node.checksum is not None and (type(node.checksum) is not int or
                        not 0 <= node.checksum <= UINT32_MAX)):
                raise ValueError('The dynamic UObject export graph exceeds its qualified bounds')
            definition = (node.path, None if node.outer is None else node.outer.guid, node.checksum)
            if node.guid in definitions and definitions[node.guid] != definition:
                raise ValueError('A dynamic UObject export GUID changes its path binding')
            definitions[node.guid] = definition
            if (node.path == name and type(node.outer) is GuidExportNode and
                    node.outer.path == package and node.outer.outer is None and
                    node.guid != node.outer.guid):
                result.add((node.guid, CLASS_PATH))
            node, depth = node.outer, depth+1
    return tuple(sorted(result))


def preflight_creation(update, *, actor_guids, exported_class_bindings, allocated_guids):
    """Validate before reserving this fresh GUID in the caller's private namespace."""
    actors = _namespace(actor_guids, 'Actor', 128)
    namespace = _namespace(allocated_guids, 'complete allocated')
    if (type(exported_class_bindings) is not tuple or not 1 <= len(exported_class_bindings) <= 128 or
            any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not int or
                not 3 <= row[0] <= UINT32_MAX or not row[0] & 1 or
                row[1] != CLASS_PATH for row in exported_class_bindings) or
            len({row[0] for row in exported_class_bindings}) != len(exported_class_bindings)):
        raise ValueError('Exact qualified dynamic UObject class export bindings are required')
    if (type(update) is not DynamicObjectCreation or
            any(type(value) is not int or not 2 <= value <= UINT32_MAX
                for value in (update.actor_guid, update.guid, update.class_guid)) or
            update.actor_guid & 1 or update.guid & 1 or not update.class_guid & 1 or
            update.actor_guid not in actors or not actors <= namespace or
            update.class_guid not in namespace or update.guid in namespace or
            (update.class_guid, update.class_path) not in exported_class_bindings or
            update.class_path != CLASS_PATH or update.source_sha256 != SOURCE_SHA256 or
            type(update.payload) is not bytes or update.payload != b'\0\0' or
            type(update.payload_bit_count) is not int or update.payload_bit_count != 9):
        raise ValueError('A source-qualified empty dynamic UObject, exact Actor/class and fresh GUID are required')
    return update


def write_creation(writer, update, **kwargs):
    """Append the complete content header atomically, without package exports."""
    if type(writer) is not BitWriter:
        raise ValueError('A bounded bit writer is required for dynamic UObject creation')
    preflight_creation(update, **kwargs)
    staged = BitWriter(maximum_bits=256)
    staged.write_bool(True)
    staged.write_bool(False)
    staged.write_packed_int(update.guid)
    staged.write_bool(False)
    staged.write_packed_int(update.class_guid)
    staged.write_packed_int(update.payload_bit_count)
    staged.write_payload(update.payload, update.payload_bit_count)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count
