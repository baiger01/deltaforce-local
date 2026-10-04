"""Callback-only paths for selected Class or qualified template metadata.

The caller must select Class or explicitly qualified template metadata and verify the image/read scope. This is
not an instance, account, or player-state discovery API. No process is opened and
no native getter is called. Offsets and separators follow saved 10ead090 and
10ead1e0, qualified in evidence/native-metadata-object-path-resolver.json.
"""
from dataclasses import dataclass
import struct

from native_metadata_names import MAX_ADDRESS, object_name
from native_metadata_objects import ObjectRecord, validate_object_record

SHIPPING_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CODE_CACHE_MANIFEST_SHA256 = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
PACKAGE_CLASS_RVA = 0x1e34ca90
CLASS_OFFSET = 8
OUTER_OFFSET = 0x10
NAME_OFFSET = 0x1c
MAX_DEPTH = 32  # Local read policy, not a native recursion limit.


class PathResolutionError(ValueError):
    """A complete, stable, bounded metadata path was not established."""


@dataclass(frozen=True)
class _Node:
    address: int
    record: ObjectRecord
    class_address: int
    outer: int
    token: bytes
    name: str


def _address(value, size=1):
    if type(value) is not int or not 0 < value <= MAX_ADDRESS - size + 1:
        raise PathResolutionError('Invalid bounded metadata address')
    return value


def _read(reader, address, size):
    _address(address, size)
    value = reader(address, size)
    if not isinstance(value, bytes) or len(value) != size:
        raise PathResolutionError('Read callback did not return exact bytes')
    return value


def _fields(reader, address):
    _address(address, NAME_OFFSET + 8)
    class_address, = struct.unpack('<Q', _read(reader, address + CLASS_OFFSET, 8))
    outer, = struct.unpack('<Q', _read(reader, address + OUTER_OFFSET, 8))
    token = _read(reader, address + NAME_OFFSET, 8)
    _address(class_address)
    if outer:
        _address(outer, NAME_OFFSET + 8)
    return class_address, outer, token


def _node(reader, module_base, address):
    record = validate_object_record(reader, module_base, address)
    class_address, outer, token = _fields(reader, address)
    name = str(object_name(reader, module_base, address))
    if _read(reader, address + NAME_OFFSET, 8) != token:
        raise PathResolutionError('Metadata name token changed during reads')
    if validate_object_record(reader, module_base, address) != record:
        raise PathResolutionError('Metadata registry identity changed during reads')
    return _Node(address, record, class_address, outer, token, name)


def _unchanged(reader, module_base, node):
    if _fields(reader, node.address) != (node.class_address, node.outer, node.token):
        raise PathResolutionError('Metadata class, outer or name changed during path reads')
    if validate_object_record(reader, module_base, node.address) != node.record:
        raise PathResolutionError('Metadata registry identity changed during path reads')


def object_path(read_exact, module_base, object_address, max_depth=32):
    """Resolve a selected Class or qualified template metadata object's path.

    Each node and the Package singleton must be a live registry identity; serial
    zero is allowed. The Outer chain and all observed class/name/identity fields
    are checked again before returning. Cycles, missing data and chains above the
    local 32-node bound are rejected. ``object_address=0`` returns native ``None``
    without accessing memory. No stop-Outer variant or instance discovery exists.
    """
    if not callable(read_exact) or type(max_depth) is not int or not 1 <= max_depth <= MAX_DEPTH:
        raise PathResolutionError('Invalid callback or metadata depth budget')
    _address(module_base, PACKAGE_CLASS_RVA + 8)
    if type(object_address) is not int or object_address < 0:
        raise PathResolutionError('Invalid metadata object address')
    if object_address == 0:
        return 'None'
    _address(object_address, NAME_OFFSET + 8)
    cell = module_base + PACKAGE_CLASS_RVA
    package_bytes = _read(read_exact, cell, 8)
    package_address, = struct.unpack('<Q', package_bytes)
    _address(package_address, NAME_OFFSET + 8)
    package = _node(read_exact, module_base, package_address)
    if package.name != 'Package':
        raise PathResolutionError('Package singleton name is not confirmed')

    nodes = []
    seen = set()
    current = object_address
    while current:
        if current in seen:
            raise PathResolutionError('Metadata Outer cycle')
        if len(nodes) >= max_depth:
            raise PathResolutionError('Metadata Outer chain exceeds depth budget')
        seen.add(current)
        node = _node(read_exact, module_base, current)
        nodes.append(node)
        current = node.outer

    pieces = [nodes[-1].name]
    for index in range(len(nodes) - 2, -1, -1):
        outer = nodes[index + 1]
        if outer.class_address == package_address:
            separator = '.'
        elif not outer.outer:
            # Native would inspect Outer.Outer.Class here; do not guess a class
            # or dereference zero for an inconsistent metadata chain.
            raise PathResolutionError('Non-Package Outer has no parent for separator')
        else:
            separator = ':' if nodes[index + 2].class_address == package_address else '.'
        pieces.extend((separator, nodes[index].name))

    for node in nodes:
        _unchanged(read_exact, module_base, node)
    _unchanged(read_exact, module_base, package)
    if _read(read_exact, cell, 8) != package_bytes:
        raise PathResolutionError('Package singleton changed during path reads')
    return ''.join(pieces)
