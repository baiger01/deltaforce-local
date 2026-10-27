"""Restricted ordinary RepLayout UObject-reference streams.

Recovered consumer: 12db90d0 -> 12dbacf0 -> 12dbb3a0 -> 10e8ed20.
Packed GUID branch: 12bbb3c0/12bbc520, GUID != 1 and export mode false.
Source ledger: work/evidence/map-entry-next-20261005/
ordinary-rep-layout-object-stream-spec.json. This codec selects no field,
class, GUID, or connection. Callers must qualify those separately. It does
not implement the alternate internal-ACK or array/debug-option branches.
"""
from dataclasses import dataclass

from dfserver.replication.legacy_ds_actor_content import ActorContentBlock
from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX


MAX_REFERENCES = 32  # Local bound, not an engine limit.
EMPTY_REP_LAYOUT_BITS = 9


@dataclass(frozen=True)
class ObjectReference:
    handle: int
    actor_guid: int


def _references(references):
    if type(references) is not tuple or not 1 <= len(references) <= MAX_REFERENCES:
        raise ValueError('An explicit bounded nonempty tuple of references is required')
    previous = 0
    for item in references:
        if not isinstance(item, ObjectReference):
            raise ValueError('An explicit ObjectReference is required')
        if type(item.handle) is not int or not previous < item.handle <= 65535:
            raise ValueError('Ordinary scalar handles must be positive and strictly increasing')
        # This subset deliberately excludes null, default, and static GUIDs.
        # Local dynamic Actor GUIDs are even; their live mappings are external.
        if (type(item.actor_guid) is not int or not 2 <= item.actor_guid <= UINT32_MAX
                or item.actor_guid & 1):
            raise ValueError('An explicit normal dynamic Actor GUID is required')
        previous = item.handle
    return references


def build_object_reference_content(references):
    """Encode option=false, ascending handles/GUIDs, zero terminal handle."""
    references = _references(references)
    writer = BitWriter(maximum_bits=1 + (2 * MAX_REFERENCES + 1) * 40)
    writer.write_bool(False)
    for item in references:
        writer.write_packed_int(item.handle)
        writer.write_packed_int(item.actor_guid)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def read_object_reference_content(block):
    """Decode only this restricted stream, with no padding inside its slice."""
    if not isinstance(block, ActorContentBlock) or block.has_rep_layout is not True:
        raise ValueError('An explicit ordinary RepLayout Actor content block is required')
    reader = BitReader(block.payload, bit_count=block.payload_bit_count)
    if reader.read_bool():
        raise ValueError('The debug/checksum option branch is not supported')
    references = []
    while True:
        handle = reader.read_packed_int()
        if not handle:
            break
        if len(references) >= MAX_REFERENCES:
            raise ValueError('Reference stream exceeds local bound')
        references.append(ObjectReference(handle, reader.read_packed_int()))
    if reader.remaining:
        raise ValueError('Reference stream has trailing bits inside the content slice')
    return _references(tuple(references))


def build_empty_rep_layout_content():
    """Encode only option=false and the zero terminal handle.

    Source 12db92b8 reads the first packed handle; 12dbacf0 walks past
    unmatched commands without reading values; 12db9365/68 accepts zero.
    This is a nonzero nine-bit property slice, unlike a zero-length Actor
    content body which ProcessBunch skips at 128619c5/cc. Its caller must
    qualify the ordinary non-internal-ACK path and an existing Actor channel.
    Encoding does not prove replicator creation, native acceptance or Ready.
    """
    writer = BitWriter(maximum_bits=EMPTY_REP_LAYOUT_BITS)
    writer.write_bool(False)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def read_empty_rep_layout_content(block):
    """Validate the isolated canonical empty stream and return no fields.

    Exact bit length and canonical zero byte padding are local constraints;
    padding is never included inside the native property slice. Alternate
    option branches, field values and following replicator fields are excluded.
    """
    if not isinstance(block, ActorContentBlock) or block.has_rep_layout is not True:
        raise ValueError('An explicit ordinary RepLayout Actor content block is required')
    if (type(block.payload_bit_count) is not int or
            block.payload_bit_count != EMPTY_REP_LAYOUT_BITS):
        raise ValueError('An empty RepLayout stream requires exactly nine bits')
    if (not isinstance(block.payload, bytes) or len(block.payload) != 2 or
            block.payload[1] & 0xfe):
        raise ValueError('An exact canonical empty RepLayout bit slice is required')
    reader = BitReader(block.payload, bit_count=block.payload_bit_count)
    if reader.read_bool():
        raise ValueError('The debug/checksum option branch is not supported')
    if reader.read_packed_int() != 0:
        raise ValueError('An empty RepLayout stream requires a zero terminal handle')
    if reader.remaining:
        raise ValueError('Empty RepLayout stream has trailing bits inside the content slice')
    return ()
