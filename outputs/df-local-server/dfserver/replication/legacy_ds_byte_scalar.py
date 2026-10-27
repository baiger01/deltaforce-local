"""Pinned FByteProperty value bits only; no field, enum label or Role default.

Consumer 10e8ec50 reads descriptor+90. A null enum selects eight bits; a
qualified UEnum maximum selects ceilLog2(maximum). Its ordinary archive
virtual+68 transfers that exact bit count at the current cursor. Source:
work/evidence/map-entry-next-20261007/role-byte-net-serialize.10e8ec50.asm.txt.
Callers must qualify the actual descriptor, enum data and receiving field.
"""
from dataclasses import dataclass

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_scalar_serializers import SHIPPING_SHA256
from dfserver.replication.legacy_ds_actor_content import ActorContentBlock
from dfserver.replication.legacy_ds_rep_layout_refs import ObjectReference, _references

BYTE_SERIALIZER_RVA = 0x10e8ec50


@dataclass(frozen=True)
class NativeByteEnumBinding:
    client_sha256: str
    serializer_target_rva: int
    enum_present: bool
    enum_maximum: int | None


def qualified_byte_bit_count(binding):
    if (type(binding) is not NativeByteEnumBinding
            or binding.client_sha256 != SHIPPING_SHA256
            or type(binding.serializer_target_rva) is not int
            or binding.serializer_target_rva != BYTE_SERIALIZER_RVA
            or type(binding.enum_present) is not bool):
        raise ValueError('An exact observed native byte/enum binding is required')
    if not binding.enum_present:
        if binding.enum_maximum is not None:
            raise ValueError('The null-enum branch has no enum maximum')
        return 8
    maximum = binding.enum_maximum
    if type(maximum) is not int or not 0 <= maximum <= 256:
        raise ValueError('A qualified byte-sized enum maximum is required')
    return 0 if maximum <= 1 else (maximum - 1).bit_length()


def write_byte_enum_value(writer, value, *, binding):
    """Append representable unsigned byte bits atomically, without alignment.

    No enum membership or gameplay meaning is inferred. The caller supplies
    an observed binding; this codec never turns an opcode/name into a binding.
    Values whose high bits would be lost are rejected by local policy.
    """
    if not isinstance(writer, BitWriter):
        raise ValueError('A native bit writer is required')
    width = qualified_byte_bit_count(binding)
    if type(value) is not int or not 0 <= value <= 255 or value >= 1 << width:
        raise ValueError('An exactly representable unsigned byte value is required')
    staged = BitWriter(maximum_bits=max(1, width))
    staged.write_bits(value, width)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return width


@dataclass(frozen=True)
class ByteEnumField:
    handle: int
    value: int
    binding: NativeByteEnumBinding


def build_byte_reference_content(byte_fields, references):
    """Restricted ordinary scalar stream with explicit caller-qualified handles.

    Option=false, strictly ascending handles, a byte/enum or resolved dynamic
    reference value, then terminal handle zero. No field/Role mapping, remote
    value, ownership or enum business meaning is selected by this codec.
    Native arrays, internal-ACK and checksum/debug branches are excluded.
    """
    if type(byte_fields) is not tuple or not 1 <= len(byte_fields) <= 2:
        raise ValueError('One or two explicit qualified byte fields are required')
    if type(references) is not tuple:
        raise ValueError('An explicit tuple of resolved dynamic references is required')
    if references:
        _references(references)
    for field in byte_fields:
        if (type(field) is not ByteEnumField or type(field.handle) is not int
                or not 1 <= field.handle <= 65535):
            raise ValueError('An explicit ordinary scalar byte handle is required')
    fields = sorted(byte_fields + references, key=lambda field: field.handle)
    if len({field.handle for field in fields}) != len(fields):
        raise ValueError('Ordinary scalar handles must be unique')
    writer = BitWriter(maximum_bits=1 + (len(fields)+1)*40 + len(byte_fields)*8 + len(references)*40)
    writer.write_bool(False)
    for field in fields:
        writer.write_packed_int(field.handle)
        if type(field) is ByteEnumField:
            write_byte_enum_value(writer,field.value,binding=field.binding)
        elif type(field) is ObjectReference:
            writer.write_packed_int(field.actor_guid)
        else:
            raise ValueError('Only explicit byte fields and resolved dynamic references are supported')
    writer.write_packed_int(0)
    return ActorContentBlock(True,writer.to_bytes(),writer.bit_count)
