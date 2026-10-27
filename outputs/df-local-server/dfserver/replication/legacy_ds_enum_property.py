"""Value bits for the separately qualified FEnumProperty native serializer."""
from dataclasses import dataclass

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_scalar_serializers import SHIPPING_SHA256


ENUM_PROPERTY_SERIALIZER_RVA = 0x10e29fa0


@dataclass(frozen=True)
class NativeEnumPropertyBinding:
    client_sha256: str
    serializer_target_rva: int
    enum_maximum: int
    archive_version: int


def enum_property_bit_count(binding):
    if (type(binding) is not NativeEnumPropertyBinding or
            binding.client_sha256 != SHIPPING_SHA256 or
            type(binding.serializer_target_rva) is not int or
            binding.serializer_target_rva != ENUM_PROPERTY_SERIALIZER_RVA or
            type(binding.enum_maximum) is not int or not 0 <= binding.enum_maximum <= 255 or
            type(binding.archive_version) is not int or not 0 <= binding.archive_version <= 65535):
        raise ValueError('A qualified byte-backed FEnumProperty binding is required')
    # Native 10e29faa/10e29fe2 includes the maximum starting at version 12.
    exclusive = binding.enum_maximum + int(binding.archive_version >= 12)
    return max(0, exclusive - 1).bit_length()


def write_enum_property_value(writer, value, *, binding):
    width = enum_property_bit_count(binding)
    if (not isinstance(writer, BitWriter) or type(value) is not int or
            not 0 <= value <= binding.enum_maximum or value >= 1 << width):
        raise ValueError('An exactly representable enum property value is required')
    staged = BitWriter(maximum_bits=max(1, width))
    staged.write_bits(value, width)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return width
