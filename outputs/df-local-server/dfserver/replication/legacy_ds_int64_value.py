"""Source-qualified FInt64Property value bits; no field selection or networking.

HeroID's observed descriptor table is 15a86560, independently confirmed by
gen4 -> FInt64Property construction, sizeof8 and its table assignment in
player-state-human-fixed-class-type-sources.json. The current descriptor's
v90 is the generic serializer 10e5ce20; v88 is shared eight-byte leaf286c000.
The leaf's existing normal archive subset is raw8 with explicit no-byteswap.

This value codec supplies neither a Hero-to-Avatar mapping nor a RepLayout
handle, notification, Actor channel, initialization timing or send operation.
"""
from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_scalar_serializers import NativeScalarBinding, SHIPPING_SHA256

INT64_PROPERTY_VTABLE_RVA = 0x15a86560
INT64_SERIALIZER_RVA = 0x10e5ce20
INT64_SCALAR_LEAF_RVA = 0x286c000


def write_int64_value(writer, value, *, binding, no_byteswap):
    """Append exactly signed64 bits at the current bit cursor, atomically."""
    if (type(writer) is not BitWriter or type(binding) is not NativeScalarBinding
            or binding.client_sha256 != SHIPPING_SHA256
            or type(binding.serializer_target_rva) is not int
            or binding.serializer_target_rva != INT64_SERIALIZER_RVA
            or type(binding.scalar_leaf_target_rva) is not int
            or binding.scalar_leaf_target_rva != INT64_SCALAR_LEAF_RVA
            or type(binding.property_vtable_rva) is not int
            or binding.property_vtable_rva != INT64_PROPERTY_VTABLE_RVA):
        raise ValueError('The observed source-qualified FInt64Property table and leaf are required')
    if no_byteswap is not True:
        raise ValueError('An explicit no-byteswap archive profile is required')
    if type(value) is not int or not -(1 << 63) <= value < (1 << 63):
        raise ValueError('A signed int64 value is required')
    staged = BitWriter(maximum_bits=64)
    staged.write_bytes(value.to_bytes(8, 'little', signed=True))
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count
