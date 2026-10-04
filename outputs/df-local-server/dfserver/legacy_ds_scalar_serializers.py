"""Source-qualified scalar value encoders for the observed native property hooks.

These are value bits only, not a RepLayout stream, a field-handle mapping, or
a connection implementation. Binding is a caller-supplied observation of the
property descriptor's virtual+0x90 target in this exact Shipping build. It
does not prove that any particular property exists or accepts the value.

The int subset excludes byte swapping. The object subset excludes export
mode and GUID1/default paths, and requires explicit caller declarations of
type-compatible resolution and completed export acknowledgements. This
module does not perform either check. GUID0 is the native null reference.
Source: work/evidence/native-rep-layout-scalar-serialization-rules.json.
"""

from dataclasses import dataclass

from .legacy_ds_bit_archive import BitWriter, UINT32_MAX


SHIPPING_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
BOOL_SERIALIZER_RVA = 0x10e8ebe0
INT32_SERIALIZER_RVA = 0x10e5ce20
INT32_SCALAR_LEAF_RVA = 0x286bf70
INT32_PROPERTY_VTABLE_RVA = 0x15a863c0
OBJECT_SERIALIZER_RVA = 0x10e8ed20
MAX_SCALAR_BITS = 40


@dataclass(frozen=True)
class NativeScalarBinding:
    """An observed property hook, never inferred from an opcode or a name."""

    client_sha256: str
    serializer_target_rva: int
    scalar_leaf_target_rva: int | None = None
    property_vtable_rva: int | None = None


def _qualify(writer, binding, target):
    if not isinstance(writer, BitWriter):
        raise ValueError('A native bit writer is required')
    if not isinstance(binding, NativeScalarBinding):
        raise ValueError('An observed native scalar binding is required')
    if (type(binding.client_sha256) is not str or
            binding.client_sha256 != SHIPPING_SHA256):
        raise ValueError('The exact source Shipping SHA is required')
    if (type(binding.serializer_target_rva) is not int or
            binding.serializer_target_rva != target):
        raise ValueError('The observed serializer hook does not qualify this subset')


def _append(writer, staged):
    # This single append validates capacity before changing the caller cursor.
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def write_bool_value(writer, value, *, binding):
    """Append one boolean bit atomically; descriptor masks are memory-only."""
    _qualify(writer, binding, BOOL_SERIALIZER_RVA)
    if type(value) is not bool:
        raise ValueError('A boolean value is required')
    staged = BitWriter(maximum_bits=1)
    # 10e8ec14 setne; 10e8ec19 archive virtual+0x68, R8d=1.
    staged.write_bool(value)
    return _append(writer, staged)


def write_int32_value(writer, value, *, binding, no_byteswap):
    """Append signed int32 as four raw little-endian bytes, without alignment.

    no_byteswap must be exactly True: native leaf286bf70 has a separate
    archive+0x29 bit0x20 path to helper10b4b540 which is outside this subset.
    """
    _qualify(writer, binding, INT32_SERIALIZER_RVA)
    # virtual+0x90 is generic. Only this observed FIntProperty vtable and its
    # virtual+0x88 leaf establish the signed32 subset; other numerics can
    # share the generic entry point and are deliberately not inferred.
    if (type(binding.scalar_leaf_target_rva) is not int or
            binding.scalar_leaf_target_rva != INT32_SCALAR_LEAF_RVA or
            type(binding.property_vtable_rva) is not int or
            binding.property_vtable_rva != INT32_PROPERTY_VTABLE_RVA):
        raise ValueError('The observed FIntProperty table and signed32 leaf are required')
    if no_byteswap is not True:
        raise ValueError('An explicit no-byteswap archive profile is required')
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise ValueError('A signed int32 value is required')
    staged = BitWriter(maximum_bits=32)
    # FIntProperty slot+0x88 -> 286bf70: normal archive virtual+0x60, 4 bytes.
    # FBitWriter10b4a840 copies byte_count*8 at the existing bit cursor.
    staged.write_bytes(value.to_bytes(4, 'little', signed=True))
    return _append(writer, staged)


def write_resolved_object_reference(writer, guid, *, binding, export_mode,
                                    reference_resolved, exports_acknowledged):
    """Append an ordinary packed GUID, given a caller-resolved object contract.

    reference_resolved declares the GUID resolves to an object compatible
    with this descriptor's expected class, or GUID0 deliberately denotes
    null. exports_acknowledged declares any required mapping exports have
    completed their acknowledgement flow. Neither declaration is verified
    here; these value bits do not register a mapping or create an actor.
    """
    _qualify(writer, binding, OBJECT_SERIALIZER_RVA)
    if export_mode is not False:
        raise ValueError('Only explicit non-export PackageMap mode is supported')
    if reference_resolved is not True or exports_acknowledged is not True:
        raise ValueError('Explicit resolved and export-acknowledged contracts are required')
    if type(guid) is not int or not 0 <= guid <= UINT32_MAX or guid == 1:
        raise ValueError('An ordinary uint32 reference other than GUID1 is required')
    staged = BitWriter(maximum_bits=MAX_SCALAR_BITS)
    # Object hook10e8ed76 -> PackageMap virtual+0x260. Ordinary writer12bbc5de
    # is packed GUID only; GUID0 returns early, GUID1/export require flags.
    staged.write_packed_int(guid)
    return _append(writer, staged)
