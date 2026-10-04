"""Ordinary class-cache field envelopes for Actor-selector content.

Pinned native source: work/evidence/native-actor-replicator-first-body-envelope.json,
ReadFieldHeaderAndPayload12864bf0. The normal (not internal-ACK) profile reads
a class-dependent bounded RepIndex, a packed payload bit count, and that exact
unaligned payload. Fields end at their parent body's EOF; index zero is not an
end marker. These are envelopes, not property serializers or RPC definitions.

The caller must recover the real ClassNetCache exclusive maximum and each field
mapping for this client version. This module has no game-specific default index,
class path, property handle, ready notification, or possession implementation.
It intentionally cannot construct the separate RepLayout/property region.
"""

from dataclasses import dataclass

from .legacy_ds_actor_content import ActorContentBlock
from .legacy_ds_bit_archive import BitReader, BitWriter, MAX_BITS, UINT32_MAX


MAX_FIELDS = 256


@dataclass(frozen=True)
class NormalClassFieldProfile:
    # Native12864fe4..fff: ClassNetCache[+0]+ClassNetCache[+28]+1.
    exclusive_index_maximum: int
    internal_ack: bool

    def __post_init__(self):
        if (type(self.exclusive_index_maximum) is not int or
                not 1 <= self.exclusive_index_maximum <= UINT32_MAX):
            raise ValueError('Explicit class-cache exclusive index maximum is required')
        if type(self.internal_ack) is not bool or self.internal_ack:
            raise ValueError('Only the explicit normal non-internal-ACK field profile is supported')


@dataclass(frozen=True)
class ClassFieldEnvelope:
    rep_index: int
    payload: bytes
    payload_bit_count: int


@dataclass(frozen=True)
class ClassFieldLimits:
    max_fields: int = MAX_FIELDS
    max_payload_bits: int = MAX_BITS
    max_total_bits: int = MAX_BITS

    def __post_init__(self):
        for value, minimum, maximum in (
                (self.max_fields, 0, MAX_FIELDS),
                (self.max_payload_bits, 0, MAX_BITS),
                (self.max_total_bits, 1, MAX_BITS)):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError('Invalid local class-field resource limit')


DEFAULT_LIMITS = ClassFieldLimits()


def _validate(profile, limits):
    if not isinstance(profile, NormalClassFieldProfile):
        raise ValueError('An explicit NormalClassFieldProfile is required')
    if not isinstance(limits, ClassFieldLimits):
        raise ValueError('An explicit ClassFieldLimits is required')
    profile.__post_init__()
    limits.__post_init__()


def _stage(writer, field, profile, limits):
    if not isinstance(field, ClassFieldEnvelope):
        raise ValueError('An explicit ClassFieldEnvelope is required')
    if (type(field.payload_bit_count) is not int or
            not 0 <= field.payload_bit_count <= limits.max_payload_bits):
        raise ValueError('Class-field payload exceeds local bound')
    writer.write_bounded_int(field.rep_index, profile.exclusive_index_maximum)
    writer.write_packed_int(field.payload_bit_count)
    writer.write_payload(field.payload, field.payload_bit_count)


def write_class_fields(writer, fields, *, profile, limits=DEFAULT_LIMITS):
    """Append a complete bounded tuple atomically, with no terminal field."""
    if not isinstance(writer, BitWriter):
        raise ValueError('A native bit writer is required')
    _validate(profile, limits)
    if not isinstance(fields, tuple) or len(fields) > limits.max_fields:
        raise ValueError('Class fields require a locally bounded tuple')
    staged = BitWriter(maximum_bits=limits.max_total_bits)
    for field in fields:
        _stage(staged, field, profile, limits)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def write_class_field(writer, field, *, profile, limits=DEFAULT_LIMITS):
    return write_class_fields(writer, (field,), profile=profile, limits=limits)


def _read(reader, start, profile, limits):
    rep_index = reader.read_bounded_int(profile.exclusive_index_maximum)
    length = reader.read_packed_int()
    if length > limits.max_payload_bits:
        raise ValueError('Class-field payload exceeds local bound')
    if reader.position - start + length > limits.max_total_bits:
        raise ValueError('Class-field operation exceeds local total-bit bound')
    return ClassFieldEnvelope(rep_index, reader.read_payload(length), length)


def read_class_field(reader, *, profile, limits=DEFAULT_LIMITS):
    """Read one field atomically while preserving the caller's suffix."""
    if not isinstance(reader, BitReader):
        raise ValueError('A native bit reader is required')
    _validate(profile, limits)
    if limits.max_fields < 1:
        raise ValueError('Class-field count budget is empty')
    start = reader.position
    try:
        return _read(reader, start, profile, limits)
    except Exception:
        reader.position = start
        raise


def read_class_fields(reader, *, profile, limits=DEFAULT_LIMITS):
    """Consume only a reader bounded to the field region's exact bit count."""
    if not isinstance(reader, BitReader):
        raise ValueError('A native bit reader is required')
    _validate(profile, limits)
    start = reader.position
    result = []
    try:
        if reader.remaining > limits.max_total_bits:
            raise ValueError('Class-field sequence exceeds local total-bit bound')
        while reader.remaining:
            if len(result) >= limits.max_fields:
                raise ValueError('Class-field count exceeds local bound')
            result.append(_read(reader, start, profile, limits))
        return tuple(result)
    except Exception:
        reader.position = start
        raise


def build_class_field_content(fields, *, profile, limits=DEFAULT_LIMITS):
    """Wrap ordinary field envelopes in one false-RepLayout Actor block.

    No actual class field is selected or inferred, and opaque bodies are not
    certified property/RPC payloads. Empty fields do not signal game readiness.
    """
    writer = BitWriter()
    write_class_fields(writer, fields, profile=profile, limits=limits)
    return ActorContentBlock(False, writer.to_bytes(), writer.bit_count)


def read_class_field_content(block, *, profile, limits=DEFAULT_LIMITS):
    if not isinstance(block, ActorContentBlock) or block.has_rep_layout is not False:
        raise ValueError('Only explicit false-RepLayout Actor field content is supported')
    reader = BitReader(block.payload, bit_count=block.payload_bit_count)
    return read_class_fields(reader, profile=profile, limits=limits)
