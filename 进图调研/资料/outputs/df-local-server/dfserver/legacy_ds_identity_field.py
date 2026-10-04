"""Physical fields from the delegated native identity loader at 0x12bc0e60.

This is a dissection component, not an account-provider mapping or a native
identity factory. It assumes a valid native type after resolution; unresolved
hash zero is rejected. No semantic success, canonical writer, UDP decoder or
control dispatcher is provided. Choosing this delegated archive branch still
requires separate evidence from its caller.
"""
from dataclasses import dataclass

from .legacy_ds_control_fields import (
    DEFAULT_MAX_STRING_UNITS, MAX_PAYLOAD_BYTES, UnsupportedControlProfile,
    decode_string,
)


@dataclass(frozen=True)
class IdentityWireField:
    flags: int
    wire_type_hash: int
    resolved_type_hash: int | None
    type_name: str | None
    encoded_bytes: bytes | None
    identifier_text: str | None
    explicit_empty: bool


def decode_identity_field(data, offset=0, *, default_type_hash=None,
                          max_string_units=DEFAULT_MAX_STRING_UNITS):
    """Return (physical fields, end); this never declares identity acceptance.

    Hash zero needs the caller's verified registry result. Nonzero hashes stay
    opaque: no QQ/WeChat association is inferred. Type-name validity, registry
    token validity, encoded-text normalization and object reconstruction belong
    to the native factory and are deliberately not represented by this result.
    """
    if (not isinstance(data, bytes) or type(offset) is not int or
            not 0 <= offset < len(data)):
        raise ValueError('Truncated or invalid identity flags')
    if (type(max_string_units) is not int or
            not 1 <= max_string_units <= DEFAULT_MAX_STRING_UNITS):
        raise ValueError('Invalid local identity string bound')
    if default_type_hash is not None and (type(default_type_hash) is not int or
                                          not 1 <= default_type_hash <= 255):
        raise ValueError('Invalid resolved default identity type hash')
    start, flags = offset, data[offset]
    offset += 1
    wire_hash = flags >> 3
    if flags & 1 and flags & 2:
        # The native loader exits before resolving a type or reading content.
        return IdentityWireField(flags, wire_hash, None, None, None, None, True), offset
    effective_hash = wire_hash or default_type_hash
    if effective_hash is None:
        raise UnsupportedControlProfile('Native default identity type is unresolved')
    type_name = None
    if effective_hash == 31:
        type_name, offset = decode_string(data, offset, max_units=max_string_units)
    encoded, text = None, None
    if flags & 1:
        if offset >= len(data):
            raise ValueError('Truncated encoded identity byte count')
        count = data[offset]
        offset += 1
        end = offset + count
        if end > len(data):
            raise ValueError('Truncated encoded identity contents')
        encoded, offset = data[offset:end], end
    else:
        # Bit 1 has no observed early-empty effect on the unencoded branch.
        text, offset = decode_string(data, offset, max_units=max_string_units)
    if offset - start > MAX_PAYLOAD_BYTES:
        raise ValueError('Identity field exceeds the local byte bound')
    return IdentityWireField(flags, wire_hash, effective_hash, type_name,
                             encoded, text, False), offset
