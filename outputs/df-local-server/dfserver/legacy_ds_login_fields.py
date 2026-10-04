"""Physical Login5 fields from the inspected native PendingNetGame sender.

Field order is Response FString, URL FString, delegated identity and Platform
FString. The native BitWriter constructor sets archive+2b mask10, selecting
identity helper12bc0e60 through12bab170. Saved official packet ordinals7/9
confirmed the four-field layout and used an explicit-empty identity (flags3).

This module only consumes already decoded, byte-aligned control data. It has
no network or admission effects and does not accept an account, resolve a
provider, construct native identity objects or send Welcome. Resource bounds
are local policies. Nonzero identity type hashes remain opaque; hash0 needs
a separately verified registry result unless the explicit-empty branch applies.
"""
from dataclasses import dataclass, field

from .legacy_ds_control_fields import (
    DEFAULT_MAX_STRING_UNITS, MAX_PAYLOAD_BYTES, UnsupportedControlProfile,
    decode_string,
)
from .legacy_ds_identity_field import IdentityWireField, decode_identity_field


@dataclass(frozen=True)
class Login5Fields:
    # URL may carry Cookie/SecretKey and identity may carry an identifier. None
    # of the native text/identity contents belongs in an implicit debug repr.
    response: str = field(repr=False)
    url: str = field(repr=False)
    identity: IdentityWireField = field(repr=False)
    platform: str = field(repr=False)
    field_ends: tuple[int, int, int, int]


def decode_login5_at(payload, offset=0, *, default_type_hash=None,
                     max_string_units=DEFAULT_MAX_STRING_UNITS):
    """Return (physical fields, end), without authenticating their contents.

    A native-valid resolved type is a precondition of the existing identity
    dissector. The optional default_type_hash is an external registry result,
    never a QQ/WeChat assumption. Response is not a password: the inspected
    native sender writes literal "0". field_ends are byte offsets from the
    beginning of payload, including a nonzero initial message offset.
    """
    if (not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD_BYTES or
            type(offset) is not int or not 0 <= offset < len(payload)):
        raise ValueError('Invalid bounded Login5 payload or offset')
    if payload[offset] != 5:
        raise UnsupportedControlProfile('Expected native Login control ID5')
    at = offset + 1
    response, at = decode_string(payload, at, max_units=max_string_units)
    response_end = at
    url, at = decode_string(payload, at, max_units=max_string_units)
    url_end = at
    identity, at = decode_identity_field(payload, at,
        default_type_hash=default_type_hash, max_string_units=max_string_units)
    identity_end = at
    platform, at = decode_string(payload, at, max_units=max_string_units)
    return Login5Fields(response, url, identity, platform,
                        (response_end, url_end, identity_end, at)), at


def decode_single_login5(payload, *, payload_bits=None, default_type_hash=None,
                         max_string_units=DEFAULT_MAX_STRING_UNITS):
    """Consume exactly one complete byte-aligned ID5, rejecting trailing bytes.

    A dispatcher handling more than one control message must use
    decode_login5_at and separately consume every other proven message schema.
    This convenience function cannot swallow subsequent messages as success.
    """
    if not isinstance(payload, bytes):
        raise ValueError('Login5 input must be bytes')
    if payload_bits is not None and (type(payload_bits) is not int or
                                     payload_bits != len(payload) * 8):
        raise UnsupportedControlProfile('Login5 requires exact byte-aligned control data')
    result, end = decode_login5_at(payload, default_type_hash=default_type_hash,
                                  max_string_units=max_string_units)
    if end != len(payload):
        raise ValueError('Unconsumed bytes after the single Login5 message')
    return result
