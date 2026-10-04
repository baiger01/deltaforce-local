"""Bounded field codec for already decoded, byte-aligned native control data.

The non-byte-swapped string rules come from native helper 0x109ea340 and
the complete narrow conversion helper 0xd60360 in the saved native samples. Message
field order comes from the proven fallback table in UControlChannel's body.
Fallback consumption is not NotifyControlMessage business acceptance.

This module has no UDP/bunch header codec, control dispatcher, ACK policy,
identity serializer or actor replication. Unknown messages are rejected.
Narrow bytes above 0x7f become '?', matching the observed caller's replacement
argument; they are not decoded using UTF-8 or a Windows code page. This codec
still supports only the non-swapped profile and raw UTF-16LE wide strings.
Resource bounds and canonical encoder input restrictions are local policies.
"""
from dataclasses import dataclass
import struct
from types import MappingProxyType


MAX_PAYLOAD_BYTES = 8192
DEFAULT_MAX_STRING_UNITS = 4096
_SCHEMAS = MappingProxyType({
    0: ('u8', 'u32', 'string'),
    1: ('string', 'string', 'string'),
    2: ('u32',),
    3: ('string',),
    4: ('u32',),
    6: ('string',),
    9: (),
})


class UnsupportedControlProfile(ValueError):
    """A field or message requires a native branch not yet recovered."""


def _string_bound(max_units):
    if type(max_units) is not int or not 1 <= max_units <= DEFAULT_MAX_STRING_UNITS:
        raise ValueError('Invalid local string-unit bound')


def decode_string(data, offset=0, *, max_units=DEFAULT_MAX_STRING_UNITS):
    """Return (value, end) for the native non-swapped string representation.

    The native loader overwrites the final unit with NUL, rather than checking
    it. Interior NULs survive unless the wide 0xffff normalization path runs.
    Length-one strings normalize to the empty string. Unpaired UTF-16 surrogate
    units are preserved, matching the observed raw TCHAR copy operation.
    """
    _string_bound(max_units)
    if (not isinstance(data, bytes) or type(offset) is not int or
            not 0 <= offset <= len(data) or len(data) - offset < 4):
        raise ValueError('Truncated or invalid string length')
    count = struct.unpack_from('<i', data, offset)[0]
    if count == -(1 << 31):
        raise ValueError('Native string length cannot be INT_MIN')
    units = abs(count)
    if units > max_units:
        raise ValueError('String exceeds the local unit bound')
    wide = count < 0
    start, end = offset + 4, offset + 4 + units * (2 if wide else 1)
    if end > len(data):
        raise ValueError('Truncated string payload')
    if not units:
        return '', end
    if not wide:
        raw = data[start:end - 1]  # The final serialized byte is forced to NUL.
        return ''.join(chr(byte) if byte <= 0x7f else '?' for byte in raw), end
    raw = data[start:end - 2]
    words = struct.unpack('<' + 'H' * (units - 1), raw)
    if 0xffff in words:
        # Native replaces the first 0xffff then shrinks according to the first
        # NUL. It does not apply this shrink to every ordinary wide string.
        stop = words.index(0xffff)
        if 0 in words[:stop]:
            stop = words.index(0)
        raw = raw[:stop * 2]
    return raw.decode('utf-16-le', errors='surrogatepass'), end


def encode_string(value, *, force_unicode=False, max_units=DEFAULT_MAX_STRING_UNITS):
    """Encode a canonical FString without embedded NULs.

    Native normally writes a zero count for an empty ASCII FString. Forcing
    Unicode writes -1 followed by a two-byte terminator, including for empty.
    """
    _string_bound(max_units)
    if not isinstance(value, str) or type(force_unicode) is not bool:
        raise ValueError('Invalid canonical string or Unicode flag')
    if '\0' in value:
        raise ValueError('Canonical encoder strings cannot contain embedded NULs')
    wide = force_unicode or any(ord(char) > 0x7f for char in value)
    if not wide and not value:
        return b'\0' * 4
    raw = value.encode('utf-16-le', errors='surrogatepass') if wide else value.encode('ascii')
    units = len(raw) // (2 if wide else 1) + 1
    if units > max_units:
        raise ValueError('String exceeds the local unit bound')
    return struct.pack('<i', -units if wide else units) + raw + (b'\0\0' if wide else b'\0')


@dataclass(frozen=True)
class ControlMessage:
    message_id: int
    fields: tuple


def _schema(message_id):
    if type(message_id) is not int or message_id not in _SCHEMAS:
        raise UnsupportedControlProfile('Control message layout is not implemented')
    return _SCHEMAS[message_id]


def encode_message(message_id, *fields, force_unicode=False,
                   max_string_units=DEFAULT_MAX_STRING_UNITS):
    """Encode field order only; this does not send or accept a control message."""
    schema = _schema(message_id)
    _string_bound(max_string_units)
    if type(force_unicode) is not bool or len(fields) != len(schema):
        raise ValueError('Control field count or Unicode flag mismatch')
    output = bytearray((message_id,))
    for kind, value in zip(schema, fields):
        if kind == 'string':
            output.extend(encode_string(value, force_unicode=force_unicode,
                                        max_units=max_string_units))
        else:
            limit = 255 if kind == 'u8' else 0xffffffff
            if type(value) is not int or not 0 <= value <= limit:
                raise ValueError('Invalid unsigned control field')
            output.extend(bytes((value,)) if kind == 'u8' else struct.pack('<I', value))
        if len(output) > MAX_PAYLOAD_BYTES:
            raise ValueError('Control payload exceeds the local byte bound')
    if message_id == 0 and fields[0] != 1:
        raise UnsupportedControlProfile('Only the native non-swapped endian profile is recovered')
    return bytes(output)


def decode_messages(payload, *, payload_bits=None, max_messages=32,
                    max_string_units=DEFAULT_MAX_STRING_UNITS):
    """Decode a complete byte-aligned control payload atomically.

    No message tuple is returned on a partial, unknown or unsupported input.
    Neither successful parsing nor this function's return value implies that
    native NotifyControlMessage consumed or accepted the same bytes.
    """
    _string_bound(max_string_units)
    if (not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD_BYTES or
            type(max_messages) is not int or not 1 <= max_messages <= 32):
        raise ValueError('Invalid bounded control payload')
    if payload_bits is not None and (type(payload_bits) is not int or
                                     payload_bits != len(payload) * 8):
        raise UnsupportedControlProfile('Only exact byte-aligned control payloads are recovered')
    offset, messages = 0, []
    while offset < len(payload):
        if len(messages) >= max_messages:
            raise ValueError('Control payload exceeds the local message bound')
        message_id = payload[offset]
        offset += 1
        values = []
        for kind in _schema(message_id):
            if kind == 'string':
                value, offset = decode_string(payload, offset, max_units=max_string_units)
            else:
                size = 1 if kind == 'u8' else 4
                if len(payload) - offset < size:
                    raise ValueError('Truncated unsigned control field')
                value = payload[offset] if size == 1 else struct.unpack_from('<I', payload, offset)[0]
                offset += size
                if message_id == 0 and not values and value != 1:
                    raise UnsupportedControlProfile('Only the non-swapped endian profile is recovered')
            values.append(value)
        messages.append(ControlMessage(message_id, tuple(values)))
    return tuple(messages)
