"""Codec for the source-qualified ordinary and extended restart bodies.

This does not identify the surrounding UDP envelope or implement a DS server.
The constructor writes three one-bit fields, a little-endian float32 and a
20-byte cookie, followed by the Unreal termination bit. During restart the
native writer appends its old authorized20-byte cookie before that terminator.
See work/evidence/native-restart-handshake-minimal-state-machine.json; this
physical format alone does not authorize a peer or identify the UDP envelope.
"""

from dataclasses import dataclass
import math
import struct


COOKIE_BYTES = 20
BODY_BITS = 195
WIRE_BYTES = 25
EXTENDED_BODY_BITS = BODY_BITS + COOKIE_BYTES * 8
EXTENDED_WIRE_BYTES = WIRE_BYTES + COOKIE_BYTES


@dataclass(frozen=True)
class LegacyHandshakePayload:
    restart: bool
    third_flag: bool
    timestamp: float
    cookie: bytes
    old_cookie: bytes | None = None


def encode_payload(payload: LegacyHandshakePayload) -> bytes:
    if type(payload.restart) is not bool or type(payload.third_flag) is not bool:
        raise ValueError('Handshake flags must be boolean')
    if not isinstance(payload.cookie, bytes) or len(payload.cookie) != COOKIE_BYTES:
        raise ValueError('Handshake cookie must contain exactly 20 bytes')
    if payload.old_cookie is not None and (
            not payload.restart or not isinstance(payload.old_cookie, bytes) or
            len(payload.old_cookie) != COOKIE_BYTES):
        raise ValueError('Extended restart requires a fixed old authorized cookie')
    if isinstance(payload.timestamp, bool) or not isinstance(payload.timestamp, (float, int)):
        raise ValueError('Handshake timestamp must be numeric')
    try:
        timestamp = struct.pack('<f', payload.timestamp)
    except (OverflowError, struct.error) as error:
        raise ValueError('Handshake timestamp must fit float32') from error
    if not math.isfinite(struct.unpack('<f', timestamp)[0]):
        raise ValueError('Handshake timestamp must be finite')
    bits = 1 | (int(payload.restart) << 1) | (int(payload.third_flag) << 2)
    bits |= int.from_bytes(timestamp, 'little') << 3
    bits |= int.from_bytes(payload.cookie, 'little') << 35
    body_bits, wire_bytes = BODY_BITS, WIRE_BYTES
    if payload.old_cookie is not None:
        bits |= int.from_bytes(payload.old_cookie, 'little') << BODY_BITS
        body_bits, wire_bytes = EXTENDED_BODY_BITS, EXTENDED_WIRE_BYTES
    bits |= 1 << body_bits
    return bits.to_bytes(wire_bytes, 'little')


def decode_payload(data: bytes) -> LegacyHandshakePayload:
    if not isinstance(data, bytes) or len(data) not in (WIRE_BYTES, EXTENDED_WIRE_BYTES):
        raise ValueError('Only exact ordinary25-byte or extended45-byte bodies are supported')
    # Ordinary/extended cookies end at194/354; terminator195/355, then4 zero bits.
    if data[-1] & 0xf8 != 0x08:
        raise ValueError('Invalid handshake termination bit or padding')
    bits = int.from_bytes(data, 'little')
    if not bits & 1:
        raise ValueError('Packet is not a handshake body')
    timestamp = struct.unpack('<f', ((bits >> 3) & 0xffffffff).to_bytes(4, 'little'))[0]
    if not math.isfinite(timestamp):
        raise ValueError('Handshake timestamp must be finite')
    cookie = ((bits >> 35) & ((1 << 160) - 1)).to_bytes(COOKIE_BYTES, 'little')
    old_cookie = None
    if len(data) == EXTENDED_WIRE_BYTES:
        if not bits & 2:
            raise ValueError('An extended body must be a restart echo')
        old_cookie = ((bits >> BODY_BITS) & ((1 << 160) - 1)).to_bytes(COOKIE_BYTES, 'little')
    return LegacyHandshakePayload(bool(bits & 2), bool(bits & 4), timestamp, cookie, old_cookie)
