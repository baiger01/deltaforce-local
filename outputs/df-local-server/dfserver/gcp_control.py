"""GCP transport authentication body layouts, not account policy.

Field widths and bounds are independently implemented from the native readers.
Unknown scalar meanings and credential payloads stay opaque. This module does
not validate official credentials, authorize game accounts or dispatch gameplay.
"""
from dataclasses import dataclass, field


class _Reader:
    def __init__(self, data):
        if not isinstance(data, bytes):
            raise ValueError('Expected immutable transport body bytes')
        self.data, self.at = data, 0

    def take(self, size):
        if size < 0 or size > len(self.data) - self.at:
            raise ValueError('Truncated transport authentication body')
        result = self.data[self.at:self.at + size]
        self.at += size
        return result

    def number(self, size):
        return int.from_bytes(self.take(size), 'big')

    def blob(self, maximum):
        length = self.number(2)
        if length > maximum:
            raise ValueError('Transport field exceeds its native bound')
        return self.take(length)

    def finish(self):
        if self.at != len(self.data):
            raise ValueError('Unexpected trailing transport authentication bytes')


def _number(value, size):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << (size * 8):
        raise ValueError('Invalid unsigned transport scalar')
    return value.to_bytes(size, 'big')


def _blob(value, maximum):
    if not isinstance(value, bytes) or len(value) > maximum:
        raise ValueError('Invalid opaque transport field')
    return _number(len(value), 2) + value


def _version(version):
    if version not in (11, 12):
        raise ValueError('Only the observed control layout versions 11 and 12 are implemented')


@dataclass(frozen=True)
class AuthRequest:
    auth_type: int
    opaque_credential: bytes = field(repr=False)
    opaque_auth_data: bytes = field(repr=False)
    opaque_context: bytes = field(repr=False)

    def encode(self):
        return (_number(self.auth_type, 2) + _blob(self.opaque_credential, 64)
                + _blob(self.opaque_auth_data, 4096) + _blob(self.opaque_context, 256))


def parse_auth_request(plaintext, *, version=12):
    _version(version)
    reader = _Reader(plaintext)
    result = AuthRequest(reader.number(2), reader.blob(64), reader.blob(4096), reader.blob(256))
    reader.finish()
    return result


@dataclass(frozen=True)
class CommonAuthResponse:
    opaque_word16: int
    variant_type: int
    variant_value: object = field(repr=False)
    opaque_word64: int = field(repr=False)

    def encode(self):
        prefix = _number(self.opaque_word16, 2) + _number(self.variant_type, 1)
        if self.variant_type == 0:
            if self.variant_value is not None:
                raise ValueError('The empty variant cannot carry a value')
            variant = b''
        elif self.variant_type in (1, 2):
            variant = _number(self.variant_value, 4 if self.variant_type == 1 else 8)
        elif self.variant_type == 3:
            value = self.variant_value
            if (not isinstance(value, bytes) or not 1 <= len(value) <= 256
                    or value[-1:] != b'\x00' or b'\x00' in value[:-1]):
                raise ValueError('Invalid bounded transport C string')
            variant = _number(len(value), 4) + value
        else:
            raise NotImplementedError('Unknown transport response variant')
        return prefix + variant + _number(self.opaque_word64, 8)


@dataclass(frozen=True)
class AuthResponse:
    common: CommonAuthResponse = field(repr=False)
    extra_word16: int
    extra_data4096: bytes = field(repr=False)
    extra_word32: int
    extra_data1024: bytes = field(repr=False)
    last_word32: int
    last_word16: int
    last_data1024: bytes = field(repr=False)

    def encode(self):
        if not isinstance(self.common, CommonAuthResponse):
            raise ValueError('Missing common transport response')
        return (self.common.encode() + _number(self.extra_word16, 2)
                + _blob(self.extra_data4096, 4096) + _number(self.extra_word32, 4)
                + _blob(self.extra_data1024, 1024) + _number(self.last_word32, 4)
                + _number(self.last_word16, 2) + _blob(self.last_data1024, 1024))


def parse_auth_response_prefix(plaintext, *, version=12):
    """Return a response and consumed bytes for the ACK's embedded subcase.

    The outer frame's second word is 11, but its third word is the 12 passed
    to the native control reader. The native common/start readers cap their
    own layout version at 4, so the common 64-bit word is still present.
    """
    _version(version)
    reader = _Reader(plaintext)
    word16, variant_type = reader.number(2), reader.number(1)
    if variant_type == 0:
        value = None
    elif variant_type in (1, 2):
        value = reader.number(4 if variant_type == 1 else 8)
    elif variant_type == 3:
        length = reader.number(4)
        if not 1 <= length <= 256:
            raise ValueError('Invalid transport C string length')
        value = reader.take(length)
        if value[-1:] != b'\x00' or b'\x00' in value[:-1]:
            raise ValueError('Invalid transport C string terminator')
    else:
        raise NotImplementedError('Unknown transport response variant')
    common = CommonAuthResponse(word16, variant_type, value, reader.number(8))
    response = AuthResponse(common, reader.number(2), reader.blob(4096), reader.number(4),
                            reader.blob(1024), reader.number(4), reader.number(2), reader.blob(1024))
    return response, reader.at


def parse_auth_response(plaintext, *, version=12):
    response, consumed = parse_auth_response_prefix(plaintext, version=version)
    if consumed != len(plaintext):
        raise ValueError('Unexpected trailing transport authentication bytes')
    return response


@dataclass(frozen=True)
class ReadyResponse:
    """Observed 0x6002 layout; the frame's third word selects version 12."""
    relay_position: int
    relay_identity: bytes = field(repr=False)
    relay_word64: int = field(repr=False)
    compression_method: int = 0
    compression_limit: int = 0
    opaque_extension_words: tuple[int, int, int, int] = (0, 0, 0, 0)

    def encode(self, *, version=12):
        _version(version)
        if not isinstance(self.relay_identity, bytes) or len(self.relay_identity) != 16:
            raise ValueError('Relay identity must contain exactly 16 bytes')
        if len(self.opaque_extension_words) != 4:
            raise ValueError('Ready response requires four extension words')
        prefix = (_number(self.relay_position, 4) + self.relay_identity
                  + _number(self.relay_word64, 8) + _number(self.compression_method, 1)
                  + _number(self.compression_limit, 4))
        if version == 11:
            if any(self.opaque_extension_words):
                raise ValueError('Version 11 cannot carry version 12 extension words')
            return prefix
        return prefix + b''.join(_number(word, 4) for word in self.opaque_extension_words)


def parse_ready_response(plaintext, *, version=12):
    _version(version)
    reader = _Reader(plaintext)
    prefix = (reader.number(4), reader.take(16), reader.number(8),
              reader.number(1), reader.number(4))
    extension = tuple(reader.number(4) for _ in range(4)) if version == 12 else (0, 0, 0, 0)
    result = ReadyResponse(*prefix, extension)
    reader.finish()
    return result
