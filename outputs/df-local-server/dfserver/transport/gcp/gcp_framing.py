"""Observed 0x3366 GCloud framing, independently implemented from field layout.

This handles packet boundaries only. gcp_handshake and gcp_crypto implement
observed DH fields and mode 3 body encryption separately. Authentication and
business messages are not implemented here.
The unnamed words stay opaque until their meaning is established.
"""
from dataclasses import dataclass
import struct

BASE = struct.Struct('>HHHHBIII')
MAGIC = 0x3366
MAX_HEADER = 65536
MAX_BODY = 1024 * 1024


@dataclass(frozen=True)
class Frame:
    version: int
    header_word4: int
    command: int
    payload_encryption_flag: int
    header_word9: int
    extra_header: bytes
    body: bytes

    @property
    def wire_size(self):
        return BASE.size + len(self.extra_header) + len(self.body)

    def encode(self):
        header_size = BASE.size + len(self.extra_header)
        _validate(MAGIC, self.version, header_size, len(self.body))
        return BASE.pack(MAGIC, self.version, self.header_word4, self.command,
                         self.payload_encryption_flag, self.header_word9,
                         header_size, len(self.body)) + self.extra_header + self.body


def _validate(magic, version, header_size, body_size):
    if magic != MAGIC:
        raise ValueError('Unexpected GCP magic')
    if not 1 <= version <= 11:
        raise ValueError('Unsupported GCP version')
    if not BASE.size <= header_size <= MAX_HEADER:
        raise ValueError('Invalid GCP header length')
    if body_size > MAX_BODY:
        raise ValueError('GCP body exceeds the configured limit')


def decode_prefix(data):
    """Return (frame, bytes consumed), or None when a valid prefix is incomplete."""
    if len(data) < BASE.size:
        return None
    magic, version, word4, command, encryption, word9, header_size, body_size = BASE.unpack_from(data)
    _validate(magic, version, header_size, body_size)
    total = header_size + body_size
    if len(data) < total:
        return None
    return Frame(version, word4, command, encryption, word9,
                 bytes(data[BASE.size:header_size]), bytes(data[header_size:total])), total


class StreamDecoder:
    """Handle split/coalesced TCP reads without searching past malformed bytes."""
    def __init__(self):
        self._pending = bytearray()
        self._failed = False

    @property
    def pending_bytes(self):
        return len(self._pending)

    def feed(self, data):
        if self._failed:
            raise ValueError('Decoder is closed after invalid input')
        result = []
        try:
            # A bounded slice also permits a read containing many full frames.
            for offset in range(0, len(data), 65536):
                self._pending.extend(data[offset:offset + 65536])
                consumed = 0
                while True:
                    with memoryview(self._pending)[consumed:] as remaining:
                        decoded = decode_prefix(remaining)
                    if decoded is None:
                        break
                    frame, size = decoded
                    result.append(frame)
                    consumed += size
                if consumed:
                    del self._pending[:consumed]
                if len(self._pending) > MAX_HEADER + MAX_BODY:
                    raise ValueError('GCP receive buffer exceeded')
        except ValueError:
            self._failed = True
            self._pending.clear()
            raise
        return result

    def finish(self):
        if self._failed:
            raise ValueError('Decoder is closed after invalid input')
        if self._pending:
            raise ValueError('Truncated GCP stream')
