"""Independent GCP v11 0x4013 data-header and receive-pipeline implementation.

The implemented route variant is zero, observed in the available capture.
Other route layouts and the native new-protocol business envelope remain
unverified. This codec does not open a gateway or authorize game accounts.
"""
from dataclasses import dataclass
import struct
import zlib

from .gcp_crypto import decode_received_body, encrypt_body
from .gcp_framing import Frame, MAX_BODY

DATA_COMMAND = 0x4013
DEFAULT_MAX_PLAINTEXT = 65536
MAX_ADDITIONAL_MESSAGES = 254


@dataclass(frozen=True)
class DataHeader:
    compression_flag: int = 0
    opaque_flag: int = 0
    # The wire supplies lengths for the first N messages. The remaining body
    # is message N + 1; N is not the total message count.
    leading_lengths: tuple[int, ...] = ()

    def encode(self):
        for value in (self.compression_flag, self.opaque_flag):
            if not isinstance(value, int) or not 0 <= value <= 255:
                raise ValueError('Invalid GCP data-header byte')
        if len(self.leading_lengths) > MAX_ADDITIONAL_MESSAGES:
            raise ValueError('Too many merged GCP messages')
        if any(not isinstance(n, int) or not 0 <= n <= 65535 for n in self.leading_lengths):
            raise ValueError('Invalid merged GCP message length')
        return bytes((self.compression_flag, self.opaque_flag, 0, len(self.leading_lengths))) + b''.join(
            struct.pack('>H', n) for n in self.leading_lengths)


@dataclass(frozen=True)
class DecodedData:
    header: DataHeader
    messages: tuple[bytes, ...]


def parse_data_header(frame):
    if frame.version != 11 or frame.command != DATA_COMMAND:
        raise ValueError('Only GCP v11 0x4013 data frames are implemented')
    raw = frame.extra_header
    if len(raw) < 4:
        raise ValueError('Truncated GCP data header')
    compression, opaque, route, count = raw[:4]
    if route != 0:
        raise ValueError('Unsupported GCP data route variant')
    if count > MAX_ADDITIONAL_MESSAGES:
        raise ValueError('Too many merged GCP messages')
    if len(raw) != 4 + count * 2:
        raise ValueError('Truncated or trailing GCP merge lengths')
    lengths = tuple(struct.unpack_from('>H', raw, 4 + i * 2)[0] for i in range(count))
    return DataHeader(compression, opaque, lengths)


def _validate_limit(max_output):
    if not isinstance(max_output, int) or not 1 <= max_output <= MAX_BODY:
        raise ValueError('Invalid GCP decompressed body limit')


def decompress_body(body, method, *, max_output=DEFAULT_MAX_PLAINTEXT):
    """Decode negotiated method 1 (raw LZ4) or 2 (zlib), with a hard limit.

    The configurable limit is our receiver policy, not a recovered universal
    SDK limit. LZ4 must not use the Python library's stored-size prefix.
    """
    _validate_limit(max_output)
    if not body or len(body) > MAX_BODY:
        raise ValueError('Invalid GCP compressed body length')
    if method == 1:
        from lz4 import block
        try:
            decoded = block.decompress(body, uncompressed_size=max_output)
        except block.LZ4BlockError as exc:
            raise ValueError('Invalid or oversized raw LZ4 body') from exc
    elif method == 2:
        decoder = zlib.decompressobj()
        try:
            decoded = decoder.decompress(body, max_output + 1)
        except zlib.error as exc:
            raise ValueError('Invalid zlib body') from exc
        if len(decoded) > max_output or decoder.unconsumed_tail:
            raise ValueError('GCP decompressed body exceeds the configured limit')
        if not decoder.eof or decoder.unused_data:
            raise ValueError('Truncated or trailing zlib body')
    else:
        raise ValueError('Unsupported GCP compression method')
    if not decoded or len(decoded) > max_output:
        raise ValueError('Invalid or oversized decompressed GCP body')
    return decoded


def compress_body(body, method, *, max_output=DEFAULT_MAX_PLAINTEXT):
    _validate_limit(max_output)
    if not body or len(body) > max_output:
        raise ValueError('Invalid GCP plaintext length')
    if method == 1:
        from lz4 import block
        encoded = block.compress(body, store_size=False)
    elif method == 2:
        encoded = zlib.compress(body)
    else:
        raise ValueError('Unsupported GCP compression method')
    if len(encoded) > MAX_BODY:
        raise ValueError('GCP compressed body exceeds the configured limit')
    return encoded


def split_messages(header, body, *, max_output=DEFAULT_MAX_PLAINTEXT):
    _validate_limit(max_output)
    if not body or len(body) > max_output:
        raise ValueError('Invalid GCP plaintext length')
    # Validate header values even for manually constructed DataHeader objects.
    header.encode()
    if not header.leading_lengths:
        return (bytes(body),)
    remaining = len(body) - sum(header.leading_lengths)
    # Only the explicitly encoded leading lengths are uint16. The final
    # message consumes the remaining body and has no wire length field.
    if any(n == 0 for n in header.leading_lengths) or not 1 <= remaining <= max_output:
        raise ValueError('Merged GCP lengths do not fit the plaintext body')
    messages = []
    offset = 0
    for size in (*header.leading_lengths, remaining):
        messages.append(bytes(body[offset:offset + size]))
        offset += size
    return tuple(messages)


def decode_data_frame(frame, key, *, direction, compression_method,
                      max_output=DEFAULT_MAX_PLAINTEXT):
    """Decrypt first, decompress when flagged, then split merged messages."""
    _validate_limit(max_output)
    header = parse_data_header(frame)
    body = decode_received_body(frame, key, direction=direction)
    if header.compression_flag:
        body = decompress_body(body, compression_method, max_output=max_output)
    return DecodedData(header, split_messages(header, body, max_output=max_output))


def encode_data_frame(messages, key, *, direction, compression_method=0,
                      compressed=False, opaque_flag=0, header_word4=13,
                      header_word9=0, max_output=DEFAULT_MAX_PLAINTEXT):
    """Construct our mode-3 encrypted v11 frame; no account policy is implied."""
    _validate_limit(max_output)
    if direction not in ('client_to_server', 'server_to_client'):
        raise ValueError('Unknown GCP message direction')
    messages = tuple(messages)
    if not 1 <= len(messages) <= MAX_ADDITIONAL_MESSAGES + 1:
        raise ValueError('Invalid GCP message count')
    if any(not isinstance(m, bytes) or not m for m in messages):
        raise ValueError('GCP messages must be nonempty bytes')
    # Bound before concatenating; a single unmerged message need not be uint16.
    if sum(map(len, messages)) > max_output:
        raise ValueError('GCP plaintext body exceeds the configured limit')
    header = DataHeader(int(bool(compressed)), opaque_flag, tuple(map(len, messages[:-1])))
    extra_header = header.encode()
    body = b''.join(messages)
    split_messages(header, body, max_output=max_output)
    if compressed:
        body = compress_body(body, compression_method, max_output=max_output)
    body = encrypt_body(body, key)
    encryption_flag = int(direction == 'server_to_client')
    return Frame(11, header_word4, DATA_COMMAND, encryption_flag, header_word9, extra_header, body)
