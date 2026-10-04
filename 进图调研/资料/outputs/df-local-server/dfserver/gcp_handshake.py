"""GCP DH headers and version 11 ACK bodies.

The client's configured DH modulus must be provided separately. Control fields
remain opaque where their meanings are unknown; game account login is absent.
"""
from dataclasses import dataclass, field
import struct

from .gcp_crypto import DH_MAX_BYTES, encrypt_body, server_key_exchange
from .gcp_framing import Frame
from .gcp_control import AuthResponse, parse_auth_response_prefix


@dataclass(frozen=True)
class DhHello:
    client_public_key: bytes = field(repr=False)
    opaque_dh_context: bytes = field(repr=False)
    encryption_method: int
    opaque_remaining_header: bytes = field(repr=False)


@dataclass(frozen=True)
class DhAckHeader:
    server_public_key: bytes = field(repr=False)
    compression_method: int
    compression_threshold: int
    compression_maximum: int

    def encode(self):
        if not 1 <= len(self.server_public_key) <= DH_MAX_BYTES:
            raise ValueError('Invalid DH server public length')
        return b'\x03' + struct.pack('>H', len(self.server_public_key)) + self.server_public_key + struct.pack(
            '>BII', self.compression_method, self.compression_threshold, self.compression_maximum)


@dataclass(frozen=True)
class DhAckBody:
    """Optional transport start response followed by opaque context."""
    opaque_context: bytes = field(repr=False)
    embedded_response: AuthResponse | None = field(default=None, repr=False)

    def encode(self):
        if not isinstance(self.opaque_context, bytes) or len(self.opaque_context) > DH_MAX_BYTES:
            raise ValueError('Invalid DH acknowledgement context')
        if self.embedded_response is None:
            prefix = b'\x00'
        elif isinstance(self.embedded_response, AuthResponse):
            prefix = b'\x01' + self.embedded_response.encode()
        else:
            raise ValueError('Invalid embedded transport response')
        return prefix + struct.pack('>H', len(self.opaque_context)) + self.opaque_context


@dataclass(frozen=True)
class ServerDhAcknowledgement:
    frame: Frame = field(repr=False)
    session_key: bytes = field(repr=False)


def parse_ack_body(plaintext, *, version=11):
    """Decode the version 11 ACK including known response variants.

    The native decoder permits a zero context length. A pointer check following
    its length load is not a nonzero-length check. Trailing bytes are rejected
    here rather than silently treating an unknown layout as supported.
    """
    if version != 11:
        raise ValueError('Only version 11 acknowledgement bodies are implemented')
    if not isinstance(plaintext, bytes) or not plaintext:
        raise ValueError('Missing DH acknowledgement body')
    if plaintext[0] not in (0, 1):
        raise ValueError('Invalid DH acknowledgement discriminator or length')
    response, offset = None, 1
    if plaintext[0] == 1:
        response, consumed = parse_auth_response_prefix(plaintext[1:], version=version)
        offset += consumed
    if len(plaintext) < offset + 2:
        raise ValueError('Missing DH acknowledgement context length')
    context_length = int.from_bytes(plaintext[offset:offset + 2], 'big')
    if context_length > DH_MAX_BYTES or len(plaintext) != offset + 2 + context_length:
        raise ValueError('Invalid DH acknowledgement context length')
    return DhAckBody(plaintext[offset + 2:], response)


def create_server_ack(hello_frame, prime_bytes, *, body, header_word4, header_word9,
                      compression_method, compression_threshold, compression_maximum):
    """Build a fresh encrypted ACK; this does not authorize a game account.

    Unknown header words, compression choices and context values are explicit
    caller inputs. No value is guessed from an encrypted capture or the hello's
    opaque slot, and the original client's modulus is never substituted.
    """
    if not isinstance(prime_bytes, bytes) or len(prime_bytes) != DH_MAX_BYTES:
        raise ValueError('The configured DH modulus must be supplied separately')
    if not isinstance(body, DhAckBody):
        raise ValueError('Expected a supported DH acknowledgement body')
    plaintext = body.encode()
    hello = parse_hello(hello_frame)
    public, key = server_key_exchange(prime_bytes, hello.client_public_key)
    header = DhAckHeader(public, compression_method, compression_threshold, compression_maximum)
    frame = Frame(11, header_word4, 0x1002, 1, header_word9, header.encode(), encrypt_body(plaintext, key))
    # Check bounds and header field widths before publishing the result.
    frame.encode()
    return ServerDhAcknowledgement(frame, key)


def parse_hello(frame):
    if frame.command != 0x1001 or frame.version != 11 or frame.body:
        raise ValueError('Expected the observed version 11 empty-body hello')
    ext = frame.extra_header
    if len(ext) < 3 or ext[0] != 3:
        raise ValueError('Only the observed DH key mode 3 is supported')
    public_length = int.from_bytes(ext[1:3], 'big')
    if not 1 <= public_length <= DH_MAX_BYTES:
        raise ValueError('Invalid DH client public length')
    context_start = 3 + public_length
    method_start = context_start + DH_MAX_BYTES
    if len(ext) <= method_start:
        raise ValueError('Truncated DH hello header')
    public = ext[3:context_start]
    context = ext[context_start:method_start]
    if int.from_bytes(public, 'big') <= 1:
        raise ValueError('Invalid DH public value')
    if ext[method_start] != 3:
        raise ValueError('Only observed encryption method 3 is implemented')
    return DhHello(public, context, ext[method_start], ext[method_start + 1:])


def parse_ack_header(frame):
    if frame.command != 0x1002 or frame.version != 11:
        raise ValueError('Expected version 11 handshake acknowledgement')
    ext = frame.extra_header
    if len(ext) < 3 or ext[0] != 3:
        raise ValueError('Only the observed DH key mode 3 is supported')
    public_length = int.from_bytes(ext[1:3], 'big')
    end = 3 + public_length
    if not 1 <= public_length <= DH_MAX_BYTES or len(ext) != end + 9:
        raise ValueError('Invalid DH acknowledgement header length')
    method, threshold, maximum = struct.unpack_from('>BII', ext, end)
    return DhAckHeader(ext[3:end], method, threshold, maximum)
