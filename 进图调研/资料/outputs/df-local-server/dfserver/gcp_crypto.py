"""Own implementation of the observed legacy GCP mode 3 transport cipher.

This module implements DH -> MD5 -> AES-128-CBC with the SDK's footer. It
does not authenticate game accounts or decrypt a captured session without its
private exponent. The fixed IV/footer are protocol constants, not credentials.
"""
import hashlib
import secrets

from .gcp_framing import MAX_BODY

IV = bytes(range(16))
FOOTER = b'tsf4g'
DH_GENERATOR = 2
DH_MAX_BYTES = 64


def _minimal_big_endian(value):
    if value <= 0:
        raise ValueError('DH value must be positive')
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')


def _validate_dh(prime, public_key):
    if not isinstance(prime, int) or not 5 <= prime < 1 << (8 * DH_MAX_BYTES) or prime % 2 == 0:
        raise ValueError('Invalid or oversized DH modulus')
    if not isinstance(public_key, int) or not 1 < public_key < prime - 1:
        raise ValueError('Invalid DH public key')


def derive_session_key(prime, peer_public_key, private_exponent):
    """Match unpadded DH_compute_key followed by MD5 of the shared bytes."""
    _validate_dh(prime, peer_public_key)
    if not isinstance(private_exponent, int) or not 1 < private_exponent < prime - 1:
        raise ValueError('Invalid DH private exponent')
    shared = pow(peer_public_key, private_exponent, prime)
    if shared <= 1:
        raise ValueError('Degenerate DH shared value')
    return hashlib.md5(_minimal_big_endian(shared), usedforsecurity=False).digest()


def server_key_exchange(prime_bytes, client_public_bytes):
    """Generate our ephemeral server public value and session key.

    Only our new exchange is supported; neither private exponents nor keys are
    logged or persisted. Parameter provenance/primality is the caller's concern.
    """
    if len(prime_bytes) != DH_MAX_BYTES or not 1 <= len(client_public_bytes) <= DH_MAX_BYTES:
        raise ValueError('Invalid DH wire lengths')
    prime = int.from_bytes(prime_bytes, 'big')
    client_public = int.from_bytes(client_public_bytes, 'big')
    _validate_dh(prime, client_public)
    for _ in range(32):
        private = secrets.randbelow(prime - 3) + 2
        public = pow(DH_GENERATOR, private, prime)
        if 1 < public < prime - 1 and pow(client_public, private, prime) > 1:
            return _minimal_big_endian(public), derive_session_key(prime, client_public, private)
    raise ValueError('Cannot construct a nondegenerate DH exchange')


def encrypted_size(plaintext_size):
    if not isinstance(plaintext_size, int) or not 0 < plaintext_size <= MAX_BODY:
        raise ValueError('Invalid GCP plaintext length')
    remainder = plaintext_size % 16
    padding = (16 if remainder <= 10 else 32) - remainder
    total = plaintext_size + padding
    if total > MAX_BODY:
        raise ValueError('GCP encrypted body exceeds the configured limit')
    return total


def _cipher(key):
    if not isinstance(key, bytes) or len(key) != 16:
        raise ValueError('GCP mode 3 requires a 16-byte session key')
    # Keep the business backend usable without the optional crypto dependency.
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher(algorithms.AES(key), modes.CBC(IV))


def encrypt_body(plaintext, key, *, random_bytes=secrets.token_bytes):
    """Encode random filler + tsf4g + one padding-length byte, then AES-CBC."""
    total = encrypted_size(len(plaintext))
    padding = total - len(plaintext)
    filler = random_bytes(padding - 6)
    if len(filler) != padding - 6:
        raise ValueError('Random filler returned an incorrect length')
    padded = bytes(plaintext) + filler + FOOTER + bytes([padding])
    encryptor = _cipher(key).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_body(ciphertext, key):
    """Reject wrong keys, truncation and invalid footer before returning bytes."""
    if not ciphertext or len(ciphertext) % 16 or len(ciphertext) > MAX_BODY:
        raise ValueError('Invalid GCP ciphertext length')
    decryptor = _cipher(key).decryptor()
    padded = decryptor.update(bytes(ciphertext)) + decryptor.finalize()
    if padded[-6:-1] != FOOTER:
        raise ValueError('GCP encryption footer mismatch')
    padding = padded[-1]
    size = len(padded) - padding
    if size <= 0 or not 6 <= padding <= 21 or encrypted_size(size) != len(padded):
        raise ValueError('Invalid GCP encryption padding')
    return padded[:size]


def decode_received_body(frame, key, *, direction):
    """Encryption flag affects S2C; negotiated method encrypts C2S regardless."""
    if direction not in ('client_to_server', 'server_to_client'):
        raise ValueError('Unknown GCP message direction')
    if not frame.body:
        return b''
    if direction == 'client_to_server' or frame.payload_encryption_flag:
        return decrypt_body(frame.body, key)
    return frame.body
