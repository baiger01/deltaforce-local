"""Small versioned identity response consumed only by our native component."""
import struct

HEADER = struct.Struct("<4sHHQII")
CONTENT_TYPE = "application/vnd.df-local.identity"


def encode_identity(identity):
    if identity.get("provider") != "local":
        raise ValueError("Only our local identity is supported")
    native_id, expires = identity["native_id"], identity["expires"]
    if type(native_id) is not int or not 1 <= native_id < 2**63:
        raise ValueError("Invalid native identity")
    if type(expires) is not int or not 1 <= expires < 2**32:
        raise ValueError("Invalid identity expiry")
    name = identity["username"].encode("utf-8")
    if not 1 <= len(name) <= 256 or b"\0" in name:
        raise ValueError("Invalid identity display name")
    return HEADER.pack(b"DFID", 1, HEADER.size, native_id, expires, len(name)) + name
