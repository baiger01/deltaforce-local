"""Socket GUID decoding from the installed client's captured native instructions.

This follows the ordinary native branch, including its 32-bit ID mask and
63-bit parent mask. Optional client hotfix-dispatcher replacement branches are
not reproduced. Assembly supports paths through depth three; higher depths are
rejected rather than reinterpreted as a guessed 64-bit byte layout.
"""


INVALID_SOCKET_GUID = 0x7FFFFFFFFFFFFFFF
MAX_ASSEMBLY_DEPTH = 3
SOURCE = {
    'capture': 'work/evidence/socket-runtime-full-code.txt',
    'capture_sha256': '08fc9c4523cb291e31190e3111ec20d9d32d8e5cfe25d07d0bcef86bf072923d',
    'image_base': 0x140000000,
    'functions': {
        'decode_socket_id': {'rva': 0x507F1E0, 'wrapper_rva': 0x60B5430,
            'code_256_sha256': '5bdf74c426ba43a64ee4a2283ce7c7ecbfd01767af9cea826ca0b31b02862618'},
        'decode_socket_parent': {'rva': 0x507F060, 'wrapper_rva': 0x60B5330,
            'code_256_sha256': '3355a9be6e56fe309f8715f60a2b7077d475e7bdfb5ddf1ce9d99b3e8b04b5d5'},
        'socket_type': {'rva': 0x507EFD0,
            'code_256_sha256': '1f336ef01be504b6bfa26daa79898ac40533e5ec21fa90cb37bf6963e4ae30aa'},
        'socket_depth': {'rva': 0x507F160,
            'code_256_sha256': '9cf39fe1dc927ce1f5d9bac9425add1e40c2b86b532ebf50772f9a90b2e1056e'},
    },
}


def _uint64(guid):
    if type(guid) is not int or not 0 <= guid < 1 << 64:
        raise ValueError('Socket GUID must be an unsigned 64-bit integer')
    return guid


def socket_type(guid):
    return (_uint64(guid) >> 48) & 0xFF


def socket_depth(guid):
    return _uint64(guid) >> 56


def decode_socket_id(guid):
    guid = _uint64(guid)
    depth = socket_depth(guid)
    if guid == 0 and depth == 0:
        return 0
    if depth > 7 or guid == INVALID_SOCKET_GUID or socket_type(guid) == 2:
        return INVALID_SOCKET_GUID
    # RVA 0x507F274 shl eax,cl uses a five-bit shift count, then movsxd.
    shift = depth * 8
    mask = (0xFF << (shift & 31)) & 0xFFFFFFFF
    if mask & 0x80000000:
        mask |= 0xFFFFFFFF00000000
    return ((guid & mask) >> (shift & 63)) & 0xFF


def decode_socket_parent(guid):
    guid = _uint64(guid)
    depth, kind = socket_depth(guid), socket_type(guid)
    if guid == 0 or depth > 7 or guid == INVALID_SOCKET_GUID:
        return INVALID_SOCKET_GUID
    if kind == 2 or depth == 0:
        return 0
    # RVA 0x507F0F6 sar uses the positive 0x7fff... sentinel as the mask.
    mask = INVALID_SOCKET_GUID >> (((8 - depth) * 8) & 63)
    return (guid & mask) | (((depth - 1) << 8 | kind) << 48)


def socket_path(guid):
    """Return root-to-leaf slot IDs, including legitimate slot zero."""
    guid = _uint64(guid)
    depth = socket_depth(guid)
    if guid == 0 or guid == INVALID_SOCKET_GUID or socket_type(guid) == 2:
        raise ValueError('Socket GUID does not identify an assembly socket')
    if depth > MAX_ASSEMBLY_DEPTH:
        raise ValueError('This native socket depth is not supported for assembly')
    reverse_path = []
    for _ in range(depth + 1):
        slot = decode_socket_id(guid)
        if slot == INVALID_SOCKET_GUID:
            raise ValueError('Invalid native socket path')
        reverse_path.append(slot)
        guid = decode_socket_parent(guid)
    if guid != 0:
        raise ValueError('Native socket path did not reach its root')
    return tuple(reversed(reverse_path))
