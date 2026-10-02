"""Decode configuration FNames using the verified installed native code."""

import hashlib
import struct


EXPECTED_PE = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
EXPECTED_CODE = {
    'registration_name_ascii_copy': (0x10b5fd00, 0x210,
        '53e290d967c755214d67eb14ab3a0e1c666141c60e2fb6d42fed2f6b822e4f49'),
    'registration_name_wide_copy': (0x10b5ff10, 0x290,
        'dba7eac567eb1a94a701046a74e7783c5d288db7918d4f01818543c41813861d'),
    'registration_name_constructor': (0x10b56070, 768,
        '48bfec196115515bb2538f02a2d4897cfaca6c9ecf0490151fd0da809acf857b'),
    'registration_name_lookup': (0x10b6ea10, 1024,
        'cbb1330e74b7232548583b716e9404314df0f04e9c962b1a983c0f8ab9e62864'),
    'registration_name_pool_find': (0x10b70cf0, 1024,
        '50547cd1a1a3c195a4319ec03a6ae3f93e72f9d955edf35488fc34d550493487'),
    'registration_name_entry_match': (0x10b54060, 1024,
        '1ccf899466ab3c4e60929d365faffd3f154d2c46d5f2a543d44ea46b585affe5'),
}
ASCII_TARGETS = (0x10b5fd33, 0x10b5fd5c, 0x10b5fd8c, 0x10b5fdbc,
                 0x10b5fde1, 0x10b5fe0c, 0x10b5fe3c, 0x10b5fe6c, 0x10b5fe9c)
WIDE_TARGETS = (0x10b5ff43, 0x10b5ff7e, 0x10b5ffbe, 0x10b5fffe,
                0x10b6002e, 0x10b6005f, 0x10b60091, 0x10b600ce, 0x10b6010e)
POOL_RVA = 0x1e326a80


def source_key(length, wide=False):
    if not 1 <= length <= 1023:
        raise ValueError('Invalid source name length')
    remainder = length % 9
    if remainder == 0:
        value = (length & 0x1f) + 0x80 + length
    elif remainder == 1:
        value = (length ^ 0xdf) + 0x80 + length
    elif remainder == 2:
        value = (length | 0xcf) + 0x80 + length
    elif remainder == 3:
        value = length * 0x21 + 0x80
    elif remainder == 4:
        value = (length >> 2) + 0x80 + length
    elif remainder == 5:
        value = length * 3 + 0x85 if wide else (length - 0x29) * 3
    elif remainder == 6:
        value = ((length << 2) | 5) + 0x80 + length
    elif remainder == 7:
        value = ((length >> 4) | 7) + 0x80 + length
    else:
        value = (length ^ 0xc) + 0x80 + length
    return (value & (0xffff if wide else 0xff)) | 0x7f


class ConfigNameCodec:
    def __init__(self, capture):
        if capture['native_pe_sha256'] != EXPECTED_PE or capture['module_base'] != 0x140000000:
            raise ValueError('Unsupported native build')
        for name, (rva, size, digest) in EXPECTED_CODE.items():
            block = capture['fixed_code'][name]
            code = bytes.fromhex(block['bytes'])
            if ((block['rva'], block['size'], len(code)) != (rva, size, size)
                    or hashlib.sha256(code).hexdigest() != digest):
                raise ValueError('Name code witness changed: ' + name)
        for name, offset, expected in (
                ('registration_name_ascii_copy', 0x1ec, ASCII_TARGETS),
                ('registration_name_wide_copy', 0x260, WIDE_TARGETS)):
            code = bytes.fromhex(capture['fixed_code'][name]['bytes'])
            if struct.unpack_from('<9I', code, offset) != expected:
                raise ValueError('Name branch table changed')

    def transform(self, data, length, wide=False):
        width = 2 if wide else 1
        if len(data) != length * width:
            raise ValueError('Name byte count mismatch')
        key = source_key(length, wide)
        result = bytearray(data)
        if int.from_bytes(result[:width], 'little') == 0:
            return bytes(result)
        # The actual wide loop transforms every other UTF-16 code unit.
        for index in range(0, length, 2 if wide else 1):
            offset = index * width
            value = int.from_bytes(result[offset:offset + width], 'little') ^ key
            result[offset:offset + width] = value.to_bytes(width, 'little')
        return bytes(result)

    def decode_config_name(self, entry, number=0):
        if number != 0 or len(entry) < 2:
            raise ValueError('Unsupported numbered or incomplete configuration name')
        header, = struct.unpack_from('<H', entry)
        length, wide = header >> 6, bool(header & 1)
        result = self.transform(entry[2:], length, wide).decode('utf-16le' if wide else 'ascii')
        if '\0' in result:
            raise ValueError('Embedded configuration-name terminator')
        return result


def read_config_name(read, base, codec, comparison_id, number=0, *, max_chars=96):
    """Follow only one FName already found in a verified configuration record."""
    if type(comparison_id) is not int or not 0 <= comparison_id < 0x80000000 or number != 0:
        raise ValueError('Unsupported configuration FName')
    pointer_address = base + POOL_RVA + 8 + (comparison_id >> 18) * 8
    pointer = read(pointer_address, 8)
    block, = struct.unpack('<Q', pointer)
    if block <= 0 or block & 1 or block >= 0x800000000000:
        raise ValueError('Invalid configuration name block')
    address = block + (comparison_id & 0x3ffff) * 2
    header = read(address, 2, module_only=False)
    value, = struct.unpack('<H', header)
    length, wide = value >> 6, bool(value & 1)
    if not 1 <= length <= max_chars:
        raise ValueError('Configuration name exceeds the bounded read')
    chars = read(address + 2, length * (2 if wide else 1), module_only=False)
    if read(pointer_address, 8) != pointer or read(address, 2, module_only=False) != header:
        raise ValueError('Configuration name changed during capture')
    return codec.decode_config_name(header + chars, number)
