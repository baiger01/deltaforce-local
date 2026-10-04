"""Bounded, callback-only name resolution for the pinned Delta Force image.

This module does not open a process, call native code, or prove that a caller's
memory snapshot belongs to the pinned build. The caller owns that verification.
Offsets and the character transform are from saved code, not a generic UE layout.
No object outer/path traversal is implemented.
"""
from dataclasses import dataclass
import struct

SHIPPING_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CODE_CACHE_MANIFEST_SHA256 = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
NAME_POOL_RVA = 0x1e326a80
NAME_POOL_INITIALIZED_RVA = 0x1e3267ac
BLOCK_ARRAY_OFFSET = 8
MAX_BLOCKS = 8192
BLOCK_BYTES = 0x80000
MAX_NAME_UNITS = 1023
MAX_ADDRESS = 0x7fffffffffff

class NameResolutionError(ValueError):
    """The bounded resolver could not establish a stable, valid name."""

@dataclass(frozen=True)
class ResolvedName:
    base_text: str
    entry_id: int
    number: int
    is_wide: bool
    display_text: str

    def __str__(self):
        return self.display_text

def _address(value, length=1):
    if type(value) is not int or type(length) is not int or length <= 0 or not 0 < value <= MAX_ADDRESS - length + 1:
        raise NameResolutionError('Invalid bounded read address')
    return value

def _read(reader, address, length):
    _address(address, length)
    result = reader(address, length)
    if not isinstance(result, bytes) or len(result) != length:
        raise NameResolutionError('Read callback did not return exact bytes')
    return result

def _key(length, wide):
    """Literal integer operations in 10b5fd00 / 10b5ff10, before XOR."""
    case = length % 9
    if case == 0:
        key = (length & 0x1f) + length + 0x80
    elif case == 1:
        key = (length ^ 0xdf) + length + 0x80
    elif case == 2:
        key = (length | 0xcf) + length + 0x80
    elif case == 3:
        key = length * 0x21 + 0x80
    elif case == 4:
        key = (length >> 2) + length + 0x80
    elif case == 5:
        key = (length * 3 + 0x85) if wide else ((length - 0x29) * 3)
    elif case == 6:
        key = ((length << 2) | 5) + length + 0x80
    elif case == 7:
        key = ((length >> 4) | 7) + length + 0x80
    else:
        key = (length ^ 0xc) + length + 0x80
    return (key & (0xffff if wide else 0xff)) | 0x7f

def _characters(payload, length, wide, number):
    if wide:
        units = list(struct.unpack('<' + 'H' * length, payload))
        if units[0] != 0:
            key = _key(length, True)
            # The saved code increments eax by 2 while addressing r8+rax*2.
            for index in range(0, length, 2):
                units[index] ^= key
        raw = struct.pack('<' + 'H' * length, *units)
    else:
        chars = bytearray(payload)
        if chars[0] != 0:
            key = _key(length, False)
            for index in range(length):
                chars[index] ^= key
        # The zero-number fast FString path replaces negative signed bytes with
        # its explicit '?' fallback. The suffix AppendString path sign extends.
        units = [char if char < 0x80 else (0x3f if number == 0 else char | 0xff00)
                 for char in chars]
        raw = struct.pack('<' + 'H' * length, *units)
    try:
        text = raw.decode('utf-16-le', errors='strict')
    except UnicodeDecodeError as error:
        raise NameResolutionError('Malformed name UTF16') from error
    if '\0' in text:
        raise NameResolutionError('Name contains NUL; unsupported for metadata labels')
    return text

def resolve_name(read_exact, module_base, token8, *, with_number=True):
    """Resolve an explicit 8-byte name token using at most six bounded reads.

    ``read_exact(address, length)`` must return bytes of exactly that length.
    A stable pool pointer/header is checked again after the bounded payload read.
    Number formatting follows native signed-int32 decimal of ``number-1``.
    Empty entries, malformed UTF16, NUL names and an uninitialized pool fail
    closed as stricter local metadata-reader policy.
    """
    if not callable(read_exact) or type(with_number) is not bool:
        raise NameResolutionError('Invalid read callback or number policy')
    _address(module_base, NAME_POOL_RVA + BLOCK_ARRAY_OFFSET + MAX_BLOCKS * 8)
    if not isinstance(token8, bytes) or len(token8) != 8:
        raise NameResolutionError('Name token must be exactly eight bytes')
    entry_id, number = struct.unpack('<II', token8)
    block, offset = entry_id >> 18, (entry_id & 0x3ffff) * 2
    if block >= MAX_BLOCKS:
        raise NameResolutionError('Name block index exceeds the native block table')
    if _read(read_exact, module_base + NAME_POOL_INITIALIZED_RVA, 1) != b'\1':
        raise NameResolutionError('Name pool is not confirmed initialized')
    slot = module_base + NAME_POOL_RVA + BLOCK_ARRAY_OFFSET + block * 8
    pointer_bytes = _read(read_exact, slot, 8)
    pointer, = struct.unpack('<Q', pointer_bytes)
    _address(pointer, BLOCK_BYTES)
    header_bytes = _read(read_exact, pointer + offset, 2)
    header, = struct.unpack('<H', header_bytes)
    length, wide = header >> 6, bool(header & 1)
    if not 0 < length <= MAX_NAME_UNITS:
        raise NameResolutionError('Empty or excessive name entry')
    payload_bytes = length * (2 if wide else 1)
    if offset + 2 + payload_bytes > BLOCK_BYTES:
        raise NameResolutionError('Name payload crosses the bounded native block')
    payload = _read(read_exact, pointer + offset + 2, payload_bytes)
    if _read(read_exact, pointer + offset, 2) != header_bytes or _read(read_exact, slot, 8) != pointer_bytes:
        raise NameResolutionError('Name entry changed during its bounded reads')
    text = _characters(payload, length, wide, number)
    suffix = ''
    if with_number and number:
        signed = (number - 1) & 0xffffffff
        if signed >= 0x80000000:
            signed -= 0x100000000
        suffix = '_' + str(signed)
    return ResolvedName(text, entry_id, number, wide, text + suffix)

def object_name(read_exact, module_base, address, *, field_representation=None):
    """Read one name token. rep0 metadata uses +28; rep1/UObject uses +1c."""
    if field_representation is not None and (type(field_representation) is not int or field_representation not in (0, 1)):
        raise NameResolutionError('Unsupported field representation')
    offset = 0x28 if field_representation == 0 else 0x1c
    _address(address, offset + 8)
    token = _read(read_exact, address + offset, 8)
    return resolve_name(read_exact, module_base, token)
