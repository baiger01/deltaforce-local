"""Pure bounded decoders for the recovered same-build visibility parameters.

Sources: work/evidence/map-entry-next-20261007/level-visibility-static-source.json
and level-visibility-wire-body-source.json. The body API requires its bit
boundary; the restricted parameter API also handles the one presence bit.
Neither implements bunches, packets, receipt, or dispatch. The caller must
establish the actual PackageMap.v278 compatibility. No native calls or I/O.

Name hardcoded encoding branches on archive+0x54; callers must supply that
observed version when a hardcoded name occurs. ASCII paths and valid UTF-16LE
are accepted. Malformed/noncanonical names accepted permissively by native
code are rejected; the bounds below intentionally define a narrower subset.
"""
from dataclasses import dataclass

CLASS_PATH = "/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C"
SHIPPING_SHA256 = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
SERVER_FUNCTION_FLAGS = 0x80220CC1
MAX_BODY_BYTES = 1024 * 1024
MAX_ENTRIES = 4096
MAX_NAME_UNITS = 4096
HARDCODED_NAME_LIMIT = 0x25D


class VisibilityDecodeError(ValueError):
    """The provided body is malformed, unsupported, or exceeds a bound."""


@dataclass(frozen=True)
class LevelVisibilityProfile:
    class_path: str
    exclusive_index_maximum: int
    single_index: int
    multiple_index: int
    server_function_flags: int
    source_sha256: str
    runtime_package_map_override_observed: bool = False
    actual_string_fixture_eof_verified: bool = True

    def __post_init__(self):
        expected = ((self.exclusive_index_maximum, 245), (self.single_index, 83),
                    (self.multiple_index, 84), (self.server_function_flags, SERVER_FUNCTION_FLAGS))
        if (self.class_path != CLASS_PATH
                or any(type(value) is not int or value != required for value, required in expected)
                or type(self.source_sha256) is not str or len(self.source_sha256) != 64
                or any(character not in "0123456789abcdef" for character in self.source_sha256)
                or self.runtime_package_map_override_observed is not False
                or type(self.actual_string_fixture_eof_verified) is not bool):
            raise ValueError("The exact source-qualified visibility profile is required")


@dataclass(frozen=True)
class NativeName:
    text: str | None
    number: int
    hardcoded_index: int | None = None


@dataclass(frozen=True)
class LevelVisibility:
    package_name: NativeName
    file_name: NativeName
    is_visible: bool
    file_name_omitted: bool


@dataclass(frozen=True)
class VisibilityBody:
    levels: tuple[LevelVisibility, ...]
    begin_bit: int
    next_bit: int
    bits_consumed: int
    multiple: bool


@dataclass(frozen=True)
class VisibilityParameters:
    rep_index: int
    parameter_present: bool
    levels: tuple[LevelVisibility, ...]
    next_bit: int
    bits_consumed: int


class _Bits:
    def __init__(self, raw: bytes, end: int, start: int):
        if not isinstance(raw, bytes) or len(raw) > MAX_BODY_BYTES:
            raise VisibilityDecodeError("Body byte budget/type mismatch")
        if (type(end) is not int or type(start) is not int
                or not 0 <= start <= end <= len(raw) * 8):
            raise VisibilityDecodeError("Body bit bounds mismatch")
        self.raw, self.end, self.pos = raw, end, start

    def read(self, count: int) -> int:
        if not 0 <= count <= self.end - self.pos:
            raise VisibilityDecodeError("Body exhausted")
        value = 0
        for index in range(count):
            value |= ((self.raw[self.pos >> 3] >> (self.pos & 7)) & 1) << index
            self.pos += 1
        return value

    def octets(self, count: int) -> bytes:
        if not 0 <= count * 8 <= self.end - self.pos:
            raise VisibilityDecodeError("Name payload exhausted")
        return bytes(self.read(8) for _ in range(count))

    def packed_u32(self) -> int:
        # 10b4c190: bit 0 is continuation; bits 1..7 are payload.
        value = 0
        for group in range(5):
            octet = self.read(8)
            if group == 4 and (octet >> 1) > 15:
                raise VisibilityDecodeError("Packed u32 overflow")
            value |= (octet >> 1) << (group * 7)
            if not octet & 1:
                if group and not octet >> 1:
                    raise VisibilityDecodeError("Noncanonical packed u32")
                return value
        raise VisibilityDecodeError("Unterminated packed u32")

    def bounded_u32(self, maximum: int) -> int:
        value, mask = 0, 1
        while value + mask < maximum:
            value |= self.read(1) * mask
            mask <<= 1
        return value


def _string(bits: _Bits) -> str:
    # 109ea340: signed length; positive ANSI octets, negative UTF-16 units.
    count = bits.read(32)
    if count & 0x80000000:
        count -= 1 << 32
    if count == -(1 << 31) or abs(count) > MAX_NAME_UNITS:
        raise VisibilityDecodeError("Name length exceeds fixed budget")
    if not count:
        return ""
    wide = count < 0
    raw = bits.octets(abs(count) * (2 if wide else 1))
    terminator = b"\0\0" if wide else b"\0"
    if not raw.endswith(terminator):
        raise VisibilityDecodeError("Name lacks canonical terminator")
    body = raw[:-len(terminator)]
    try:
        text = body.decode("utf-16le" if wide else "ascii", errors="strict")
    except UnicodeError as error:
        raise VisibilityDecodeError("Unsupported name encoding") from error
    if "\0" in text or "\uffff" in text:
        raise VisibilityDecodeError("Noncanonical name text")
    return text


def _name(bits: _Bits, name_version: int | None) -> NativeName:
    # 10e05bc0: one hardcoded bit, then version-dependent index OR string+u32.
    if not bits.read(1):
        text = _string(bits)
        return NativeName(text=text, number=bits.read(32))
    if name_version is None:
        raise VisibilityDecodeError("Hardcoded name requires observed archive name version")
    index = (bits.bounded_u32(0x19B) if name_version < 6 else bits.packed_u32())
    if index >= HARDCODED_NAME_LIMIT:
        raise VisibilityDecodeError("Hardcoded index exceeds native name table")
    # Native hardcoded path resets number to zero. This API preserves the index;
    # it does not invent the static name-table text for nonzero indices.
    return NativeName(text=None, number=0, hardcoded_index=index)


def _level(bits: _Bits, name_version: int | None) -> LevelVisibility:
    # 12d4c0d0: omission bit, visibility bit, package, conditional filename.
    omitted = bool(bits.read(1))
    visible = bool(bits.read(1))
    package = _name(bits, name_version)
    file_name = package if omitted else _name(bits, name_version)
    return LevelVisibility(package, file_name, visible, omitted)


def decode_level_visibility_body(
    raw: bytes, bit_count: int, *, multiple: bool, bit_offset: int = 0,
    name_version: int | None = None, require_end: bool = True,
) -> VisibilityBody:
    """Decode one struct or a uint16-counted struct array at an established bit.

    ``name_version`` corresponds to the native archive field +0x54, not a UE
    release label. A missing value is permitted only for string-name bodies.
    ``require_end`` checks the exact supplied body boundary, never pad bytes.
    """
    if type(multiple) is not bool or type(require_end) is not bool:
        raise VisibilityDecodeError("Body mode must be boolean")
    if name_version is not None and (type(name_version) is not int
                                    or not 0 <= name_version <= 0xFFFFFFFF):
        raise VisibilityDecodeError("Archive name version is invalid")
    bits = _Bits(raw, bit_count, bit_offset)
    # 12dc20b0 reads two raw serialized bytes, not an IntPacked count.
    count = bits.read(16) if multiple else 1
    if count > MAX_ENTRIES:
        raise VisibilityDecodeError("Visibility count exceeds fixed budget")
    levels = tuple(_level(bits, name_version) for _ in range(count))
    if require_end and bits.pos != bits.end:
        raise VisibilityDecodeError("Body has trailing bits")
    return VisibilityBody(levels, bit_offset, bits.pos, bits.pos - bit_offset, multiple)


def decode_level_visibility_parameters(
    raw: bytes, bit_count: int, *, rep_index: int,
    name_version: int | None = None, profile: LevelVisibilityProfile | None = None,
) -> VisibilityParameters:
    """Decode a present 83 / 84 parameter slice, including its presence bit.

    Same-build FStructProperty / FArrayProperty class flags are 0x108001 /
    0x208001. Neither sets the BoolProperty bit17 bypass checked by RPC reader
    12db9672..12db96e1. Native absent/default arguments are outside this subset;
    this function rejects them without changing a caller's visibility state.
    RPC dispatch, receipt and package-existence checks remain with the caller.
    """
    if profile is not None:
        if type(profile) is not LevelVisibilityProfile:
            raise VisibilityDecodeError("A qualified visibility profile is required")
        profile.__post_init__()
    if type(rep_index) is not int or rep_index not in (83, 84):
        raise VisibilityDecodeError("Only qualified visibility fields 83 and 84 are accepted")
    bits = _Bits(raw, bit_count, 0)
    if not bits.read(1):
        raise VisibilityDecodeError("Visibility subset requires a present parameter")
    body = decode_level_visibility_body(raw, bit_count, multiple=rep_index == 84,
                                       bit_offset=1, name_version=name_version)
    return VisibilityParameters(rep_index, True, body.levels, body.next_bit, body.next_bit)
