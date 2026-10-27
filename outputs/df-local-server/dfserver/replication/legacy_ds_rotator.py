"""The pinned FRotator short-axis archive; no native calls or packet sending.

Recovered from SerializeNewActor 0x12bcce26 -> 0x10ab4e20 -> 0x10ab83a0
in the 2026-10-18 qualified code cache. Each axis has one presence bit,
followed by a raw little-endian uint16 only when nonzero. Native constants
at 0x158f829c, 0x14ec832c and 0x14f8d21c supply the float32 operations.
"""
from dataclasses import dataclass
import math
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter

MAX_ROTATOR_BITS = 51


def _float32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


@dataclass(frozen=True)
class CompressedRotator16:
    steps: tuple[int, int, int]

    def __post_init__(self):
        if (type(self.steps) is not tuple or len(self.steps) != 3 or
                any(type(v) is not int or not 0 <= v <= 65535 for v in self.steps)):
            raise ValueError('Three explicit uint16 rotation steps are required')

    @classmethod
    def from_degrees(cls, values):
        if (type(values) is not tuple or len(values) != 3 or
                any(type(v) not in (int, float) or not math.isfinite(v) or
                    not -360 <= v <= 360 for v in values)):
            raise ValueError('Three finite authored rotation angles in [-360, 360] are required')
        steps = []
        for value in values:
            scaled = _float32(_float32(value) * 182.04444885253906)
            rounded_input = _float32(_float32(scaled + scaled) + 0.5)
            # CVTSS2SI with normal nearest/even rounding followed by SAR 1.
            steps.append((round(rounded_input) >> 1) & 65535)
        return cls(tuple(steps))

    def native_float_components(self):
        self.__post_init__()
        return tuple(_float32(value * 0.0054931640625) for value in self.steps)


def write_compressed_rotator16(writer, rotation):
    if not isinstance(writer, BitWriter) or type(rotation) is not CompressedRotator16:
        raise ValueError('A bit writer and explicit compressed rotator are required')
    rotation.__post_init__()
    staged = BitWriter(maximum_bits=MAX_ROTATOR_BITS)
    for value in rotation.steps:
        staged.write_bool(value != 0)
        if value:
            staged.write_bits(value, 16)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count
