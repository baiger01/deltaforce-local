"""Recovered compressed spawn-vector branch; no Actor or GUID side effects.

This build's helper12bab4b0 reads a compression bit when archive+54 >= 13,
then SerializeInt(B,24) and three SerializeInt(component,1<<(B+2)). Each
component is biased by 1<<(B+1) and multiplied by float32 0.1. The caller
must provide the archive's version explicitly; Hello's checksum is not it.

Inputs are integer quantization steps. Float-to-integer rounding, the raw
float branch, rotators, object exports and spawning are not implemented here.
The writer chooses any minimal width accepted by the recovered reader; this
does not assert the original writer always chooses the same width.
"""
from dataclasses import dataclass
import struct

from .legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX


MAX_COMPONENT_BITS = 24
MIN_STEP = -(1 << MAX_COMPONENT_BITS)
MAX_STEP = (1 << MAX_COMPONENT_BITS) - 1
NATIVE_SCALE = struct.unpack('<f', bytes.fromhex('cdcccc3d'))[0]


def _version(value):
    if type(value) is not int or not 0 <= value <= UINT32_MAX:
        raise ValueError('An explicit native archive network version is required')


def _float32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


@dataclass(frozen=True)
class QuantizedVector10:
    steps: tuple[int, int, int]

    def __post_init__(self):
        if (not isinstance(self.steps, tuple) or len(self.steps) != 3 or
                any(type(value) is not int or not MIN_STEP <= value <= MAX_STEP
                    for value in self.steps)):
            raise ValueError('Three bounded integer quantization steps are required')

    def native_float_components(self):
        # Match cvtdq2ps followed by mulss with the actual float32 constant.
        return tuple(_float32(_float32(value) * NATIVE_SCALE) for value in self.steps)


def read_compressed_vector10(reader, *, archive_network_version):
    """Read atomically; reject the unverified raw branch without moving cursor."""
    if not isinstance(reader, BitReader):
        raise ValueError('A native bit reader is required')
    _version(archive_network_version)
    start = reader.position
    try:
        if archive_network_version >= 13 and not reader.read_bool():
            raise ValueError('Raw spawn-vector serialization is not implemented')
        width = reader.read_bounded_int(MAX_COMPONENT_BITS)
        bias, maximum = 1 << (width + 1), 1 << (width + 2)
        steps = tuple(reader.read_bounded_int(maximum) - bias for _ in range(3))
        return QuantizedVector10(steps)
    except ValueError:
        reader.position = start
        raise


def write_compressed_vector10(writer, vector, *, archive_network_version):
    """Append an accepted compressed branch without guessing float rounding."""
    if not isinstance(writer, BitWriter) or not isinstance(vector, QuantizedVector10):
        raise ValueError('A native bit writer and quantized vector are required')
    _version(archive_network_version)
    width = 0
    while any(not -(1 << (width+1)) <= value < (1 << (width+1))
              for value in vector.steps):
        width += 1
    staged = BitWriter(maximum_bits=81)
    if archive_network_version >= 13:
        staged.write_bool(True)
    staged.write_bounded_int(width, MAX_COMPONENT_BITS)
    bias, maximum = 1 << (width+1), 1 << (width+2)
    for value in vector.steps:
        staged.write_bounded_int(value+bias, maximum)
    # A single append makes a too-small caller archive an atomic failure.
    writer.write_payload(staged.to_bytes(), staged.bit_count)
