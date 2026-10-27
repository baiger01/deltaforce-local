"""Bounded LSB-first archive primitives recovered from this client build.

Native bit mask table: 01 02 04 08 10 20 40 80. SerializeInt uses a
value-dependent stop condition, including when its maximum is not a power
of two. SerializeIntPacked stores seven value bits in bits 1..7 of each
eight-bit group and the continuation flag in bit 0. Groups do not align
the archive cursor. These are codecs, not connection acceptance or ACKs.

The 8192-byte archive bound and rejecting overlong packed integers are
local policies. Native source identities live in protocol evidence.
"""

MAX_BITS = 8192 * 8
UINT32_MAX = (1 << 32) - 1


def _uint(value, maximum, label):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('Invalid ' + label)


def _maximum(maximum):
    if type(maximum) is not int or not 1 <= maximum <= UINT32_MAX:
        raise ValueError('Invalid exclusive bounded-integer maximum')


class BitReader:
    def __init__(self, data, *, bit_count=None):
        if not isinstance(data, bytes) or len(data) * 8 > MAX_BITS:
            raise ValueError('Invalid bounded bit archive')
        if bit_count is None:
            bit_count = len(data) * 8
        _uint(bit_count, len(data) * 8, 'archive bit count')
        self._value = int.from_bytes(data, 'little')
        self.bit_count = bit_count
        self.position = 0

    @property
    def remaining(self):
        return self.bit_count - self.position

    def read_bits(self, count):
        _uint(count, MAX_BITS, 'read bit count')
        if count > self.remaining:
            raise ValueError('Truncated bit archive')
        result = (self._value >> self.position) & ((1 << count) - 1)
        self.position += count
        return result

    def read_bool(self):
        return bool(self.read_bits(1))

    def read_bytes(self, count):
        _uint(count, MAX_BITS // 8, 'read byte count')
        return self.read_bits(count * 8).to_bytes(count, 'little')

    def read_bounded_int(self, maximum):
        _maximum(maximum)
        value, mask = 0, 1
        while value + mask < maximum:
            if self.read_bits(1):
                value += mask
            mask <<= 1
        return value

    def read_packed_int(self):
        value = 0
        for group in range(5):
            unit = self.read_bits(8)
            payload = unit >> 1
            if group == 4 and (payload > 15 or unit & 1):
                raise ValueError('Packed integer exceeds uint32')
            value |= payload << (group * 7)
            if not unit & 1:
                if group and not payload:
                    raise ValueError('Noncanonical overlong packed integer')
                return value
        raise ValueError('Unterminated packed integer')

    def read_payload(self, count):
        """Return an exact bit slice in zero-padded little-endian bytes."""
        return self.read_bits(count).to_bytes((count + 7) // 8, 'little')


class BitWriter:
    def __init__(self, *, maximum_bits=MAX_BITS):
        if type(maximum_bits) is not int or not 1 <= maximum_bits <= MAX_BITS:
            raise ValueError('Invalid local bit archive bound')
        self.maximum_bits = maximum_bits
        self.bit_count = 0
        self._value = 0

    def write_bits(self, value, count):
        _uint(count, MAX_BITS, 'write bit count')
        _uint(value, (1 << count) - 1, 'bit field value')
        if self.bit_count + count > self.maximum_bits:
            raise ValueError('Bit archive exceeds local bound')
        self._value |= value << self.bit_count
        self.bit_count += count

    def write_bool(self, value):
        if type(value) is not bool:
            raise ValueError('A boolean bit value is required')
        self.write_bits(int(value), 1)

    def write_bytes(self, value):
        if not isinstance(value, bytes):
            raise ValueError('Byte archive input is required')
        self.write_bits(int.from_bytes(value, 'little'), len(value) * 8)

    def write_bounded_int(self, value, maximum):
        _maximum(maximum)
        _uint(value, maximum - 1, 'bounded integer')
        mask, partial = 1, 0
        while partial + mask < maximum:
            bit = bool(value & mask)
            self.write_bool(bit)
            if bit:
                partial += mask
            mask <<= 1

    def write_packed_int(self, value):
        _uint(value, UINT32_MAX, 'packed uint32')
        while True:
            remaining = value >> 7
            self.write_bits(((value & 127) << 1) | bool(remaining), 8)
            if not remaining:
                return
            value = remaining

    def write_payload(self, value, count):
        if (not isinstance(value, bytes) or type(count) is not int or
                not 0 <= count <= MAX_BITS or len(value) != (count + 7) // 8):
            raise ValueError('Invalid exact bit payload')
        self.write_bits(int.from_bytes(value, 'little'), count)

    def to_bytes(self):
        return self._value.to_bytes((self.bit_count + 7) // 8, 'little')
