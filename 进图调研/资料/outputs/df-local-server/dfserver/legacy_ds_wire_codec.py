"""Native packet-notify and bunch codecs for the recovered current build.

This profile covers ordinary connections (not internal ACK/replay archives),
the current packed channel-index/name format, and the non-swapped archive.
Inputs start after any opaque routing bytes. PacketHandler termination is an
explicit observed local envelope, separate from the proven native serializers.
Parsing is atomic and has no ACK, identity, connection or gameplay side effect.

Raw flag4/connection_flag names deliberately preserve unresolved meanings.
Channel sequences are the ten-bit wire value, not reconstructed signed values.
"""
from dataclasses import dataclass
import struct

from .legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from .legacy_ds_control_fields import decode_string, encode_string

SEQUENCE_MASK = 0x3fff


def _uint(value, maximum, field):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('Invalid ' + field)


def _packet_bound(max_packet_bytes):
    if type(max_packet_bytes) is not int or not 1 <= max_packet_bytes <= 1492:
        raise ValueError('Invalid explicit native MaxPacket byte bound')


@dataclass(frozen=True)
class ChannelName:
    hardcoded_index: int | None = None
    text: str | None = None
    number: int = 0


@dataclass(frozen=True)
class WireBunch:
    channel_index: int
    payload: bytes
    payload_bits: int
    open: bool = False
    close: bool = False
    close_reason: int = 0
    flag4: bool = False
    reliable: bool = False
    connection_flag: bool = False
    package_exports: bool = False
    must_be_mapped: bool = False
    partial: bool = False
    partial_initial: bool = False
    partial_final: bool = False
    channel_sequence: int | None = None
    channel_name: ChannelName | None = None
    header_start_bit: int | None = None
    payload_start_bit: int | None = None


@dataclass(frozen=True)
class WirePacket:
    sequence: int
    acknowledged_sequence: int
    history: tuple[int, ...]
    packet_info: bool
    frame: int
    server_frame_time: int | None
    bunches: tuple[WireBunch, ...]
    consumed_bits: int


def _read_string(reader):
    header = reader.read_bytes(4)
    count = struct.unpack('<i', header)[0]
    if count == -(1 << 31) or abs(count) > 4096:
        raise ValueError('Channel name exceeds the local string bound')
    raw = header + reader.read_bytes(abs(count) * (2 if count < 0 else 1))
    return decode_string(raw)[0]


def _read_name(reader):
    if reader.read_bool():
        index = reader.read_packed_int()
        if index >= 0x25d:
            raise ValueError('Native hardcoded name index is out of range')
        return ChannelName(hardcoded_index=index)
    return ChannelName(text=_read_string(reader), number=reader.read_bits(32))


def _write_name(writer, name):
    if not isinstance(name, ChannelName):
        raise ValueError('A decoded channel name is required')
    if name.hardcoded_index is not None:
        _uint(name.hardcoded_index, 0x19a, 'canonical native hardcoded name')
        if name.text is not None or name.number != 0:
            raise ValueError('Hardcoded channel names cannot carry text/number')
        writer.write_bool(True)
        writer.write_packed_int(name.hardcoded_index)
    else:
        if not isinstance(name.text, str):
            raise ValueError('Channel name text is required')
        _uint(name.number, UINT32_MAX, 'channel name number')
        writer.write_bool(False)
        writer.write_bytes(encode_string(name.text))
        writer.write_bits(name.number, 32)


def _read_bunch(reader, max_packet_bytes):
    start = reader.position
    control = reader.read_bool()
    is_open = reader.read_bool() if control else False
    is_close = reader.read_bool() if control else False
    if control and not (is_open or is_close):
        raise ValueError('Noncanonical control bit without open/close flags')
    reason = reader.read_bounded_int(15) if is_close else 0
    flag4, reliable, connection_flag = (reader.read_bool() for _ in range(3))
    index = reader.read_packed_int()
    exports, mapped, partial = (reader.read_bool() for _ in range(3))
    sequence = reader.read_bounded_int(1024) if reliable else None
    initial = reader.read_bool() if partial else False
    final = reader.read_bool() if partial else False
    name = _read_name(reader) if reliable or is_open else None
    count = reader.read_bounded_int(max_packet_bytes * 8)
    payload_start = reader.position
    payload = reader.read_payload(count)
    return WireBunch(index, payload, count, is_open, is_close, reason, flag4,
                     reliable, connection_flag, exports, mapped, partial,
                     initial, final, sequence, name, start, payload_start)


def _write_bunch(writer, bunch, max_packet_bytes):
    if not isinstance(bunch, WireBunch):
        raise ValueError('An explicit wire bunch is required')
    for field in ('open', 'close', 'flag4', 'reliable', 'connection_flag',
                  'package_exports', 'must_be_mapped', 'partial',
                  'partial_initial', 'partial_final'):
        if type(getattr(bunch, field)) is not bool:
            raise ValueError('Invalid bunch boolean ' + field)
    _uint(bunch.channel_index, UINT32_MAX, 'channel index')
    _uint(bunch.close_reason, 14, 'close reason')
    if not bunch.close and bunch.close_reason != 0:
        raise ValueError('Close reason requires a close flag')
    if not bunch.partial and (bunch.partial_initial or bunch.partial_final):
        raise ValueError('Partial endpoints require a partial flag')
    if not bunch.reliable and bunch.channel_sequence is not None:
        raise ValueError('Unreliable bunches cannot carry channel sequence')
    if not (bunch.reliable or bunch.open) and bunch.channel_name is not None:
        raise ValueError('This bunch header cannot carry a channel name')
    control = bunch.open or bunch.close
    writer.write_bool(control)
    if control:
        writer.write_bool(bunch.open)
        writer.write_bool(bunch.close)
        if bunch.close:
            writer.write_bounded_int(bunch.close_reason, 15)
    for value in (bunch.flag4, bunch.reliable, bunch.connection_flag):
        writer.write_bool(value)
    writer.write_packed_int(bunch.channel_index)
    for value in (bunch.package_exports, bunch.must_be_mapped, bunch.partial):
        writer.write_bool(value)
    if bunch.reliable:
        writer.write_bounded_int(bunch.channel_sequence, 1024)
    if bunch.partial:
        writer.write_bool(bunch.partial_initial)
        writer.write_bool(bunch.partial_final)
    if bunch.reliable or bunch.open:
        _write_name(writer, bunch.channel_name)
    writer.write_bounded_int(bunch.payload_bits, max_packet_bytes * 8)
    writer.write_payload(bunch.payload, bunch.payload_bits)


def decode_native_packet(data, *, bit_count, max_packet_bytes, received_by_server):
    """Read packet notify, metadata and all bunches, without accepting them."""
    _packet_bound(max_packet_bytes)
    if (type(received_by_server) is not bool or not isinstance(data, bytes) or
            len(data) > max_packet_bytes):
        raise ValueError('Invalid explicit receive-side profile')
    reader = BitReader(data, bit_count=bit_count)
    header = reader.read_bits(32)
    advertised = (header & 15) + 1
    # Native reads min(advertised, 8). Current encoder produces 1..8;
    # rejecting 9..16 here is a strict local policy, not native behavior.
    if advertised > 8:
        raise ValueError('Unsupported noncanonical packet history count')
    history = tuple(reader.read_bits(32) for _ in range(advertised))
    info = reader.read_bool()
    timing = reader.read_bits(8) if info and not received_by_server else None
    frame = reader.read_bits(8)
    bunches = []
    while reader.remaining:
        if len(bunches) >= 32:
            raise ValueError('Packet exceeds the local bunch count bound')
        bunches.append(_read_bunch(reader, max_packet_bytes))
    return WirePacket(header >> 18, (header >> 4) & SEQUENCE_MASK, history,
                      info, frame, timing, tuple(bunches), reader.position)


def encode_native_packet(packet, *, max_packet_bytes, received_by_server):
    _packet_bound(max_packet_bytes)
    if not isinstance(packet, WirePacket) or type(received_by_server) is not bool:
        raise ValueError('An explicit native packet profile is required')
    _uint(packet.sequence, SEQUENCE_MASK, 'packet sequence')
    _uint(packet.acknowledged_sequence, SEQUENCE_MASK, 'acknowledged sequence')
    if not isinstance(packet.history, tuple) or not 1 <= len(packet.history) <= 8:
        raise ValueError('Invalid canonical history words')
    if type(packet.packet_info) is not bool:
        raise ValueError('Invalid packet info bit')
    _uint(packet.frame, 255, 'packet frame')
    if packet.packet_info and not received_by_server:
        _uint(packet.server_frame_time, 255, 'server frame time')
    elif packet.server_frame_time is not None:
        raise ValueError('Frame time is absent in this metadata profile')
    if not isinstance(packet.bunches, tuple) or len(packet.bunches) > 32:
        raise ValueError('Invalid local bunch count')
    writer = BitWriter(maximum_bits=max_packet_bytes * 8)
    writer.write_bits((packet.sequence << 18) | (packet.acknowledged_sequence << 4) |
                      (len(packet.history) - 1), 32)
    for word in packet.history:
        _uint(word, UINT32_MAX, 'history word')
        writer.write_bits(word, 32)
    writer.write_bool(packet.packet_info)
    if packet.packet_info and not received_by_server:
        writer.write_bits(packet.server_frame_time, 8)
    writer.write_bits(packet.frame, 8)
    for bunch in packet.bunches:
        _write_bunch(writer, bunch, max_packet_bytes)
    return writer.to_bytes(), writer.bit_count


def decode_observed_application(body, *, max_packet_bytes, received_by_server):
    """Unwrap the local fixture's one handler bit and adjacent terminators."""
    _packet_bound(max_packet_bytes)
    if (not isinstance(body, bytes) or not 1 <= len(body) <= max_packet_bytes or
            not body[-1]):
        raise ValueError('Invalid observed application body')
    value = int.from_bytes(body, 'little')
    if value & 1:
        raise ValueError('Handshake body is not an application body')
    outer = value.bit_length() - 1
    inner = (value & ((1 << outer) - 1)).bit_length() - 1
    if inner != outer - 1:
        raise ValueError('Unsupported observed PacketHandler termination')
    bits = inner - 1
    raw = ((value >> 1) & ((1 << bits) - 1)).to_bytes((bits + 7) // 8, 'little')
    return decode_native_packet(raw, bit_count=bits, max_packet_bytes=max_packet_bytes,
                                received_by_server=received_by_server)


def encode_observed_application(packet, *, max_packet_bytes, received_by_server):
    raw, bits = encode_native_packet(packet, max_packet_bytes=max_packet_bytes,
                                     received_by_server=received_by_server)
    value = (int.from_bytes(raw, 'little') << 1) | (1 << (bits + 1)) | (1 << (bits + 2))
    result = value.to_bytes((bits + 3 + 7) // 8, 'little')
    if len(result) > max_packet_bytes:
        raise ValueError('Observed envelope exceeds explicit MaxPacket bound')
    return result
