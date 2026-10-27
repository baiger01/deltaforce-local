"""Ordinary PC ping RPC scalar parameters recovered from this client build.

Source: map-entry-next-20261005 PC ping native wire-schema evidence. UStruct
parameters have one outer presence bit. The server Ping has a double and five
floats; its client return has two doubles and one float. Scalar payloads are
unaligned raw IEEE bytes in the explicitly non-byte-swapped profile.

These functions identify no class-cache index, perform no admission/ACK/RPC
dispatch and do not implement a clock/validation policy. A caller must qualify
the actual function descriptor, access direction and wire-schema source first.
"""
from dataclasses import dataclass
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter


@dataclass(frozen=True)
class OrdinaryRPCScalarProfile:
    internal_ack: bool
    byte_swapping: bool

    def __post_init__(self):
        if type(self.internal_ack) is not bool or self.internal_ack:
            raise ValueError('Only the explicit ordinary RPC parameter profile is supported')
        if type(self.byte_swapping) is not bool or self.byte_swapping:
            raise ValueError('Only the explicit non-byte-swapped scalar profile is supported')


@dataclass(frozen=True)
class ServerBouncePingParams:
    tc1: float
    exact_ping: float
    delta_ts: float
    old_ping: float
    delta_tc: float
    client_delta_time: float


@dataclass(frozen=True)
class ClientReturnPingParams:
    server_returned_client_time_stamp: float
    delta_ts: float
    in_server_time_stamp: float


def _profile(profile):
    if type(profile) is not OrdinaryRPCScalarProfile:
        raise ValueError('An explicit ordinary scalar RPC profile is required')
    profile.__post_init__()


def _write(writer, values, formats, profile):
    _profile(profile)
    if type(writer) is not BitWriter:
        raise ValueError('An exact native bit writer is required')
    staged = BitWriter(maximum_bits=225)
    staged.write_bool(values is not None)
    if values is not None:
        for value, code in zip(values, formats):
            # IEEE NaN/Inf are preserved by the codec; semantic validation
            # belongs to the recovered handler and explicit local clock policy.
            if type(value) not in (int, float):
                raise ValueError('RPC scalar must be a numeric value, excluding booleans')
            try:
                raw = struct.pack('<' + code, value)
            except (OverflowError, struct.error) as error:
                raise ValueError('RPC scalar is outside its IEEE representation') from error
            staged.write_payload(raw, len(raw) * 8)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def _read(reader, formats, record_type, profile):
    _profile(profile)
    if type(reader) is not BitReader:
        raise ValueError('An exact native bit reader is required')
    start = reader.position
    try:
        values = None
        if reader.read_bool():
            values = record_type(*(struct.unpack('<' + code,
                reader.read_payload(struct.calcsize(code) * 8))[0] for code in formats))
        if reader.remaining:
            raise ValueError('RPC parameter reader must be bounded to exact field EOF')
        return values
    except Exception:
        reader.position = start
        raise


def write_server_bounce_ping(writer, params, *, profile):
    if params is not None and type(params) is not ServerBouncePingParams:
        raise ValueError('A ServerBouncePingParams or absent struct is required')
    values = None if params is None else (params.tc1, params.exact_ping,
        params.delta_ts, params.old_ping, params.delta_tc, params.client_delta_time)
    return _write(writer, values, ('d', 'f', 'f', 'f', 'f', 'f'), profile)


def read_server_bounce_ping(reader, *, profile):
    return _read(reader, ('d', 'f', 'f', 'f', 'f', 'f'), ServerBouncePingParams, profile)


def write_client_return_ping(writer, params, *, profile):
    if params is not None and type(params) is not ClientReturnPingParams:
        raise ValueError('A ClientReturnPingParams or absent struct is required')
    values = None if params is None else (params.server_returned_client_time_stamp,
                                        params.delta_ts, params.in_server_time_stamp)
    return _write(writer, values, ('d', 'd', 'f'), profile)


def read_client_return_ping(reader, *, profile):
    return _read(reader, ('d', 'd', 'f'), ClientReturnPingParams, profile)
