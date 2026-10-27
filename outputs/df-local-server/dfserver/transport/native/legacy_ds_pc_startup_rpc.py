"""Qualified ordinary PC startup RPC bodies and an empty ready acknowledgement.

No indices are selected by this module. The owner-side native source qualifier
supplies the exact class, fields and direction. This is protocol receipt state;
it neither calls a native GameMode nor establishes possession or scene readiness.
"""
from dataclasses import dataclass
import math
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.replication.legacy_ds_actor_content import read_actor_content_blocks, write_actor_content_blocks
from dfserver.replication.legacy_ds_actor_fields import ClassFieldEnvelope, build_class_field_content, NormalClassFieldProfile, read_class_fields
from dfserver.transport.native.legacy_ds_wire_codec import WireBunch, ChannelName
from dfserver.transport.native.legacy_ds_current_pc_rpc_profile import (
    CURRENT_RPC_SOURCE_SHA256, qualify_current_pc_rpc_sources, require_current_profile)


@dataclass(frozen=True)
class PCStartupField:
    name: str
    rep_index: int
    parameter_kind: str


@dataclass(frozen=True)
class PCStartupProfile:
    class_path: str
    exclusive_index_maximum: int
    requests: tuple
    acknowledgement_index: int
    source_sha256: str
    current_qualification: object = None

    def __post_init__(self):
        expected = {'ServerShortTimeout': 'empty', 'Server_RcvACWorldTime': 'float32',
                    'ServerFieldOfView': 'float32', 'NotifySeamlessLoginReady': 'bool'}
        if (type(self.class_path) is not str or not self.class_path.startswith('/Game/') or
                type(self.exclusive_index_maximum) is not int or not 1 <= self.exclusive_index_maximum <= 4096 or
                type(self.requests) is not tuple or len(self.requests) != 4 or
                any(type(f) is not PCStartupField or expected.get(f.name) != f.parameter_kind or
                    type(f.rep_index) is not int or not 0 <= f.rep_index < self.exclusive_index_maximum
                    for f in self.requests) or
                {f.name for f in self.requests} != set(expected) or
                len({f.rep_index for f in self.requests}) != 4 or
                type(self.acknowledgement_index) is not int or
                not 0 <= self.acknowledgement_index < self.exclusive_index_maximum or
                self.acknowledgement_index in {f.rep_index for f in self.requests} or
                type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in self.source_sha256)):
            raise ValueError('An explicit qualified PC startup profile is required')
        if self.current_qualification is not None:
            require_current_profile(self.current_qualification, class_path=self.class_path,
                exclusive_index_maximum=self.exclusive_index_maximum, source_sha256=self.source_sha256)
            if ({f.name: f.rep_index for f in self.requests} != {
                    'ServerShortTimeout': 79, 'Server_RcvACWorldTime': 150,
                    'ServerFieldOfView': 216, 'NotifySeamlessLoginReady': 141} or
                    self.acknowledgement_index != 131):
                raise ValueError('The exact current PC startup indices are required')
        elif self.source_sha256 == CURRENT_RPC_SOURCE_SHA256:
            raise ValueError('The current PC report requires explicit current qualification')


@dataclass(frozen=True)
class PCStartupRequest:
    name: str
    value: object


def decode_pc_startup_bunch(bunch, *, channel_index, profile):
    if type(profile) is not PCStartupProfile:
        raise ValueError('A qualified PC startup profile is required')
    profile.__post_init__()
    if (type(bunch) is not WireBunch or bunch.channel_index != channel_index or
            not bunch.reliable or bunch.channel_name != ChannelName(hardcoded_index=102) or
            type(bunch.channel_sequence) is not int or not 0 <= bunch.channel_sequence < 1024 or
            any((bunch.open, bunch.close, bunch.flag4, bunch.connection_flag,
                 bunch.package_exports, bunch.must_be_mapped, bunch.partial,
                 bunch.partial_initial, bunch.partial_final)) or not 1 <= bunch.payload_bits <= 4096):
        raise ValueError('Only a complete reliable PC Actor bunch is supported')
    blocks = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
    if not blocks or len(blocks) > 8:
        raise ValueError('A bounded nonempty startup content is required')
    schema = {f.rep_index: f for f in profile.requests}
    result = []
    for block in blocks:
        if block.has_rep_layout:
            raise ValueError('Startup RPC receiver does not consume property replication')
        fields = read_class_fields(BitReader(block.payload, bit_count=block.payload_bit_count),
            profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
        if not fields or len(fields) > 8:
            raise ValueError('A bounded nonempty startup field list is required')
        for field in fields:
            definition = schema.get(field.rep_index)
            if definition is None:
                raise ValueError('Unsupported PC startup RPC')
            reader = BitReader(field.payload, bit_count=field.payload_bit_count)
            if definition.parameter_kind == 'empty':
                value = None
            elif definition.parameter_kind == 'bool':
                # Native FBoolProperty class flag bit17 skips the per-parent
                # presence marker; virtual90 consumes one bit directly.
                value = reader.read_bool()
            else:
                value = struct.unpack('<f', reader.read_payload(32))[0] if reader.read_bool() else 0.0
                if not math.isfinite(value):
                    raise ValueError('Non-finite client startup scalar')
            if reader.remaining:
                raise ValueError('Startup parameter body must end at exact EOF')
            result.append(PCStartupRequest(definition.name, value))
            if len(result) > 8:
                raise ValueError('Startup request count exceeds local budget')
    return tuple(result)


def build_pc_ready_ack(*, channel_index, channel_sequence, profile):
    if type(profile) is not PCStartupProfile:
        raise ValueError('A qualified PC startup profile is required')
    profile.__post_init__()
    block = build_class_field_content((ClassFieldEnvelope(profile.acknowledgement_index, b'', 0),),
        profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
    writer = BitWriter(maximum_bits=512)
    write_actor_content_blocks(writer, (block,))
    return WireBunch(channel_index, writer.to_bytes(), writer.bit_count, reliable=True,
                     channel_sequence=channel_sequence, channel_name=ChannelName(hardcoded_index=102))
