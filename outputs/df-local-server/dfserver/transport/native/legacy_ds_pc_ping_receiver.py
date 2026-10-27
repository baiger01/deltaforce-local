"""Explicit same-build PC Ping receiver; no scene-ready or possession messages.

The caller supplies qualified class-cache indices and clock values. Only plain
unreliable Actor Ping bunches are consumed. Other bunches in a mixed packet
remain unacknowledged even when a recognized Ping receives its own response.
"""
from dataclasses import dataclass
import math

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.replication.legacy_ds_actor_content import read_actor_content_blocks, write_actor_content_blocks
from dfserver.replication.legacy_ds_actor_fields import read_class_fields, ClassFieldEnvelope, build_class_field_content, NormalClassFieldProfile
from dfserver.transport.native.legacy_ds_pc_rpc_fields import OrdinaryRPCScalarProfile, ClientReturnPingParams, read_server_bounce_ping, write_client_return_ping
from dfserver.transport.native.legacy_ds_wire_codec import WireBunch
from dfserver.transport.native.legacy_ds_current_pc_rpc_profile import CURRENT_RPC_SOURCE_SHA256, require_current_profile


@dataclass(frozen=True)
class PCPingProfile:
    class_path: str
    exclusive_index_maximum: int
    request_index: int
    reply_index: int
    source_sha256: str
    minimum_reply_interval: float = 0.1  # Local clock/throttling policy.
    maximum_replies: int = 4096  # Separate from the bounded control outbox.
    current_qualification: object = None

    def __post_init__(self):
        if (type(self.class_path) is not str or not self.class_path.startswith('/Game/') or
                type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in self.source_sha256) or
                type(self.exclusive_index_maximum) is not int or
                not 1 <= self.exclusive_index_maximum <= 4096 or
                any(type(i) is not int or not 0 <= i < self.exclusive_index_maximum
                    for i in (self.request_index, self.reply_index)) or
                self.request_index == self.reply_index or
                type(self.minimum_reply_interval) not in (int, float) or
                not math.isfinite(self.minimum_reply_interval) or
                not 0.05 <= self.minimum_reply_interval <= 2 or
                type(self.maximum_replies) is not int or not 1 <= self.maximum_replies <= 8192):
            raise ValueError('An explicit bounded PC Ping profile is required')
        if self.current_qualification is not None:
            require_current_profile(self.current_qualification, class_path=self.class_path,
                exclusive_index_maximum=self.exclusive_index_maximum, source_sha256=self.source_sha256)
            if self.request_index != 151 or self.reply_index != 138:
                raise ValueError('The exact current PC Ping indices are required')
        elif self.source_sha256 == CURRENT_RPC_SOURCE_SHA256:
            raise ValueError('The current PC report requires explicit current qualification')


def decode_pc_ping_bunches(bunches, *, channel_index, profile):
    if type(profile) is not PCPingProfile:
        raise ValueError('A qualified PC Ping profile is required')
    profile.__post_init__()
    if type(bunches) is not tuple or not 1 <= len(bunches) <= 8:
        raise ValueError('Only bounded Ping-only packets are supported')
    params = []
    for bunch in bunches:
        if (type(bunch) is not WireBunch or bunch.channel_index != channel_index or
                any((bunch.open, bunch.close, bunch.flag4, bunch.reliable,
                     bunch.connection_flag, bunch.package_exports, bunch.must_be_mapped,
                     bunch.partial, bunch.partial_initial, bunch.partial_final)) or
                bunch.channel_sequence is not None or bunch.channel_name is not None or
                not 1 <= bunch.payload_bits <= 4096):
            raise ValueError('Only plain unreliable PC Ping bunches are supported')
        blocks = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
        if not blocks or len(blocks) > 8:
            raise ValueError('A bounded nonempty Actor Ping content is required')
        for block in blocks:
            if block.has_rep_layout:
                raise ValueError('Ping receiver does not consume property replication')
            fields = read_class_fields(BitReader(block.payload, bit_count=block.payload_bit_count),
                profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
            if not fields or len(fields) > 8:
                raise ValueError('A bounded nonempty Ping field list is required')
            for field in fields:
                if field.rep_index != profile.request_index or field.payload_bit_count != 225:
                    raise ValueError('Unknown PC RPC or unsupported Ping parameters')
                value = read_server_bounce_ping(BitReader(field.payload, bit_count=field.payload_bit_count),
                    profile=OrdinaryRPCScalarProfile(False, False))
                if value is None or not all(math.isfinite(getattr(value, name))
                                            for name in value.__dataclass_fields__):
                    raise ValueError('Ping parameters must be a finite present struct')
                params.append(value)
                if len(params) > 8:
                    raise ValueError('Ping packet request budget exceeded')
    return tuple(params)


def select_pc_ping_bunches(bunches, *, channel_index, profile):
    """Select whole recognized bunches; never strip unknown fields from a bunch."""
    if type(bunches) is not tuple or not 1 <= len(bunches) <= 256:
        raise ValueError('A bounded application bunch tuple is required')
    selected = []
    requests = 0
    for bunch in bunches:
        try:
            params = decode_pc_ping_bunches((bunch,), channel_index=channel_index, profile=profile)
        except ValueError:
            continue
        selected.append(bunch)
        requests += len(params)
        if requests > 8:
            raise ValueError('Ping packet request budget exceeded')
    return tuple(selected)


def build_pc_ping_reply(params, *, channel_index, profile, world_seconds, delta_seconds):
    if (type(profile) is not PCPingProfile or
            any(type(v) not in (int, float) or not math.isfinite(v) or v < 0
                for v in (world_seconds, delta_seconds)) or delta_seconds > 2):
        raise ValueError('Server-owned finite clocks and the native delta bound are required')
    profile.__post_init__()
    # Native normal reply echoes TC1, uses a connection clock delta, and converts
    # local World time to float32. No official validation result is fabricated.
    writer = BitWriter(maximum_bits=161)
    write_client_return_ping(writer, ClientReturnPingParams(params.tc1, delta_seconds, world_seconds),
                             profile=OrdinaryRPCScalarProfile(False, False))
    block = build_class_field_content((ClassFieldEnvelope(profile.reply_index,
        writer.to_bytes(), writer.bit_count),),
        profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
    content = BitWriter(maximum_bits=4096)
    write_actor_content_blocks(content, (block,))
    return WireBunch(channel_index, content.to_bytes(), content.bit_count)
