"""Isolated, opt-in preflight of qualified existing-Actor RPC envelopes.

This module never sends an ACK, dispatches an RPC, creates an Actor, or changes
admission/packet-notify state. The caller must bind each profile to the current
connection's actual Actor and ClassNetCache, and independently recover function
flags, access policy, and the RPC-specific parameter schema. A name or a cache
representation byte alone is insufficient. There are no built-in game fields.

Source framing: native-actor-content-block-envelope.json and
map-entry-next-20261005/pc-inbound-field-and-rpc-decode-requirements.json.
Native channel seeds: native-cookie-sequence-initialization-semantics.json.
Retry-window and fail-closed restrictions are bounded local policy. Decoder
callbacks must be pure; only the returned decoded values may be dispatched
after the caller atomically accepts the whole packet and its other channels.
"""

from dataclasses import dataclass, field
import hashlib
import re

from dfserver.replication.legacy_ds_actor_content import read_actor_content_blocks
from dfserver.replication.legacy_ds_actor_fields import NormalClassFieldProfile, read_class_field_content
from dfserver.transport.native.legacy_ds_bit_archive import BitReader
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch, WirePacket, encode_observed_application


CHANNEL_MASK = 1023
MAX_CHANNELS = 16
MAX_PACKET_FIELDS = 256
MAX_RETRY_WINDOW = 128  # Strictly smaller than half of the ten-bit ring.
ACTOR_NAME = ChannelName(hardcoded_index=102)


def _uint(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Invalid explicit ' + label)


def _sha(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('A pinned source SHA256 is required')


def _class_path(value):
    if (type(value) is not str or not 1 <= len(value) <= 512 or
            not value.startswith(('/Game/', '/Script/')) or '.' not in value or
            any(char in value for char in '\0\r\n?')):
        raise ValueError('An explicit qualified class path is required')


@dataclass(frozen=True)
class NativeRPCFieldProfile:
    rep_index: int
    name: str
    receiver_class_path: str
    descriptor_representation: int
    incompatible: bool
    function_flags: int
    driver_role_predicate: bool
    access_allowed: bool
    wire_reliable: bool
    function_source_sha256: str
    permission_source_sha256: str
    parameter_schema_source_sha256: str
    decoder: object = field(repr=False, compare=False)

    def __post_init__(self):
        _uint(self.rep_index, 0, 16383, 'RPC RepIndex')
        _class_path(self.receiver_class_path)
        if (type(self.descriptor_representation) is not int or
                self.descriptor_representation != 1 or type(self.incompatible) is not bool or
                self.incompatible):
            raise ValueError('An explicit compatible native RPC descriptor is required')
        if (type(self.name) is not str or not 1 <= len(self.name) <= 256 or
                any(char in self.name for char in '\0\r\n')):
            raise ValueError('An explicit qualified RPC name is required')
        _uint(self.function_flags, 0, 0xffffffff, 'native UFunction flags')
        if (type(self.driver_role_predicate) is not bool or
                type(self.access_allowed) is not bool or not self.access_allowed or
                type(self.wire_reliable) is not bool):
            raise ValueError('An explicit allowed native RPC access profile is required')
        # Exact recovered masks, without assigning guessed role/flag enum names.
        mask = 0x200000 if self.driver_role_predicate else 0x1004000
        if not self.function_flags & 0x40 or not self.function_flags & mask:
            raise ValueError('Native function flags do not qualify this RPC direction')
        for pin in (self.function_source_sha256, self.permission_source_sha256,
                    self.parameter_schema_source_sha256):
            _sha(pin)
        if not callable(self.decoder):
            raise ValueError('A source-qualified pure parameter decoder is required')


@dataclass(frozen=True)
class ActorChannelReceiveProfile:
    channel_index: int
    actor_guid: int
    class_path: str
    class_cache_source_sha256: str
    exclusive_index_maximum: int
    fields: tuple

    def __post_init__(self):
        # Control0 and Voice1 are excluded; these are already-created Actors.
        _uint(self.channel_index, 2, 0xffffffff, 'existing Actor channel')
        _uint(self.actor_guid, 2, 0xfffffffe, 'dynamic Actor GUID')
        if self.actor_guid & 1:
            raise ValueError('An explicit dynamic Actor GUID is required')
        _class_path(self.class_path)
        _sha(self.class_cache_source_sha256)
        _uint(self.exclusive_index_maximum, 1, 16385, 'actual class-cache maximum')
        if type(self.fields) is not tuple or len(self.fields) > MAX_PACKET_FIELDS:
            raise ValueError('A bounded tuple of qualified RPC fields is required')
        indexes = set()
        for spec in self.fields:
            if type(spec) is not NativeRPCFieldProfile:
                raise ValueError('An explicit NativeRPCFieldProfile is required')
            NativeRPCFieldProfile.__post_init__(spec)
            if (spec.receiver_class_path != self.class_path or
                    spec.rep_index >= self.exclusive_index_maximum - 1 or
                    spec.rep_index in indexes):
                raise ValueError('RPC field disagrees with the actual Actor class-cache profile')
            indexes.add(spec.rep_index)


@dataclass(frozen=True)
class DecodedActorField:
    channel_index: int
    actor_guid: int
    class_path: str
    rep_index: int
    name: str
    payload_bit_count: int
    value: object = field(repr=False)


@dataclass(frozen=True)
class ActorPacketPreflight:
    receiver: object = field(repr=False)
    decoded_fields: tuple
    reliable_duplicates: int


class ActorInboundReceiver:
    """Connection-owned per-channel state, with no peer or packet ACK authority.

    initial_channel_sequence is the accepted Hello's initial channel sequence,
    not the control channel's later expected sequence or an arbitrary first RPC.
    preflight_packet returns a clone; the caller must commit it only together
    with the packet-notify/control/admission transaction. Mixed/unknown channels
    are rejected here and must be validated by that outer transaction.
    """

    def __init__(self, *, profiles, initial_channel_sequence, max_packet_bytes,
                 retry_window=MAX_RETRY_WINDOW):
        _uint(initial_channel_sequence, 0, CHANNEL_MASK, 'Hello channel sequence')
        _uint(max_packet_bytes, 1, 1492, 'native MaxPacket')
        _uint(retry_window, 1, MAX_RETRY_WINDOW, 'reliable retry window')
        if type(profiles) is not tuple or not 1 <= len(profiles) <= MAX_CHANNELS:
            raise ValueError('A bounded nonempty tuple of existing Actor profiles is required')
        self._profiles = {}
        guids = set()
        for profile in profiles:
            if type(profile) is not ActorChannelReceiveProfile:
                raise ValueError('An explicit ActorChannelReceiveProfile is required')
            ActorChannelReceiveProfile.__post_init__(profile)
            if profile.channel_index in self._profiles or profile.actor_guid in guids:
                raise ValueError('Existing Actor channels and GUIDs must be distinct')
            self._profiles[profile.channel_index] = profile
            guids.add(profile.actor_guid)
        self.max_packet_bytes = max_packet_bytes
        self.retry_window = retry_window
        self.initial_channel_sequence = initial_channel_sequence
        self._expected = {index: initial_channel_sequence for index in self._profiles}
        self._consumed = {index: {} for index in self._profiles}

    def clone(self):
        result = ActorInboundReceiver(profiles=tuple(self._profiles.values()),
            initial_channel_sequence=self.initial_channel_sequence,
            max_packet_bytes=self.max_packet_bytes, retry_window=self.retry_window)
        result._expected = dict(self._expected)
        result._consumed = {index: dict(history) for index, history in self._consumed.items()}
        return result

    def channel_state(self, channel_index):
        _uint(channel_index, 2, 0xffffffff, 'existing Actor channel')
        if channel_index not in self._profiles:
            raise ValueError('Unknown existing Actor channel')
        return {'expected_sequence': self._expected[channel_index],
                'remembered_reliable_sequences': tuple(self._consumed[channel_index])}

    @staticmethod
    def _existing_actor_bunch(bunch):
        if type(bunch) is not WireBunch or any(getattr(bunch, name) for name in (
                'open', 'close', 'flag4', 'connection_flag', 'package_exports',
                'must_be_mapped', 'partial', 'partial_initial', 'partial_final')):
            raise ValueError('Unsupported existing-Actor bunch profile')
        if (bunch.reliable and bunch.channel_name != ACTOR_NAME) or (
                not bunch.reliable and bunch.channel_name is not None):
            raise ValueError('An explicit existing Actor channel name is required')

    def preflight_packet(self, packet):
        """Validate all frames/sequences, then decode purely, returning staged state.

        Unknown subobjects/fields and RepLayout regions are rejected. A decoder
        must consume its exact field body without changing archive identity.
        Expected new sequence wins over retry digests when the ring wraps.
        """
        if type(packet) is not WirePacket or not packet.bunches:
            raise ValueError('A nonempty explicit Actor wire packet is required')
        # Revalidate dataclasses and reserve the complete packet, not just bodies.
        encode_observed_application(packet, max_packet_bytes=self.max_packet_bytes,
                                    received_by_server=True)
        staged = self.clone()
        pending, duplicates = [], 0
        for bunch in packet.bunches:
            self._existing_actor_bunch(bunch)
            profile = staged._profiles.get(bunch.channel_index)
            if profile is None:
                raise ValueError('Actor channel has no qualified current class profile')
            digest = hashlib.sha256(bunch.payload_bits.to_bytes(4, 'little') + bunch.payload).digest()
            history = staged._consumed[bunch.channel_index]
            if bunch.reliable and bunch.channel_sequence != staged._expected[bunch.channel_index]:
                if history.get(bunch.channel_sequence) != digest:
                    raise ValueError('Unexpected reliable Actor sequence or conflicting retry')
                duplicates += 1
                continue
            field_profiles = {spec.rep_index: spec for spec in profile.fields}
            blocks = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
            for block in blocks:
                envelopes = read_class_field_content(block, profile=NormalClassFieldProfile(
                    profile.exclusive_index_maximum, False))
                for envelope in envelopes:
                    spec = field_profiles.get(envelope.rep_index)
                    if spec is None:
                        raise ValueError('Actor field has no qualified native RPC schema')
                    if spec.wire_reliable != bunch.reliable:
                        raise ValueError('Actor field does not match its qualified reliability profile')
                    if len(pending) >= MAX_PACKET_FIELDS:
                        raise ValueError('Actor packet exceeds the local decoded-field limit')
                    pending.append((profile, spec, envelope))
            if bunch.reliable:
                history.pop(bunch.channel_sequence, None)
                history[bunch.channel_sequence] = digest
                while len(history) > staged.retry_window:
                    history.pop(next(iter(history)))
                staged._expected[bunch.channel_index] = (bunch.channel_sequence + 1) & CHANNEL_MASK
        decoded = []
        for profile, spec, envelope in pending:
            reader = BitReader(envelope.payload, bit_count=envelope.payload_bit_count)
            original_value = reader._value
            try:
                value = spec.decoder(reader)
            except Exception:
                raise ValueError('Qualified Actor parameter decoder failed') from None
            if (reader.bit_count != envelope.payload_bit_count or reader._value != original_value or
                    type(reader.position) is not int or reader.position != envelope.payload_bit_count):
                raise ValueError('Qualified Actor parameter decoder did not consume the exact body')
            decoded.append(DecodedActorField(profile.channel_index, profile.actor_guid,
                profile.class_path, spec.rep_index, spec.name, envelope.payload_bit_count, value))
        return ActorPacketPreflight(staged, tuple(decoded), duplicates)
