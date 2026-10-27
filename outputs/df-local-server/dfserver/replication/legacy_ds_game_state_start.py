"""One qualified GameState BeginPlay property on an existing Actor channel.

The owner-side source qualifier supplies the actual handle; no client mappings
are selected here. This requests native StartPlay notification, not possession,
all-player readiness, physics, AI, or a playable-world assertion.

The distinct current profile requires all six source-bound fields and uses the
ordinary non-byte-swapped scalar subset. Historical scalar guards stay intact.
"""
from dataclasses import dataclass
from collections.abc import Mapping

from dfserver.replication.legacy_ds_actor_content import ActorContentBlock, write_actor_content_blocks
from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_scalar_serializers import NativeScalarBinding, write_bool_value, BOOL_SERIALIZER_RVA
from dfserver.replication.legacy_ds_scalar_serializers import write_uint64_value, INT32_SERIALIZER_RVA, UINT64_SCALAR_LEAF_RVA, UINT64_PROPERTY_VTABLE_RVA
from dfserver.transport.native.legacy_ds_wire_codec import WireBunch, ChannelName


_CURRENT_CLIENT_SHA256 = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
_CURRENT_SOURCE_SHA256 = '64e5979c79b0876f62c6e03a9ad0407a88aaff3d7b9b81ed9961c920e4c2399a'
_CURRENT_CLASS_PATH = '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C'
_CURRENT_FIELDS = (
    ('begin_play_handle', 'bReplicatedHasBegunPlay', 19, 'FBoolProperty', 21),
    ('all_ready_handle', 'bStartMathWithAllPlayerReady', 24, 'FBoolProperty', 21),
    ('map_id_handle', 'MapId', 52, 'FUInt64Property', 20),
    ('room_id_handle', 'RoomId', 53, 'FUInt64Property', 20),
    ('abseil_handle', 'bCanSwitchToAbseil', 107, 'FBoolProperty', 21),
    ('real_start_handle', 'bMatchRealStart', 108, 'FBoolProperty', 21),
)


def current_actor_field(qualification, role, name):
    # Historical callers do not activate the separate current source contract.
    from dfserver.replication.legacy_ds_current_actor_profile import current_actor_field as field
    return field(qualification, role, name)


def _current_profile(profile):
    from dfserver.replication.legacy_ds_current_actor_profile import (
        CURRENT_CLIENT_SHA256, CURRENT_ACTOR_PROFILE_SHA256, require_current_actor_qualification)
    qualification = require_current_actor_qualification(profile.current_qualification)
    if (CURRENT_CLIENT_SHA256 != _CURRENT_CLIENT_SHA256 or CURRENT_ACTOR_PROFILE_SHA256 != _CURRENT_SOURCE_SHA256 or
            profile.client_sha256 != qualification.client_sha256 or profile.client_sha256 != CURRENT_CLIENT_SHA256 or
            profile.source_sha256 != qualification.source_sha256 or profile.source_sha256 != CURRENT_ACTOR_PROFILE_SHA256 or
            profile.class_path != _CURRENT_CLASS_PATH):
        raise ValueError('Current and historical GameState source identities cannot be mixed')
    for attribute, name, handle, family, opcode in _CURRENT_FIELDS:
        if type(getattr(profile, attribute)) is not int or getattr(profile, attribute) != handle:
            raise ValueError('All six exact current GameState handles are required')
        row = current_actor_field(qualification, 'GameState', name)
        if not isinstance(row, Mapping):
            raise ValueError('A complete current GameState property binding is required')
        try:
            binding = row['property_method_binding']
            methods = {method['slot']: method['target_rva'] for method in binding['methods']}
            numeric = family == 'FUInt64Property'
            if (row['receiver_class'] != 'BP_GameState_PVPVE_C' or row['field'] != name or
                    type(row['relative_handle']) is not int or row['relative_handle'] != handle or
                    row['family'] != family or type(row['dispatch_opcode']) is not int or row['dispatch_opcode'] != opcode or
                    binding['concrete_vtable_rva'] != ('0x1ab60a40' if numeric else '0x15a867b0') or
                    methods['0x90'] != ('0x10e5c7c0' if numeric else '0x10e8e580') or
                    numeric and methods['0x88'] != '0x286bcc0'):
                raise ValueError('Current GameState property family/table/serializer binding disagrees')
        except (KeyError, TypeError) as error:
            raise ValueError('A complete current GameState property binding is required') from error


@dataclass(frozen=True)
class GameStateStartProfile:
    class_path: str
    begin_play_handle: int
    client_sha256: str
    source_sha256: str
    all_ready_handle: int | None = None
    abseil_handle: int | None = None
    map_id_handle: int | None = None
    room_id_handle: int | None = None
    real_start_handle: int | None = None
    current_qualification: object = None

    def __post_init__(self):
        if (type(self.class_path) is not str or not self.class_path.startswith('/Game/') or
                type(self.begin_play_handle) is not int or not 1 <= self.begin_play_handle <= 65535 or
                any(type(v) is not str or len(v) != 64 or any(c not in '0123456789abcdef' for c in v)
                    for v in (self.client_sha256, self.source_sha256)) or
                self.all_ready_handle is not None and (type(self.all_ready_handle) is not int or
                    not self.begin_play_handle < self.all_ready_handle <= 65535) or
                self.abseil_handle is not None and (self.all_ready_handle is None or
                    type(self.abseil_handle) is not int or not self.all_ready_handle < self.abseil_handle <= 65535)):
            raise ValueError('An explicit qualified GameState BeginPlay profile is required')
        if (self.map_id_handle is None) != (self.room_id_handle is None) or (
                self.map_id_handle is not None and (type(self.map_id_handle) is not int or
                type(self.room_id_handle) is not int or not 1 <= self.map_id_handle < self.room_id_handle <= 65535)):
            raise ValueError('MatchInfo requires both separately qualified identity fields')
        if self.real_start_handle is not None and (
                self.abseil_handle is None or type(self.real_start_handle) is not int or
                not self.abseil_handle < self.real_start_handle <= 65535):
            raise ValueError('Real match start requires its own qualified post-entry field')
        if self.current_qualification is not None:
            _current_profile(self)
        elif self.client_sha256 == _CURRENT_CLIENT_SHA256 or self.source_sha256 == _CURRENT_SOURCE_SHA256:
            raise ValueError('The current GameState build requires explicit current source qualification')


def build_game_state_start(*, channel_index, channel_sequence, profile):
    if type(profile) is not GameStateStartProfile:
        raise ValueError('A qualified GameState BeginPlay profile is required')
    return _build_boolean(channel_index, channel_sequence, profile, profile.begin_play_handle)


def build_game_state_all_ready(*, channel_index, channel_sequence, profile):
    if type(profile) is not GameStateStartProfile or profile.all_ready_handle is None:
        raise ValueError('An explicit source-qualified all-player-ready field is required')
    return _build_boolean(channel_index, channel_sequence, profile, profile.all_ready_handle)


def build_game_state_abseil(*, channel_index, channel_sequence, profile):
    if type(profile) is not GameStateStartProfile or profile.abseil_handle is None:
        raise ValueError('An explicit source-qualified entry-permission field is required')
    return _build_boolean(channel_index, channel_sequence, profile, profile.abseil_handle)


def build_game_state_real_start(*, channel_index, channel_sequence, profile):
    if type(profile) is not GameStateStartProfile or profile.real_start_handle is None:
        raise ValueError('An explicit source-qualified real match start field is required')
    return _build_boolean(channel_index, channel_sequence, profile, profile.real_start_handle)


def _build_boolean(channel_index, channel_sequence, profile, handle):
    if type(profile) is not GameStateStartProfile:
        raise ValueError('A qualified GameState BeginPlay profile is required')
    profile.__post_init__()
    if (type(channel_index) is not int or not 2 <= channel_index <= 65535 or
            type(channel_sequence) is not int or not 0 <= channel_sequence < 1024):
        raise ValueError('An existing reliable Actor channel sequence is required')
    values = BitWriter(maximum_bits=96)
    values.write_bool(False)  # Ordinary property stream checksum option.
    values.write_packed_int(handle)
    if profile.current_qualification is not None:
        if handle not in (19, 24, 107, 108):
            raise ValueError('Only the four qualified current GameState boolean stages are supported')
        # Current Bool NetSerializeItem10e8e580 passes one bit to slot68.
        values.write_bool(True)
    else:
        write_bool_value(values, True, binding=NativeScalarBinding(profile.client_sha256, BOOL_SERIALIZER_RVA))
    values.write_packed_int(0)
    writer = BitWriter(maximum_bits=128)
    write_actor_content_blocks(writer, (ActorContentBlock(True, values.to_bytes(), values.bit_count),))
    return WireBunch(channel_index, writer.to_bytes(), writer.bit_count, reliable=True,
                     channel_sequence=channel_sequence, channel_name=ChannelName(hardcoded_index=102))


def build_game_state_match_info(*, channel_index, channel_sequence, profile, map_id, room_id):
    if type(profile) is not GameStateStartProfile or profile.map_id_handle is None:
        raise ValueError('Source-qualified MatchInfo identity handles are required')
    profile.__post_init__()
    if (type(channel_index) is not int or not 2 <= channel_index <= 65535 or
            type(channel_sequence) is not int or not 0 <= channel_sequence < 1024):
        raise ValueError('An existing reliable Actor channel sequence is required')
    binding = (None if profile.current_qualification is not None else
        NativeScalarBinding(profile.client_sha256, INT32_SERIALIZER_RVA,
                            UINT64_SCALAR_LEAF_RVA, UINT64_PROPERTY_VTABLE_RVA))
    values = BitWriter(maximum_bits=256)
    values.write_bool(False)
    for handle, value in ((profile.map_id_handle, map_id), (profile.room_id_handle, room_id)):
        values.write_packed_int(handle)
        if profile.current_qualification is not None:
            if type(value) is not int or not 0 <= value < 1 << 64:
                raise ValueError('An explicit unsigned64 current MatchInfo value is required')
            # Qualified leaf286bcc0 transfers eight bytes; its byte-swap branch
            # is outside this same explicit no-byteswap MatchInfo subset.
            values.write_bytes(value.to_bytes(8, 'little'))
        else:
            write_uint64_value(values, value, binding=binding, no_byteswap=True)
    values.write_packed_int(0)
    writer = BitWriter(maximum_bits=320)
    write_actor_content_blocks(writer, (ActorContentBlock(True, values.to_bytes(), values.bit_count),))
    return WireBunch(channel_index, writer.to_bytes(), writer.bit_count, reliable=True,
                     channel_sequence=channel_sequence, channel_name=ChannelName(hardcoded_index=102))
