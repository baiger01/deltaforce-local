"""Source-qualified ClientRestart and ServerAcknowledgePossession value bodies.

The same-build native declarations each contain one Pawn object parameter.
RPC parameters use one presence bit followed by a normal packed NetGUID,
without a property handle, RepLayout option bit, or terminal handle. Actor
content and ClassNetCache field envelopes remain separate existing codecs.

The caller owns resolution, completed mapping exports, admission, lifecycle
ordering and idempotence. Encoding or receiving this RPC is not possession,
input/camera initialization, scene readiness, or playable-map verification.
"""
from dataclasses import dataclass

from dfserver.replication.legacy_ds_actor_content import read_actor_content_blocks, write_actor_content_blocks
from dfserver.replication.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content, read_class_fields
from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.replication.legacy_ds_scalar_serializers import NativeScalarBinding, OBJECT_SERIALIZER_RVA, SHIPPING_SHA256, write_resolved_object_reference
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch
from dfserver.transport.native.legacy_ds_current_pc_rpc_profile import (
    CURRENT_RPC_SOURCE_SHA256, require_current_profile, require_current_object_binding,
    write_current_object_reference)


CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'
CLIENT_FUNCTION_FLAGS = 0x01020CC0
SERVER_FUNCTION_FLAGS = 0x80220CC0
OBJECT_PROPERTY_VTABLE_RVA = 0x15A86B80
MAX_PARAMETER_BITS = 41


def _pawn_guid(value):
    if type(value) is not int or not 2 <= value <= UINT32_MAX or value & 1:
        raise ValueError('An explicit normal dynamic Pawn GUID is required')
    return value


@dataclass(frozen=True)
class PCRestartProfile:
    class_path: str
    exclusive_index_maximum: int
    restart_index: int
    acknowledgement_index: int
    client_function_flags: int
    server_function_flags: int
    source_sha256: str
    object_binding: NativeScalarBinding
    current_qualification: object = None

    def __post_init__(self):
        current = self.current_qualification is not None
        if current:
            require_current_profile(self.current_qualification, class_path=self.class_path,
                exclusive_index_maximum=self.exclusive_index_maximum, source_sha256=self.source_sha256)
        elif self.source_sha256 == CURRENT_RPC_SOURCE_SHA256:
            raise ValueError('The current PC report requires explicit current qualification')
        integers = ((self.exclusive_index_maximum, 244 if current else 245), (self.restart_index, 42),
                    (self.acknowledgement_index, 67),
                    (self.client_function_flags, CLIENT_FUNCTION_FLAGS),
                    (self.server_function_flags, SERVER_FUNCTION_FLAGS))
        if (self.class_path != CLASS_PATH or
                any(type(value) is not int or value != expected for value, expected in integers) or
                type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in self.source_sha256)):
            raise ValueError('The exact source-qualified PC restart declaration is required')
        binding = self.object_binding
        if current:
            require_current_object_binding(binding)
        elif (type(binding) is not NativeScalarBinding or
                binding.client_sha256 != SHIPPING_SHA256 or
                type(binding.serializer_target_rva) is not int or
                binding.serializer_target_rva != OBJECT_SERIALIZER_RVA or
                type(binding.property_vtable_rva) is not int or
                binding.property_vtable_rva != OBJECT_PROPERTY_VTABLE_RVA or
                binding.scalar_leaf_target_rva is not None):
            raise ValueError('The declared Pawn object property serializer is required')


def _profile(profile):
    if type(profile) is not PCRestartProfile:
        raise ValueError('A qualified PC restart profile is required')
    profile.__post_init__()


def encode_pawn_parameter(*, pawn_guid, profile, reference_resolved, exports_acknowledged):
    """Return only the one-Pawn RPC parameter slice, given explicit contracts."""
    _profile(profile)
    _pawn_guid(pawn_guid)
    writer = BitWriter(maximum_bits=MAX_PARAMETER_BITS)
    # FObjectProperty class flags 0x04018001 do not set the bool bit17 bypass.
    # RPC reader12db9682..96e1 therefore consumes this parent presence bit.
    writer.write_bool(True)
    if profile.current_qualification is not None:
        write_current_object_reference(writer, pawn_guid, qualification=profile.current_qualification,
            binding=profile.object_binding, reference_resolved=reference_resolved,
            exports_acknowledged=exports_acknowledged)
    else:
        write_resolved_object_reference(writer, pawn_guid, binding=profile.object_binding,
            export_mode=False, reference_resolved=reference_resolved,
            exports_acknowledged=exports_acknowledged)
    return writer.to_bytes(), writer.bit_count


def decode_pawn_parameter(payload, payload_bits, *, expected_pawn_guid=None):
    """Accept one present dynamic Pawn reference with exact parameter EOF.

    Null/default/static references and an absent argument are outside this
    local possession-confirmation subset, although native RPCs can use null.
    """
    if type(payload_bits) is not int or not 1 <= payload_bits <= MAX_PARAMETER_BITS:
        raise ValueError('A bounded exact Pawn parameter slice is required')
    if expected_pawn_guid is not None:
        _pawn_guid(expected_pawn_guid)
    reader = BitReader(payload, bit_count=payload_bits)
    if not reader.read_bool():
        raise ValueError('Possession confirmation requires a present Pawn parameter')
    guid = _pawn_guid(reader.read_packed_int())
    if reader.remaining:
        raise ValueError('Pawn parameter body must end at exact EOF')
    if expected_pawn_guid is not None and guid != expected_pawn_guid:
        raise ValueError('Possession acknowledgement names another Pawn')
    return guid


def build_pc_restart(*, channel_index, channel_sequence, profile, pawn_guid,
                     reference_resolved, exports_acknowledged):
    """Build one reliable false-RepLayout ClientRestart on the supplied PC channel."""
    _profile(profile)
    if (type(channel_index) is not int or not 2 <= channel_index <= 65535 or
            type(channel_sequence) is not int or not 0 <= channel_sequence < 1024):
        raise ValueError('An explicit PC Actor channel and reliable sequence are required')
    payload, bits = encode_pawn_parameter(pawn_guid=pawn_guid, profile=profile,
        reference_resolved=reference_resolved, exports_acknowledged=exports_acknowledged)
    block = build_class_field_content((ClassFieldEnvelope(profile.restart_index, payload, bits),),
        profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
    writer = BitWriter(maximum_bits=512)
    write_actor_content_blocks(writer, (block,))
    return WireBunch(channel_index, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=channel_sequence, channel_name=ChannelName(hardcoded_index=102))


def decode_pc_possession_ack_bunch(bunch, *, channel_index, profile, expected_pawn_guid):
    """Accept only a whole one-field acknowledgement for the caller's bound Pawn."""
    _profile(profile)
    _pawn_guid(expected_pawn_guid)
    if (type(channel_index) is not int or not 2 <= channel_index <= 65535 or
            type(bunch) is not WireBunch or bunch.channel_index != channel_index or
            not bunch.reliable or bunch.channel_name != ChannelName(hardcoded_index=102) or
            type(bunch.channel_sequence) is not int or not 0 <= bunch.channel_sequence < 1024 or
            any((bunch.open, bunch.close, bunch.flag4, bunch.connection_flag,
                 bunch.package_exports, bunch.must_be_mapped, bunch.partial,
                 bunch.partial_initial, bunch.partial_final)) or
            type(bunch.payload_bits) is not int or not 1 <= bunch.payload_bits <= 512):
        raise ValueError('Only a complete reliable PC acknowledgement bunch is supported')
    blocks = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
    if len(blocks) != 1 or blocks[0].has_rep_layout is not False:
        raise ValueError('The whole acknowledgement must contain one ordinary RPC block')
    fields = read_class_fields(BitReader(blocks[0].payload,
        bit_count=blocks[0].payload_bit_count),
        profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
    if len(fields) != 1 or fields[0].rep_index != profile.acknowledgement_index:
        raise ValueError('The whole acknowledgement must contain only the qualified RPC')
    field = fields[0]
    return decode_pawn_parameter(field.payload, field.payload_bit_count,
        expected_pawn_guid=expected_pawn_guid)
