"""Source-qualified historical/default and current/explicit view-target RPCs.

ClientSetViewTarget declares Actor A followed by ViewTargetTransitionParams.
The native RPC reader initializes the struct before consuming its presence bit;
its same-build C++ constructor writes BlendTime=0, BlendFunction=1, BlendExp=2
and bLockOutgoing=false. The historical subset omits TransitionParams. The
current subset requires explicit transition values and the current three-bit
enum. Neither dispatches a camera method or proves possession or playability.
"""

from dataclasses import dataclass
import math
import struct

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
MAX_PARAMETER_BITS = 42
MAX_BUNCH_BITS = 512


def _actor_guid(value):
    if type(value) is not int or not 2 <= value <= UINT32_MAX or value & 1:
        raise ValueError('An explicit normal dynamic Actor GUID is required')
    return value


@dataclass(frozen=True)
class PCViewTargetProfile:
    class_path: str
    exclusive_index_maximum: int
    view_target_index: int
    verify_index: int
    client_function_flags: int
    server_function_flags: int
    source_sha256: str
    object_binding: NativeScalarBinding
    current_qualification: object = None
    current_transition: object = None

    def __post_init__(self):
        current = self.current_qualification is not None
        if current:
            require_current_profile(self.current_qualification, class_path=self.class_path,
                exclusive_index_maximum=self.exclusive_index_maximum, source_sha256=self.source_sha256)
            if self.current_transition is not None:
                if type(self.current_transition) is not PCViewTargetTransition:
                    raise ValueError('An explicit typed current view transition is required')
                self.current_transition.__post_init__()
        elif self.source_sha256 == CURRENT_RPC_SOURCE_SHA256:
            raise ValueError('The current PC report requires explicit current qualification')
        elif self.current_transition is not None:
            raise ValueError('Current transitions cannot be attached to a historical RPC profile')
        expected = ((self.exclusive_index_maximum, 244 if current else 245), (self.view_target_index, 53),
                    (self.verify_index, 85), (self.client_function_flags, CLIENT_FUNCTION_FLAGS),
                    (self.server_function_flags, SERVER_FUNCTION_FLAGS))
        if (self.class_path != CLASS_PATH or
                any(type(value) is not int or value != fixed for value, fixed in expected) or
                type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in self.source_sha256)):
            raise ValueError('The exact source-qualified PC view-target profile is required')
        binding = self.object_binding
        if current:
            require_current_object_binding(binding)
        elif (type(binding) is not NativeScalarBinding or binding.client_sha256 != SHIPPING_SHA256 or
                type(binding.serializer_target_rva) is not int or
                binding.serializer_target_rva != OBJECT_SERIALIZER_RVA or
                type(binding.property_vtable_rva) is not int or
                binding.property_vtable_rva != OBJECT_PROPERTY_VTABLE_RVA or
                binding.scalar_leaf_target_rva is not None):
            raise ValueError('The recovered Actor object-property serializer is required')


def _profile(profile):
    if type(profile) is not PCViewTargetProfile:
        raise ValueError('A qualified PC view-target profile is required')
    profile.__post_init__()


def encode_default_view_target_parameters(*, actor_guid, profile, reference_resolved,
                                          exports_acknowledged):
    _profile(profile)
    if profile.current_qualification is not None:
        raise ValueError('Current view-target RPC requires explicit transition values')
    _actor_guid(actor_guid)
    writer = BitWriter(maximum_bits=MAX_PARAMETER_BITS)
    writer.write_bool(True)
    write_resolved_object_reference(writer, actor_guid, binding=profile.object_binding,
        export_mode=False, reference_resolved=reference_resolved,
        exports_acknowledged=exports_acknowledged)
    # Both field classes lack the bool bit17 bypass. The struct's native
    # initialization has already run when RPC reader12db96e1 skips its commands.
    writer.write_bool(False)
    return writer.to_bytes(), writer.bit_count


@dataclass(frozen=True)
class PCViewTargetTransition:
    blend_time: float
    blend_function: int
    blend_exp: float
    lock_outgoing: bool

    def __post_init__(self):
        try:
            finite = all(type(v) in (int, float) and math.isfinite(v)
                         for v in (self.blend_time, self.blend_exp))
        except OverflowError:
            finite = False
        if (not finite or
                type(self.blend_function) is not int or not 0 <= self.blend_function <= 4 or
                type(self.lock_outgoing) is not bool):
            raise ValueError('Explicit finite transition values and a nonsentinel current enum are required')


def encode_view_target_parameters(*, actor_guid, profile, transition, reference_resolved,
                                  exports_acknowledged):
    """Encode a present current transition, without assuming C++ initializer defaults."""
    _profile(profile)
    _actor_guid(actor_guid)
    if profile.current_qualification is None or type(transition) is not PCViewTargetTransition:
        raise ValueError('A current RPC profile and explicit transition record are required')
    transition.__post_init__()
    try:
        scalars = (struct.pack('<f', transition.blend_time), struct.pack('<f', transition.blend_exp))
    except (OverflowError, struct.error) as error:
        raise ValueError('Transition scalar exceeds its float32 representation') from error
    writer = BitWriter(maximum_bits=110)
    writer.write_bool(True)
    write_current_object_reference(writer, actor_guid, qualification=profile.current_qualification,
        binding=profile.object_binding, reference_resolved=reference_resolved,
        exports_acknowledged=exports_acknowledged)
    writer.write_bool(True)
    writer.write_payload(scalars[0], 32)
    writer.write_bits(transition.blend_function, 3)
    writer.write_payload(scalars[1], 32)
    writer.write_bool(transition.lock_outgoing)
    return writer.to_bytes(), writer.bit_count


def decode_default_view_target_parameters(payload, payload_bits, *, expected_actor_guid=None):
    if (type(payload_bits) is not int or not 10 <= payload_bits <= MAX_PARAMETER_BITS or
            not isinstance(payload, bytes) or len(payload) != (payload_bits + 7) // 8 or
            int.from_bytes(payload, 'little') >> payload_bits):
        raise ValueError('An exact bounded default-transition parameter slice is required')
    if expected_actor_guid is not None:
        _actor_guid(expected_actor_guid)
    reader = BitReader(payload, bit_count=payload_bits)
    if not reader.read_bool():
        raise ValueError('This view-target subset requires a present Actor')
    guid = _actor_guid(reader.read_packed_int())
    if reader.read_bool():
        raise ValueError('An explicit transition body is outside this qualified subset')
    if reader.remaining:
        raise ValueError('View-target parameters must end at exact EOF')
    if expected_actor_guid is not None and expected_actor_guid != guid:
        raise ValueError('View-target parameters name another Actor')
    return guid


def build_pc_view_target(*, channel_index, channel_sequence, profile, actor_guid,
                         reference_resolved, exports_acknowledged, transition=None):
    _profile(profile)
    if (type(channel_index) is not int or not 2 <= channel_index <= 65535 or
            type(channel_sequence) is not int or not 0 <= channel_sequence < 1024):
        raise ValueError('An explicit PC channel and reliable sequence are required')
    if profile.current_qualification is not None:
        payload, bits = encode_view_target_parameters(actor_guid=actor_guid, profile=profile,
            transition=profile.current_transition if transition is None else transition,
            reference_resolved=reference_resolved,
            exports_acknowledged=exports_acknowledged)
    else:
        if transition is not None:
            raise ValueError('Explicit transition values require the current source-qualified profile')
        payload, bits = encode_default_view_target_parameters(actor_guid=actor_guid, profile=profile,
            reference_resolved=reference_resolved, exports_acknowledged=exports_acknowledged)
    block = build_class_field_content((ClassFieldEnvelope(profile.view_target_index, payload, bits),),
        profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
    writer = BitWriter(maximum_bits=MAX_BUNCH_BITS)
    write_actor_content_blocks(writer, (block,))
    return WireBunch(channel_index, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=channel_sequence, channel_name=ChannelName(hardcoded_index=102))


def decode_pc_verify_view_target_bunch(bunch, *, channel_index, profile):
    """Accept only a complete ordinary one-field ServerVerifyViewTarget request.

    This RPC has no parameters. It is a request, not a view-target acknowledgement.
    The caller must isolate and validate a known field from a mixed bunch before
    supplying it here; passing a mixed whole bunch is rejected atomically.
    """
    _profile(profile)
    if (type(channel_index) is not int or not 2 <= channel_index <= 65535 or
            type(bunch) is not WireBunch or type(bunch.channel_index) is not int or
            bunch.channel_index != channel_index or bunch.reliable is not True or
            type(bunch.channel_sequence) is not int or not 0 <= bunch.channel_sequence < 1024 or
            type(bunch.close_reason) is not int or bunch.close_reason != 0 or
            type(bunch.channel_name) is not ChannelName or
            type(bunch.channel_name.hardcoded_index) is not int or
            bunch.channel_name.hardcoded_index != 102 or bunch.channel_name.text is not None or
            type(bunch.channel_name.number) is not int or bunch.channel_name.number != 0 or
            any(getattr(bunch, flag) is not False for flag in (
                'open', 'close', 'flag4', 'connection_flag', 'package_exports', 'must_be_mapped',
                'partial', 'partial_initial', 'partial_final')) or
            type(bunch.payload_bits) is not int or not 1 <= bunch.payload_bits <= MAX_BUNCH_BITS or
            not isinstance(bunch.payload, bytes) or
            len(bunch.payload) != (bunch.payload_bits + 7) // 8 or
            int.from_bytes(bunch.payload, 'little') >> bunch.payload_bits):
        raise ValueError('A complete ordinary reliable PC verification request is required')
    blocks = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
    if len(blocks) != 1 or blocks[0].has_rep_layout is not False:
        raise ValueError('View-target verification requires one ordinary Actor block')
    fields = read_class_fields(BitReader(blocks[0].payload, bit_count=blocks[0].payload_bit_count),
        profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
    if (len(fields) != 1 or fields[0].rep_index != profile.verify_index or
            fields[0].payload_bit_count != 0 or fields[0].payload != b''):
        raise ValueError('The whole request must contain only the empty qualified verification RPC')
    return None
