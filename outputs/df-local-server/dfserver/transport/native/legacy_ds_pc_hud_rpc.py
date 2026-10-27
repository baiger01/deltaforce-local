"""Source-qualified ClientSetHUD using the cooked SOL GameMode's HUD class."""
from dataclasses import dataclass

from dfserver.replication.legacy_ds_actor_content import write_actor_content_blocks
from dfserver.replication.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content
from dfserver.transport.native.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.replication.legacy_ds_scalar_serializers import NativeScalarBinding, SHIPPING_SHA256, write_resolved_object_reference
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch

CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'
HUD_CLASS_PATH = '/Game/BluePrints/UIServer/BP_DFMHUD.BP_DFMHUD_C'


@dataclass(frozen=True)
class PCHUDProfile:
    class_path: str
    exclusive_index_maximum: int
    hud_index: int
    client_function_flags: int
    hud_class_path: str
    source_sha256: str
    object_binding: NativeScalarBinding

    def __post_init__(self):
        binding = self.object_binding
        if (self.class_path != CLASS_PATH or self.hud_class_path != HUD_CLASS_PATH or
                any(type(v) is not int or v != expected for v, expected in (
                    (self.exclusive_index_maximum, 245), (self.hud_index, 51),
                    (self.client_function_flags, 0x05020cc0))) or
                type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in self.source_sha256) or
                type(binding) is not NativeScalarBinding or
                binding != NativeScalarBinding(SHIPPING_SHA256, 0x10e8ed20, None, 0x1ab61800)):
            raise ValueError('The cooked SOL HUD and qualified FClassProperty declaration are required')


def build_pc_hud(*, channel_index, channel_sequence, profile, class_guid,
                 reference_resolved, exports_acknowledged):
    if (type(profile) is not PCHUDProfile or
            type(class_guid) is not int or not 3 <= class_guid <= UINT32_MAX or not class_guid & 1 or
            type(channel_index) is not int or not 2 <= channel_index <= 65535 or
            type(channel_sequence) is not int or not 0 <= channel_sequence < 1024):
        raise ValueError('An explicit static HUD class GUID and reliable PC channel are required')
    profile.__post_init__()
    value = BitWriter(maximum_bits=41)
    # FClassProperty flags 0x04018401 do not bypass the RPC presence bit.
    value.write_bool(True)
    write_resolved_object_reference(value, class_guid, binding=profile.object_binding,
        export_mode=False, reference_resolved=reference_resolved,
        exports_acknowledged=exports_acknowledged)
    block = build_class_field_content((ClassFieldEnvelope(profile.hud_index,
        value.to_bytes(), value.bit_count),), profile=NormalClassFieldProfile(245, False))
    writer = BitWriter(maximum_bits=512)
    # 12bbc520 adds the referenced loadable class to MustBeMappedGuids;
    # 1286612a/1286626e consume uint16 count + packed GUIDs before ActorContent.
    # The cache resolves the class's package Outer recursively. Export ACK alone
    # does not retain the loaded UClass or delay an RPC during an async reload.
    writer.write_bits(1, 16)
    writer.write_packed_int(class_guid)
    write_actor_content_blocks(writer, (block,))
    return WireBunch(channel_index, writer.to_bytes(), writer.bit_count, reliable=True,
        must_be_mapped=True, channel_sequence=channel_sequence,
        channel_name=ChannelName(hardcoded_index=102))
