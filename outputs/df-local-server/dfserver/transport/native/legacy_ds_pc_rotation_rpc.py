"""The qualified ClientSetRotation RPC, independent of socket/native execution.

FRotator's CppStructOps NetSerialize calls SerializeCompressedShorts in this
build. Unlike the struct parameter, bResetCamera has no RPC presence bit.
The caller supplies the actual spawn rotation and owns possession ordering.
"""
from dataclasses import dataclass

from dfserver.replication.legacy_ds_actor_content import write_actor_content_blocks
from dfserver.replication.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content
from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_rotator import CompressedRotator16, write_compressed_rotator16
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch
from dfserver.transport.native.legacy_ds_current_pc_rpc_profile import CURRENT_RPC_SOURCE_SHA256, require_current_profile

CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'


@dataclass(frozen=True)
class PCRotationProfile:
    class_path: str
    exclusive_index_maximum: int
    rotation_index: int
    client_function_flags: int
    source_sha256: str
    current_qualification: object = None

    def __post_init__(self):
        current = self.current_qualification is not None
        if current:
            require_current_profile(self.current_qualification, class_path=self.class_path,
                exclusive_index_maximum=self.exclusive_index_maximum, source_sha256=self.source_sha256)
        elif self.source_sha256 == CURRENT_RPC_SOURCE_SHA256:
            raise ValueError('The current PC report requires explicit current qualification')
        if (self.class_path != CLASS_PATH or
                any(type(v) is not int or v != expected for v, expected in (
                    (self.exclusive_index_maximum, 244 if current else 245), (self.rotation_index, 14),
                    (self.client_function_flags, 0x01820cc0))) or
                type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in self.source_sha256)):
            raise ValueError('The source-qualified ClientSetRotation declaration is required')


def encode_rotation_parameters(*, profile, rotation, reset_camera):
    if type(profile) is not PCRotationProfile or type(reset_camera) is not bool:
        raise ValueError('A typed rotation profile and explicit camera-reset boolean are required')
    profile.__post_init__()
    if type(rotation) is not CompressedRotator16:
        raise ValueError('An explicit source-qualified spawn rotation is required')
    writer = BitWriter(maximum_bits=53)
    writer.write_bool(True)
    write_compressed_rotator16(writer, rotation)
    writer.write_bool(reset_camera)
    return writer.to_bytes(), writer.bit_count


def build_pc_rotation(*, channel_index, channel_sequence, profile, rotation, reset_camera):
    if (type(channel_index) is not int or not 2 <= channel_index <= 65535 or
            type(channel_sequence) is not int or not 0 <= channel_sequence < 1024):
        raise ValueError('An explicit PC Actor channel and reliable sequence are required')
    payload, bits = encode_rotation_parameters(profile=profile, rotation=rotation, reset_camera=reset_camera)
    block = build_class_field_content((ClassFieldEnvelope(profile.rotation_index, payload, bits),),
        profile=NormalClassFieldProfile(profile.exclusive_index_maximum, False))
    writer = BitWriter(maximum_bits=512)
    write_actor_content_blocks(writer, (block,))
    return WireBunch(channel_index, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=channel_sequence, channel_name=ChannelName(hardcoded_index=102))
