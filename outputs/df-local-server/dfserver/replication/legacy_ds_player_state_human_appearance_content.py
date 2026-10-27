"""Fixed three-field ordinary PlayerState content, never a packet or publisher.

Handles/types must come from the separately sealed complete BP_SOLPlayerState
metadata profile. Values are explicit caller inputs, with no Hero/Avatar mapping.
This only implements option=false and the declared no-byteswap archive subset.
"""
from dfserver.replication.legacy_ds_actor_content import ActorContentBlock
from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_int64_value import write_int64_value
from dfserver.replication.legacy_ds_scalar_serializers import NativeScalarBinding, SHIPPING_SHA256, write_uint64_value

HANDLES = (140, 142, 143)
PROPERTY_TABLES = (0x15a86560, 0x1ab60db0, 0x1ab60db0)
PAYLOAD_BITS = 249


def build_player_state_human_appearance_content(*, hero_id, same_team_avatar_id,
        diff_team_avatar_id, bindings, no_byteswap, normal_actor_receive_contract):
    """Build only an isolated hasRepLayout ActorContentBlock with all three IDs."""
    if normal_actor_receive_contract is not True or no_byteswap is not True:
        raise ValueError('Explicit normal receiver and no-byteswap archive contracts are required')
    if type(bindings) is not tuple or len(bindings) != 3:
        raise ValueError('Exactly three explicit typed scalar bindings are required')
    for binding, table in zip(bindings, PROPERTY_TABLES):
        if (type(binding) is not NativeScalarBinding or binding.client_sha256 != SHIPPING_SHA256
                or type(binding.serializer_target_rva) is not int or binding.serializer_target_rva != 0x10e5ce20
                or type(binding.scalar_leaf_target_rva) is not int or binding.scalar_leaf_target_rva != 0x286c000
                or type(binding.property_vtable_rva) is not int or binding.property_vtable_rva != table):
            raise ValueError('Exact observed signed64/unsigned64 descriptor tables and hooks are required')
    values = (hero_id, same_team_avatar_id, diff_team_avatar_id)
    if (type(hero_id) is not int or not -(1 << 63) <= hero_id < (1 << 63)
            or any(type(value) is not int or not 0 <= value < (1 << 64) for value in values[1:])):
        raise ValueError('Explicit signed64 HeroID and unsigned64 AvatarIds are required')
    writer = BitWriter(maximum_bits=PAYLOAD_BITS)
    writer.write_bool(False)
    for index, (handle, value, binding) in enumerate(zip(HANDLES, values, bindings)):
        writer.write_packed_int(handle)
        encode = write_int64_value if index == 0 else write_uint64_value
        encode(writer, value, binding=binding, no_byteswap=True)
    writer.write_packed_int(0)
    if writer.bit_count != PAYLOAD_BITS:
        raise ValueError('Fixed PlayerState content bit bound changed')
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)
