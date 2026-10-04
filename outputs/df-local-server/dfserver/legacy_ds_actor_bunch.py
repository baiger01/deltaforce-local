"""Compose GUID exports, an ordinary Actor-open header and explicit content.

UChannel::ReceivedRawBunch12868710 calls ReceiveNetGUIDBunch12bc5540 and,
on a successful ordinary in-order receive, continues to ReceivedNextBunch
with the same advanced cursor. Source: work/evidence/native-guid-export-
envelope.json. NAME_Actor=102 is independently recorded in
work/evidence/native-actor-channel-name-adjacent.json.

This module only constructs one unpartial reliable WireBunch. It allocates
no GUIDs, invents no paths/checksums, sends nothing and changes no connection
state. Optional Actor-selector content blocks carry opaque caller-supplied
replication bodies; no property/RPC field handle is invented. An export's
transport ACK is distinct from resolving a native object
or creating/possessing an Actor. The header's references_resolvable contract
remains a caller-declared local-profile precondition, not client acceptance.
"""

from .legacy_ds_actor_open import write_actor_open
from .legacy_ds_actor_content import (
    DEFAULT_LIMITS as DEFAULT_CONTENT_LIMITS, write_actor_content_blocks,
)
from .legacy_ds_bit_archive import BitWriter, UINT32_MAX
from .legacy_ds_guid_exports import DEFAULT_LIMITS, write_guid_exports
from .legacy_ds_wire_codec import ChannelName, WireBunch


def _exported_guids(exports):
    """Gather roots and recursive outers only after export validation succeeds."""
    result = set()
    for root in exports:
        node = root
        while node is not None:
            result.add(node.guid)
            node = node.outer
    return result


def build_actor_bunch(*, exports, actor_guid, archetype_guid, level_guid,
                      connection_network_version, archive_network_version,
                      references_resolvable, channel_index, channel_sequence,
                      max_packet_bytes, location, scale, velocity,
                      local_player_index=None, export_limits=DEFAULT_LIMITS,
                      force_unicode=False, content_blocks=(),
                      content_limits=DEFAULT_CONTENT_LIMITS,
                      game_replication_flags=None):
    """Return a pure Actor bunch with explicit GUIDs and connection profile.

    Archetype and, when serialized by this version, Level must occur in the
    supplied export graph, including its recursive outers. Membership does
    not verify that a path exists or resolves on the client. The dynamic
    Actor GUID must not occur anywhere in that graph. The delegated header
    validates version equality, Level rules, GUID kinds and vector inputs.
    Content follows that header and any explicitly selected base-PC index tail;
    ProcessBunch reaches ReadContentBlockPayload only after InitActor's
    OnActorChannelOpen returns. Derived PC additional headers remain unverified.

    max_packet_bytes bounds temporary payload storage using the explicit
    native byte range. It does NOT prove that a packet containing this bunch
    fits: encode_native_packet must still account for its packet/bunch headers
    and apply its own exclusive payload-length and total packet limits.
    """
    if type(channel_index) is not int or not 1 <= channel_index <= UINT32_MAX:
        raise ValueError('An explicit nonzero uint32 Actor channel index is required')
    if type(channel_sequence) is not int or not 0 <= channel_sequence < 1024:
        raise ValueError('An explicit ten-bit Actor channel sequence is required')
    if type(max_packet_bytes) is not int or not 1 <= max_packet_bytes <= 1492:
        raise ValueError('Invalid explicit native MaxPacket byte bound')

    staged = BitWriter(maximum_bits=max_packet_bytes * 8)
    write_guid_exports(staged, exports, limits=export_limits,
                       force_unicode=force_unicode)
    # The export writer has already checked type/depth/node bounds and rejects
    # cycles before this walk; no unvalidated graph traversal is performed.
    exported = _exported_guids(exports)
    write_actor_open(staged, actor_guid=actor_guid, archetype_guid=archetype_guid,
                     level_guid=level_guid,
                     connection_network_version=connection_network_version,
                     archive_network_version=archive_network_version,
                     references_resolvable=references_resolvable,
                     location=location, scale=scale, velocity=velocity,
                     local_player_index=local_player_index,
                     game_replication_flags=game_replication_flags)
    if actor_guid in exported:
        raise ValueError('The new dynamic Actor GUID conflicts with the export graph')
    if archetype_guid not in exported:
        raise ValueError('The archetype GUID is missing from the export graph')
    if level_guid is not None and level_guid not in exported:
        raise ValueError('The Level GUID is missing from the export graph')
    write_actor_content_blocks(staged, content_blocks, limits=content_limits)

    return WireBunch(channel_index=channel_index, payload=staged.to_bytes(),
                     payload_bits=staged.bit_count, open=True, reliable=True,
                     package_exports=True, channel_sequence=channel_sequence,
                     channel_name=ChannelName(hardcoded_index=102))
