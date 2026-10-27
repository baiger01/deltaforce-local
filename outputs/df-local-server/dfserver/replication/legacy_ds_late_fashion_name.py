"""One captured-default-name diagnostic candidate, never a gameplay mapping.

The owner prepares this block through the sealed work-side factory first. This
transport profile checks its exact isolated content and evidence scope without
reading files, accessing a process, or claiming the actual PackageMap grammar.
"""
from dataclasses import dataclass, field

from dfserver.replication.legacy_ds_actor_content import ActorContentBlock
from dfserver.replication.legacy_ds_actor_content import write_actor_content_blocks
from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch
from dfserver.replication.legacy_ds_fname_string import NativeFNameStringDiagnosticBinding, build_diagnostic_fname_content, SHIPPING_SHA256, FNAME_TABLE_RVA, FNAME_LEAF_RVA, GENERIC_SERIALIZER_RVA, SPEC_SHA256

PAWN_CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C'
SUMMARY_SHA256 = '5f8bc953f6cbe1ed1ee86534cf255a5d989208104d6d3d475661b32037d1c856'
SNAPSHOT_SHA256 = 'e5e68e3c7223548855992d0eae26e3b99b2aab896f9f3a5003016dd33deead6c'


@dataclass(frozen=True)
class LateFashionNameDiagnostic:
    content_block: ActorContentBlock = field(repr=False)
    source_summary_sha256: str
    source_snapshot_sha256: str
    source_spec_sha256: str

    def __post_init__(self):
        if (type(self.content_block) is not ActorContentBlock or
                self.content_block.has_rep_layout is not True or
                type(self.content_block.payload) is not bytes or
                type(self.content_block.payload_bit_count) is not int or
                self.source_summary_sha256 != SUMMARY_SHA256 or
                self.source_snapshot_sha256 != SNAPSHOT_SHA256 or
                self.source_spec_sha256 != SPEC_SHA256):
            raise ValueError('Exact captured diagnostic Fashion name evidence required')
        binding = NativeFNameStringDiagnosticBinding(SHIPPING_SHA256, FNAME_TABLE_RVA,
            FNAME_LEAF_RVA, GENERIC_SERIALIZER_RVA, SPEC_SHA256)
        expected = build_diagnostic_fname_content(handle=149, text='1000145', number=0,
            binding=binding, diagnostic_probe=True)
        if self.content_block != expected or self.content_block.payload_bit_count != 154:
            raise ValueError('Only the isolated captured default Fashion name block is allowed')


def build_late_fashion_name_bunch(diagnostic, channel, sequence, maximum_bits):
    if type(diagnostic) is not LateFashionNameDiagnostic:
        raise ValueError('A qualified isolated Fashion diagnostic is required')
    diagnostic.__post_init__()
    writer = BitWriter(maximum_bits=maximum_bits)
    write_actor_content_blocks(writer, (diagnostic.content_block,))
    return WireBunch(channel, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=sequence, channel_name=ChannelName(hardcoded_index=102))
