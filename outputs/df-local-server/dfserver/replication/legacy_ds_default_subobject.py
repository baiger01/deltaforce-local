"""Post-open update for a source-declared, constructor-created subobject.

The parent Actor set must be acknowledged before this followup is sent. Name /
Outer exports use the consumer-compatible flags3 subset, not a claim that the
original server emits the same export. Resolution and model loading still need
native verification. This does not replace the separately guarded live Fashion
observation / retained-session APIs.
"""
from dataclasses import dataclass
import re

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter, MAX_BITS, UINT32_MAX
from dfserver.replication.legacy_ds_actor_content import ResolvedStableSubobjectContentBlock, ResolvedStableSubobjectProfile, write_actor_content_blocks
from dfserver.replication.legacy_ds_even_component_guid_exports import EvenComponentBinding, EvenComponentExportNode, EvenComponentExportProfile, ExistingPawnOuterReference, write_even_component_guid_exports


@dataclass(frozen=True)
class DefaultSubobjectUpdate:
    actor_guid: int
    guid: int
    name: str
    source_sha256: str
    payload: bytes
    payload_bit_count: int
    has_rep_layout: bool = True

    def __post_init__(self):
        if (any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1
                for g in (self.actor_guid, self.guid)) or self.actor_guid == self.guid or
                type(self.name) is not str or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,255}', self.name) or
                type(self.source_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', self.source_sha256) or
                type(self.payload) is not bytes or type(self.payload_bit_count) is not int or
                not 1 <= self.payload_bit_count <= MAX_BITS or type(self.has_rep_layout) is not bool):
            raise ValueError('An exact bounded source-declared default subobject update is required')
        BitReader(self.payload, bit_count=self.payload_bit_count)


def write_default_subobject_followup(writer, update, actor_blocks, actor_guids):
    """Keep the single-component caller contract."""
    return write_default_subobjects_followup(writer, (update,), actor_blocks, actor_guids)


def write_default_subobjects_followup(writer, updates, actor_blocks, actor_guids):
    """Export bounded default Names/Outer, then Actor and component bodies.

    The source-producing caller qualifies the constructor name, type and native
    name-stability contract. These are expected receive conditions, not a claim
    of a live PackageMap observation. The transport separately owns the parent's
    reliable creation receipt and uses exactly these bytes on every retry.
    """
    exports, body = default_subobject_followup_parts(updates, actor_blocks, actor_guids)
    staged = BitWriter(maximum_bits=writer.maximum_bits)
    staged.write_payload(*exports)
    staged.write_payload(*body)
    writer.write_payload(staged.to_bytes(), staged.bit_count)


def default_subobject_followup_parts(updates, actor_blocks, actor_guids):
    """Return separate export and resolved-body regions for an ACKed export stage.

    These exact Name/Outer export bytes remain unfragmented. A caller sending
    the two regions separately must ACK the export bunch before sending body.
    The combined small-bunch writer above retains the original wire bytes.
    """
    if (type(updates) is not tuple or not 1 <= len(updates) <= 8 or
            any(type(update) is not DefaultSubobjectUpdate for update in updates)):
        raise ValueError('One to eight explicit source-declared default subobjects are required')
    parent = updates[0].actor_guid
    for update in updates:
        update.__post_init__()
    if (type(actor_guids) is not tuple or parent not in actor_guids or
            any(update.actor_guid != parent or update.guid in actor_guids for update in updates) or
            len({u.guid for u in updates}) != len(updates) or
            len({u.name for u in updates}) != len(updates)):
        raise ValueError('Default subobjects require distinct names and GUIDs under the same parent')
    def facts():
        return (tuple((u.actor_guid, u.guid, u.name, u.source_sha256,
            u.payload, u.payload_bit_count, u.has_rep_layout) for u in updates), actor_guids)

    original = facts()

    def source_owner_current():
        for update in updates:
            update.__post_init__()
        return original == facts()

    staged = BitWriter(maximum_bits=MAX_BITS)
    bindings = tuple(EvenComponentBinding(u.guid, u.name, parent) for u in updates)
    export_profile = EvenComponentExportProfile(parent, bindings,
        True, True, True, True, True, True, True, source_owner_current)
    write_even_component_guid_exports(staged, tuple(EvenComponentExportNode(u.guid,
        u.name, ExistingPawnOuterReference(parent)) for u in updates),
        enabled=True, profile=export_profile)
    exports = staged.to_bytes(), staged.bit_count
    staged = BitWriter(maximum_bits=MAX_BITS)
    content_profile = ResolvedStableSubobjectProfile(parent, actor_guids,
        tuple(u.guid for u in updates), 'normal_client', True, True, True)
    blocks = tuple(ResolvedStableSubobjectContentBlock(u.guid, u.has_rep_layout, u.payload,
        u.payload_bit_count) for u in updates)
    write_actor_content_blocks(staged, actor_blocks + blocks,
        allow_resolved_stable_subobjects=True, resolved_stable_subobject_profile=content_profile)
    if not source_owner_current():
        raise ValueError('Default subobject source or parent changed during preparation')
    return exports, (staged.to_bytes(), staged.bit_count)
