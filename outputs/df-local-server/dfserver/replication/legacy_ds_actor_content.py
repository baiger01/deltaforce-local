"""Restricted Actor and opt-in resolved stable subobject content blocks.

The pinned native evidence is work/evidence/native-actor-content-block-envelope.json.
Each block contains bHasRepLayout, the true Actor selector, packed uint32 bit
length and precisely that many payload bits. No byte alignment or terminal
block marker is inserted. The containing bunch's exact end bounds the sequence.

This module neither resolves an Actor nor creates property handles/RPCs. A true
selector refers to the channel's existing Actor. Local budgets and atomic failure
are deliberately stricter policies; encoding is not native acceptance.

The default remains Actor-only. An explicit caller-qualified normal-client
profile may opt into the already-resolved stable non-Actor subset: selector0,
ordinary packed object GUID, stably-named bit1, then the same length and body.
Source12863812/12863d89..12863e49 returns the resolved subobject without a
class reference;12864b0f/12864bc4 reads the packed bit length and exact payload.
No GUID is allocated/exported, class is created or wire object is resolved here.
The profile's resolved/non-Actor/stable-name declarations must be qualified by
the caller; GUID membership and codec roundtrips are not native proof.
"""

from dataclasses import dataclass

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter, MAX_BITS, UINT32_MAX


MAX_BLOCKS = 256


class UnsupportedActorContentProfile(ValueError):
    pass


@dataclass(frozen=True)
class ActorContentBlock:
    has_rep_layout: bool
    payload: bytes
    payload_bit_count: int


@dataclass(frozen=True)
class ResolvedStableSubobjectContentBlock:
    subobject_guid: int
    has_rep_layout: bool
    payload: bytes
    payload_bit_count: int


@dataclass(frozen=True)
class ResolvedStableSubobjectProfile:
    """Bounded caller declarations, not a native GUID dictionary or verifier."""
    channel_actor_guid: int
    known_actor_guids: tuple[int, ...]
    resolved_non_actor_guids: tuple[int, ...]
    receive_mode: str
    references_resolved: bool
    stable_names_qualified: bool
    non_actor_classes_qualified: bool

    def __post_init__(self):
        if (type(self.channel_actor_guid) is not int or
                not 2 <= self.channel_actor_guid <= UINT32_MAX or
                type(self.known_actor_guids) is not tuple or
                not 1 <= len(self.known_actor_guids) <= 64 or
                any(type(guid) is not int or not 2 <= guid <= UINT32_MAX
                    for guid in self.known_actor_guids) or
                len(set(self.known_actor_guids)) != len(self.known_actor_guids) or
                self.channel_actor_guid not in self.known_actor_guids or
                type(self.resolved_non_actor_guids) is not tuple or
                not 1 <= len(self.resolved_non_actor_guids) <= 32 or
                any(type(guid) is not int or not 2 <= guid <= UINT32_MAX or
                    guid in self.known_actor_guids for guid in self.resolved_non_actor_guids) or
                len(set(self.resolved_non_actor_guids)) != len(self.resolved_non_actor_guids)):
            raise UnsupportedActorContentProfile('Explicit distinct resolved non-Actor references are required')
        if (type(self.receive_mode) is not str or self.receive_mode != 'normal_client' or
                self.references_resolved is not True or self.stable_names_qualified is not True or
                self.non_actor_classes_qualified is not True):
            raise UnsupportedActorContentProfile('Only caller-qualified resolved stable normal-client subobjects are supported')


@dataclass(frozen=True)
class ActorContentLimits:
    max_blocks: int = MAX_BLOCKS
    max_payload_bits: int = MAX_BITS
    max_total_bits: int = MAX_BITS

    def __post_init__(self):
        for value, minimum, maximum, label in (
            (self.max_blocks, 0, MAX_BLOCKS, 'block count'),
            (self.max_payload_bits, 0, MAX_BITS, 'payload bits'),
            (self.max_total_bits, 1, MAX_BITS, 'total bits'),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError('Invalid local Actor content ' + label + ' limit')


DEFAULT_LIMITS = ActorContentLimits()


def _limits(limits):
    if not isinstance(limits, ActorContentLimits):
        raise ValueError('Explicit ActorContentLimits are required')
    limits.__post_init__()
    return limits


def _stable_policy(enabled, profile):
    if type(enabled) is not bool:
        raise ValueError('Resolved stable subobject mode requires an explicit boolean')
    if enabled:
        if type(profile) is not ResolvedStableSubobjectProfile:
            raise UnsupportedActorContentProfile('The exact resolved stable subobject profile is required')
        profile.__post_init__()
    elif profile is not None:
        raise UnsupportedActorContentProfile('A subobject profile cannot enable the default Actor-only mode')
    return profile


def _stage_block(writer, block, limits, *, stable_profile=None):
    subobject = type(block) is ResolvedStableSubobjectContentBlock
    if subobject:
        if (stable_profile is None or type(block.subobject_guid) is not int or
                block.subobject_guid not in stable_profile.resolved_non_actor_guids or
                block.subobject_guid in stable_profile.known_actor_guids):
            raise UnsupportedActorContentProfile('Subobject reference is not an allowed resolved non-Actor')
    elif not isinstance(block, ActorContentBlock):
        raise ValueError('An explicit ActorContentBlock is required')
    if type(block.has_rep_layout) is not bool:
        raise ValueError('An explicit boolean RepLayout flag is required')
    if (type(block.payload_bit_count) is not int or
            not 0 <= block.payload_bit_count <= limits.max_payload_bits):
        raise ValueError('Actor content payload exceeds local bound')
    # Source128636a5 output bOutHasRepLayout;128637d1 Actor selector true.
    writer.write_bool(block.has_rep_layout)
    writer.write_bool(not subobject)
    if subobject:
        writer.write_packed_int(block.subobject_guid)  # Normal PackageMap reference, no exports/default-path.
        writer.write_bool(True)  # Only the resolved stably-named client branch; no class/create/delete fields.
    # Source12864b0f v78;12864bc4 exact bit transfer without alignment.
    writer.write_packed_int(block.payload_bit_count)
    writer.write_payload(block.payload, block.payload_bit_count)


def write_actor_content_block(writer, block, *, limits=DEFAULT_LIMITS,
                              allow_resolved_stable_subobjects=False,
                              resolved_stable_subobject_profile=None):
    """Append one Actor block atomically and return its added bit count."""
    return write_actor_content_blocks(writer, (block,), limits=limits,
        allow_resolved_stable_subobjects=allow_resolved_stable_subobjects,
        resolved_stable_subobject_profile=resolved_stable_subobject_profile)


def write_actor_content_blocks(writer, blocks, *, limits=DEFAULT_LIMITS,
                               allow_resolved_stable_subobjects=False,
                               resolved_stable_subobject_profile=None):
    """Atomically append a tuple of blocks, with no sequence terminal bit."""
    if not isinstance(writer, BitWriter):
        raise ValueError('A native bit writer is required')
    limits = _limits(limits)
    stable_profile = _stable_policy(allow_resolved_stable_subobjects, resolved_stable_subobject_profile)
    if not isinstance(blocks, tuple) or len(blocks) > limits.max_blocks:
        raise ValueError('Actor content blocks require a bounded tuple')
    staged = BitWriter(maximum_bits=limits.max_total_bits)
    for block in blocks:
        _stage_block(staged, block, limits, stable_profile=stable_profile)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def _read_block(reader, start, limits, *, stable_profile=None):
    has_rep_layout = reader.read_bool()
    subobject_guid = None
    if not reader.read_bool():
        if stable_profile is None:
            raise UnsupportedActorContentProfile('Subobject selector is not supported')
        subobject_guid = reader.read_packed_int()
        if (subobject_guid not in stable_profile.resolved_non_actor_guids or
                subobject_guid in stable_profile.known_actor_guids):
            raise UnsupportedActorContentProfile('Subobject reference is not an allowed resolved non-Actor')
        if reader.read_bool() is not True:
            raise UnsupportedActorContentProfile('Class creation, deletion and non-stable subobjects are unsupported')
    length = reader.read_packed_int()
    if length > limits.max_payload_bits:
        raise ValueError('Actor content payload exceeds local bound')
    if reader.position - start + length > limits.max_total_bits:
        raise ValueError('Actor content operation exceeds local total-bit bound')
    payload = reader.read_payload(length)
    if subobject_guid is not None:
        return ResolvedStableSubobjectContentBlock(subobject_guid, has_rep_layout, payload, length)
    return ActorContentBlock(has_rep_layout, payload, length)


def read_actor_content_block(reader, *, limits=DEFAULT_LIMITS,
                             allow_resolved_stable_subobjects=False,
                             resolved_stable_subobject_profile=None):
    """Read one block atomically; leave the caller's following fields intact."""
    if not isinstance(reader, BitReader):
        raise ValueError('A native bit reader is required')
    limits = _limits(limits)
    stable_profile = _stable_policy(allow_resolved_stable_subobjects, resolved_stable_subobject_profile)
    if limits.max_blocks < 1:
        raise ValueError('Actor content block-count budget is empty')
    start = reader.position
    try:
        return _read_block(reader, start, limits, stable_profile=stable_profile)
    except Exception:
        reader.position = start
        raise


def read_actor_content_blocks(reader, *, limits=DEFAULT_LIMITS,
                              allow_resolved_stable_subobjects=False,
                              resolved_stable_subobject_profile=None):
    """Atomically consume blocks to this reader's exact parent-bunch EOF.

    The caller must bound bit_count to the content region, excluding unrelated
    fields and byte-padding. A zero-bit body is valid; it is not an end marker.
    """
    if not isinstance(reader, BitReader):
        raise ValueError('A native bit reader is required')
    limits = _limits(limits)
    stable_profile = _stable_policy(allow_resolved_stable_subobjects, resolved_stable_subobject_profile)
    start = reader.position
    blocks = []
    try:
        if reader.remaining > limits.max_total_bits:
            raise ValueError('Actor content sequence exceeds local total-bit bound')
        while reader.remaining:
            if len(blocks) >= limits.max_blocks:
                raise ValueError('Actor content block count exceeds local bound')
            blocks.append(_read_block(reader, start, limits, stable_profile=stable_profile))
        return tuple(blocks)
    except Exception:
        reader.position = start
        raise
