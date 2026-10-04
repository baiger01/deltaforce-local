"""Restricted Actor-selector content blocks; replication bodies stay opaque.

The pinned native evidence is work/evidence/native-actor-content-block-envelope.json.
Each block contains bHasRepLayout, the true Actor selector, packed uint32 bit
length and precisely that many payload bits. No byte alignment or terminal
block marker is inserted. The containing bunch's exact end bounds the sequence.

This module neither resolves an Actor nor creates property handles/RPCs. A true
selector refers to the channel's existing Actor. Local budgets and atomic failure
are deliberately stricter policies; encoding is not native acceptance.
"""

from dataclasses import dataclass

from .legacy_ds_bit_archive import BitReader, BitWriter, MAX_BITS


MAX_BLOCKS = 256


class UnsupportedActorContentProfile(ValueError):
    pass


@dataclass(frozen=True)
class ActorContentBlock:
    has_rep_layout: bool
    payload: bytes
    payload_bit_count: int


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


def _stage_block(writer, block, limits):
    if not isinstance(block, ActorContentBlock):
        raise ValueError('An explicit ActorContentBlock is required')
    if type(block.has_rep_layout) is not bool:
        raise ValueError('An explicit boolean RepLayout flag is required')
    if (type(block.payload_bit_count) is not int or
            not 0 <= block.payload_bit_count <= limits.max_payload_bits):
        raise ValueError('Actor content payload exceeds local bound')
    # Source128636a5 output bOutHasRepLayout;128637d1 Actor selector true.
    writer.write_bool(block.has_rep_layout)
    writer.write_bool(True)
    # Source12864b0f v78;12864bc4 exact bit transfer without alignment.
    writer.write_packed_int(block.payload_bit_count)
    writer.write_payload(block.payload, block.payload_bit_count)


def write_actor_content_block(writer, block, *, limits=DEFAULT_LIMITS):
    """Append one Actor block atomically and return its added bit count."""
    return write_actor_content_blocks(writer, (block,), limits=limits)


def write_actor_content_blocks(writer, blocks, *, limits=DEFAULT_LIMITS):
    """Atomically append a tuple of blocks, with no sequence terminal bit."""
    if not isinstance(writer, BitWriter):
        raise ValueError('A native bit writer is required')
    limits = _limits(limits)
    if not isinstance(blocks, tuple) or len(blocks) > limits.max_blocks:
        raise ValueError('Actor content blocks require a bounded tuple')
    staged = BitWriter(maximum_bits=limits.max_total_bits)
    for block in blocks:
        _stage_block(staged, block, limits)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def _read_block(reader, start, limits):
    has_rep_layout = reader.read_bool()
    if not reader.read_bool():
        raise UnsupportedActorContentProfile('Subobject selector is not supported')
    length = reader.read_packed_int()
    if length > limits.max_payload_bits:
        raise ValueError('Actor content payload exceeds local bound')
    if reader.position - start + length > limits.max_total_bits:
        raise ValueError('Actor content operation exceeds local total-bit bound')
    return ActorContentBlock(has_rep_layout, reader.read_payload(length), length)


def read_actor_content_block(reader, *, limits=DEFAULT_LIMITS):
    """Read one block atomically; leave the caller's following fields intact."""
    if not isinstance(reader, BitReader):
        raise ValueError('A native bit reader is required')
    limits = _limits(limits)
    if limits.max_blocks < 1:
        raise ValueError('Actor content block-count budget is empty')
    start = reader.position
    try:
        return _read_block(reader, start, limits)
    except Exception:
        reader.position = start
        raise


def read_actor_content_blocks(reader, *, limits=DEFAULT_LIMITS):
    """Atomically consume blocks to this reader's exact parent-bunch EOF.

    The caller must bound bit_count to the content region, excluding unrelated
    fields and byte-padding. A zero-bit body is valid; it is not an end marker.
    """
    if not isinstance(reader, BitReader):
        raise ValueError('A native bit reader is required')
    limits = _limits(limits)
    start = reader.position
    blocks = []
    try:
        if reader.remaining > limits.max_total_bits:
            raise ValueError('Actor content sequence exceeds local total-bit bound')
        while reader.remaining:
            if len(blocks) >= limits.max_blocks:
                raise ValueError('Actor content block count exceeds local bound')
            blocks.append(_read_block(reader, start, limits))
        return tuple(blocks)
    except Exception:
        reader.position = start
        raise
