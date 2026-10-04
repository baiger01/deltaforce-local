"""Restricted ordinary-reference SerializeNewActor field encoder.

Source: work/evidence/native-post-join-actor-prerequisites.json. This codec
does not export objects, allocate GUIDs, create/possess a Pawn, or send a
bunch. The caller must already have evidence that the referenced archetype
and Level objects are resolvable by the client; its declaration is a
precondition, not verification performed by this module.

Only the non-export PackageMap mode is represented: ordinary packed uint32
references, no GUID1/default-path flags. Rotation is always absent. Vector
inputs are integer QuantizedVector10 steps, with no guessed float rounding.
Absent vectors/rotation leave the client's defaults to its native reader.
The optional game replication byte is the source-recovered PackageMap
NetRepActorInterface extension, not an OnActorChannelOpen byte. Its value and
class qualification remain the caller's explicit contract. See work/evidence/
native-game-package-map-replication-flags-tail.json and
native-pawn-net-rep-interface-writer-source.json.
The optional PC tail encodes the evidenced base-class local-player index0;
it does not establish compatibility with a derived game-class override.
"""

from .legacy_ds_bit_archive import BitWriter, UINT32_MAX
from .legacy_ds_quantized_vector import QuantizedVector10, write_compressed_vector10


# Three maximum-width packed GUIDs, three compressed vectors, four presence
# bits, the optional game replication u8, and the optional u8 PC tail. This is our subset's bound, not a native
# actor-bunch size limit.
MAX_ACTOR_OPEN_BITS = 3 * 40 + 3 * 81 + 4 + 8 + 8


def _uint32(value, label):
    if type(value) is not int or not 0 <= value <= UINT32_MAX:
        raise ValueError('An explicit uint32 ' + label + ' is required')


def write_actor_open(writer, *, actor_guid, archetype_guid,
                     connection_network_version, archive_network_version,
                     references_resolvable, level_guid=None, location=None,
                     scale=None, velocity=None, local_player_index=None,
                     game_replication_flags=None):
    """Append this subset atomically and return the number of appended bits.

    actor_guid names the new dynamic actor; it must be nonzero and even.
    references_resolvable must be exactly True and concerns the archetype
    and (when present) Level references, not an already-created actor.
    Nonzero references must be distinct because they identify different
    object types. GUID0 and GUID1 are not supported object references here.

    Connection versions >=5 require an explicit non-null Level reference;
    older versions must omit it. Native accepts a null Level through part
    of its spawn path, but its final WorldSpawn behavior is not recovered,
    so this subset rejects that branch. The FInBunch constructor propagates
    connection+1528 to archive+54; this codec requires those explicit
    versions to match. Hello's network checksum is not either version.

    local_player_index=None emits a generic actor header. Explicit int0
    appends the evidenced base PlayerController u8; no alignment is added.
    Export-path and present-rotation parameters deliberately do not exist.
    game_replication_flags=None omits the game-specific interface extension;
    an explicit int0..3 emits the source-recovered raw byte immediately after
    transforms and before the PC hook byte. Do not use a default flag or infer
    interface qualification from the actor's name alone.
    """
    if not isinstance(writer, BitWriter):
        raise ValueError('A native bit writer is required')
    _uint32(connection_network_version, 'connection network version')
    _uint32(archive_network_version, 'archive network version')
    if connection_network_version != archive_network_version:
        raise ValueError('Connection and archive network versions must match')
    if references_resolvable is not True:
        raise ValueError('An explicit pre-resolved object-reference contract is required')

    _uint32(actor_guid, 'Actor GUID')
    if not actor_guid or actor_guid & 1:
        raise ValueError('Only nonzero even dynamic Actor GUIDs are supported')
    _uint32(archetype_guid, 'archetype GUID')
    if archetype_guid < 2:
        raise ValueError('An ordinary nonzero archetype reference other than GUID1 is required')
    references = [actor_guid, archetype_guid]
    if connection_network_version >= 5:
        _uint32(level_guid, 'Level GUID')
        if level_guid < 2:
            raise ValueError('An explicit non-null ordinary Level reference is required')
        references.append(level_guid)
    elif level_guid is not None:
        raise ValueError('Level GUID is not serialized by connection versions below5')
    if len(set(references)) != len(references):
        raise ValueError('Different Actor, archetype and Level objects require distinct GUIDs')
    if local_player_index is not None and (
            type(local_player_index) is not int or local_player_index != 0):
        raise ValueError('Only explicit int0 is supported for the base PC player index')
    if game_replication_flags is not None and (
            type(game_replication_flags) is not int or not 0 <= game_replication_flags <= 3):
        raise ValueError('Game replication flags require an explicit int0..3 from a qualified writer')
    for vector in (location, scale, velocity):
        if vector is not None and not isinstance(vector, QuantizedVector10):
            raise ValueError('Optional vectors require QuantizedVector10 integer steps')

    staged = BitWriter(maximum_bits=MAX_ACTOR_OPEN_BITS)
    # SerializeNewActor: 12bcb174, 12bcca50, >=5 gate12bcca69/70, 12bcca90.
    # Ordinary GUID writer12bbc5de/6bb/727 emits only packed_u32, no flags.
    staged.write_packed_int(actor_guid)
    staged.write_packed_int(archetype_guid)
    if connection_network_version >= 5:
        staged.write_packed_int(level_guid)

    def optional_vector(vector):
        staged.write_bool(vector is not None)
        if vector is not None:
            write_compressed_vector10(staged, vector,
                archive_network_version=archive_network_version)

    # The flags are interleaved with their values, not four leading bits:
    # 12bcce11 location; 12bcce26 rotation; 12bcce7a scale; 12bccea2 velocity.
    optional_vector(location)
    staged.write_bool(False)
    optional_vector(scale)
    optional_vector(velocity)
    if game_replication_flags is not None:
        # GPPackageMap v2e0 -> 4e251a0 consumes one raw byte before spawn.
        staged.write_bits(game_replication_flags, 8)
    if local_player_index is not None:
        # Base PC OnActorChannelOpen12d4dde3/de05 consumes this unaligned u8.
        staged.write_bits(local_player_index, 8)

    # BitWriter validates capacity/padding before mutation in this one append.
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count

