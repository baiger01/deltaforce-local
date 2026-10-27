"""Pure numeric flag calculation recovered from this build's native writer.

Source: work/evidence/native-pawn-net-rep-interface-writer-source.json.
The actual native method0x4e198f0 computes two bits before serializing one
raw byte. Its numeric Actor+0x98 states are deliberately not named as engine
enums. All state and connection facts must come from an explicit server
model. A client CDO's defaults are not those server-side facts.

This module neither writes a byte nor changes an Actor, admits a peer,
registers an interface, or demonstrates native spawn acceptance.
"""
from dataclasses import dataclass


SOURCE_BUILD_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SOURCE_WRITER_RVA = 0x4E198F0
SOURCE_WRITER_CODE_SHA256 = 'c55775afd5dbf7f8f395e8ea5ad1eba60eeb9ce42d3ed94b51cfeeb1f1fd7258'
SOURCE_EVIDENCE_RELATIVE_PATH = 'work/evidence/native-pawn-net-rep-interface-writer-source.json'
SOURCE_EVIDENCE_SHA256 = 'f1fd2d3a03818d769d60e58d772f43aaa02ad4240e61e5836879e0670bff6c19'


@dataclass(frozen=True)
class GameSpawnFlags:
    effective_state_u8: int
    flags_u8: int
    state_downgraded: bool
    downgrade_reason: str | None


def calculate_game_spawn_flags(*, source_build_sha256: str,
                               original_state_u8: int,
                               actor_byte93_mask20: bool,
                               owner_connection_match: bool,
                               connection_present: bool,
                               actor_is_connection_actor: bool,
                               actor_in_connection_actor_array: bool) -> GameSpawnFlags:
    """Calculate the source-qualified flags from explicit state/ownership facts.

    0x4e19914..2e: state2 with a nonmatching owner invokes0x12583dc0.
    That helper writes state1 only when Actor+0x93 mask0x20 is set.
    0x4e1993f: bit0 is whether the resulting numeric state equals1.
    0x4e19946..88: bit1 is whether a present connection references this
    Actor at+0x90 or in its+0x98 array. These offsets are not GUIDs.

    No inputs have business defaults. Connections absent from this bounded
    server profile cannot simultaneously claim any connection match.
    """
    if type(source_build_sha256) is not str or source_build_sha256 != SOURCE_BUILD_SHA256:
        raise ValueError('The exact source-qualified Shipping build SHA256 is required')
    if type(original_state_u8) is not int or not 0 <= original_state_u8 <= 255:
        raise ValueError('original_state_u8 must be an explicit integer byte')
    booleans = {
        'actor_byte93_mask20': actor_byte93_mask20,
        'owner_connection_match': owner_connection_match,
        'connection_present': connection_present,
        'actor_is_connection_actor': actor_is_connection_actor,
        'actor_in_connection_actor_array': actor_in_connection_actor_array,
    }
    for name, value in booleans.items():
        if type(value) is not bool:
            raise ValueError(f'{name} must be an explicit bool')
    if not connection_present and (owner_connection_match or actor_is_connection_actor or
                                   actor_in_connection_actor_array):
        raise ValueError('An absent connection cannot claim a connection match')

    downgraded = (original_state_u8 == 2 and not owner_connection_match and
                  actor_byte93_mask20)
    effective = 1 if downgraded else original_state_u8
    flags = (1 if effective == 1 else 0) | (
        2 if connection_present and (actor_is_connection_actor or
                                    actor_in_connection_actor_array) else 0)
    reason = 'native_numeric_state_2_changed_to_1_for_nonmatching_owner' if downgraded else None
    return GameSpawnFlags(effective, flags, downgraded, reason)
