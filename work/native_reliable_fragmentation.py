"""Pure outgoing reliable Actor-content splitting for the qualified ordinary path.

Source: work/research_updated_transport_79fb7b10.json, SendBunch 0x1286ca40
and partial receive 0x12867e10. This preserves wire framing only. Actor Open
payloads, GUID exports, mapped dependencies, retransmission and peer acceptance
remain the caller's separate responsibilities. No source or process is read.
"""
from dataclasses import replace

from dfserver.transport.native.legacy_ds_wire_codec import (
    ChannelName, WireBunch, WirePacket, encode_observed_application)

TRANSPORT_SOURCE_PATH = "work/research_updated_transport_79fb7b10.json"
TRANSPORT_SOURCE_SHA256 = "d127c9b551192ba1a126f3b5f5e2c90f9a9a6a0e6d4ff806b6d037941fb73e92"
NATIVE_RESERVED_BUNCH_BITS = 562
DEFAULT_LOCAL_MAX_ASSEMBLED_BYTES = 65536
MAX_LOCAL_ASSEMBLED_BYTES = 1024 * 1024
MAX_LOCAL_FRAGMENTS = 256
OFFICIAL_LIVE_ASSEMBLY_LIMIT_QUALIFIED = False
ACTOR_TEXT_NAME = ChannelName(text="Actor")


def _uint(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Invalid explicit " + label)


def _validate_bunch(bunch, local_max_assembled_bytes):
    if type(bunch) is not WireBunch:
        raise ValueError("An explicit reliable Actor-content WireBunch is required")
    for field in ("open", "close", "flag4", "reliable", "connection_flag",
            "package_exports", "must_be_mapped", "partial", "partial_initial", "partial_final"):
        if type(getattr(bunch, field)) is not bool:
            raise ValueError("Invalid bunch boolean " + field)
    if not bunch.reliable or any(getattr(bunch, field) for field in (
            "flag4", "connection_flag", "package_exports", "must_be_mapped",
            "partial", "partial_initial", "partial_final")):
        raise ValueError("Unsupported reliable Actor-content flags")
    _uint(bunch.channel_index, 2, 0xffffffff, "existing Actor channel index")
    _uint(bunch.channel_sequence, 0, 1023, "first fragment channel sequence")
    _uint(bunch.close_reason, 0, 14, "close reason")
    if not bunch.close and bunch.close_reason:
        raise ValueError("Close reason requires a close flag")
    # The transport proof does not bind current hardcoded name indices to text.
    if type(bunch.channel_name) is not ChannelName or bunch.channel_name != ACTOR_TEXT_NAME:
        raise ValueError("Explicit unnumbered Actor text channel name required")
    _uint(bunch.payload_bits, 1, local_max_assembled_bytes * 8, "local assembled payload bit bound")
    if type(bunch.payload) is not bytes or len(bunch.payload) != (bunch.payload_bits + 7) // 8:
        raise ValueError("Canonical exact payload bytes required")
    if bunch.payload_bits % 8 and bunch.payload[-1] >> (bunch.payload_bits % 8):
        raise ValueError("Nonzero unused final payload bits are noncanonical")


def _check_packet_fit(fragment, max_packet_bytes, connection_overhead_bits):
    # Eight history words, the conditional frame-time byte and the actual
    # observed handler envelope form the largest supported metadata profile.
    packet = WirePacket(16383, 16383, (0xffffffff,) * 8, True, 255, 255,
        (fragment,), 0)
    body = encode_observed_application(packet, max_packet_bytes=max_packet_bytes,
        received_by_server=False)
    if len(body) * 8 + connection_overhead_bits > max_packet_bytes * 8:
        raise ValueError("Observed packet plus explicit connection overhead exceeds MaxPacket")


def split_reliable_bunch(bunch, *, max_packet_bytes, connection_overhead_bits,
        local_max_assembled_bytes=DEFAULT_LOCAL_MAX_ASSEMBLED_BYTES):
    """Return immutable, individually packet-sized WireBunch pieces.

    The input sequence belongs to the first outgoing piece. Reserve len(result)
    reliable sequences atomically and send each piece in its own packet. No ACK
    state is read or advanced here. The native connection overhead is required
    from the caller and is never inferred from fixtures or packet lengths.

    Native compares against MaxPacket*8-overhead-562 before splitting; only the
    split piece size is rounded down to a byte. Unsplit inputs remain ordinary
    bunches. Every non-final piece is byte aligned; the last retains all valid
    bits. Open, if supplied, is carried only on the first piece and close only
    on the last. This does not qualify an Actor Open payload or admission.

    Assembly bytes and fragment count are bounded local resource policies, not
    recovered official live limits. Export/mapped and unresolved flag paths are
    deliberately outside this helper's qualified subset.
    """
    _uint(max_packet_bytes, 1, 1492, "native MaxPacket byte bound")
    _uint(connection_overhead_bits, 0, max_packet_bytes * 8, "native connection overhead bits")
    _uint(local_max_assembled_bytes, 1, MAX_LOCAL_ASSEMBLED_BYTES, "local assembly byte policy")
    budget = max_packet_bytes * 8 - connection_overhead_bits - NATIVE_RESERVED_BUNCH_BITS
    aligned_budget = budget // 8 * 8
    if aligned_budget < 8:
        raise ValueError("Positive byte-aligned native payload budget required")
    _validate_bunch(bunch, local_max_assembled_bytes)
    if bunch.payload_bits <= budget:
        _check_packet_fit(bunch, max_packet_bytes, connection_overhead_bits)
        return (bunch,)
    count = (bunch.payload_bits + aligned_budget - 1) // aligned_budget
    if count > MAX_LOCAL_FRAGMENTS:
        raise ValueError("Object exceeds the local fragment-count policy")
    pieces = []
    for index in range(count):
        first, last = index == 0, index == count - 1
        start = index * aligned_budget
        bits = min(aligned_budget, bunch.payload_bits - start)
        piece = replace(bunch, payload=bunch.payload[start // 8:(start + bits + 7) // 8],
            payload_bits=bits, open=bunch.open and first, close=bunch.close and last,
            close_reason=bunch.close_reason if last else 0,
            partial=True, partial_initial=first, partial_final=last,
            channel_sequence=(bunch.channel_sequence + index) & 1023,
            header_start_bit=None, payload_start_bit=None)
        _check_packet_fit(piece, max_packet_bytes, connection_overhead_bits)
        pieces.append(piece)
    return tuple(pieces)
