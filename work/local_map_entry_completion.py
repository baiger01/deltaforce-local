"""Observe ordered post-travel markers in a bounded, caller-scoped log slice.

The caller must delimit the current trial by log identity and starting offset.
These markers establish a completed loading lifecycle, not Pawn possession or
playability. Results contain only counters and booleans, never native log text.
"""
from dataclasses import dataclass
from pathlib import Path
import re
from threading import Lock


MAX_LOG_BYTES = 64 * 1024 * 1024
XOR_TABLE = bytes(value ^ 0x5C for value in range(256))
UTF8_BOM = b"\xef\xbb\xbf"

# A seamless request logs several ancillary "LoadMap:" messages. Only its
# Cur/URL record starts a new request; ordinary LogLoad uses its own marker.
_LOAD_MAP_REQUEST = re.compile(
    r"\bSeamless\s+LoadMap\s*:\s*Cur\s*:|"
    r"\bLogLoad\s*:\s*(?:Display\s*:\s*)?LoadMap\s*:"
)
_SUBWORLD = re.compile(
    r"\bNewSubWorldName\s*[:=]\s*([A-Za-z0-9_]+)(?![A-Za-z0-9_])"
)
_HANDLE_PLAYER = re.compile(r"\bHandleClientPlayer\b")
_TRAVEL_END = re.compile(r"\bOnSeamlessTravelEnd\b")
_LOADING_FINISHED = re.compile(
    r"\bUGPGameLoadingManager\b[^\r\n]*\bOnLoadingFlowFinished\b"
)
_FORMAT_MARKERS = re.compile(
    r"\b(?:NewSubWorldName|HandleClientPlayer|OnSeamlessTravelEnd|"
    r"UGPGameLoadingManager|LoadMap)\b"
)


@dataclass(frozen=True)
class MapEntryCompletion:
    complete: bool
    expected_subworld_seen: bool
    handle_client_player_seen: bool
    seamless_travel_end_seen: bool
    loading_flow_finished_seen: bool
    load_map_requests: int
    subworld_changes: int
    expected_subworld_changes: int
    handle_client_player_events: int
    seamless_travel_end_events: int
    loading_flow_finished_events: int
    resets: int
    ignored_out_of_order_events: int


def _validate_subworld(expected_subworld: str) -> None:
    if not isinstance(expected_subworld, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_]{0,127}", expected_subworld
    ):
        raise ValueError("Expected subworld must be a bounded native name")


def _empty_counts() -> dict[str, int]:
    return dict.fromkeys((
        "load_map_requests", "subworld_changes", "expected_subworld_changes",
        "handle_client_player_events", "seamless_travel_end_events",
        "loading_flow_finished_events", "resets", "ignored_out_of_order_events",
    ), 0)


class MapEntryCompletionObserver:
    """Thread-safe gate for decoded records from the current trial's follower.

    Call reset() when the follower observes log rotation or truncation. The
    observer does not find session boundaries or read historical logs itself.
    """

    def __init__(self, expected_subworld: str = "Dam_Iris_Level1"):
        _validate_subworld(expected_subworld)
        self._expected_subworld = expected_subworld
        self._lock = Lock()
        self._stage = 0
        self._counts = _empty_counts()

    def reset(self) -> None:
        """Discard both progress and counts when the source log changes."""
        with self._lock:
            self._stage = 0
            self._counts = _empty_counts()

    @property
    def complete(self) -> bool:
        with self._lock:
            return self._stage == 4

    def snapshot(self) -> MapEntryCompletion:
        with self._lock:
            stage = self._stage
            return MapEntryCompletion(
                complete=stage == 4,
                expected_subworld_seen=stage >= 1,
                handle_client_player_seen=stage >= 2,
                seamless_travel_end_seen=stage >= 3,
                loading_flow_finished_seen=stage == 4,
                **self._counts,
            )

    def observe_line(self, line: str) -> None:
        """Consume one already decoded record without retaining its contents."""
        if not isinstance(line, str):
            raise TypeError("Decoded log record must be text")
        if "\n" in line.rstrip("\r\n") or "\r" in line.rstrip("\r\n"):
            raise ValueError("Observe one decoded log record at a time")
        with self._lock:
            self._observe_line(line)

    def _observe_line(self, line: str) -> None:
        counts = self._counts
        stage = self._stage
        if _LOAD_MAP_REQUEST.search(line):
            counts["load_map_requests"] += 1
            counts["resets"] += int(stage != 0)
            stage = 0
        world = _SUBWORLD.search(line)
        if world:
            counts["subworld_changes"] += 1
            counts["resets"] += int(stage != 0)
            matched = world[1] == self._expected_subworld
            counts["expected_subworld_changes"] += int(matched)
            self._stage = 1 if matched else 0
            return

        player = bool(_HANDLE_PLAYER.search(line))
        travel_end = bool(_TRAVEL_END.search(line))
        loading_finished = bool(_LOADING_FINISHED.search(line))
        counts["handle_client_player_events"] += int(player)
        counts["seamless_travel_end_events"] += int(travel_end)
        counts["loading_flow_finished_events"] += int(loading_finished)
        # At most one phase advances per record: multiple marker names in one
        # line are not evidence of three successive lifecycle callbacks.
        if stage == 1 and player:
            stage = 2
        elif stage == 2 and travel_end:
            stage = 3
        elif stage == 3 and loading_finished:
            stage = 4
        elif 0 < stage < 4 and (
            travel_end and stage < 2 or loading_finished and stage < 3
        ):
            counts["ignored_out_of_order_events"] += 1
        self._stage = stage


def _decode_log(raw: bytes) -> str:
    """Accept plain alerts and native UTF-8 BOM plus XOR-0x5c logs."""
    if not isinstance(raw, bytes):
        raise TypeError("Log input must be bytes")
    if len(raw) > MAX_LOG_BYTES:
        raise ValueError("Log input exceeds the bounded byte budget")
    has_bom = raw.startswith(UTF8_BOM)
    payload = raw[len(UTF8_BOM):] if has_bom else raw
    plain = payload.decode("utf-8", "replace")
    native = payload.translate(XOR_TABLE).decode("utf-8", "replace")
    plain_score = len(_FORMAT_MARKERS.findall(plain))
    native_score = len(_FORMAT_MARKERS.findall(native))
    # Native files have an unencoded BOM; caller slices may omit that BOM.
    # Recognizable fixed markers also allow a plain UTF-8 BOM alert file.
    if native_score > plain_score or has_bom and native_score == plain_score:
        return native
    return plain


def observe_map_entry_completion(
    raw: bytes, expected_subworld: str = "Dam_Iris_Level1"
) -> MapEntryCompletion:
    """Find an ordered lifecycle in the latest request of this log slice.

    Require the expected NewSubWorldName, then distinct records containing
    HandleClientPlayer, OnSeamlessTravelEnd, and finally the loading manager's
    OnLoadingFlowFinished. Early or unrelated loading callbacks cannot finish
    the gate. A later LoadMap request or subworld switch clears prior progress.
    Event counters cover the slice; the seen flags describe its latest request.
    """
    observer = MapEntryCompletionObserver(expected_subworld)
    text = _decode_log(raw)
    # 0 awaiting subworld; 1 awaiting player; 2 awaiting travel end;
    # 3 awaiting loading completion; 4 complete.
    for line in text.splitlines():
        observer.observe_line(line)
    return observer.snapshot()


def read_map_entry_completion(
    log_path: Path, expected_subworld: str = "Dam_Iris_Level1", *, offset: int = 0
) -> MapEntryCompletion:
    """Read at most the byte budget plus one sentinel from a scoped log offset.

    Log identity/rotation checks belong to the caller. No full log, path, or
    connection argument is included in the returned observation.
    """
    if type(offset) is not int or offset < 0:
        raise ValueError("Log offset must be a nonnegative integer")
    with Path(log_path).open("rb") as stream:
        stream.seek(offset)
        raw = stream.read(MAX_LOG_BYTES + 1)
    return observe_map_entry_completion(raw, expected_subworld)
