"""One observed Weilong-default trial, with no Uin or general Hero mapping."""
from dataclasses import dataclass, field
from contextlib import contextmanager
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat
import threading
import time
from dfserver.replication.legacy_ds_actor_content import ActorContentBlock, write_actor_content_blocks
from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch

ROOT = Path(__file__).resolve().parents[3]
CLASS_PATH = '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C'
TRIAL_OPERATOR = 88000000025
PROFILE_PATH = 'work/evidence/map-entry-next-20261007/official-human-player-state-trial-profile-20261008.json'
PROFILE_SHA256 = '1d1430958136b40054561ffb27b8f1b382cda4edc3716e4c6a7341c09eb12415'
PIN_PATHS = {PROFILE_PATH, 'work/native_player_state_human_trial_profile.py'} | {
    'outputs/df-local-server/dfserver/' + name + '.py' for name in (
        'legacy_ds_player_state_human_appearance_content', 'legacy_ds_int64_value',
        'legacy_ds_scalar_serializers', 'legacy_ds_bit_archive', 'legacy_ds_actor_content')}
_SOURCE_CYCLE = threading.local()
_SOURCE_CYCLE_SECONDS = .25


def _source_fingerprint(path, resolved_root):
    resolved = path.resolve(strict=True)
    details = resolved.stat()
    if not resolved.is_relative_to(resolved_root) or not stat.S_ISREG(details.st_mode):
        return None
    return (resolved, details.st_dev, details.st_ino, details.st_size,
            details.st_mtime_ns, details.st_ctime_ns)


def source_proof_cycle(profiles):
    # The temporary contextlib factory is never an owned module-level callable.
    return contextmanager(_source_proof_cycle_generator)(profiles)


def _source_proof_cycle_generator(profiles):
    """One receive/poll file snapshot, prepared outside the network owner lock.

    This caches no owner/namespace decision. Each positive proof expires within
    250 ms and is discarded on scope exit, including exceptions. Every reuse
    rechecks file identity/size/times without opening, reading or hashing files.
    Changed sources, unknown/replaced profiles and expired proofs fail closed;
    no failed/expired proof is refreshed while the network owner lock is held.
    """
    if type(profiles) is not tuple or len(profiles) > 32:
        raise ValueError('A bounded explicit source-profile snapshot is required')
    previous = getattr(_SOURCE_CYCLE, 'proofs', None)
    proofs, checked = {}, {}
    for profile in profiles:
        if type(profile) is not LatePlayerStateHumanAppearanceDiagnostic:
            raise ValueError('An exact PlayerState source profile is required')
        pins, root = profile.pins, ROOT
        key = (root, pins)
        if key not in checked:
            started = time.monotonic()
            try:
                resolved_root = root.resolve(strict=True)
                files = profile._read_source_proof(resolved_root)
            except (OSError, ValueError):
                resolved_root, files = None, None
            checked[key] = resolved_root, files, started + _SOURCE_CYCLE_SECONDS
        resolved_root, files, deadline = checked[key]
        proofs[id(profile)] = (profile, pins, root, resolved_root, files, deadline)
    _SOURCE_CYCLE.proofs = proofs
    try:
        yield
    finally:
        _SOURCE_CYCLE.proofs = previous


@dataclass(frozen=True)
class LatePlayerStateHumanAppearanceDiagnostic:
    content: ActorContentBlock = field(repr=False)
    pins: tuple = field(repr=False)

    def __post_init__(self):
        if (type(self.content) is not ActorContentBlock or self.content.has_rep_layout is not True or
                self.content.payload_bit_count != 249 or type(self.content.payload) is not bytes or
                len(self.content.payload) != 32 or self.content.payload[-1] & 0xfe or
                type(self.pins) is not tuple or len(self.pins) != len(PIN_PATHS) or
                any(type(pair) is not tuple or len(pair) != 2 for pair in self.pins)):
            raise ValueError('Qualified fixed PlayerState trial content and pins are required')
        pins = dict(self.pins)
        if set(pins) != PIN_PATHS or pins.get(PROFILE_PATH) != PROFILE_SHA256:
            raise ValueError('Exact PlayerState trial profile is required')
        for path, digest in self.pins:
            if (type(path) is not str or ':' in path or '\\' in path or
                    PurePosixPath(path).is_absolute() or any(p in ('', '.', '..') for p in path.split('/')) or
                    type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None):
                raise ValueError('Invalid PlayerState trial source pin')
        reader = BitReader(self.content.payload, bit_count=249)
        if reader.read_bool():
            raise ValueError('PlayerState trial requires ordinary field handles')
        for index, handle in enumerate((140, 142, 143)):
            if reader.read_packed_int() != handle or int.from_bytes(reader.read_bytes(8), 'little', signed=index == 0) != TRIAL_OPERATOR:
                raise ValueError('Only the observed Weilong-default field triple is allowed')
        if reader.read_packed_int() != 0 or reader.remaining:
            raise ValueError('PlayerState trial has extra field content')

    def sources_current(self):
        proofs = getattr(_SOURCE_CYCLE, 'proofs', None)
        if proofs is not None:
            proof = proofs.get(id(self))
            if not (proof is not None and proof[0] is self and proof[1] == self.pins and
                    proof[2] == ROOT and proof[4] is not None and time.monotonic() < proof[5]):
                proofs[id(self)] = None
                return False
            try:
                current = all(_source_fingerprint(ROOT / relative, proof[3]) == fingerprint
                              for relative, fingerprint in proof[4]) and time.monotonic() < proof[5]
            except (OSError, ValueError):
                current = False
            if not current:
                # Once a profile has drifted, restoring its stat fields cannot
                # revive this cycle's proof. A new cycle must re-read/hash it.
                proofs[id(self)] = None
            return current
        return self._read_sources_current()

    def _read_sources_current(self):
        return self._read_source_proof(ROOT.resolve(strict=True)) is not None

    def _read_source_proof(self, resolved_root):
        files = []
        for relative, expected in self.pins:
            path = ROOT / relative
            before = _source_fingerprint(path, resolved_root)
            if before is None or before[3] > 1024 * 1024:
                return None
            with path.open('rb') as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                return None
            after = _source_fingerprint(path, resolved_root)
            if (before != after or
                    hashlib.sha256(raw).hexdigest() != expected):
                return None
            files.append((relative, after))
        return tuple(files)


def build_late_player_state_human_appearance_bunch(profile, channel, sequence, maximum_bits):
    profile.__post_init__()
    writer = BitWriter(maximum_bits=maximum_bits)
    write_actor_content_blocks(writer, (profile.content,))
    return WireBunch(channel, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=sequence, channel_name=ChannelName(hardcoded_index=102))
