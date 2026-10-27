"""Ordinary manager timeline values; no transport or native object methods."""
from dataclasses import dataclass, replace
import hashlib
import json
import math
import struct

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, MAX_BITS
from export_weapon_switch_timeline_schema import ROOT, OUTPUT, CLIENT_SHA

SCHEMA_SHA256 = '120ce53787f8ae19fa5040a6bbb1e64bd31adff8f2971372bd38db1c2bb4a13b'


def schema_binding():
    raw = OUTPUT.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The exact native owner timeline schema changed')
    schema = json.loads(raw)
    if (schema.get('kind') != 'source_qualified_owned_weapon_switch_timeline_v1' or
            schema.get('client_sha256') != CLIENT_SHA):
        raise ValueError('Unsupported native owner timeline schema')
    for relative, digest in schema['sources'].items():
        path = (ROOT/relative).resolve()
        if not path.is_relative_to(ROOT.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Changed owner timeline native source: ' + relative)
    return schema


def source_pins():
    pins = dict(schema_binding()['sources'])
    pins[OUTPUT.relative_to(ROOT).as_posix()] = SCHEMA_SHA256
    for relative in ('work/weapon_switch_timeline_codec.py', 'work/export_weapon_switch_timeline_schema.py',
            'work/inspect_owned_weapon_switch_timeline_enums.py',
            'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Invalid explicit switch-frame integer')
    return value


def _time(value):
    if type(value) not in (int, float) or value < 0:
        raise ValueError('A finite nonnegative local server clock is required')
    try:
        if not math.isfinite(value):
            raise ValueError('A finite nonnegative local server clock is required')
        raw = struct.pack('<f', value)
    except (OverflowError, struct.error) as error:
        raise ValueError('The local clock exceeds native float32') from error
    if not math.isfinite(struct.unpack('<f', raw)[0]):
        raise ValueError('The local clock exceeds native float32')
    return raw


@dataclass(frozen=True)
class LocalInitialSwitchClock:
    frame_no: int
    world_time: float


@dataclass(frozen=True)
class SwitchFrame:
    local_frame_no: int = -1
    remote_frame_no: int = -1
    dep_frame_no: int = -1
    world_time: float = 0.0
    last_identity: int = 0
    pending_identity: int = 0
    switch_type: int = 0
    operation: int = 0
    context: int = 0


@dataclass(frozen=True)
class InitialSwitchTimeline:
    data: tuple[SwitchFrame, ...]
    front: int = 0
    rear: int = 1
    max_size: int = 1


def initial_timeline(unique_id, clock):
    schema_binding()
    _integer(unique_id, 1, (1 << 32)-1)
    if type(clock) is not LocalInitialSwitchClock:
        raise ValueError('An explicit local initial-switch clock is required')
    _integer(clock.frame_no, 1, (1 << 31)-1)
    _time(clock.world_time)
    # These are explicit local server choices. The previous local client frame
    # is unknown; -1 retains the native no-frame sentinel, never a sampled value.
    frame = SwitchFrame(clock.frame_no, -1, -1, clock.world_time, 0, unique_id, 2, 0, 2)
    return InitialSwitchTimeline((SwitchFrame(), frame))


def import_remote_frame(frame):
    """Native 58ef280 copies the server's local/remote frame numbers exchanged."""
    if type(frame) is not SwitchFrame:
        raise ValueError('An exact native switch frame is required')
    return replace(frame, local_frame_no=frame.remote_frame_no, remote_frame_no=frame.local_frame_no)


def encode(timeline, *, maximum_bits=MAX_BITS):
    """Encode a complete fresh two-slot ring in one ordinary RepLayout update."""
    schema = schema_binding()
    if (type(timeline) is not InitialSwitchTimeline or type(timeline.data) is not tuple or
            (timeline.front, timeline.rear, timeline.max_size) != (0, 1, 1) or
            any(type(v) is not int for v in (timeline.front, timeline.rear, timeline.max_size)) or
            len(timeline.data) != 2 or timeline.data[0] != SwitchFrame()):
        raise ValueError('The complete fresh ring requires the unused slot and one initial frame')
    writer = BitWriter(maximum_bits=maximum_bits)
    writer.write_bool(False)
    writer.write_packed_int(9)
    writer.write_bits(len(timeline.data), 16)
    for ordinal, frame in enumerate(timeline.data):
        if type(frame) is not SwitchFrame:
            raise ValueError('The native switch frame type is required')
        values = (frame.local_frame_no, frame.remote_frame_no, frame.dep_frame_no,
                  frame.world_time, frame.last_identity, frame.pending_identity,
                  frame.switch_type, frame.operation, frame.context)
        for local, value in enumerate(values, 1):
            writer.write_packed_int(ordinal*9 + local)
            if local <= 3:
                writer.write_bits(_integer(value, -1, (1 << 31)-1) & 0xffffffff, 32)
            elif local == 4:
                writer.write_bytes(_time(value))
            elif local in (5, 6):
                writer.write_bits(_integer(value, 0, (1 << 32)-1), 32)
            else:
                name = ('SwitchType', 'Operation', 'SwitchWeaponContext')[local-7]
                enum = schema['enums'][name]
                if type(value) is not int or value not in tuple(r['value'] for r in enum['entries']):
                    raise ValueError('A real native switch-frame enum value is required')
                writer.write_bits(value, enum['wire_bits'])
    active = timeline.data[1]
    if (active.local_frame_no <= 0 or active.remote_frame_no != -1 or active.dep_frame_no != -1 or
            active.last_identity != 0 or active.pending_identity == 0 or
            (active.switch_type, active.operation, active.context) != (2, 0, 2)):
        raise ValueError('Only the explicit fresh local initial-instant-switch policy is supported')
    writer.write_packed_int(0)
    for handle, value in ((10, timeline.front), (11, timeline.rear), (12, timeline.max_size)):
        writer.write_packed_int(handle)
        writer.write_bits(value, 32)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)
