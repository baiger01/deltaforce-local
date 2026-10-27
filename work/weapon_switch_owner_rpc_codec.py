"""Qualified owning switch RPC values and directional C->S component envelope.

This is an offline codec, not a socket dispatcher or an authorization boundary.
The caller must bind the current admitted Pawn channel and stable WeaponManager
GUID before decoding. Unknown fields remain opaque; partial bunches require the
transport's normal reliable assembler before this decoder is called.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import math
import struct

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_actor_fields import (ClassFieldEnvelope, NormalClassFieldProfile,
    build_class_field_content, read_class_fields)
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_wire_codec import WireBunch, ChannelName
from export_weapon_switch_owner_rpc_schema import ROOT, OUTPUT
from weapon_switch_timeline_codec import SwitchFrame

SCHEMA_SHA256 = 'c0390175d3b9070aa7cc54d70b03c6820f5836624a12a5f88f56a483f8b1cd8a'


@lru_cache(maxsize=1)
def _qualified_schema_raw():
    raw = OUTPUT.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The exact owning switch RPC schema changed')
    document = json.loads(raw)
    if document.get('kind') != 'source_qualified_weapon_switch_owner_rpc_v1':
        raise ValueError('Unsupported owning switch RPC source')
    # Qualification occurs once before serving. The integration must include
    # source_pins in its existing current-profile/source-generation guards.
    for relative, digest in document['sources'].items():
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Owning switch RPC source changed: ' + relative)
    return raw


def schema_binding():
    return json.loads(_qualified_schema_raw())


def source_pins():
    from weapon_switch_timeline_codec import source_pins as timeline_pins
    pins = timeline_pins()
    for relative, digest in schema_binding()['sources'].items():
        if relative in pins and pins[relative] != digest:
            raise ValueError('Owning switch source groups disagree')
        pins[relative] = digest
    pins[OUTPUT.relative_to(ROOT).as_posix()] = SCHEMA_SHA256
    for relative in ('work/weapon_switch_owner_rpc_codec.py',
            'work/export_weapon_switch_owner_rpc_schema.py',
            'work/audit_weapon_switch_ingame_lifecycle.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_fields.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
            'outputs/df-local-server/dfserver/legacy_ds_pc_receipt.py',
            'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return pins


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Invalid bounded owning switch integer')
    return value


def float32(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError('A finite native float32 is required')
    try:
        raw = struct.pack('<f', value)
    except (OverflowError, struct.error) as error:
        raise ValueError('Float exceeds native float32') from error
    if not math.isfinite(struct.unpack('<f', raw)[0]):
        raise ValueError('Float exceeds native float32')
    return raw


@dataclass(frozen=True)
class SwitchCheckCode:
    last: float = 0.0
    pending: float = 0.0


@dataclass(frozen=True)
class VerifyFrameRequest:
    frame: SwitchFrame
    check_code: SwitchCheckCode
    frame_present: bool = True
    check_code_present: bool = True


def write_frame(writer, frame):
    if type(frame) is not SwitchFrame:
        raise ValueError('An exact switch frame is required')
    for value in (frame.local_frame_no, frame.remote_frame_no, frame.dep_frame_no):
        writer.write_bits(integer(value, -(1 << 31), (1 << 31)-1) & 0xffffffff, 32)
    writer.write_bytes(float32(frame.world_time))
    writer.write_bits(integer(frame.last_identity, 0, UINT32_MAX), 32)
    writer.write_bits(integer(frame.pending_identity, 0, UINT32_MAX), 32)
    for value, maximum, width in ((frame.switch_type, 8, 4), (frame.operation, 2, 2),
                                  (frame.context, 41, 6)):
        writer.write_bits(integer(value, 0, maximum), width)


def _read_frame(reader):
    values = [reader.read_bits(32) for _ in range(3)]
    values = [value - (1 << 32) if value & (1 << 31) else value for value in values]
    values.extend((struct.unpack('<f', reader.read_bytes(4))[0], reader.read_bits(32),
                   reader.read_bits(32), reader.read_bits(4), reader.read_bits(2), reader.read_bits(6)))
    result = SwitchFrame(*values)
    write_frame(BitWriter(maximum_bits=204), result)
    return result


def _slice(payload, bits, maximum):
    if (type(payload) is not bytes or type(bits) is not int or not 0 <= bits <= maximum or
            len(payload) != (bits + 7)//8 or int.from_bytes(payload, 'little') >> bits):
        raise ValueError('An exact bounded owning switch archive is required')
    return BitReader(payload, bit_count=bits)


def encode_verify_parameters(request):
    schema_binding()
    if (type(request) is not VerifyFrameRequest or type(request.frame) is not SwitchFrame or
            type(request.check_code) is not SwitchCheckCode or
            any(type(flag) is not bool for flag in (request.frame_present, request.check_code_present))):
        raise ValueError('An exact owning switch request is required')
    writer = BitWriter(maximum_bits=270)
    writer.write_bool(request.frame_present)
    if request.frame_present:
        write_frame(writer, request.frame)
    elif request.frame != SwitchFrame():
        raise ValueError('An absent ClientFrame must retain its native constructor defaults')
    writer.write_bool(request.check_code_present)
    if request.check_code_present:
        writer.write_bytes(float32(request.check_code.last))
        writer.write_bytes(float32(request.check_code.pending))
    elif request.check_code != SwitchCheckCode():
        raise ValueError('An absent check-code struct must retain native zeros')
    return writer.to_bytes(), writer.bit_count


def decode_verify_parameters(payload, bits):
    schema_binding()
    reader = _slice(payload, bits, 270)
    present = reader.read_bool()
    frame = _read_frame(reader) if present else SwitchFrame()
    check_present = reader.read_bool()
    check = (SwitchCheckCode(*struct.unpack('<ff', reader.read_bytes(8)))
             if check_present else SwitchCheckCode())
    result = VerifyFrameRequest(frame, check, present, check_present)
    encode_verify_parameters(result)
    if reader.remaining:
        raise ValueError('Owning switch RPC parameters must end at exact EOF')
    return result


def decode_verify_bunch(bunch, *, pawn_channel, manager_guid):
    schema = schema_binding()
    integer(pawn_channel, 2, 65535)
    integer(manager_guid, 2, UINT32_MAX)
    if manager_guid & 1:
        raise ValueError('The qualified normal default component GUID is required')
    if (type(bunch) is not WireBunch or bunch.channel_index != pawn_channel or
            type(bunch.channel_sequence) is not int or not 0 <= bunch.channel_sequence < 1024 or
            bunch.reliable is not True or type(bunch.channel_name) is not ChannelName or
            bunch.channel_name != ChannelName(hardcoded_index=102) or
            type(bunch.close_reason) is not int or bunch.close_reason != 0 or
            any(getattr(bunch, name) is not False for name in (
                'open', 'close', 'flag4', 'connection_flag', 'package_exports', 'must_be_mapped',
                'partial', 'partial_initial', 'partial_final'))):
        raise ValueError('One complete reliable admitted Pawn component RPC is required')
    reader = _slice(bunch.payload, bunch.payload_bits, 4096)
    if reader.read_bool() or reader.read_bool():
        raise ValueError('Owning switch requires an ordinary non-Actor content block')
    if reader.read_packed_int() != manager_guid:
        raise ValueError('The component is not this Pawn owned WeaponManager')
    # C->S receiver12863d2f skips the S->C stable-name selector completely.
    length = reader.read_packed_int()
    payload = reader.read_payload(length)
    if reader.remaining:
        raise ValueError('Mixed owning switch content requires caller isolation')
    fields = read_class_fields(BitReader(payload, bit_count=length),
        profile=NormalClassFieldProfile(schema['exclusive_index_maximum'], False))
    if len(fields) != 1 or fields[0].rep_index != schema['verify_index']:
        raise ValueError('Only the qualified ServerVerifyFrame RPC is supported')
    return decode_verify_parameters(fields[0].payload, fields[0].payload_bit_count)


class InvalidOwnerParameters(ValueError):
    """A recognized owner field whose bounded parameter body is malformed."""


def decode_verify_bunch_requests(bunch, *, pawn_channel, manager_guid):
    """Read ordered owner fields from complete ordinary C->S content blocks.

    Other components and property regions are skipped by their declared bit
    length. Their original bytes remain in the owning transport journal. No
    class-cache profile is inferred for those unrelated regions.
    """
    from dfserver.legacy_ds_pc_receipt import MAX_ASSEMBLY_BITS
    schema = schema_binding()
    integer(pawn_channel, 2, 65535)
    integer(manager_guid, 2, UINT32_MAX)
    if manager_guid & 1:
        raise ValueError('The qualified normal default component GUID is required')
    if (type(bunch) is not WireBunch or bunch.channel_index != pawn_channel or
            type(bunch.channel_sequence) is not int or not 0 <= bunch.channel_sequence < 1024 or
            bunch.reliable is not True or bunch.channel_name != ChannelName(hardcoded_index=102) or
            type(bunch.close_reason) is not int or bunch.close_reason != 0 or
            any(getattr(bunch, name) is not False for name in (
                'open', 'close', 'flag4', 'connection_flag', 'package_exports', 'must_be_mapped',
                'partial', 'partial_initial', 'partial_final'))):
        raise ValueError('A complete admitted ordinary Pawn RPC body is required')
    reader = _slice(bunch.payload, bunch.payload_bits, MAX_ASSEMBLY_BITS)
    requests = []
    blocks = 0
    while reader.remaining:
        blocks += 1
        if blocks > 256:
            raise ValueError('The bounded owning content block count was exceeded')
        has_rep_layout, is_actor = reader.read_bool(), reader.read_bool()
        guid = None if is_actor else reader.read_packed_int()
        # Source receiver12863d2f has no C->S stable-name selector.
        length = reader.read_packed_int()
        payload = reader.read_payload(length)
        if has_rep_layout or is_actor or guid != manager_guid:
            continue
        fields = read_class_fields(BitReader(payload, bit_count=length),
            profile=NormalClassFieldProfile(schema['exclusive_index_maximum'], False))
        for item in fields:
            if item.rep_index != schema['verify_index']:
                continue
            if len(requests) >= 256:
                raise ValueError('The bounded owning RPC count was exceeded')
            try:
                requests.append(decode_verify_parameters(item.payload, item.payload_bit_count))
            except ValueError as error:
                raise InvalidOwnerParameters(str(error)) from error
    return tuple(requests)


def invalid_frame_block(client_frame_no):
    """Ordinary component RPC body; caller wraps the S->C qualified component."""
    schema = schema_binding()
    writer = BitWriter(maximum_bits=33)
    writer.write_bool(True)
    writer.write_bits(integer(client_frame_no, 0, (1 << 31)-1), 32)
    return build_class_field_content((ClassFieldEnvelope(schema['invalid_frame_index'],
        writer.to_bytes(), writer.bit_count),),
        profile=NormalClassFieldProfile(schema['exclusive_index_maximum'], False))
