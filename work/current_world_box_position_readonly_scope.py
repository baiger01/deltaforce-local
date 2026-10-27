"""Bounded current SafeBox plain-root positions in the selected owning World.

Observed root translation and the native zero-origin branch are separate from
authored comparisons, PackageMap references, permissions and server authority.
"""
from copy import deepcopy
from dataclasses import dataclass
from fractions import Fraction
import math
from pathlib import Path
import struct

from native_replication_metadata_core import MetadataSession
import native_current_box_position_sources as sources
from observe_owned_gameplay_metadata import address

SHIPPING_SHA256, IMAGE_SIZE = sources.SHIPPING_SHA256, sources.IMAGE_SIZE
SOURCE = sources.SOURCE
MAX_READ_BYTES, MAX_READ_CALLS, MAX_IDENTITY_CALLS = 4096, 256, 128


def source_pins():
    pins = sources.source_pins()
    if Path(__file__).resolve() != sources.ROOT / 'work/current_world_box_position_readonly_scope.py':
        raise ValueError('The position reader was imported from another checkout')
    return pins


@dataclass(frozen=True)
class PositionTarget:
    address: int | None
    actor_path: str
    class_path: str
    guid: int


def _protocol_position(xyz, origin, gate, default):
    if gate <= 0 or origin == default:
        return list(xyz), 'identity_bitcopy'
    result = []
    for value, integer in zip(xyz, origin):
        if (struct.unpack('<f', struct.pack('<f', integer))[0] != integer
                or 0 < abs(value) < 2. ** -126):
            raise ValueError('The exact native rebase arithmetic subset is unavailable')
        exact = Fraction.from_float(value) + integer
        candidate = struct.unpack('<f', struct.pack('<f', float(exact)))[0]
        if (not exact or not math.isfinite(candidate) or 0 < abs(candidate) < 2. ** -126
                or Fraction.from_float(candidate) != exact):
            raise ValueError('The native rebase rounding environment is not qualified')
        result.append(candidate)
    return result, 'exact_float32_add_origin'


def _position_frame(xyz, origin, gate, default):
    try:
        protocol, branch = _protocol_position(xyz, origin, gate, default)
        return protocol, branch, list(protocol)
    except ValueError as error:
        if str(error) != 'The native rebase rounding environment is not qualified':
            raise
    # Preserve the exact affine transform separately. It is not the native
    # float32 protocol result, whose rounding mode has not been observed.
    exact_xyz = []
    for value, integer in zip(xyz, origin):
        if (struct.unpack('<f', struct.pack('<f', integer))[0] != integer or
                0 < abs(value) < 2. ** -126):
            raise ValueError('The exact affine coordinate subset is unavailable')
        exact = Fraction.from_float(value) + integer
        candidate = float(exact)
        if not math.isfinite(candidate) or Fraction.from_float(candidate) != exact:
            raise ValueError('The affine coordinate is not exactly representable in float64')
        exact_xyz.append(candidate)
    return None, 'native_rounding_unqualified_exact_affine_only', exact_xyz


def observe_scope(*, session, module_base, pc_address, pawn_address, targets,
                  membership_observation, object_identity, object_path, final_recheck, source_pins):
    pins = globals()['source_pins']()
    if (not isinstance(session, MetadataSession) or type(source_pins) is not dict
            or any(source_pins.get(key) != digest for key, digest in pins.items())
            or any(not callable(callback) for callback in (object_identity, object_path, final_recheck))):
        raise ValueError('The exact position source seal, session and current root callbacks are required')
    manifest = {row['actor_path']: row for row in sources.membership.sealed_scope.qualified_actor_paths()
                if row['class_path'].endswith('BP_Interactor_Container_SafeBox_C')}
    if (type(targets) is not tuple or len(targets) != 3 or any(type(row) is not PositionTarget
            or row.actor_path not in manifest or row.class_path != manifest[row.actor_path]['class_path']
            or type(row.guid) is not int or not 3 <= row.guid <= 0xffffffff or not row.guid & 1 for row in targets)
            or len({row.actor_path for row in targets}) != 3 or len({row.guid for row in targets}) != 3
            or len({row.address for row in targets if row.address is not None}) != sum(row.address is not None for row in targets)):
        raise ValueError('Only the three exact current SafeBox paths and distinct manifest GUIDs are accepted')
    result = dict(kind='owned_current_world_box_positions_v1', status='refused', positions=[],
        source_pins=pins, process_memory_written=False, native_methods_invoked=False, packets_sent=False,
        snapshot_is_atomic=False, server_coordinate_provider_created=False, interaction_permission_inferred=False,
        authored_position_used_as_runtime_position=False, identity_fields_roots_and_frame_rechecked=False)
    facts, identities, paths = {}, {}, {}
    calls = size = identity_calls = 0
    start_calls, start_bytes = session.calls, session.bytes_read

    def stable(at, count):
        nonlocal calls, size
        if (type(at) is not int or count not in (4, 8, 12, 16)
                or not 0x10000 <= at <= (1 << 47) - count):
            raise ValueError('The fixed box position span is invalid')
        if calls + 2 > MAX_READ_CALLS or size + count * 2 > MAX_READ_BYTES:
            raise ValueError('The fixed box position read budget is exhausted')
        calls, size = calls + 2, size + count * 2
        return session.stable(at, count)

    def fact(at, count):
        raw = stable(at, count)
        if facts.setdefault((at, count), raw) != raw:
            raise ValueError('A current box position field changed')
        return raw

    def pointer(at):
        return address(struct.unpack('<Q', fact(at, 8))[0])

    def path_of(at):
        value = object_path(at)
        if type(value) is not str or not 0 < len(value) <= 4096 or paths.setdefault(at, value) != value:
            raise ValueError('A current box position object path changed')
        return value

    def typed(at, expected):
        nonlocal identity_calls
        if identity_calls >= MAX_IDENTITY_CALLS:
            raise ValueError('The fixed box position identity budget is exhausted')
        identity_calls += 1
        at = address(at)
        row = object_identity(at, expected)
        if (type(row) is not dict or address(row['address']) != at or expected not in row['class_ancestry']
                or row['is_cdo'] is not False or type(row['serial']) is not int or row['serial'] <= 0
                or type(row['object_index']) is not int or row['object_index'] < 0
                or identities.setdefault((at, expected), deepcopy(row)) != row):
            raise ValueError('A typed initialized box position identity changed')
        path_of(at)
        return row

    def location(at):
        packed = struct.unpack('<Q', fact(at + 0x180, 8))[0]
        root = address(sources.packed_reference.decode_direct_reference(packed, source_pins=pins))
        root_identity = typed(root, 'SceneComponent')
        if address(root_identity['outer_address']) != at:
            raise ValueError('The current SceneComponent root belongs to another Actor')
        if struct.unpack('<H', fact(root + 0x240, 4)[:2])[0] != 0xffff:
            raise ValueError('The current SceneComponent translation requires an unsupported decoder')
        xyz = struct.unpack('<3f', fact(root + 0x220, 16)[:12])
        if not all(math.isfinite(value) for value in xyz):
            raise ValueError('The current root world translation is nonfinite')
        return xyz, {key: root_identity[key] for key in ('object_index', 'serial')}

    try:
        if (getattr(session, 'module_sha256', None) != SHIPPING_SHA256
                or getattr(session, 'module_size', None) != IMAGE_SIZE or final_recheck() is not True):
            raise ValueError('The current owned position roots or image cannot be rechecked')
        base, pc, pawn = map(address, (module_base, pc_address, pawn_address))
        if base + IMAGE_SIZE > 1 << 47:
            raise ValueError('The current position image extent is invalid')
        pc_identity, pawn_identity = typed(pc, 'PlayerController'), typed(pawn, 'Pawn')
        level = address(pc_identity['outer_address'])
        if address(pawn_identity['outer_address']) != level:
            raise ValueError('The selected PC and Pawn do not share the current Level')
        typed(level, 'Level')
        world = pointer(level + 0xa8)
        typed(world, 'World')
        member = membership_observation
        if (type(member) is not dict or member.get('kind') != 'owned_current_world_actor_membership_v1'
                or member.get('identity_fields_roots_and_process_rechecked') is not True
                or member.get('current_world_path') != path_of(world)):
            raise ValueError('The current PC/Pawn owning World membership witness is unavailable')
        members = {row['actor_path']: row for row in member['actors']}
        origin = struct.unpack('<3i', fact(world + 0x640, 12))
        gate = struct.unpack('<i', fact(base + 0x1e4dc898, 4))[0]
        default = struct.unpack('<3i', fact(base + 0x1e2f8028, 12))
        pawn_xyz, pawn_root_identity = location(pawn)
        pawn_protocol, branch, pawn_unrounded = _position_frame(pawn_xyz, origin, gate, default)
        authored, positions = sources.authored_positions(), []
        for target in targets:
            row = dict(guid=target.guid, actor_path=target.actor_path, class_path=target.class_path,
                status='current_instance_not_found', identity_fields_and_frame_rechecked=False)
            if target.address is not None:
                actor = address(target.address)
                identity = typed(actor, 'Actor')
                actor_level = address(identity['outer_address'])
                typed(actor_level, 'Level')
                if (path_of(actor) != target.actor_path
                        or path_of(address(identity['class_address'])) != target.class_path
                        or path_of(actor_level) != manifest[target.actor_path]['level_path']
                        or pointer(actor_level + 0xa8) != world):
                    raise ValueError('The current SafeBox path, class or owning World differs')
                if members.get(target.actor_path, {}).get('current_loaded_visible_level_membership_observed') is True:
                    xyz, root_identity = location(actor)
                    protocol, row_branch, unrounded = _position_frame(xyz, origin, gate, default)
                    row.update(status='observed', root_world_translation_xyz=list(xyz),
                        protocol_zero_origin_xyz=protocol, world_origin_xyz=list(origin), world_path=path_of(world),
                        unrounded_zero_origin_xyz=unrounded,
                        native_protocol_position_reproduced=protocol is not None,
                        native_rebase_branch=row_branch, authored_root_xyz=list(authored[target.actor_path]),
                        actor_weak_identity={key: identity[key] for key in ('object_index', 'serial')},
                        root_weak_identity=root_identity,
                        authored_position_equal=(tuple(protocol) == authored[target.actor_path]
                            if protocol is not None else None),
                        authored_delta_xyz=([protocol[i] - authored[target.actor_path][i] for i in range(3)]
                            if protocol is not None else None),
                        identity_fields_and_frame_rechecked=True)
                else:
                    row['status'] = 'current_loaded_visible_membership_unqualified'
            positions.append(row)
        if final_recheck() is not True:
            raise ValueError('The final owned position root recheck refused')
        for (at, count), old in facts.items():
            if stable(at, count) != old:
                raise ValueError('A current box position field changed before publication')
        for (at, expected), old in tuple(identities.items()):
            if typed(at, expected) != old:
                raise ValueError('A current box position identity changed before publication')
        if any(object_path(at) != old for at, old in paths.items()) or globals()['source_pins']() != pins:
            raise ValueError('A current position path or source changed before publication')
        if (getattr(session, 'module_sha256', None) != SHIPPING_SHA256
                or getattr(session, 'module_size', None) != IMAGE_SIZE):
            raise ValueError('The current position image identity changed before publication')
        result.update(status='observed' if all(row['status'] == 'observed' for row in positions) else 'partial',
            positions=positions, pawn_root_world_translation_xyz=list(pawn_xyz),
            pawn_weak_identity={key: pawn_identity[key] for key in ('object_index', 'serial')},
            pawn_root_weak_identity=pawn_root_identity,
            pawn_protocol_zero_origin_xyz=pawn_protocol, world_origin_xyz=list(origin),
            pawn_unrounded_zero_origin_xyz=pawn_unrounded,
            pawn_native_protocol_position_reproduced=pawn_protocol is not None,
            native_rebase_branch=branch, rebase_gate_i32=gate, default_origin_xyz=list(default),
            identity_fields_roots_and_frame_rechecked=True)
    except (ValueError, OSError, KeyError, TypeError, OverflowError) as error:
        result.update(status='refused', positions=[], reason=str(error))
    result.update(position_read_calls=calls, position_read_bytes=size, identity_calls=identity_calls,
        shared_read_calls=session.calls - start_calls, shared_read_bytes=session.bytes_read - start_bytes)
    return result
