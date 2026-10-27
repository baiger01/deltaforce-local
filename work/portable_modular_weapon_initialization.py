"""Pure Modular Actor/complete manager initialization from one frozen ticket.

No transport, process, object constructor or active-weapon selection is used.
Slot values require a separately rechecked typed manager observation. The
unclosed business-position to native equipment-position mapping is omitted.
"""
from dataclasses import dataclass
import hashlib
import json
import re

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from export_portable_modular_weapon_schema import ROOT, OUTPUT, derive
from owned_weapon_values_codec import (CLIENT_SHA, actor_schema_binding,
    ACTOR_SCHEMA_PATH, ACTOR_SCHEMA_SHA256, schema_binding as value_schema_binding,
    manager_weapon_bindings_update, replicate_owner_update, WeaponPair)
from portable_carried_weapon_selection import select, source_pins as selection_source_pins
from portable_map_owned_weapon import (OwnedWeaponStage, empty_hand_initialization,
    weapon_info_update, active_weapon_update)
from portable_source_guard import cached_qualification

SCHEMA_SHA256 = '4399d3865172dd5b07e9355788b06032c4d82a658d48a65a9f90e9c0658e51c6'


@cached_qualification(ROOT, extra_pins=lambda: {
    OUTPUT.relative_to(ROOT).as_posix(): SCHEMA_SHA256,
    **{p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in (
        'work/portable_modular_weapon_initialization.py', 'work/export_portable_modular_weapon_schema.py',
        'work/portable_source_guard.py')}})
def schema_binding():
    raw = OUTPUT.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The current Modular Actor schema changed')
    actual = json.loads(raw)
    if actual != derive():
        raise ValueError('The Modular schema differs from the actual observed class')
    for relative, expected in actual['sources'].items():
        path = (ROOT/relative).resolve()
        if not path.is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('The Modular source changed: '+relative)
    return actual


def source_pins():
    actual = schema_binding()
    pins = dict(actual['sources'])
    from weapon_actor_network_role import source_pins as role_pins
    pins.update(role_pins())
    from portable_melee_weapon import source_pins as melee_pins
    pins.update(melee_pins())
    for relative, digest in selection_source_pins().items():
        if relative in pins and pins[relative] != digest:
            raise ValueError('Modular source groups disagree: '+relative)
        pins[relative] = digest
    pins[OUTPUT.relative_to(ROOT).as_posix()] = SCHEMA_SHA256
    pins[ACTOR_SCHEMA_PATH] = ACTOR_SCHEMA_SHA256
    from weapon_native_default_slot import native_default_slot
    for relative, expected in native_default_slot()['sources'].items():
        if relative in pins and pins[relative] != expected:
            raise ValueError('Native slot policy source groups disagree: '+relative)
        pins[relative] = expected
    for relative in ('work/portable_modular_weapon_initialization.py',
            'work/export_portable_modular_weapon_schema.py', 'work/owned_weapon_values_codec.py',
            'work/owned_weapon_fast_array_codec.py', 'work/portable_map_owned_weapon.py',
            'work/weapon_native_default_slot.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


@dataclass(frozen=True)
class ManagerSlotObservation:
    value: int
    report_raw: bytes
    report_sha256: str
    trial_report_sha256: str


def manager_slot_from_report(raw, *, expected_sha256, expected_trial_report_sha256):
    """Bind a byte to a caller-selected exact owned-trial observation, never a default."""
    if (type(raw) is not bytes or not 0 < len(raw) <= 32*1024*1024 or
            any(type(d) is not str or re.fullmatch('[0-9a-f]{64}', d) is None
                for d in (expected_sha256, expected_trial_report_sha256)) or
            hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise ValueError('An exact bounded manager slot observation is required')
    report = json.loads(raw)
    if (type(report) is not dict or report.get('kind') != 'owned_weapon_scoped_readonly_state_v1' or
            report.get('status') not in ('observed', 'partial') or report.get('client_sha256') != CLIENT_SHA or
            report.get('trial_report_sha256') != expected_trial_report_sha256 or
            not all(report.get(k) is True for k in (
                'identities_and_fields_rechecked', 'selected_roots_rechecked', 'process_identity_rechecked')) or
            any(report.get(k) is not False for k in (
                'process_memory_written', 'native_methods_invoked', 'native_layouts_constructed',
                'packets_sent', 'code_sampled', 'historical_process_pointers_reused'))):
        raise ValueError('A rechecked current-trial readonly manager scope is required')
    matches = [r for r in report.get('objects', ()) if r.get('scope') == 'manager']
    if len(matches) != 1:
        raise ValueError('One exact typed manager scope is required')
    manager = matches[0]
    schema = schema_binding()
    identity = manager.get('identity', {})
    slot = manager.get('state', {}).get('weapon_slot', {})
    before = schema['manager']['slot']
    field = slot.get('field', {})
    if (manager.get('status', 'observed') != 'observed' or
            manager.get('class_path') != schema['manager']['class_path'] or
            identity.get('name') != 'WeaponManager' or identity.get('is_cdo') is not False or
            type(slot.get('value')) is not int or not 0 <= slot['value'] <= 255 or
            field.get('name') != 'WeaponSlot' or
            (field.get('storage_offset'), field.get('element_bytes'), field.get('field_vtable_rva')) !=
                (before['storage_offset'], before['storage_bytes'], int(before['property_vtable_rva'], 16))):
        raise ValueError('The slot is not the actual current manager byte declaration')
    return ManagerSlotObservation(slot['value'], raw, expected_sha256, expected_trial_report_sha256)


@dataclass(frozen=True)
class WeaponBinding:
    actor_guid: int
    unique_id: int
    weapon_rec_id: int
    inventory_gid: int | None
    pair: WeaponPair | None


@dataclass(frozen=True)
class ModularWeaponInitialization:
    bindings: tuple[WeaponBinding, ...]
    stages: tuple[OwnedWeaponStage, ...]
    qualification: dict


def _actor_content(schema, *, pawn_guid, unique_id, gun, slot):
    fields = schema['actor']['fields']
    values = [('Owner', pawn_guid, None), ('WeaponID', gun.weapon_rec_id, 64),
              ('WeaponGuid', gun.inventory_gid, 64)]
    if slot is not None:
        values.append(('WeaponSlot', slot, 8))
    values.extend((('ServerWeaponIdentity', unique_id, 32), ('CharacterOwner', pawn_guid, None)))
    writer = BitWriter()
    writer.write_bool(False)
    from weapon_actor_network_role import write_network_role
    write_network_role(writer)
    for name, value, width in values:
        field = fields[name]
        writer.write_packed_int(field.get('ordinary_handle', field.get('inner_handle')))
        if width is None:
            writer.write_packed_int(value)
        else:
            writer.write_bits(value, width)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def initialize(ticket, *, pawn_guid, empty_hand_guid, gun_allocations,
        manager_component_guid, replicate_component_guid, pawn_open_acknowledged,
        weapon_opens_acknowledged, initial_state_is_fresh=False,
        manager_binding_snapshot_complete=False, used_unique_ids=(), manager_slot=None,
        native_slot_policy=None, initial_active_inventory_gid=None, schema=None,
        melee_actor_guid=None):
    """Return Actor stages, replicate Owner and complete parallel binding tables.

    gun_allocations contains the exact complete (frozen inventory GID, Actor
    GUID) set. Stages require actual opens/base content and every previous stage
    receipt. This replaces the older EmptyHand-only initialization as one whole
    transaction; it must not be appended after a separately generated partial
    manager list. No equipment position is inferred. The separate native slot
    policy first assigns the manager's constructor default and requires its
    receipt before any weapon Actor. It creates complete WeaponInfo pairs and
    finally selects the explicit equipped GID, or EmptyHand when omitted.
    This is a local server choice, not the native GetDefaultWeapon score result.
    """
    actual = schema_binding()
    if schema is not None and schema != actual:
        raise ValueError('Changed Modular Actor initialization schema')
    guns = select(ticket).guns
    from portable_melee_weapon import select as select_melee, initial_content as melee_content
    melee = select_melee(ticket) if melee_actor_guid is not None else None
    if melee_actor_guid is not None and melee is None:
        raise ValueError('A melee Actor requires its exact frozen equipped item')
    if (type(gun_allocations) is not tuple or len(gun_allocations) != len(guns) or
            len(guns) > 2 or any(type(r) is not tuple or len(r) != 2 or
                any(type(v) is not int for v in r) for r in gun_allocations)):
        raise ValueError('The complete frozen gun-to-Actor allocation is required')
    by_gid = dict(gun_allocations)
    if len(by_gid) != len(gun_allocations) or set(by_gid) != {g.inventory_gid for g in guns}:
        raise ValueError('The exact complete equipped inventory GIDs are required')
    if initial_active_inventory_gid is not None and (
            type(initial_active_inventory_gid) is not int or initial_active_inventory_gid not in by_gid or
            native_slot_policy is None):
        raise ValueError('Local active selection requires an exact frozen equipped GID and explicit slot policy')
    guids = (pawn_guid, empty_hand_guid, manager_component_guid, replicate_component_guid,
             *(by_gid[g.inventory_gid] for g in guns),
             *((melee_actor_guid,) if melee is not None else ()))
    if (any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1 for g in guids) or
            len(set(guids)) != len(guids) or pawn_open_acknowledged is not True or
            weapon_opens_acknowledged is not True or initial_state_is_fresh is not True or
            manager_binding_snapshot_complete is not True):
        raise ValueError('Distinct current acknowledged weapon Actors/components and a fresh complete set are required')
    slot_initialization = None
    if native_slot_policy is not None:
        from weapon_native_default_slot import (qualify_native_default_slot_policy,
            build_native_default_slot_update)
        if manager_slot is not None:
            raise ValueError('Sampled manager state and an explicit native-default assignment are exclusive')
        qualify_native_default_slot_policy(native_slot_policy)
        slot_initialization = build_native_default_slot_update(
            pawn_guid=pawn_guid, manager_component_guid=manager_component_guid,
            explicit_native_default_initialization=True,
            pawn_content_receipted=True, component_metadata_receipted=True, policy=native_slot_policy)
        slot = slot_initialization.value
    elif manager_slot is not None:
        if type(manager_slot) is not ManagerSlotObservation or manager_slot != manager_slot_from_report(
                manager_slot.report_raw, expected_sha256=manager_slot.report_sha256,
                expected_trial_report_sha256=manager_slot.trial_report_sha256):
            raise ValueError('WeaponSlot requires the current typed manager observation')
        slot = manager_slot.value
    else:
        slot = None
    empty = empty_hand_initialization(ticket, pawn_guid=pawn_guid, weapon_guid=empty_hand_guid,
        manager_component_guid=manager_component_guid, replicate_component_guid=replicate_component_guid,
        pawn_open_acknowledged=True, weapon_open_acknowledged=True, weapon_slot=slot,
        initial_state_is_fresh=True, manager_binding_snapshot_complete=True, used_unique_ids=used_unique_ids)
    bindings = [WeaponBinding(empty_hand_guid, empty.unique_id, empty.weapon_rec_id, None, empty.pair)]
    opens = (pawn_guid, empty_hand_guid, *(by_gid[g.inventory_gid] for g in guns),
             *((melee_actor_guid,) if melee is not None else ()))
    stages = []
    if slot_initialization is not None:
        stages.append(OwnedWeaponStage('manager_slot', pawn_guid, None,
            (slot_initialization.update,), None, opens))
    stages.append(OwnedWeaponStage('empty_hand_actor', empty_hand_guid,
        empty.stages[0].actor_content, (), len(stages)-1 if stages else None, opens))
    used = set(used_unique_ids) | {empty.unique_id}
    baseline = value_schema_binding()
    common = [int(k) for k, path in baseline['fast_class_path']['ids_to_paths'].items()
              if path == actual['actor']['class_path']]
    if len(common) != 1:
        raise ValueError('One source-qualified Modular common class ID is required')
    switch = next(e['value'] for e in baseline['switch_type']['entries']
                  if e['name'] == 'EWeaponSwitchType::Default')
    snapshot_sha = hashlib.sha256(ticket.loadout_snapshot).hexdigest()
    for gun in guns:
        seed = json.dumps(['portable_modular_identity_v1', ticket.cookie, ticket.player_id,
            ticket.room_id, snapshot_sha, gun.inventory_gid], separators=(',', ':')).encode()
        for counter in range(len(used)+2):
            unique = int.from_bytes(hashlib.sha256(seed+counter.to_bytes(4, 'little')).digest()[:4],
                                    'little') & 0x7fffffff
            if unique and unique not in used:
                break
        else:
            raise ValueError('No bounded unused local Modular identity was found')
        used.add(unique)
        pair = None if slot is None else WeaponPair(False, switch, unique, common[0], 0, slot)
        actor = by_gid[gun.inventory_gid]
        bindings.append(WeaponBinding(actor, unique, gun.weapon_rec_id, gun.inventory_gid, pair))
        stages.append(OwnedWeaponStage('modular_actor', actor,
            _actor_content(actual, pawn_guid=pawn_guid, unique_id=unique, gun=gun, slot=slot),
            (), len(stages)-1, opens))
    if melee is not None:
        seed = json.dumps(['portable_melee_identity_v1', ticket.cookie, ticket.player_id,
            ticket.room_id, snapshot_sha, melee.inventory_gid], separators=(',', ':')).encode()
        for counter in range(len(used)+2):
            unique = int.from_bytes(hashlib.sha256(seed+counter.to_bytes(4, 'little')).digest()[:4],
                                    'little') & 0x7fffffff
            if unique and unique not in used:
                break
        else:
            raise ValueError('No distinct local melee runtime identity is available')
        pair = None if slot is None else WeaponPair(False, switch, unique,
            melee.path_id, 0, slot, path_type=melee.path_type)
        bindings.append(WeaponBinding(melee_actor_guid, unique, melee.weapon_rec_id,
            melee.inventory_gid, pair))
        stages.append(OwnedWeaponStage('melee_actor', melee_actor_guid,
            melee_content(melee, pawn_guid=pawn_guid, unique_id=unique, slot=slot),
            (), len(stages)-1, opens))
    owner = replicate_owner_update(baseline, pawn_guid=pawn_guid,
        component_guid=replicate_component_guid, pawn_open_acknowledged=True)
    manager = manager_weapon_bindings_update(actor_schema_binding(), pawn_guid=pawn_guid,
        component_guid=manager_component_guid,
        bindings=tuple((b.actor_guid, b.unique_id, b.weapon_rec_id) for b in bindings),
        empty_hand_guid=empty_hand_guid, actor_opens_acknowledged=True)
    for name, update in (('replicate_owner', owner), ('manager_bindings', manager)):
        stages.append(OwnedWeaponStage(name, pawn_guid, None, (update,), len(stages)-1, opens))
    if slot is not None:
        info = weapon_info_update(baseline, pawn_guid=pawn_guid,
            component_guid=replicate_component_guid,
            changed_pairs=tuple((index, b.pair) for index, b in enumerate(bindings, 1)),
            array_key=1, base_key=-1, deleted_ids=())
        stages.append(OwnedWeaponStage('weapon_info', pawn_guid, None, (info,), len(stages)-1, opens))
    active = None
    if slot_initialization is not None:
        active = (bindings[0] if initial_active_inventory_gid is None else
            next(b for b in bindings if b.inventory_gid == initial_active_inventory_gid))
        update = active_weapon_update(baseline, pawn_guid=pawn_guid,
            component_guid=replicate_component_guid, pair=active.pair)
        stages.append(OwnedWeaponStage('active_weapon', pawn_guid, None, (update,), len(stages)-1, opens))
    return ModularWeaponInitialization(tuple(bindings), tuple(stages),
        dict(snapshot_sha256=snapshot_sha, actor_schema_sha256=SCHEMA_SHA256,
            binding_count=len(bindings), identity_is_inventory_gid=False,
            identity_origin='ticket_cookie_and_exact_snapshot_and_inventory_gid_local_nonzero_uint31',
            manager_lists_are_complete_replacements=True, equip_position_emitted=False,
            weapon_info_created=slot is not None, active_weapon_overridden=active is not None,
            weapon_slot_origin=('explicit_source_qualified_native_default_assignment'
                if slot_initialization is not None else
                None if slot is None else 'rechecked_current_typed_manager'),
            weapon_slot_report_sha256=None if manager_slot is None else manager_slot.report_sha256,
            current_value_observed=manager_slot is not None,
            local_initialization_policy=(None if slot_initialization is None else dict(
                kind='explicit_source_qualified_native_default_slot',
                value=slot_initialization.value,
                contract_sha256=native_slot_policy.contract_sha256,
                manager_assignment_stage=0,
                assignment_ack_required_before_weapon_actors=True)),
            initial_active_inventory_gid=None if active is None else active.inventory_gid,
            initial_active_actor_guid=None if active is None else active.actor_guid,
            active_selection_origin=(None if active is None else
                'source_qualified_empty_hand_fallback' if active.inventory_gid is None else
                'explicit_caller_local_initial_weapon_selection'),
            native_default_active_result_claimed=False,
            selected_melee_actor_created=melee is not None, native_gameplay_verified=False,
            melee_actor_guid=melee_actor_guid,
            required_gate='Actual opens/base contents and each previous stage own full-send positive ACK',
            gaps=('business_position_to_actor_equip_position',
                  'current_native_default_active_score_not_observed') +
                 (() if melee is not None else ('selected_melee_actor_mapping',)) +
                 (() if active is not None else ('initial_active_weapon_choice',))))
