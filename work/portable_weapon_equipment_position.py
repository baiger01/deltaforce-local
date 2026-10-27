"""Frozen SOL gun positions through the native Actor RepNotify/Core setter.

This emits an ordinary replicated property, with no process access or direct
Core/recipe mutation. The scheduler must receipt all physical recipes first,
then receipt these position stages before selecting Active or its owner ring.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter
from portable_carried_weapon_selection import select, source_pins as selection_pins
from portable_modular_weapon_initialization import (
    ModularWeaponInitialization, WeaponBinding, schema_binding as actor_schema,
    source_pins as initialization_pins)
from portable_modular_weapon_recipe import (
    build as recipes, _packet_preflight, source_pins as recipe_pins)

ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/map-system-audit-20261018/'
PINS = {
    'native-owned-weapon-input-x-weapon-and-hud-bodies-v1.json':
        '349a8b88e7c9c6dc5cedae77e898d2d3d7a0b11442b80b6d9fe9054f200c8c6a',
    'native-owned-weapon-position-interface-vtable-v1.json':
        '8df20abc03d313c3a2c887a134e1ad221566a0ae8743566765da4a4791b76d8d',
    'native-owned-weapon-equip-position-getter-body-v1.json':
        'c501fb8b15b941519b52c70cd794c436917c034a8bf3d2a79f145f75d7d9940d',
    'native-owned-weapon-dfm-equip-position-vslot-v1.json':
        'b0e7b545e87b84edb8edd9af7e814603a537a4e6821bf490100bd5a0929a86ce',
    'native-owned-weapon-position-actor-lookup-body-v1.json':
        'bd2f132565d99151fe9ddb9cdd112135db9a07376e513124df6ef59b2c26771c',
    'native-owned-weapon-id-and-equipment-late-notify-bodies-v1.json':
        'ebe5bdcd61d76069fbf9f459b29aee67335b440818fd67535944404970c68a11',
    'native-owned-weapon-interface-init-setters-v1.json':
        'eaa37b6fff2ffef384aa41e362d6aa85bb6bbefe60275c0e0dac21bf7b097798',
    'native-owned-weapon-position-global-lua-v1.json':
        'd4b732d24dba5fe646399a2c69916e0dfe9fc6f1cfa3464841c7e3972474ff53',
    'native-owned-weapon-position-data-core-access-v1.json':
        'ff0113c36f84ab862f11f2d64f93037333a2c46957a58417d7c17a3d322a1db0',
    'native-owned-weapon-position-data-type-v1.json':
        'ceb6abf99fb74f8f9e65a25b6178868bf165cb252a75e5ce254456bb5de2efdb',
    'native-owned-weapon-position-core-constructor-v1.json':
        '8ce6367e732e550f49620f9b73839ca8af2c3628853f05319bfd464600252a3e',
    'native-owned-weapon-position-data-core-interface-v1.json':
        'bd37fd62108ee796e9df64fa34dfaf4c584c732c0f3b0cf58d017bcb2863dfdb',
    'native-owned-weapon-position-core-getter-v1.json':
        '8be5464ee01609472affacad0e37c7b476709cc77746b9b7401f974f4252d11d',
}


@lru_cache(maxsize=1)
def _contract_raw():
    documents = {}
    for name, digest in PINS.items():
        raw = (ROOT / BASE / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Changed source-qualified equipment position source: ' + name)
        documents[name] = json.loads(raw)

    instructions = {row['rva']: row for doc in documents.values()
        for function in doc.get('functions', ()) for row in function['instructions']}

    def native(at, expected):
        row = instructions.get(at)
        if row is None or row['bytes'] != expected:
            raise ValueError('Changed native equipment position instruction: ' + at)
        return row

    native('0xb7d0ed8', '83c26f')
    native('0xb7d0ee9', 'ff90e8000000')
    native('0xb7d1817', '4183c06f')
    native('0xb7cf291', 'ff9058010000')
    native('0x56193a9', 'ff9020040000')
    native('0x58bb338', 'ff9058020000')
    native('0x58dadc3', '8b9348080000')
    native('0x58dadc9', '488d8b88030000')
    native('0x58dadd3', '41b001')
    native('0x58dadd6', 'ff90b8040000')
    native('0x58f7039', '4c8db7c0040000')
    native('0x58f7043', '418916')
    native('0x58f7056', 'e8259b89fc')
    native('0x58f70f3', '41898728040000')
    native('0x2190b98', 'e853fb2100')
    native('0x21adc61', 'e80ad02000')
    native('0x219357a', '89bb28040000')
    native('0x21935d3', '488d05a6cc7713')
    native('0x21935da', '48898310040000')
    native('0x21bba7b', '488d81f0fbffff')
    native('0x21bbaba', '8b4318')
    type_literals = {ref.get('immutable_literal_candidate')
        for doc in documents.values() for function in doc.get('functions', ())
        for row in function['instructions'] for ref in row.get('rip_references', ())}
    if not {'GPWeaponDataComponentCore', 'GPWeaponDataInterface'} <= type_literals:
        raise ValueError('The actual Core type and native interface no longer match')
    manager = documents['native-owned-weapon-position-interface-vtable-v1.json']['vtables'][0]
    actor = documents['native-owned-weapon-dfm-equip-position-vslot-v1.json']['vtables'][0]
    core = documents['native-owned-weapon-position-data-core-interface-v1.json']['vtables'][0]
    if (next(e['target_rva'] for e in manager['entries'] if e['slot'] == '0xe8') != '0x56192d0' or
            actor['rva'] != '0x16ee9570' or
            next(e['target_rva'] for e in actor['entries'] if e['slot'] == '0x98') != '0x58f6fa0' or
            core['rva'] != '0x15910280' or
            next(e['target_rva'] for e in core['entries'] if e['slot'] == '0x258') != '0x21bba60'):
        raise ValueError('The actual equipment lookup/setter virtual slots changed')
    source = next(s for s in documents['native-owned-weapon-position-global-lua-v1.json']['sources']
        if s['source_name'] == '@DFMGlobalConst.lua')
    listing = source['functions'][0]['listing']
    positions = {}
    for name in ('MainWeaponLeft', 'MainWeaponRight'):
        index = next(n for n, line in enumerate(listing) if "='" + name + "'" in line)
        value = re.search(r'K[0-9]+=([0-9]+)$', listing[index + 1])
        if not value or 'SETTABLE' not in listing[index + 2]:
            raise ValueError('The original business position assignment changed')
        positions[name] = int(value.group(1))
    numeric_base = bytes.fromhex(instructions['0xb7d0ed8']['bytes'])[-1]
    actual_actor = actor_schema()
    field = actual_actor['actor']['fields']['WeaponEquipPosition']
    if (set(positions.values()) != {numeric_base, numeric_base + 1} or
            field['storage_offset'] != 0x388 + 0x4c0 or
            (field['wire_bits'], field['ordinary_handle']) != (32, 19)):
        raise ValueError('Frozen business positions and native property grammar disagree')
    result = dict(kind='source_qualified_sol_gun_equipment_position_v1',
        client_sha256=actual_actor['client_sha256'],
        sources={BASE + name: digest for name, digest in PINS.items()},
        business_positions=positions, numeric_key_base=numeric_base,
        lua_source=dict(name=source['source_name'], sha256=source['lua_sha256'], function='0'),
        actor_property=field,
        lookup=dict(manager_interface_slot='0xe8', actor_interface_slot='0x420',
            data_core_interface_slot='0x258'),
        on_rep=dict(rva='0x58dad70', setter_rva='0x58f6fa0',
            interface_offset=0x388, setter_virtual_slot='0x4b8', forced_notify=True,
            actor_relative_equip_position_offset=0x4c0,
            data_core_equip_position_offset=0x428, data_core_type='GPWeaponDataComponentCore'),
        core_getter=dict(native_type='GPWeaponDataComponentCore', constructor_rva='0x2193540',
            interface_offset=0x410, interface_vtable_rva='0x15910280',
            virtual_slot='0x258', method_rva='0x21bba60', interface_storage_offset=0x18,
            storage_offset=0x428),
        data_core_getter_field_qualified=True, actual_current_core_vtable_observed=False,
        native_gameplay_verified=False,
        limitations=['The actual current Core identity and possible derived virtual override are not sampled.',
            'Position RepNotify must execute on a valid recipe-initialized Core.',
            'Only the two exact frozen SOL carried gun positions are supported.'])
    return json.dumps(result, sort_keys=True, separators=(',', ':')).encode()


def schema_binding():
    return json.loads(_contract_raw())


def source_pins():
    pins = {}
    for group in (schema_binding()['sources'], selection_pins(), initialization_pins(), recipe_pins()):
        for path, digest in group.items():
            if path in pins and pins[path] != digest:
                raise ValueError('Equipment position source groups disagree')
            pins[path] = digest
    pins['work/portable_weapon_equipment_position.py'] = hashlib.sha256(
        (ROOT / 'work/portable_weapon_equipment_position.py').read_bytes()).hexdigest()
    return pins


@dataclass(frozen=True)
class EquipmentPositionActorUpdate:
    inventory_gid: int
    weapon_rec_id: int
    actor_guid: int
    equip_position: int
    actor_content: ActorContentBlock
    snapshot_sha256: str
    maximum_packet_bytes: int
    actual_receipts_observed: bool = False

    @property
    def qualification(self):
        return dict(native_gameplay_verified=False, internal_ready_flags_emitted=False,
            native_repnotify_core_sync_qualified=True, recipe_fields_replaced=False,
            preflight_only=not self.actual_receipts_observed,
            actual_receipts_observed=self.actual_receipts_observed,
            required_gate='Recipe positive ACK, then position positive ACK before Active/timeline')


def build(ticket, *, initialization, recipe_updates, known_actor_guids,
        actor_opens_acknowledged, identity_and_owner_acknowledged,
        complete_recipes_acknowledged, initial_state_is_fresh, max_packet_bytes=1024):
    if any(flag is not True for flag in (actor_opens_acknowledged,
            identity_and_owner_acknowledged, complete_recipes_acknowledged, initial_state_is_fresh)):
        raise ValueError('Current Actor identity/owner and complete recipe receipts are required')
    return _project_equipment_positions(ticket, initialization=initialization,
        recipe_updates=recipe_updates, known_actor_guids=known_actor_guids,
        max_packet_bytes=max_packet_bytes, actual_receipts_observed=True)


def project_equipment_positions(ticket, *, initialization, recipe_updates,
        known_actor_guids, max_packet_bytes=1024):
    """Validate and encode a frozen bootstrap plan without asserting live receipts."""
    return _project_equipment_positions(ticket, initialization=initialization,
        recipe_updates=recipe_updates, known_actor_guids=known_actor_guids,
        max_packet_bytes=max_packet_bytes, actual_receipts_observed=False)


def _project_equipment_positions(ticket, *, initialization, recipe_updates,
        known_actor_guids, max_packet_bytes, actual_receipts_observed):
    if type(max_packet_bytes) is not int or not 1 <= max_packet_bytes <= 1024:
        raise ValueError('The current complete packet budget must be at most 1024 bytes')
    if (type(initialization) is not ModularWeaponInitialization or
            type(initialization.bindings) is not tuple or
            not 1 <= len(initialization.bindings) <= 4 or
            any(type(row) is not WeaponBinding for row in initialization.bindings)):
        raise ValueError('The exact complete frozen initialization is required')
    contract = schema_binding()
    selection = select(ticket)
    digest = hashlib.sha256(ticket.loadout_snapshot).hexdigest()
    if initialization.qualification.get('snapshot_sha256') != digest:
        raise ValueError('The initialization belongs to another frozen loadout')
    melee_guid = initialization.qualification.get('melee_actor_guid')
    bindings = tuple(b for b in initialization.bindings[1:] if b.actor_guid != melee_guid)
    guns = {gun.inventory_gid: gun for gun in selection.guns}
    if (initialization.bindings[0].inventory_gid is not None or len(bindings) != len(guns) or
            len({row.inventory_gid for row in bindings}) != len(bindings) or
            set(row.inventory_gid for row in bindings) != set(guns) or
            any(row.weapon_rec_id != guns[row.inventory_gid].weapon_rec_id for row in bindings)):
        raise ValueError('The exact frozen gun receiver identities must match the full initialization')
    allocations = tuple((row.inventory_gid, row.actor_guid) for row in bindings)
    exact_recipes = recipes(ticket, gun_allocations=allocations, known_actor_guids=known_actor_guids,
        actor_opens_acknowledged=True, identity_and_owner_acknowledged=True,
        initial_state_is_fresh=True, max_packet_bytes=1024)
    if type(recipe_updates) is not tuple or recipe_updates != exact_recipes:
        raise ValueError('The exact complete Actor recipes must precede equipment positions')
    field = contract['actor_property']
    result = []
    for row in bindings:
        position = guns[row.inventory_gid].business_position
        if position not in contract['business_positions'].values():
            raise ValueError('No source-qualified native input position exists for this gun')
        writer = BitWriter(maximum_bits=max_packet_bytes * 8)
        writer.write_bool(False)
        writer.write_packed_int(field['ordinary_handle'])
        writer.write_bits(position, field['wire_bits'])
        writer.write_packed_int(0)
        block = ActorContentBlock(True, writer.to_bytes(), writer.bit_count)
        packet = _packet_preflight(block, max_packet_bytes)
        result.append(EquipmentPositionActorUpdate(row.inventory_gid, row.weapon_rec_id,
            row.actor_guid, position, block, digest, len(packet), actual_receipts_observed))
    return tuple(result)
