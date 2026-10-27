"""A source-qualified explicit native-default initialization, not a live slot read."""
from dataclasses import dataclass
import hashlib
import json
import struct

from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from export_gameplay_component_probe_schema import ROOT, BASE
from portable_modular_weapon_initialization import schema_binding, SCHEMA_SHA256
from portable_source_guard import cached_qualification

PINS = {
    'native-owning-weapon-manager-ctor.json':
        'c2c7e872b9ba155c1f9673ba8fb2cd19909c52cc00cda9a991be6c89f6f0f86f',
    'native-owned-weapon-multi-manager-class-getter-v1.json':
        '978ab6691afb08157b2b4d647f9d3536760d147bba6285650ef16964578a27ee',
    'native-owned-weapon-multi-constructor-and-notify-entry-v1.json':
        '5814a3789edcc4b6fd1a655fd41d8013dfc78711bdce02fda988e385763f22cb',
    'native-owned-weapon-multi-constructor-active-consumers-v1.json':
        '1ac853740eb499535e629a38ce9ae979bfc7d54de2f5ae5671892c09bd5af3fe',
    'native-owning-weapon-manager-uht-declarations.json':
        '0569188ebaa5b9549abad6a4e327fe2fc041e6f9de9566da75a6b175b925e313',
    'native-owning-weapon-cooked-character-emptyhand-defaults.json':
        'e935d6eab000430da6933ce6578e2fea6a40e9897849c14597c734bf742dc543',
}


def source_pins():
    from portable_modular_weapon_initialization import source_pins as modular_source_pins
    pins = dict(native_default_slot()['sources'])
    for relative, expected in modular_source_pins().items():
        if relative in pins and pins[relative] != expected:
            raise ValueError('Native default slot source groups disagree: '+relative)
        pins[relative] = expected
    relative = 'work/weapon_native_default_slot.py'
    pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


@cached_qualification(ROOT, extra_pins=lambda: {
    p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in (
        'work/weapon_native_default_slot.py', 'work/portable_source_guard.py')})
def native_default_slot():
    """Qualify the exact native class constructor value and local cooked override absence.

    The inherited SOL template and later runtime writes are separate facts. A
    caller may explicitly initialize this field to the native default, but
    must not describe the result as an observation of the current manager.
    """
    docs, pins = {}, {}
    for name, expected in PINS.items():
        relative = BASE+name
        raw = (ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Native default WeaponSlot source changed: '+name)
        docs[name] = json.loads(raw)
        pins[relative] = expected
    instructions = {i['rva']: i for doc in docs.values()
        for function in doc.get('functions', ()) for i in function['instructions']}
    for rva, opcode in {
        '0x55e179c': '33ed', '0x55e19b5': '4088abc8010000',
        '0x55e16a9': 'e8d2000000', '0x60c1eae': 'e9edf751ff',
        '0x60bf8f5': '488d05a4250000',
    }.items():
        if instructions.get(rva, {}).get('bytes') != opcode:
            raise ValueError('Native default WeaponSlot instruction changed: '+rva)
    rows = [r for c in docs['native-owning-weapon-manager-uht-declarations.json']['classes']
            for r in c['properties'] if r['name'] == 'WeaponSlot']
    if len(rows) != 1:
        raise ValueError('One actual native manager WeaponSlot declaration is required')
    row = rows[0]
    record = bytes.fromhex(row['record64_hex'])
    if (row['generation_low8'] != '0x0' or row['native_offset'] != '0x1c8' or
            row['array_dimension'] != 1 or struct.unpack_from('<Q', record, 40)[0] != 0):
        raise ValueError('Native WeaponSlot must be the non-enum uint8 property')
    cooked = docs['native-owning-weapon-cooked-character-emptyhand-defaults.json']['packages'][0]
    manager, = [r for r in cooked['selected_defaults'] if r['export']['name'] == 'WeaponManager']
    if (manager['tags_decoded'] is not True or manager['remaining_export_bytes'] != 4 or
            manager['export']['class_path'] != '/Script/GPGameplay.MultiWeaponManagerComponent' or
            manager['export']['template_path'] != '/Script/SOL.Default__SOLCharacter.WeaponManager' or
            any(p['name'] == 'WeaponSlot' for p in manager['properties'])):
        raise ValueError('The complete local cooked manager default changed')
    for source in cooked['source_files']:
        raw = (ROOT/source['relative_path']).read_bytes()
        if len(raw) != source['bytes'] or hashlib.sha256(raw).hexdigest() != source['sha256']:
            raise ValueError('The local cooked Pawn bytes changed')
        pins[source['relative_path']] = source['sha256']
    field = schema_binding()['manager']['slot']
    if (field['ordinary_handle'], field['storage_offset'], field['storage_bytes'],
            field['serializer_rva']) != (6, 0x1c8, 1, '0x10e8ec50'):
        raise ValueError('The actual manager byte receiver changed')
    return dict(kind='source_qualified_native_default_weapon_manager_slot_v1', value=0,
        class_path='/Script/GPGameplay.MultiWeaponManagerComponent', field='WeaponSlot',
        ordinary_handle=6, wire_bits=8, native_constructor_value_qualified=True,
        local_cooked_override=None, inherited_SOL_template_value_observed=False,
        current_value_observed=False, later_runtime_writes_excluded=False,
        use_requires_explicit_authoritative_native_default_initialization=True,
        actor_slot_must_copy_this_assigned_manager_value=True, sources=pins,
        actor_receiver_schema_sha256=SCHEMA_SHA256, native_gameplay_verified=False)


@dataclass(frozen=True)
class NativeDefaultSlotPolicy:
    value: int
    contract_sha256: str


def native_default_slot_policy():
    """Choose an explicit local initialization policy from the sealed native default."""
    source = native_default_slot()
    raw = (json.dumps(source, indent=2, sort_keys=True)+'\n').encode()
    return NativeDefaultSlotPolicy(source['value'], hashlib.sha256(raw).hexdigest())


def qualify_native_default_slot_policy(policy):
    """Recheck the source contract; a policy never becomes a sampled observation."""
    if (type(policy) is not NativeDefaultSlotPolicy or type(policy.value) is not int or
            type(policy.contract_sha256) is not str or policy != native_default_slot_policy()):
        raise ValueError('An exact source-qualified native-default slot policy is required')
    return native_default_slot()


@dataclass(frozen=True)
class NativeDefaultSlotInitialization:
    value: int
    update: DefaultSubobjectUpdate
    qualification: dict


def build_native_default_slot_update(*, pawn_guid, manager_component_guid,
        explicit_native_default_initialization=False,
        pawn_content_receipted=False, component_metadata_receipted=False, policy=None):
    """Explicitly assign the source native default before dependent Actor/pair values."""
    if (explicit_native_default_initialization is not True or
            pawn_content_receipted is not True or component_metadata_receipted is not True):
        raise ValueError('Explicit native-default initialization and actual parent/component receipts are required')
    source = native_default_slot() if policy is None else qualify_native_default_slot_policy(policy)
    raw = (json.dumps(source, indent=2, sort_keys=True)+'\n').encode()
    writer = BitWriter()
    writer.write_bool(False)
    writer.write_packed_int(source['ordinary_handle'])
    writer.write_bits(source['value'], source['wire_bits'])
    writer.write_packed_int(0)
    update = DefaultSubobjectUpdate(pawn_guid, manager_component_guid, 'WeaponManager',
        hashlib.sha256(raw).hexdigest(), writer.to_bytes(), writer.bit_count)
    return NativeDefaultSlotInitialization(source['value'], update,
        dict(source, property_assignment_is_explicit_local_policy=True,
             required_gate='Actual component metadata, then this assignment own full-send ACK, then dependent Actor/pair Slot',
             current_value_observed=False, packets_sent=False))
