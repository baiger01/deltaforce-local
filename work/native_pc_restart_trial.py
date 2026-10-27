"""Source-sealed restart setup and fail-closed saved association checks.

This module reads source files or caller-supplied metadata only. A positive
association check is a rechecked snapshot, never possession or gameplay proof.
It neither opens processes nor calls native functions, and returns no pointers.
"""
import hashlib
import json
import math
from pathlib import Path
import re
import struct

from dfserver.legacy_ds_actor_manifest import ActorManifest
from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest
from dfserver.legacy_ds_pc_restart_rpc import CLASS_PATH
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256
from native_pc_restart_profile import (
    SPEC_SHA256, qualified_pc_restart_sources, load_pc_restart_profile,
)


MAP_ID = 2201
PAWN_CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C'
TRIAL_MODULES = ('work/native_pc_restart_trial.py',
    'work/local_map_entry_completion.py', 'work/watch_client_log.py',
    'outputs/df-local-server/dfserver/legacy_ds_pc_receipt.py')
RECEIPT_SOURCE = 'work/evidence/map-entry-next-20261007/pc-reliable-receipt-native-order-review.json'
RECEIPT_SOURCE_SHA256 = '57be02ad9c2e4fc29c389b5a53cdb8ae647240e78650594596268929f9af4dd7'
GP_SOURCE = 'work/evidence/map-entry-next-20261005/native-gp-bind-gate-sources.json'
GP_SOURCE_SHA256 = '26f39eff25d9b8f495d2587888121d9f55d303b6d101e0da5df4db787cab8fa5'
FIRST_SOURCE = 'work/evidence/native-official-entry-new-source-20261006.json'
FIRST_SOURCE_SHA256 = '45b2aac764d6d1a78b170465dc4dda584522cda90c3e24fbeb455d10686e4c7f'
READY_SOURCE = 'work/evidence/map-entry-next-20261005/native-seamless-ready-rpc-source.4dbf630.asm.txt'
READY_SOURCE_SHA256 = 'ee256d7a887cddee5ee11d0aa5ba6dd59922672f2f9e6d13c1615d0aba7bcb4d'
GUID_SOURCE = 'work/evidence/map-entry-next-20261005/native-guid-object-lookup-source.json'
GUID_SOURCE_SHA256 = '647b9698e1f9343d69c5b98970078ca00ade9fd92c98e494c144338008a79c42'


def _source_bytes(root, relative):
    try:
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError('Restart trial source is outside its project')
        before = path.stat()
        if not 0 < before.st_size <= 1024 * 1024:
            raise ValueError('Restart trial source exceeds its bound')
        raw = path.read_bytes()
        after = path.stat()
        if len(raw) != before.st_size or (before.st_size, before.st_mtime_ns) != (
                after.st_size, after.st_mtime_ns):
            raise ValueError('Restart trial source changed during sealing')
        return raw
    except OSError as error:
        raise ValueError('Restart trial source is missing or unreadable') from error


def qualified_pc_restart_trial_sources(root):
    """Merge the fixed native declaration seals with the current trial modules."""
    try:
        root = Path(root).resolve(strict=True)
    except (OSError, TypeError) as error:
        raise ValueError('An existing restart trial project is required') from error
    pins = qualified_pc_restart_sources(root)
    receipt_raw = _source_bytes(root, RECEIPT_SOURCE)
    if hashlib.sha256(receipt_raw).hexdigest() != RECEIPT_SOURCE_SHA256:
        raise ValueError('Reliable receipt ordering source changed')
    receipt = json.loads(receipt_raw)
    if receipt.get('kind') != 'native_pc_reliable_receipt_order_review':
        raise ValueError('Reliable receipt ordering source is unqualified')
    pins[RECEIPT_SOURCE] = RECEIPT_SOURCE_SHA256
    for row in receipt['sources']:
        relative = row['path']
        if (type(relative) is not str or not relative.startswith('work/') or
                ':' in relative or '\\' in relative or '..' in relative.split('/')):
            raise ValueError('Reliable receipt source path is invalid')
        digest = hashlib.sha256(_source_bytes(root, relative)).hexdigest()
        if digest != row['sha256']:
            raise ValueError('Reliable receipt native source changed')
        pins[relative] = digest
    for relative in TRIAL_MODULES:
        raw = _source_bytes(root, relative)
        if relative == TRIAL_MODULES[0] and raw != Path(__file__).read_bytes():
            raise ValueError('Restart trial helper was imported from another checkout')
        pins[relative] = hashlib.sha256(raw).hexdigest()
    return pins


def install_pc_restart_profile(root, probe, manifests, sealed_sources):
    """Configure the exact PC/Pawn pair without requesting or sending restart."""
    if type(sealed_sources) is not dict:
        raise ValueError('Explicit caller-sealed restart trial sources are required')
    pins = qualified_pc_restart_trial_sources(root)
    if any(sealed_sources.get(relative) != digest for relative, digest in pins.items()):
        raise ValueError('Restart trial sources changed after sealing')
    profile = load_pc_restart_profile(root, sealed_sources)
    if (type(manifests) is not tuple or not 2 <= len(manifests) <= 16 or
            any(type(row) not in (ActorManifest, StaticActorManifest) for row in manifests)):
        raise ValueError('An immutable typed initial Actor set is required')
    pc = [row for row in manifests if type(row) is ActorManifest and row.class_path == CLASS_PATH]
    pawn = [row for row in manifests if type(row) is ActorManifest and row.class_path == PAWN_CLASS_PATH]
    if len(pc) != 1 or len(pawn) != 1:
        raise ValueError('Restart requires one exact PlayerController and Pawn class manifest')
    pc, pawn = pc[0], pawn[0]
    for row, guid in ((pc, 4), (pawn, 2)):
        if (row.client_sha256 != SHIPPING_SHA256 or type(row.actor_guid) is not int or
                row.actor_guid != guid or type(row.channel_index) is not int or
                not 2 <= row.channel_index <= 65535 or row.references_resolvable is not True):
            raise ValueError('Restart requires the qualified local Actor allocation and references')
    if pc.channel_index == pawn.channel_index:
        raise ValueError('PlayerController and Pawn require distinct Actor channels')
    setter = getattr(probe, 'set_pc_restart_profile', None)
    if not callable(setter):
        raise ValueError('An explicit restart-capable probe is required')
    setter(MAP_ID, pc, pawn, profile)
    return {'kind': 'source_qualified_pc_restart_trial_installation',
        'status': 'configured', 'map_id': MAP_ID, 'source_sha256': SPEC_SHA256,
        'player_controller': {'class_path': pc.class_path, 'actor_guid': pc.actor_guid,
                              'channel_index': pc.channel_index},
        'pawn': {'class_path': pawn.class_path, 'actor_guid': pawn.actor_guid,
                 'channel_index': pawn.channel_index},
        'restart_requested': False, 'native_dispatch_verified': False,
        'possession_verified': False, 'playable_map_verified': False}


def _dict(value):
    if type(value) is not dict:
        raise ValueError('Expected an exact metadata object')
    return value


def _rows(value, maximum):
    if type(value) is not list or len(value) > maximum:
        raise ValueError('Expected a bounded metadata array')
    return tuple(_dict(row) for row in value)


def _uint(value, maximum, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Invalid metadata integer')
    return value


def _address(value):
    if type(value) is str and re.fullmatch(r'0x[0-9a-fA-F]{1,12}', value):
        value = int(value, 16)
    return _uint(value, (1 << 47) - 1, 0x10000)


def _one(rows, predicate):
    selected = [row for row in rows if predicate(row)]
    if len(selected) != 1:
        raise ValueError('Metadata selection is missing or ambiguous')
    return selected[0]


def _weak(row, address_key='address', *, initialized=False):
    if initialized and row.get('weak_identity_initialized') is not True:
        raise ValueError('Initialized metadata identity is required')
    address = _address(row.get(address_key))
    index = _uint(row.get('object_index'), 0x7fffffff)
    serial = _uint(row.get('serial'), 0xffffffff, 1)
    if 'key' in row and row['key'] != struct.pack('<iI', index, serial).hex():
        raise ValueError('Metadata weak key is inconsistent')
    return address, index, serial


def _true(row, *keys):
    if any(row.get(key) is not True for key in keys):
        raise ValueError('Current identity and field rechecks are required')


def _association_check(metadata, pid, created_at):
    d = _dict(metadata)
    _uint(pid, 0xffffffff, 1)
    if type(created_at) not in (int, float) or not math.isfinite(created_at) or created_at <= 0:
        raise ValueError('An exact finite process creation time is required')
    if (d.get('kind') != 'existing_native_replication_metadata_export' or
            d.get('status') != 'metadata_export_complete' or d.get('client_sha256') != SHIPPING_SHA256 or
            _uint(d.get('requested_pid'), 0xffffffff, 1) != pid):
        raise ValueError('Current complete metadata for the expected process is required')
    process = _dict(d.get('collection_process_identity'))
    stamp = process.get('created_at')
    if (_uint(process.get('pid'), 0xffffffff, 1) != pid or
            type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp != created_at or
            process.get('client_sha256') != SHIPPING_SHA256):
        raise ValueError('Collection process creation or source identity differs')
    _true(process, 'executable_and_creation_time_rechecked', 'loaded_module_rechecked')
    roots = _dict(d.get('roots'))
    _true(roots, 'selected_roots_rechecked')

    gate = _dict(d.get('connection_binding_gate_observation'))
    if (gate.get('kind') != 'source_qualified_gp_bind_gate_observation' or gate.get('status') != 'observed' or
            gate.get('source_image_sha256') != SHIPPING_SHA256 or
            gate.get('source_ledger_relative_path') != GP_SOURCE or gate.get('source_ledger_sha256') != GP_SOURCE_SHA256 or
            _dict(d.get('gp_bind_gate_source_pins')).get(GP_SOURCE) != GP_SOURCE_SHA256):
        raise ValueError('The source-qualified current binding gate is required')
    _true(gate, 'guid4_matches_selected_pc_identity', 'connection_back_driver_matches',
        'driver_primary_matches', 'pc_original_connection_matches',
        'current_connection_player_controller_equals_selected_pc',
        'current_connection_owner_equals_selected_pc', 'identities_relations_fields_and_guid4_rechecked')
    driver, connection, pc = (_address(gate.get(key)) for key in
        ('driver_address', 'connection_address', 'player_controller_address'))
    if (len({driver, connection, pc}) != 3 or _uint(gate.get('local_player_index'), 255) != 0 or
            _address(gate.get('current_connection_player_controller')) != pc or
            _address(gate.get('current_connection_owner')) != pc or
            gate.get('current_connection_pc_and_owner_null') is not False):
        raise ValueError('Binding gate does not refer to the current primary PC')
    identities = _rows(gate.get('identity_qualification'), 4)
    typed = {}
    for label, address in (('NetDriver', driver), ('NetConnection', connection), ('PlayerController', pc)):
        row = _one(identities, lambda row: row.get('expected_base_class') == label)
        typed[label] = _weak(row, initialized=True)
        if typed[label][0] != address:
            raise ValueError('Binding gate typed root is inconsistent')

    binding = _dict(d.get('connection_binding_observations'))
    if (binding.get('kind') != 'source_qualified_connection_binding_observation' or
            binding.get('source_image_sha256') != SHIPPING_SHA256):
        raise ValueError('Current typed connection binding source is required')
    selected_pc = _one(_rows(binding.get('player_controllers'), 64),
        lambda row: _address(row.get('address')) == pc)
    selected_driver = _one(_rows(binding.get('drivers'), 64),
        lambda row: _address(row.get('address')) == driver)
    for row in (selected_pc, selected_driver):
        uninitialized = row.get('weak_identity_uninitialized_addresses')
        if (row.get('status') != 'observed' or type(uninitialized) is not list or len(uninitialized) > 64 or
                any(_address(address) in (driver, connection, pc) for address in uninitialized)):
            raise ValueError('Selected binding root is not fully initialized')
        _true(row, 'identity_and_fields_rechecked')
    _true(selected_pc, 'driver_primary_matches_original_connection',
        'connection_pc_is_this_pc', 'connection_owner_is_this_pc')
    _true(selected_driver, 'connection_back_driver_matches', 'player_controller_equals_owner')
    if (_address(selected_pc.get('driver')) != driver or _address(selected_pc.get('connection')) != connection or
            _address(selected_pc.get('driver_primary_connection')) != connection or
            _address(selected_driver.get('primary_connection')) != connection or
            _address(selected_driver.get('player_controller')) != pc or _address(selected_driver.get('owner')) != pc or
            _uint(selected_pc.get('object_index'), 0x7fffffff) != typed['PlayerController'][1]):
        raise ValueError('Typed binding roots do not agree with the selected PC')
    for label, identity in typed.items():
        row = _one(_rows(selected_pc.get('identity_qualification'), 4),
            lambda row: row.get('expected_base_class') == label)
        if _weak(row, initialized=True) != identity:
            raise ValueError('Typed binding and gate weak identities differ')

    mapping = _dict(d.get('connection_guid_mapping_observation'))
    qualification = _dict(d.get('guid_mapping_source_qualification'))
    if (mapping.get('status') != 'existing_guid_associations_observed' or
            _address(mapping.get('driver_address')) != driver or _address(mapping.get('connection_address')) != connection or
            qualification.get('client_sha256') != SHIPPING_SHA256 or
            qualification.get('source_path') != GUID_SOURCE or qualification.get('source_sha256') != GUID_SOURCE_SHA256):
        raise ValueError('Current same-source GUID mapping is required')
    _true(mapping, 'primary_connection_and_metadata_rechecked')
    mappings = _rows(mapping.get('mappings'), 256)
    mapped = {}
    for guid in (2, 4):
        row = _one(mappings, lambda row: type(row.get('guid')) is int and row['guid'] == guid)
        if row.get('status') != 'existing_object_observed':
            raise ValueError('The selected GUID must resolve to an existing object')
        mapped[guid] = _weak(row, 'object_address', initialized=True)
    if mapped[4] != typed['PlayerController']:
        raise ValueError('GUID4 differs from the selected PC weak identity')

    first = _dict(d.get('first_player_state_observation'))
    source_pins = _dict(d.get('first_player_state_source_pins'))
    if (first.get('kind') != 'native_first_player_prerequisite_observation' or first.get('status') != 'observed' or
            first.get('selection') != 'current_primary_local_pc_instance' or
            first.get('source_relative_path') != FIRST_SOURCE or first.get('source_sha256') != FIRST_SOURCE_SHA256 or
            source_pins.get(FIRST_SOURCE) != FIRST_SOURCE_SHA256 or source_pins.get(READY_SOURCE) != READY_SOURCE_SHA256 or
            first.get('pc_ready_ack_source_relative_path') != READY_SOURCE or
            first.get('pc_ready_ack_source_sha256') != READY_SOURCE_SHA256 or
            _uint(first.get('required_flags_mask'), 255) != 0x6e or
            _uint(first.get('flags_raw'), 255) & 0x6e != 0x6e or
            _uint(first.get('pc_ready_ack_flag_raw'), 1) != 1):
        raise ValueError('First-player source and native prerequisite fields are required')
    _uint(first.get('state_gate_raw'), 255)
    _true(first, 'identity_and_fields_rechecked', 'required_flags_present',
        'ordinary_base_bind_condition_now', 'connection_pc_equals_selected_pc',
        'connection_owner_equals_selected_pc', 'pc_ready_ack_flag_set')
    pawn = _dict(first.get('pc_pawn_reference'))
    ancestry = pawn.get('class_ancestry')
    if (pawn.get('status') != 'typed_existing_reference' or pawn.get('required_base_class') != 'Pawn' or
            _uint(pawn.get('source_offset'), 0xffffffff) != 0x3a0 or
            pawn.get('class_asset_path') != PAWN_CLASS_PATH or type(ancestry) is not list or
            not 3 <= len(ancestry) <= 64 or ancestry[0] != 'BP_DFMCharacter_C' or
            any(type(name) is not str for name in ancestry) or ancestry[-3:] != ['Pawn', 'Actor', 'Object'] or
            _weak(pawn) != mapped[2] or mapped[2][0] in (pc, driver, connection)):
        raise ValueError('PC Pawn reference differs from the exact GUID2 Pawn identity')
    classes = _rows(roots.get('classes'), 32)
    for name, path, address in (('BP_DFMCharacter_C', PAWN_CLASS_PATH, _address(pawn.get('class_address'))),
                               ('BP_DFMPlayerController_C', CLASS_PATH, None)):
        klass = _one(classes, lambda row: row.get('name') == name)
        if klass.get('asset_path') != path:
            raise ValueError('Selected native class path differs from its typed reference')
        identity = _weak(klass)
        if address is not None and identity[0] != address:
            raise ValueError('Pawn class identity differs from its selected native class')
        if name == 'BP_DFMPlayerController_C':
            candidate = _one(_rows(roots.get('controller_instance_candidates'), 64),
                lambda row: _address(row.get('address')) == pc)
            if _weak(candidate) != mapped[4] or _address(candidate.get('class_address')) != identity[0]:
                raise ValueError('The current PC class and weak identity are inconsistent')
    return True


def restart_associations_verified(metadata, pid, created_at):
    """Return only a Boolean; missing/old/mixed metadata never authorizes restart."""
    try:
        return _association_check(metadata, pid, created_at)
    except (ValueError, TypeError, KeyError, OverflowError, struct.error):
        return False


def _refresh_exact_null(value):
    return type(value) is int and value == 0 or type(value) is str and value == '0x0'

def _early_unbound_association_check(metadata, pid, created_at):
    d = _dict(metadata)
    _uint(pid, 0xffffffff, 1)
    if type(created_at) not in (int, float) or not math.isfinite(created_at) or created_at <= 0:
        raise ValueError('An exact finite process creation time is required')
    if (d.get('kind') != 'existing_native_replication_metadata_export' or
            d.get('status') != 'metadata_export_complete' or d.get('client_sha256') != SHIPPING_SHA256 or
            _uint(d.get('requested_pid'), 0xffffffff, 1) != pid):
        raise ValueError('Current complete metadata for the expected process is required')
    process = _dict(d.get('collection_process_identity'))
    stamp = process.get('created_at')
    if (_uint(process.get('pid'), 0xffffffff, 1) != pid or
            type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp != created_at or
            process.get('client_sha256') != SHIPPING_SHA256):
        raise ValueError('Collection process creation or source identity differs')
    _true(process, 'executable_and_creation_time_rechecked', 'loaded_module_rechecked')
    if any(d.get(key) is not False for key in ('game_modified', 'process_memory_written', 'native_getter_invoked')):
        raise ValueError('Only the existing read-only collector is eligible')
    roots = _dict(d.get('roots'))
    _true(roots, 'selected_roots_rechecked')

    gate = _dict(d.get('connection_binding_gate_observation'))
    if (gate.get('kind') != 'source_qualified_gp_bind_gate_observation' or gate.get('status') != 'observed' or
            gate.get('source_image_sha256') != SHIPPING_SHA256 or
            gate.get('source_ledger_relative_path') != GP_SOURCE or gate.get('source_ledger_sha256') != GP_SOURCE_SHA256 or
            _dict(d.get('gp_bind_gate_source_pins')).get(GP_SOURCE) != GP_SOURCE_SHA256):
        raise ValueError('The source-qualified current binding gate is required')
    _true(gate, 'guid4_matches_selected_pc_identity', 'connection_back_driver_matches',
        'driver_primary_matches', 'pc_original_connection_matches',
        'identities_relations_fields_and_guid4_rechecked')
    if any(gate.get(key) is not False for key in ('current_connection_player_controller_equals_selected_pc',
            'current_connection_owner_equals_selected_pc')):
        raise ValueError('Early null binding facts must be explicit')
    driver, connection, pc = (_address(gate.get(key)) for key in
        ('driver_address', 'connection_address', 'player_controller_address'))
    if (len({driver, connection, pc}) != 3 or _uint(gate.get('local_player_index'), 255) != 0 or
            type(gate.get('current_connection_player_controller')) is not int or
            gate['current_connection_player_controller'] != 0 or
            type(gate.get('current_connection_owner')) is not int or gate['current_connection_owner'] != 0 or
            gate.get('current_connection_pc_and_owner_null') is not True):
        raise ValueError('Binding gate does not refer to the current primary PC')
    identities = _rows(gate.get('identity_qualification'), 4)
    typed = {}
    for label, address in (('NetDriver', driver), ('NetConnection', connection), ('PlayerController', pc)):
        row = _one(identities, lambda row: row.get('expected_base_class') == label)
        typed[label] = _weak(row, initialized=True)
        if typed[label][0] != address:
            raise ValueError('Binding gate typed root is inconsistent')

    binding = _dict(d.get('connection_binding_observations'))
    if (binding.get('kind') != 'source_qualified_connection_binding_observation' or
            binding.get('source_image_sha256') != SHIPPING_SHA256):
        raise ValueError('Current typed connection binding source is required')
    selected_pc = _one(_rows(binding.get('player_controllers'), 64),
        lambda row: _address(row.get('address')) == pc)
    selected_driver = _one(_rows(binding.get('drivers'), 64),
        lambda row: _address(row.get('address')) == driver)
    for row in (selected_pc, selected_driver):
        uninitialized = row.get('weak_identity_uninitialized_addresses')
        if (row.get('status') != 'observed' or type(uninitialized) is not list or len(uninitialized) > 64 or
                any(_address(address) in (driver, connection, pc) for address in uninitialized)):
            raise ValueError('Selected binding root is not fully initialized')
        _true(row, 'identity_and_fields_rechecked')
    _true(selected_pc, 'driver_primary_matches_original_connection')
    _true(selected_driver, 'connection_back_driver_matches')
    if any(selected_pc.get(key) is not False for key in ('connection_pc_is_this_pc', 'connection_owner_is_this_pc')) or selected_driver.get('player_controller_equals_owner') is not False:
        raise ValueError('Early selected binding must remain explicitly unbound')
    if (_address(selected_pc.get('driver')) != driver or _address(selected_pc.get('connection')) != connection or
            _address(selected_pc.get('driver_primary_connection')) != connection or
            _address(selected_driver.get('primary_connection')) != connection or
            not _refresh_exact_null(selected_driver.get('player_controller')) or
            not _refresh_exact_null(selected_driver.get('owner')) or
            _uint(selected_pc.get('object_index'), 0x7fffffff) != typed['PlayerController'][1]):
        raise ValueError('Typed binding roots do not agree with the selected PC')
    for label, identity in typed.items():
        row = _one(_rows(selected_pc.get('identity_qualification'), 4),
            lambda row: row.get('expected_base_class') == label)
        if _weak(row, initialized=True) != identity:
            raise ValueError('Typed binding and gate weak identities differ')

    mapping = _dict(d.get('connection_guid_mapping_observation'))
    qualification = _dict(d.get('guid_mapping_source_qualification'))
    if (mapping.get('status') != 'existing_guid_associations_observed' or
            _address(mapping.get('driver_address')) != driver or _address(mapping.get('connection_address')) != connection or
            qualification.get('client_sha256') != SHIPPING_SHA256 or
            qualification.get('source_path') != GUID_SOURCE or qualification.get('source_sha256') != GUID_SOURCE_SHA256):
        raise ValueError('Current same-source GUID mapping is required')
    _true(mapping, 'primary_connection_and_metadata_rechecked')
    mappings = _rows(mapping.get('mappings'), 256)
    mapped = {}
    for guid in (2, 4):
        row = _one(mappings, lambda row: type(row.get('guid')) is int and row['guid'] == guid)
        if row.get('status') != 'existing_object_observed':
            raise ValueError('The selected GUID must resolve to an existing object')
        mapped[guid] = _weak(row, 'object_address', initialized=True)
    if mapped[4] != typed['PlayerController']:
        raise ValueError('GUID4 differs from the selected PC weak identity')

    first = _dict(d.get('first_player_state_observation'))
    source_pins = _dict(d.get('first_player_state_source_pins'))
    if (first.get('kind') != 'native_first_player_prerequisite_observation' or first.get('status') != 'observed' or
            first.get('selection') != 'current_primary_local_pc_instance' or
            first.get('source_relative_path') != FIRST_SOURCE or first.get('source_sha256') != FIRST_SOURCE_SHA256 or
            source_pins.get(FIRST_SOURCE) != FIRST_SOURCE_SHA256 or source_pins.get(READY_SOURCE) != READY_SOURCE_SHA256 or
            first.get('pc_ready_ack_source_relative_path') != READY_SOURCE or
            first.get('pc_ready_ack_source_sha256') != READY_SOURCE_SHA256 or
            _uint(first.get('required_flags_mask'), 255) != 0x6e or
            _uint(first.get('flags_raw'), 255) & 0x6e != 0x6e or
            _uint(first.get('pc_ready_ack_flag_raw'), 1) != 0):
        raise ValueError('First-player source and native prerequisite fields are required')
    if (_uint(first.get('state_gate_raw'), 255) != 1 or
            _uint(gate.get('state_gate_raw'), 255) != 1):
        raise ValueError('The observed early waiting state is required')
    _true(first, 'identity_and_fields_rechecked', 'required_flags_present', 'ordinary_base_bind_condition_now')
    if any(first.get(key) is not False for key in ('connection_pc_equals_selected_pc',
            'connection_owner_equals_selected_pc', 'pc_ready_ack_flag_set')):
        raise ValueError('Early first-player readiness must be explicitly absent')
    pawn = _dict(first.get('pc_pawn_reference'))
    ancestry = pawn.get('class_ancestry')
    if (pawn.get('status') != 'typed_existing_reference' or pawn.get('required_base_class') != 'Pawn' or
            _uint(pawn.get('source_offset'), 0xffffffff) != 0x3a0 or
            pawn.get('class_asset_path') != PAWN_CLASS_PATH or type(ancestry) is not list or
            not 3 <= len(ancestry) <= 64 or ancestry[0] != 'BP_DFMCharacter_C' or
            any(type(name) is not str for name in ancestry) or ancestry[-3:] != ['Pawn', 'Actor', 'Object'] or
            _weak(pawn) != mapped[2] or mapped[2][0] in (pc, driver, connection)):
        raise ValueError('PC Pawn reference differs from the exact GUID2 Pawn identity')
    classes = _rows(roots.get('classes'), 32)
    for name, path, address in (('BP_DFMCharacter_C', PAWN_CLASS_PATH, _address(pawn.get('class_address'))),
                               ('BP_DFMPlayerController_C', CLASS_PATH, None)):
        klass = _one(classes, lambda row: row.get('name') == name)
        if klass.get('asset_path') != path:
            raise ValueError('Selected native class path differs from its typed reference')
        identity = _weak(klass)
        if address is not None and identity[0] != address:
            raise ValueError('Pawn class identity differs from its selected native class')
        if name == 'BP_DFMPlayerController_C':
            candidate = _one(_rows(roots.get('controller_instance_candidates'), 64),
                lambda row: _address(row.get('address')) == pc)
            if _weak(candidate) != mapped[4] or _address(candidate.get('class_address')) != identity[0]:
                raise ValueError('The current PC class and weak identity are inconsistent')
    return True

def post_travel_refresh_metadata_eligible(metadata, pid, created_at):
    """Authorize one fresh observation of an exact early-null snapshot, never Restart."""
    try:
        return _early_unbound_association_check(metadata, pid, created_at)
    except (ValueError, TypeError, KeyError, OverflowError, struct.error):
        return False
