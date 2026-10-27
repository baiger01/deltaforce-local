"""Read qualified GameState entry bits using each actual property mask.

GUID6 is the local trial's declared GameState allocation, not a global client
identifier. The caller supplies the current rechecked mapping, class cache and
typed identity callback. No native method is invoked or process memory written.
"""
import hashlib
import json
from pathlib import Path

from native_connection_binding import _View
from native_gp_bind_gate import _GateBudget
from native_game_state_start_profile import SPEC_PATH, SPEC_SHA256

BOOL_CODE_SOURCE = 'work/evidence/map-entry-next-20261007/begin-play-bool-native.10e8ebe0.code'
BOOL_CODE_SHA256 = 'de22cc24de8a11838462d7977b4b8b8f0ce41d601e8b4902ca113fb06fe5e009'
BOOL_ASM_SOURCE = 'work/evidence/map-entry-next-20261007/begin-play-bool-native.10e8ebe0.asm.txt'
BOOL_ASM_SHA256 = '6b4e1a8f7f9802213950eaa17d96d6ef8977e4ebc8ac0ec6c55266c9a91524c1'


def qualified_start_observation_sources(root):
    root = Path(root).resolve(strict=True)
    pins = {}
    for relative, expected in ((SPEC_PATH, SPEC_SHA256), (BOOL_CODE_SOURCE, BOOL_CODE_SHA256),
                               (BOOL_ASM_SOURCE, BOOL_ASM_SHA256)):
        path = (root / relative).resolve(strict=True)
        raw = path.read_bytes()
        if not path.is_relative_to(root) or len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('GameState BeginPlay observation source changed')
        pins[relative] = expected
    relative = 'work/native_game_state_start_observation.py'
    pins[relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins[relative]:
        raise ValueError('BeginPlay observer was imported from another checkout')
    return pins


def observe_game_state_start(session, module_base, *, root, roots, exports, mapping, object_identity):
    budget = None
    try:
        qualified_start_observation_sources(root)
        spec = json.loads((Path(root) / SPEC_PATH).read_bytes())
        if (not isinstance(mapping, dict) or mapping.get('status') != 'existing_guid_associations_observed' or
                mapping.get('primary_connection_and_metadata_rechecked') is not True):
            raise ValueError('Current rechecked GameState GUID mapping is required')
        selected = [m for m in mapping['mappings'] if m['guid'] == 6]
        if len(selected) != 1 or selected[0]['status'] != 'existing_object_observed':
            raise ValueError('Local GameState allocation has no current object')
        candidates = [r for r in exports if r['class_name'] == 'BP_GameState_PVPVE_C' and
                      r['cache_status'] == 'exported_existing' and
                      r['driver_address'] == mapping['driver_address']]
        if len(candidates) != 1:
            raise ValueError('One current GameState class cache is required')
        cache = candidates[0]
        actor = selected[0]['object_address']
        budget = _GateBudget(session, object_identity)
        view = _View(budget, module_base)
        identity = view.object(actor, 'Actor')
        if identity[3] != cache['class_address'] or identity[1:3] != (
                selected[0]['object_index'], selected[0]['serial']):
            raise ValueError('GameState Actor class or registry identity changed')
        observed = {}
        for spec_key, output_key in (('property', 'native_begin_play_property_set'),
                                     ('all_ready_property', 'native_all_player_ready_property_set'),
                                     ('abseil_property', 'native_abseil_permission_property_set')):
            prop = spec[spec_key]
            fields = [f for n in cache['cache_nodes'] for f in n['fields']
                      if f.get('descriptor_name') == prop['name']]
            if len(fields) != 1 or fields[0]['descriptor_representation'] != 0 or fields[0]['incompatible']:
                raise ValueError('The exact existing GameState FProperty descriptor is required')
            descriptor = fields[0]['descriptor_address']
            hook = view.method(descriptor, 0x90, 0x10e8ebe0)
            if not hook['matches_saved_base_body']:
                raise ValueError('Current GameState property has a different Boolean serializer')
            # Exact source10e8ebea/10e8ec03: byte offset at+8a and field mask at+8c.
            byte_offset, byte_mask, field_mask = (view.keep(descriptor + offset, 1)[0]
                                                for offset in (0x8a, 0x8b, 0x8c))
            if (byte_offset > 7 or not byte_mask or byte_mask & (byte_mask - 1) or
                    field_mask not in (byte_mask, 0xff)):
                raise ValueError('Unsupported native Boolean property masks')
            value = view.keep(actor + prop['data_offset'] + byte_offset, 1)[0]
            observed[output_key] = bool(value & field_mask)
        parents = [f for n in cache['cache_nodes'] for f in n['fields']
                   if f.get('descriptor_name') == 'MatchInfo']
        if len(parents) != 1 or parents[0]['descriptor_representation'] != 0 or parents[0]['incompatible']:
            raise ValueError('The current MatchInfo parent descriptor is required')
        # These two unsigned64 offsets are from the sealed same-build RepLayout.
        # Read only the selected local room's identities; publish no player data.
        for prop in spec['match_info_properties']:
            value = int.from_bytes(view.keep(actor + prop['data_offset'], 8), 'little')
            if prop['name'] == 'MapID':
                observed['native_match_info_map_id'] = value
            else:
                observed['native_match_info_room_id_nonzero'] = value != 0
        view.finish()
        result = {'status': 'observed', **observed,
                  'property_name': spec['property']['name'], 'local_actor_guid': 6,
                  'actual_property_masks_used': True, 'identity_and_fields_rechecked': True}
    except (ValueError, OSError) as error:
        result = {'status': 'refused', 'reason': str(error)}
    result.update(kind='native_game_state_begin_play_property_observation',
                  source_relative_path=SPEC_PATH, source_sha256=SPEC_SHA256,
                  read_calls=budget.calls if budget else 0,
                  read_bytes=budget.bytes_read if budget else 0,
                  native_methods_invoked=False, process_memory_written=False,
                  rep_notify_execution_verified=False, possession_verified=False,
                  playable_map_verified=False, snapshot_atomic=False)
    return result
