"""Optional async observer for the already elevated owned shadow-client trial.

This module does not import the REPO collector into the BASE interpreter. Only
the observer Popen handle can be terminated. A rejected diagnostic never ends
the client or changes the protocol state.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

KIND = 'sealed_local_trial_appearance_observer_config_v1'
CONFIG_RELATIVE = Path('work/native-appearance-observer-config.json')
FLAGS = {
    'appearance_state': True,
    'player_class_metadata': True,
    'appearance_receiver_state': True,
    'appearance_apply_gate': True,
    'pawn_camera_dependency_state': True,
    'player_state_human_appearance_values': True,
}

FASHION_FLAGS = {
    'appearance_receiver_class_metadata': True,
    'appearance_existing_guid_references': True,
    'appearance_name_stability_direct': True,
}
FASHION_PROFILE_SHA = '4010e7062422de19440fca90e7c413dbd2c369ba062fcf5fad03624791162dd5'
GUID_PROFILE_SHA = '6274c8892751f49a1cc482af8c2ed62705981308dd3b1a302bd97865d03570eb'
NAME_PROFILE_SHA = 'aeedade4b455bc7a6902a46e29b1df8e000093e6acef6f53cd9e27317b7336dd'
NAME_STATIC_SHA = '7d5b8b6080c85c579ae10f1747915609c98ca63b4a38af62934ad2a347973ae4'


def reader_flags(*, include_current_fashion_contracts=False, include_current_fashion_declarations=False, retain_original_fashion_worker=False):
    if type(include_current_fashion_contracts) is not bool:
        raise ValueError('Explicit Fashion observer option required')
    if type(include_current_fashion_declarations) is not bool or include_current_fashion_declarations and include_current_fashion_contracts is not True:
        raise ValueError('Explicit declarations require current Fashion contracts')
    if (type(retain_original_fashion_worker) is not bool or retain_original_fashion_worker and not all((
            include_current_fashion_contracts,include_current_fashion_declarations))):
        raise ValueError('Retained original worker requires complete tenflag source profile')
    return {**FLAGS, **(FASHION_FLAGS if include_current_fashion_contracts else {}),
        **({'appearance_current_declarations':True} if include_current_fashion_declarations else {}),
        **({'retained_fashion_worker':True} if retain_original_fashion_worker else {})}


def config_reader_flags(data):
    if type(data) is not dict:
        raise ValueError('Observer configuration object required')
    flags = reader_flags(include_current_fashion_contracts=data.get('include_current_fashion_contracts', False),
        include_current_fashion_declarations=data.get('include_current_fashion_declarations', False),
        retain_original_fashion_worker=data.get('retain_original_fashion_worker',False))
    actual = data.get('reader_flags')
    if (type(actual) is not dict or set(actual) != set(flags) or
            any(actual[k] is not True for k in flags)):
        raise ValueError('Fixed explicit observer flag profile required')
    return flags


def safe_fashion_contract_summary(name, value):
    """Independent projection; private identity facts remain in original snapshot."""
    row = {'status': 'refused', 'refusal_reason': 'controlled_fashion_contract_projection_refused',
        'local_namespace_mapping_qualified': False, 'stable_export_qualified': False,
        'wire_values_chosen': False, 'repnotify_execution_verified': False, 'model_initialized': False,
        'process_memory_written': False, 'native_methods_invoked': False}
    if type(value) is not dict:
        row['status'] = 'not_observed'
        return row
    status = value.get('status')
    if status in ('refused', 'not_observed'):
        row['status'] = status
        return row
    try:
        kinds = {'fashion_class_metadata':'source_qualified_current_typed_Fashion_existing_class_cache_layout_metadata',
            'fashion_existing_guids':'source_qualified_existing_current_pawn_fashion_guid_references',
            'fashion_name_stability':'source_qualified_current_Fashion_name_stability_direct_subset'}
        side_key = 'native_functions_invoked' if name == 'fashion_existing_guids' else 'native_methods_invoked'
        if (status != 'observed' or value.get('kind') != kinds.get(name) or
                value.get('late_original_observation_rechecked') is not True or
                value.get('process_memory_written') is not False or value.get(side_key) is not False or
                value.get('native_methods_invoked',False) is not False or
                value.get('native_functions_invoked',False) is not False):
            raise ValueError('Original typed side-effect-free late observation required')
        common = ('read_calls', 'read_bytes', 'identity_callback_calls')
        if name == 'fashion_class_metadata':
            if (value.get('source_profile_sha256') != FASHION_PROFILE_SHA or
                    any(value.get(k) is not True for k in ('owner_equals_receiver_equals_current_pawn',
                        'same_current_primary_driver_rechecked',
                        'current_identities_relations_cache_layout_and_sources_rechecked',
                        'component_outer_equals_current_pawn', 'component_name_and_outer_identity_rechecked'))):
                raise ValueError('Current typed Fashion closure required')
            fixed = {'name': 'currentCharacterHeroID', 'native_type': 'FUInt64Property',
                'storage_bytes': 8, 'source_offset': 0x508, 'declared_repnotify': 'OnRep_CharacterAvatarID',
                'dispatch_opcode': 20}
            f = value.get('field')
            if (type(f) is not dict or any(type(f.get(k)) is not type(v) or f[k] != v for k,v in fixed.items()) or
                    any(type(f.get(k)) is not int or not lo <= f[k] <= hi for k,lo,hi in (
                        ('ordinary_handle',1,65535),('command_index',0,8191),('parent_index',0,2047))) or
                    any(not _hex_hash(f.get(k)) for k in ('command_record_sha256','parent_record_sha256'))):
                raise ValueError('Exact Fashion field required')
            row['field'] = {**fixed, **{k:f[k] for k in ('ordinary_handle','command_index','parent_index',
                'command_record_sha256','parent_record_sha256')}}
            caps = (4096,1024*1024,24)
            row.update(owner_equals_receiver_equals_current_pawn=True,
                component_outer_equals_current_pawn=True, component_name_and_outer_identity_rechecked=True)
        elif name == 'fashion_existing_guids':
            if (value.get('source_profile_sha256') != GUID_PROFILE_SHA or
                    any(value.get(k) is not True for k in ('same_owner_relations_rechecked',
                        'identities_names_outers_and_storage_rechecked'))):
                raise ValueError('Existing GUID original closure required')
            targets = value.get('targets')
            if type(targets) is not list or len(targets) != 2:
                raise ValueError('Fixed exact two targets required')
            rows = []
            for label in ('current_fashion','current_pawn'):
                matches = [x for x in targets if type(x) is dict and x.get('target_label') == label]
                if len(matches) != 1:
                    raise ValueError('Exact target identity required')
                item = matches[0]; guid = item.get('existing_guid_u32')
                if (item.get('status') == 'existing_guid_observed' and type(guid) is int and
                        2 <= guid <= 0xffffffff and item.get('reverse_and_forward_exact_key_match') is True):
                    rows.append({'target_label':label,'status':'existing_guid_observed',
                        'existing_guid_u32':guid,'reverse_and_forward_exact_key_match':True})
                elif item.get('status') == 'mapping_missing' and guid is None:
                    rows.append({'target_label':label,'status':'mapping_missing','existing_guid_u32':None})
                else:
                    raise ValueError('Exact existing mapping required')
            if rows[0]['existing_guid_u32'] is not None and rows[0]['existing_guid_u32'] == rows[1]['existing_guid_u32']:
                raise ValueError('Distinct current identities required')
            row['targets'] = rows
            caps = (4096,65536,8)
        elif name == 'fashion_name_stability':
            branches = {'net_addressable_mask_true':True,
                'object_flags_mask_and_byte_comparison_true':True,'creation_byte_comparison_false':False}
            branch = value.get('direct_branch')
            if (value.get('source_profile_sha256') != NAME_PROFILE_SHA or value.get('static_source_sha256') != NAME_STATIC_SHA or
                    type(branch) is not str or branch not in branches or
                    value.get('name_stability_predicate_value') is not branches[branch] or
                    any(value.get(k) is not True for k in ('same_original_typed_fashion_rechecked',
                        'same_current_pc_pawn_primary_route_rechecked','actual_virtual_targets_and_direct_members_rechecked')) or
                    value.get('full_name_stability_qualified') is not False or
                    value.get('stable_namespace_or_GUID_qualified') is not False):
                raise ValueError('Original direct subset closure required')
            row.update(direct_branch=branch,name_stability_predicate_value=branches[branch],
                full_name_stability_qualified=False, default_subobject_identity_qualified=False)
            caps = (256,4096,48)
        else:
            raise ValueError('Fixed Fashion observation required')
        for key, cap in zip(common,caps):
            if type(value.get(key)) is not int or not 0 <= value[key] <= cap:
                raise ValueError('Fixed observation budget required')
            row[key] = value[key]
        row.update(status='observed',source_profile_sha256=value['source_profile_sha256'],
            late_original_observation_rechecked=True)
        row.pop('refusal_reason',None)
        return row
    except Exception:
        for key in ('field', 'targets', 'direct_branch', 'name_stability_predicate_value',
                'owner_equals_receiver_equals_current_pawn', 'component_outer_equals_current_pawn',
                'component_name_and_outer_identity_rechecked'):
            row.pop(key,None)
        return row

PS_PROFILE_SHA = 'd75d8081bae1e7156d7b42f8d85608c2b38c6b0509d8eb37fad9cb9e2df7a371'
PS_FIELDS = ('HeroID', 'CurrSameTeamAvatarId', 'CurrDiffTeamAvatarId')
SHIPPING_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MAXIMUM_SECONDS = 240
GATE_REFUSALS = frozenset(('source_seal_changed', 'source_schema_changed', 'source_identity_changed',
    'same_session_receiver_required', 'fixed_image_required', 'fixed_read_budget_refused',
    'fixed_read_refused', 'incomplete_fixed_read', 'typed_identity_refused', 'fixed_pawn_class_required',
    'fixed_component_class_required', 'direct_owner_or_receiver_required',
    'owner_or_receiver_is_not_current_pawn', 'owner_identity_is_not_current_pawn',
    'late_identity_or_storage_changed', 'controlled_gate_observation_refused'))


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _hex_hash(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def source_path(root, relative):
    if (type(relative) is not str or not relative or '\\' in relative or
            Path(relative).anchor or relative.startswith('/') or '..' in Path(relative).parts):
        raise ValueError('Invalid observer source path')
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('Observer source is outside the repository')
    return path


def validate_config(path, *, base_root, game_root, expected_digest=None, helper_path=None):
    path = Path(path).resolve(strict=True)
    base_root, game_root = Path(base_root).resolve(strict=True), Path(game_root).resolve(strict=True)
    if path != (base_root / CONFIG_RELATIVE).resolve(strict=True) or path.stat().st_size > 512 * 1024:
        raise ValueError('Observer config is outside the owned BASE work directory')
    raw = path.read_bytes()
    config_digest = hashlib.sha256(raw).hexdigest()
    if expected_digest is not None and config_digest != expected_digest:
        raise ValueError('Observer config changed')
    data = json.loads(raw)
    if (type(data) is not dict or data.get('kind') != KIND or data.get('enabled') is not True or
            data.get('shadow_only') is not True or data.get('stage_label') != 'local-white-fog' or
            config_reader_flags(data) != data.get('reader_flags') or data.get('supervisor_seconds') != MAXIMUM_SECONDS or
            data.get('client_sha256') != SHIPPING_SHA or
            Path(data.get('base_root', '')).resolve(strict=True) != base_root or
            Path(data.get('game_root', '')).resolve(strict=True) != game_root):
        raise ValueError('Invalid fixed local observer configuration')
    repository = Path(data['repository_root']).resolve(strict=True)
    bridge = Path(data['bridge_path']).resolve(strict=True)
    reader = source_path(repository, 'work/read_playable_state_snapshot.py')
    if (not bridge.is_relative_to(repository / 'work') or not bridge.is_file() or
            not _hex_hash(data.get('bridge_sha256')) or digest(bridge) != data['bridge_sha256'] or
            not _hex_hash(data.get('reader_sha256')) or digest(reader) != data['reader_sha256']):
        raise ValueError('Observer bridge or reader identity changed')
    pins = data.get('source_pins')
    if (type(pins) is not dict or not pins or len(pins) > 512 or
            pins.get('work/read_playable_state_snapshot.py') != data['reader_sha256']):
        raise ValueError('Invalid sealed observer source closure')
    for relative, expected in pins.items():
        if not _hex_hash(expected) or digest(source_path(repository, relative)) != expected:
            raise ValueError('Observer source closure changed')
    if helper_path is not None and (not _hex_hash(data.get('runner_helper_sha256')) or
            digest(helper_path) != data['runner_helper_sha256']):
        raise ValueError('Observer runner helper changed')
    return data, config_digest


def trial_output(base_root, trial_root):
    base_root = Path(base_root).resolve(strict=True)
    trial_root = Path(trial_root).resolve(strict=True)
    owned = (base_root / 'work/native-client-tests').resolve(strict=True)
    if trial_root.parent != owned or not trial_root.name.isdecimal():
        raise ValueError('Observer output is outside the current owned trial')
    output = trial_root / 'automatic-appearance-observation'
    if output.exists():
        raise ValueError('Observer output already exists')
    return output


def safe_fashion_declaration_summary(value):
    """Fixed scalar diagnostics only; never copy private classes or pointers."""
    row={'kind':'source_qualified_current_Fashion_declared_field_metadata_diagnostics_v1',
        'status':'refused','refusal_reason':'controlled_current_declaration_projection_refused',
        'local_RepLayout_observed':False,'body_qualified':False,'wire_encoding_chosen':False,
        'native_methods_invoked':False,'process_memory_written':False,'raw_addresses_or_weak_keys_exported':False}
    if type(value) is not dict:
        return row
    if value.get('status') in ('disabled','refused','not_observed'):
        row['status']=value['status']
        reason=value.get('refusal_reason')
        if type(reason) is str and reason.isascii() and reason.isidentifier() and len(reason)<=96:
            row['refusal_reason']=reason
        return row
    if (value.get('status')!='observed' or value.get('kind')!='source_qualified_current_Fashion_declared_field_metadata_diagnostics_v1'
            or value.get('original_late_rechecked') is not True or
            any(value.get(k) is not False for k in ('local_RepLayout_observed','body_qualified','wire_encoding_chosen',
                'native_methods_invoked','process_memory_written','raw_addresses_or_weak_keys_exported'))):
        return row
    row.update(status='observed',original_late_rechecked=True,
        observation_scope='current_declared_field_metadata_only')
    row.pop('refusal_reason',None)
    for key in ('declaration_prefix_match_reference','equal_offset_net_declaration_present','unmodified_hook_subset'):
        if type(value.get(key)) is bool:
            row[key]=value[key]
    for key,maximum in (('read_calls',4096),('read_bytes',1048576),('identity_callback_calls',128)):
        if type(value.get(key)) is int and 0<=value[key]<=maximum:
            row[key]=value[key]
    unknown=value.get('unknown_conditions')
    if type(unknown) is list and len(unknown)<=16 and all(type(v) is str and v.isascii() and v.isidentifier() and len(v)<=96 for v in unknown):
        row['unknown_conditions']=unknown[:]
    return row


def safe_summary(value):
    """Fixed public fields only; raw roots, accounts and object pointers cannot pass."""
    if type(value) is not dict or value.get('kind') != 'automatic_local_trial_appearance_observation_v1':
        return {'status': 'refused', 'reason': 'invalid_observer_summary'}
    states = ('complete', 'refused', 'failed')
    result = {'kind': value['kind'], 'status': value.get('status') if value.get('status') in states else 'refused',
              'native_methods_invoked': False, 'process_memory_written': False, 'model_verified': False}
    status = value.get('collector_status')
    if status in ('metadata_export_complete', 'metadata_export_refused', 'metadata_export_failed'):
        result['collector_status'] = status
    elapsed = value.get('elapsed_seconds')
    if type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= MAXIMUM_SECONDS:
        result['elapsed_seconds'] = elapsed
    for name in ('appearance', 'receiver', 'apply_gate', 'camera_dependencies', 'restart_local', 'player_state'):
        item = value.get(name)
        if type(item) is not dict:
            continue
        row = {'status': item.get('status') if item.get('status') in ('observed', 'refused', 'not_observed') else 'not_observed'}
        if name == 'player_state':
            row.update(model_configuration_applied=False, repnotify_execution_verified=False,
                wire_values_chosen=False, transport_ack_proves_notify_execution=False)
            for key, maximum in (('read_calls', 69), ('read_bytes', 1344), ('identity_callback_calls', 12),
                                 ('selection_callback_calls', 4), ('numeric_property_read_calls', 9)):
                if type(item.get(key)) is int and 0 <= item[key] <= maximum:
                    row[key] = item[key]
            if row['status'] == 'observed':
                try:
                    if (item.get('source_profile_sha256') != PS_PROFILE_SHA or
                            item.get('late_original_observation_rechecked') is not True or
                            item.get('current_identities_relations_selected_records_slots_values_and_sources_rechecked') is not True or
                            item.get('pawn_player_state_is_current_player_state') is not True):
                        raise ValueError('Incomplete PS closure')
                    values = item.get('fields')
                    if type(values) is not dict:
                        raise ValueError('Fixed PS fields required')
                    fields = {}
                    for field in PS_FIELDS:
                        source = values.get(field)
                        decimal = source.get('value_decimal') if type(source) is dict else None
                        if type(decimal) is not str or not 1 <= len(decimal) <= 20:
                            raise ValueError('Fixed decimal text required')
                        number = int(decimal)
                        signed = field == 'HeroID'
                        if str(number) != decimal or not (-(2**63) <= number < 2**63 if signed else 0 <= number < 2**64):
                            raise ValueError('Fixed typed range required')
                        fields[field] = {'value_decimal': decimal}
                    backlink = item.get('pawn_private')
                    if type(backlink) is not dict or backlink.get('status') not in ('null_reference', 'same_current_pawn'):
                        raise ValueError('Fixed backlink state required')
                    row.update(fields=fields, pawn_private={'status': backlink['status']},
                        source_profile_sha256=PS_PROFILE_SHA, pawn_player_state_is_current_player_state=True,
                        current_identities_relations_selected_records_slots_values_and_sources_rechecked=True,
                        late_original_observation_rechecked=True)
                except Exception:
                    row.update(status='refused', refusal_reason='controlled_ps_summary_projection_refused')
            result[name] = row
            continue
        for key in ('receiver_equals_current_pawn', 'hero_id_is_zero', 'source_rechecked',
                    'pc_pawn_relation_matches', 'anim_proxy_is_null', 'anim_proxy_weak_identity_initialized',
                    'anim_proxy_outer_is_selected_pawn', 'camera_mode_is_null', 'blackboard_is_null'):
            if type(item.get(key)) is bool:
                row[key] = item[key]
        hero = item.get('current_character_hero_id')
        if type(hero) is int and 0 <= hero < 2**64:
            row['current_character_hero_id'] = hero
        raw_gate = item.get('stored_return_u8')
        if type(raw_gate) is int and 0 <= raw_gate <= 255:
            row['stored_return_u8'] = raw_gate
        nested = item.get('human_fallback_owner_gate_storage')
        if name == 'receiver' and type(nested) is dict:
            gate = {'status': nested.get('status') if nested.get('status') in
                    ('observed', 'refused', 'not_observed') else 'not_observed',
                'semantic_field_name_qualified': False, 'nonzero_writer_qualified': False,
                'wire_handle_or_setter_qualified': False, 'fallback_execution_verified': False}
            reason = nested.get('refusal_reason')
            if type(reason) is str and reason in GATE_REFUSALS:
                gate['refusal_reason'] = reason
            if gate['status'] == 'observed':
                for key in ('owner_equals_receiver_equals_current_pawn',
                            'identity_storage_and_sources_rechecked', 'stored_gate_nonzero'):
                    if type(nested.get(key)) is bool:
                        gate[key] = nested[key]
                byte = nested.get('stored_gate_u8')
                if type(byte) is int and 0 <= byte <= 255:
                    gate['stored_gate_u8'] = byte
                if nested.get('source_offset') == 0x11a8 and type(nested.get('source_offset')) is int:
                    gate['source_offset'] = 0x11a8
                if nested.get('source_bytes') == 1 and type(nested.get('source_bytes')) is int:
                    gate['source_bytes'] = 1
            for key, maximum in (('read_calls', 8), ('read_bytes', 50), ('identity_callback_calls', 6)):
                if type(nested.get(key)) is int and 0 <= nested[key] <= maximum:
                    gate[key] = nested[key]
            row['human_fallback_owner_gate_storage'] = gate
        result[name] = row
    if 'fashion_declarations' in value:
        result['fashion_declarations'] = safe_fashion_declaration_summary(value['fashion_declarations'])
    for name in ('fashion_class_metadata', 'fashion_existing_guids', 'fashion_name_stability'):
        if name in value:
            result[name] = safe_fashion_contract_summary(name, value[name])
    return result


class AutomaticAppearanceObserver:
    def __init__(self, base_root, game_root, trial_root, *, popen=subprocess.Popen, clock=time.monotonic):
        self.base_root, self.game_root, self.trial_root = map(Path, (base_root, game_root, trial_root))
        self.config_path = self.base_root / CONFIG_RELATIVE
        self.process, self.log, self.started = None, None, None
        self.attempted = False
        self.popen, self.clock = popen, clock
        self.config, self.config_digest = validate_config(self.config_path, base_root=self.base_root,
            game_root=self.game_root, helper_path=Path(__file__))
        self.state = {'status': 'prepared', 'source_pin_count': len(self.config['source_pins']),
            'config_sha256': self.config_digest, 'bridge_sha256': self.config['bridge_sha256'],
            'reader_sha256': self.config['reader_sha256'], 'model_verified': False}

    def start(self, *, pid, created_at, parent_pid, parent_created_at, restart_queued, gate, owned_identity, retained_owner_anchor=None):
        if self.attempted:
            return self.state
        if (restart_queued is not True or type(gate) is not dict or
                not all(gate.get(key) is True for key in ('entry_completion_observed',
                    'current_owned_process', 'typed_references_observed')) or
                type(pid) is not int or pid <= 0 or type(created_at) not in (int, float) or
                not math.isfinite(created_at) or created_at <= 0 or owned_identity != (pid, created_at) or
                type(parent_pid) is not int or parent_pid <= 0 or type(parent_created_at) not in (int, float) or
                not math.isfinite(parent_created_at) or parent_created_at <= 0):
            raise ValueError('Automatic observation requires the exact current queued Restart gate')
        self.attempted = True
        try:
            validate_config(self.config_path, base_root=self.base_root, game_root=self.game_root,
                expected_digest=self.config_digest, helper_path=Path(__file__))
            output = trial_output(self.base_root, self.trial_root)
            output.mkdir(exist_ok=False)
            self.output = output
            self.log = (output / 'private-worker-console.log').open('wb')
            command = [sys.executable, '-B', self.config['bridge_path'],
                '--config-file', str(self.config_path.resolve()), '--expected-config-sha256', self.config_digest,
                '--game-root', str(self.game_root.resolve()), '--pid', str(pid), '--created-at', str(created_at),
                '--parent-pid', str(parent_pid), '--parent-created-at', str(parent_created_at),
                '--output-directory', str(output.resolve())]
            # Keep ROOT script/reader precedence while resolving the one BASE-only policy import.
            # Never inherit additional PYTHONPATH search roots from the caller.
            child_environment = os.environ.copy()
            child_environment['PYTHONPATH'] = str((self.base_root.resolve(strict=True) / 'work').resolve(strict=True))
            retained=self.config.get('retain_original_fashion_worker',False)
            if retained:
                from dfserver.legacy_ds_fashion_retained_protocol import RetainedWorkerClient,canonical,sha,owner_anchor
                anchor=owner_anchor(retained_owner_anchor)
                command.append('--retained-fashion-pipe')
                self.process=self.popen(command,cwd=self.config['repository_root'],env=child_environment,stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=self.log,bufsize=0,
                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                self._retained_command=command[:]
                def source_check():
                    validate_config(self.config_path,base_root=self.base_root,game_root=self.game_root,
                        expected_digest=self.config_digest,helper_path=Path(__file__))
                import secrets
                self.retained_client=RetainedWorkerClient.start_owned_popen(self.process,key=secrets.token_bytes(32),
                    anchor=anchor,source_digest=sha(canonical(self.config['source_pins'])),
                    expected_game_identity=(pid,created_at),source_check=source_check,launch_policy=self)
            else:
                if retained_owner_anchor is not None:
                    raise ValueError('Retained worker is not enabled in the sealed policy')
                self.process = self.popen(command, cwd=self.config['repository_root'],env=child_environment,
                    stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.started = self.clock()
            self.state.update(status='running', stage='after_current_restart_request',
                output_relative_to_base=output.relative_to(self.base_root.resolve()).as_posix(),
                supervisor_seconds=MAXIMUM_SECONDS, additional_authorization_requested=False)
        except Exception as error:
            self.state.update(status='refused', error_type=type(error).__name__)
            if self.log is not None:
                self.log.close()
                self.log = None
        return self.state

    def bind_retained_channel_outside_lock(self):
        if not self.config.get('retain_original_fashion_worker',False) or self.process is None:
            raise ValueError('Retained original worker is default off')
        client=self.retained_client.bind_authenticated_hello_outside_lock(maximum_wait_deadline=self.started+180)
        from dfserver.legacy_ds_fashion_async_bridge import bind_original_session_channel
        return bind_original_session_channel(client)

    def poll(self):
        if self.process is None or self.state.get('status') != 'running':
            return dict(self.state)
        code = self.process.poll()
        if code is None and self.clock() - self.started >= MAXIMUM_SECONDS:
            self.close(reason='observer_supervision_timeout')
        elif code is not None:
            try:
                validate_config(self.config_path, base_root=self.base_root, game_root=self.game_root,
                    expected_digest=self.config_digest, helper_path=Path(__file__))
                path = self.output / 'summary.json'
                if path.stat().st_size > 64 * 1024:
                    raise ValueError('Observer summary exceeds its fixed bound')
                projected = safe_summary(json.loads(path.read_text('utf-8')))
                self.state.update(status='completed' if code == 0 and projected['status'] == 'complete' else 'refused',
                    exit_code=code, observation=projected)
            except Exception as error:
                self.state.update(status='refused', error_type=type(error).__name__)
            finally:
                if self.log is not None:
                    self.log.close()
                    self.log = None
        return dict(self.state)

    def close(self, *, reason='trial_cleanup'):
        client=getattr(self,'retained_client',None)
        if client is not None:client.close_outside_lock()
        if (self.process is not None and self.process.poll() is not None and
                self.state.get('status') == 'running'):
            self.poll()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
            self.state.update(status='stopped', stop_reason=reason, owned_observer_only_terminated=True)
        if self.log is not None:
            self.log.close()
            self.log = None
        return dict(self.state)
