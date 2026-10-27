"""Seal role/MapInfo initialization dependencies from saved and immutable sources."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache
from skill_entity_readonly_scope import CAPTURE, CAPTURE_SHA256, CLIENT_SHA256
from recover_economy_pak_access import installed_name_map
from extract_operator_avatar_catalog import fname, tags, property_tag

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT/'work/evidence/model-init-chain-20261018'
MANIFEST_SHA256 = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
MAP_CAPTURE = 'work/native-client-tests/1792328560808149500/owned-map-marker-metadata.json'
MAP_CAPTURE_SHA256 = 'ff8b2c90f7a07aa5a74351c7ada8c389a8c85c6a708fe0cf78c7e456dceed1c9'
NATIVE = (
    'native-dfm-skill-authority-give-expert-core-v1.json',
    'native-dfm-skill-give-expert-parameter-fields-v1.json',
    'native-skill-entity-client-replication-registration-v1.json',
    'native-skill-state-struct-declarations-v1.json',
    'native-skill-state-items-and-map-quest-structs-v1.json',
    'native-skill-state-base-fields-v1.json',
    'native-skill-state-notify-exec-v1.json',
    'native-skill-state-notify-create-entities-v1.json',
    'native-skill-state-client-add-and-reconcile-v1.json',
    'native-skill-row-type-and-map-receive-serialization-v1.json',
    'native-dfm-skill-sol-addskills-gate-v1.json',
    'native-skill-data-system-and-gs-declarations-v1.json',
    'native-skill-gs-rep-consumer-v1.json',
    'native-map-highvalue-real-exec-pairs-v1.json',
    'native-map-highvalue-actual-notify-consumer-v1.json',
    'native-map-marker-high-value-struct-fields.json',
    'native-map-name-and-skill-int-native-leaves-v1.json',
    'native-map-text-native-leaf-v1.json',
    'native-map-marker-exit-initialization.json',
    'native-vitals-health-bar-segment-and-update-bodies.json',
    'native-gp-sprint-actual-ability-gates.json',
)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _native_skill_fields(game_root):
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600', MANIFEST_SHA256, game_root)
    exe = game_root/cache.manifest['plan']['client_relative_to_game_root']
    with exe.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != CLIENT_SHA256:
            raise ValueError('The immutable skill declaration client changed')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            image = ImmutableImage(mapped)
            record = image.read(0x1cd4af80, 72)
            words = struct.unpack('<9Q', record)
            count, flags = words[7] & 0xffffffff, words[7] >> 32
            if flags != 0x45 or not 1 <= count <= 512 or words[4] != 0x9e0:
                raise ValueError('The exact large SkillDataConfig native row record changed')
            pointers = image.read(words[6]-image.image_base, count*8)
            selected = []
            names = {'SkillID', 'AbilityDataSpawnType', 'AbilitySpawnType', 'AddSkills',
                'AddSkills_Sol', 'AddSkills_Mp', 'AddSkills_Avatar', 'Slot'}
            for pointer in struct.unpack('<'+'Q'*count, pointers):
                raw = image.read(pointer-image.image_base, 56)
                cells = struct.unpack_from('<5Q', raw)
                name = image.read(cells[0]-image.image_base, 128).split(b'\0', 1)[0].decode('ascii')
                offset = cells[4] >> 32
                if name in names and offset >= 0x10:
                    selected.append(dict(name=name, native_offset=offset,
                        native_gen_flags=hex(cells[3] & 0xffffffff), property_flags=hex(cells[2]),
                        property_record_rva=hex(pointer-image.image_base), record_sha256=_sha(raw)))
            return dict(struct_params_rva='0x1cd4af80', struct_params_sha256=_sha(record),
                native_bytes=words[4], property_record_count=count,
                property_pointer_array_sha256=_sha(pointers), selected_fields=selected)


def _commands(obj, parents):
    layout = obj['existing_driver_class']['layout']
    keys = ('command_index', 'data_offset', 'relative_handle', 'parent_index', 'dispatch_opcode',
        'record_sha256', 'descriptor_name', 'current_property_declaration')
    result = []
    for command in layout['commands']:
        if command.get('parent_index') not in parents:
            continue
        row = {k: command[k] for k in keys if k in command}
        for key in ('property_serializer_hook', 'property_scalar_leaf_hook'):
            if key in command:
                row[key] = {k: command[key][k] for k in ('slot', 'vtable_rva', 'target_rva',
                    'inside_pinned_image', 'identity_rechecked')}
        result.append(row)
    return dict(class_path=obj['class_path'], commands_sha256=layout['commands_sha256'],
        parents_sha256=layout['parents_sha256'], parent_count=layout['parent_count'],
        command_count=layout['command_count'], commands=result)


def _high_value_names(table, source):
    asset = (ROOT/Path(table['source_uasset'].replace('\\', '/'))).read_bytes()
    payload = (ROOT/Path(table['source_uexp'].replace('\\', '/'))).read_bytes()
    if (_sha(asset) != table['source_uasset_sha256'] or _sha(payload) != table['source_uexp_sha256']):
        raise ValueError('The cooked high-value source changed')
    names = installed_name_map(asset)
    row = table['rows']['2201']
    fields, _ = tags(payload, row['serialized_uexp_offset']+8, names, len(payload))
    outer, = [t for t in fields if t['name'] == 'HighValueBoxInfoArray']
    count = struct.unpack_from('<I', payload, outer['value_start'])[0]
    inner = property_tag(payload, outer['value_start']+4, names, outer['end'])
    at, results = inner['value_start'], []
    if count != len(row['fields']['HighValueBoxInfoArray']) or count > 64:
        raise ValueError('The exact high-value source array changed')
    for index in range(count):
        props, at = tags(payload, at, names, outer['end'])
        tag, = [t for t in props if t['name'] == 'IconName' and t['kind'] == 'NameProperty']
        token = payload[tag['value_start']:tag['end']]
        name_index, number = struct.unpack('<II', token)
        if fname(payload, tag['value_start'], names) != row['fields']['HighValueBoxInfoArray'][index]['IconName']:
            raise ValueError('The high-value original FName token does not match its source row')
        results.append(dict(source_index=index, base_name=names[name_index], original_number=number,
            display_name=fname(payload, tag['value_start'], names), serialized_uexp_offset=tag['value_start'],
            source_token_hex=token.hex()))
    if at != outer['end']:
        raise ValueError('High-value FName source parsing did not consume its array')
    source['cooked_pair_qualified'] = True
    return results


def build(game_root):
    sources = {}
    def load(relative, expected=None):
        path = ROOT/relative
        raw = path.read_bytes()
        if expected and _sha(raw) != expected:
            raise ValueError('The exact initialization source changed: '+relative)
        sources[relative] = _sha(raw)
        return json.loads(raw)
    vitals = load(CAPTURE, CAPTURE_SHA256)
    maps = load(MAP_CAPTURE, MAP_CAPTURE_SHA256)
    for name in NATIVE:
        doc = load('work/evidence/model-init-chain-20261018/'+name)
        if doc.get('client_sha256') != CLIENT_SHA256 or doc.get('process_access') is not False:
            raise ValueError('A native dependency is not the pinned offline client: '+name)
    values = load('work/evidence/model-init-chain-20261018/native-vitals-skill-and-health-source-contract.json')
    rows = {}
    for name in ('skilldataconfig', 'skilldataconfig-combination', 'skilldataconfig-skilldev'):
        doc = load('work/evidence/model-init-chain-20261018/native-vitals-'+name+'-actual-rows.json')
        for key, row in doc['rows'].items():
            if key in rows:
                raise ValueError('Skill source redirect precedence is not qualified for duplicate row '+key)
            rows[key] = dict(source_table=doc['source_table'], **row)
    hero = values['hero_bindings']['88000000025']
    order = ('SOLUltimateSkillID', 'SOLActiveSkillID', 'SOLPassiveSkillID',
        'SOLSupportSkillID', 'SOLCommonPassiveSkillID', 'SOLCommonSkillID')
    initial = []
    for field in order:
        value = hero['source_SOL_skill_fields'][field]
        initial.extend(value if type(value) is list else [value])
    selected, missing, seen = [], [], set()
    def visit(skill_id):
        if skill_id <= 0 or skill_id in seen:
            return
        if len(seen) >= 128:
            raise ValueError('Skill source dependency graph exceeds the fixed audit bound')
        seen.add(skill_id)
        row = rows.get(str(skill_id))
        if row is None:
            missing.append(skill_id)
            return
        fields = row['fields']
        selected.append(dict(skill_id=skill_id, source_table=row['source_table'],
            serialized_uexp_offset=row['serialized_uexp_offset'],
            ability_data_spawn_flags=fields['AbilityDataSpawnType'],
            ordinary_owner_state_required_by_bit1=bool(fields['AbilityDataSpawnType'] & 2),
            ordinary_3p_state_required_by_bit2=bool(fields['AbilityDataSpawnType'] & 4),
            add_skills=fields['AddSkills'], add_skills_SOL=fields['AddSkills_Sol'],
            additional_avatar_branch=fields['AddSkills_Avatar'],
            configured_instance_class=fields['SkillEntityComponentClass'],
            configured_template_class=fields['SkillEntityTemplateClass']))
        for child in fields['AddSkills']+fields['AddSkills_Sol']:
            visit(child)
    for skill_id in initial:
        visit(skill_id)
    skill = next(o for o in vitals['objects'] if o['identity']['name'] == 'DFMSkill')
    info = next(o for o in maps['objects'] if o['scope'] == 'MapInfoSystemComponent')
    psinfo = next(o for o in maps['objects'] if o['scope'] == 'MapInfoComp')
    gs, ps = maps['root_metadata']['game_state'], maps['root_metadata']['player_state']
    high_path = 'work/evidence/map-system-audit-20261018/native-highvalueboxseamlessmapinfotable-actual-rows.json'
    high = load(high_path)
    high_source = dict(report_path=high_path, report_sha256=sources[high_path],
        source_table=high['source_table'], row='2201', serialized_uexp_offset=high['rows']['2201']['serialized_uexp_offset'])
    names = _high_value_names(high, high_source)
    for key in ('source_uasset', 'source_uexp'):
        path = Path(high[key].replace('\\', '/'))
        sources[path.as_posix()] = high[key+'_sha256']
    native_fields = _native_skill_fields(game_root)
    by_name = {r['name']: r for r in native_fields['selected_fields']}
    if (by_name['AbilityDataSpawnType']['native_offset'] != 0x80 or
            by_name['AddSkills']['native_offset'] != 0xb8 or by_name['AddSkills_Sol']['native_offset'] != 0xc8):
        raise ValueError('The native registration branch to configured flags/lists did not match')
    sources['work/seal_role_map_initialization_contract.py'] = _sha(Path(__file__).read_bytes())
    return dict(kind='source_qualified_role_map_initialization_research_contract_v1',
        client_sha256=CLIENT_SHA256, process_access=False, client_launched=False,
        gameplay_production_edited=False, sources=sources,
        native_skill_row_fields=native_fields,
        skill=dict(current_expert_id=10010, current_player_index=0,
            actual_Primary_entity_maps_and_replicated_state_values_not_yet_observed=True,
            local_ability_array_empty_does_not_prove_primary_entity_map_empty=True,
            native_expert_grant_field_order=list(order), source_first_level_skill_ids=initial,
            SOL_dependency_candidate_rows=selected, source_unresolved_dependency_ids=missing,
            runtime_redirect_variant_or_avatar_extension_claimed=False,
            native_state_registration='31ed5b0 increments int32 instance counter, writes SkillID/UniqueID; row+80 bit1 appends SkillState, bit2 appends SkillState3P. SkillDataSpawnType1 alone has no such client state.',
            normal_client_receive=[
                'SkillDetailInfo/SkillPlayerIndex ordinary ascending handles4/5/6 in one block.',
                'SkillState ordinary parent6: global h141 SkillEntityStates, h142 UpdateIndexArray, h143 bCheckSkillLeave.',
                'SkillState3P ordinary parent7: global h144 SkillEntityStates.',
                'Rep_SkillEntityStates exec607a330->3411770. HasBegunPlay bytecc&20 false defers using component+61c; true calls33e4490.',
                '33e4490->32fe140 resolves ASkillSubsystem; DataSystem+370 must be nonnull.',
                '33e7b10..33e7b34 walks40B states, passes SkillId+0 and SkillEntityUniqueID+4 to31e58e0 AddSkillEntity.',
                'AddSkillEntity looks up actual SkillDataConfig and builds local3f0-byte contexts, primary maps, template/instance as source row requests.',
                'ASkillSubsystem EntityDataList/DataSystem are nonNet state; GS AbilityExcuteDataArray callback4c7c060 is debug traversal, not this grant entry.'
            ], observed_wire=_commands(skill, {6, 7}),
            instance_id_policy='Server-owned positive int32 monotonically allocated instance IDs, frozen per admission. Configured SkillIDs are never reused as instance IDs.',
            proposed_verification='Read actual state arrays and primary map/context together, then send a source-qualified frozen owner-state roster through normal ordinary RepLayout; verify matching SkillID/UniqueID maps and native context/instance creation before calling skills fixed.'),
        sprint_health=dict(source_state='Speed1, RuntimeMaxSpeed1500, Stand340, Sprint605, Stamina100/Max100, EnableSprint1, LockSprint0, Moveable0, Health100/Max100, Shield0/Max0 in the sealed cohort.',
            invalid_shortcuts=['No200HP patch from screenshot', 'NoMoveable1 patch from zero value', 'No forced stamina visibility at full/nonchasing state', 'No empty component probe counted as initialization'],
            main_health_bar_formula='Native8aff880 reads CurHealth / (Pawn.MaxHealthBase + CurShieldHealth + epsilon);100-threshold extra-segment branch8af8fe0 is separate.',
            sprint_remaining='Current Blackboard.SprintComponent and input bitarray scope are awaiting the exact qualified supplement observation; current individual CanSprint rejection is not established. SkillState grant must be separated from independent sprint input/weapon/vitals gates.'),
        normal_array_grammar=dict(source_rva='0x12dbacf0',
            count='Raw uint16, not packed integer; proof12dbae86.',
            children='Packed child handles are one increasing stream across all array elements, derived from the native loop current-handle counter; there is no per-element zero terminator.',
            termination='One zero child-handle terminates the whole array; then continue parent stream. Nested arrays have their own uint16 count and child stream.',
            skill_owner_child_handle_count=6, skill_3p_child_handle_count=5, high_value_child_handle_count=9,
            grammar_implementation_or_client_acceptance_claimed=False),
        map_info=dict(high_value_source=high_source, high_value_original_name_tokens=names,
            high_value_source_points=32, high_value_unique_DSLoc=25,
            ordinary_receiver=_commands(info, {7, 14}),
            high_value_consumer='OnRep_HighValueBoxInfoArray nativeexec cfe22b0->c2bb290 iterates96B records; source IconName+48/DSLoc+50 ->c5e11d0 marker kind0x30, c29d520 copies HighValueBoxInfo, virtual+280 updates marker.',
            high_value_codec_gaps=['FName archive virtual+50 actual override qualification', 'FText archive virtual+48 exact history grammar', 'PlainFVector NetSerialize binding; ActorOpen packed-vector codec does not qualify it', 'Enum declaration/max-width for3 enum children'],
            high_value_preview_is_world_instance=False,
            quest_receiver=_commands(psinfo, {7, 8}),
            quest_source='MapQuestLocationData20B contains IconName FName+0 and WorldPos FVector+8. Its location array does not grant a contract/quest.',
            quest_missing='No Level1 authoritative task selection policy is closed. Real ID catalog outputs/df-local-server/protocol/native_quest_catalog.json is available; selected real quest tracking state must precede marker publication.',
            exits_receiver=_commands(ps, {95}),
            exits_source='PS.AllocatedExits currently count0. InitPlayerExits8924410 enumerates+f18 references and calls89092c0 for each actual Actor. Configured PlayerExitId values cannot substitute for UObject NetGUIDs.',
            exits_cooked_source='8 actual GameplayConfig exports33..40 are source candidates. Current-world exit identities/Actor references and condition lifecycle are handled by world research.',
            mandel_GS_receiver=_commands(gs, {55}),
            mandel_actual_GS_reference='BlueprintPlunder+1078 is observed null, normal object handle106.',
            mandel_missing='Preview event2201,8 generator candidates and16 decipher positions do not create/replicate BlueprintPlunder. Need real Actor class/CDO/creation and field layout plus authoritative active instance state.',
            implementation_order=['Freeze selected real high-value config rows and local activation policy in ticket state.',
                'Close FName/FText/plainVector/enum native serializer contracts before high-value array codec.',
                'Encode active marker entries from exact source rows with original FName base/number; await actual array readback and marker consumer evidence.',
                'Bind actual exit Actor references and actual quest tracker state, then publish their separate marker arrays.',
                'Create Mandel world system through qualified Actor lifecycle before its GS object reference/marker state.']),
        no_official_bunch_or_complete_native_gameplay_claimed=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work/evidence').resolve()):
        parser.error('A fresh evidence path is required')
    result = build(args.game_root)
    encoded = (json.dumps(result, indent=2)+'\n').encode()
    with output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps(dict(output=str(output), sha256=_sha(encoded), sources=len(result['sources']))))
