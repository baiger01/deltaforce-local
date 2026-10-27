"""Export the source-qualified GS ability dynamic-component creation subset."""
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FOLDER = 'work/evidence/model-init-chain-20261018/'
PINS = {
    'native-current-skill-game-state-factory-sources-v1.json': 'a404c0261099ced2d11cb446bc92ef4a3f8d9b4442aa53adfcd610a78a04adb0',
    'native-current-skill-gs-config-asset-source-v2.json': '904eeb71df27aab8ad7b96267b44c62f9f9eac042411166dc4764740545ed18a',
    'native-current-skill-gs-config-table-rows-v1.json': '7b0e40733c544c922757ca17494715e2b0311c3fe841d25cc225da6395e7a538',
    'native-current-skill-gs-config-key-initializer-v1.json': '4dd08e26f29d5a628153c2da025f40fc0a83532482e4b1fa611b6987d754c6be',
    'native-current-skill-gs-ability-field-assignment-v1.json': 'ec865e75e5c4a48fc7baaa7fcad6fa7ab311d4603dbd072496fd1ff3f0071cbf',
    'native-current-skill-dfm-class-registrations-v1.json': 'f71d7de5e6d43bb31648199e53d2ede1782fda113dc1e894578a2e7e8060e9e6',
    'native-current-skill-dfm-constructors-v1.json': 'deaf6394ccd5390b780e7fe92a8a0117c6be29af5208102dfdf32822d5ccc9a4',
    'native-current-skill-gs-component-declarations-v1.json': '13214f5b1d293f156194323d9f62b163cc0e1f3eb74fb1b6286c5bedd8c5cd9e',
    'native-current-skill-dynamic-subobject-receive-header-v1.json': '027ef34cb7fce8aa76a8e663b0e4e8ffe7486bae51fee5934d72742ee286770c',
    'native-current-skill-gs-created-from-replication-slot-v1.json': '9658b072a63cb59f197a3e51379e31602267788d17b48cc0f2c45159e059801e',
    'native-current-skill-gs-created-from-replication-body-v1.json': 'dd64eb0425091017d881b8d5fdffbe23df8baf62c693875245b2f6cfd2145f98',
    'native-current-skill-sol-gs-constructor-v1.json': 'c24e566e8303fa38f9e6c17cf9a7fdaf2e187eee91f3745fa59b02af54a229de',
    'native-current-skill-gs-config-registry-row-v1.json': '87de9bf2bb977b1a939cb6f8f70a75ddcc7a2e981f16f4d5702d039658bddfd7',
    'native-current-skill-gs-ability-client-binding-callers-v1.json': '749c0488c07c8182b2d8460ca8777c4f0557de34b3302dfe52aa99aaf2f803ae',
    'native-current-skill-component-register-and-beginplay-v1.json': '43d86e0ce4118dc6ba866abef25df1f7a841ec98109afe053a1f6b2a3304f370',
    'native-current-skill-component-constructor-owner-v1.json': 'eeb0d09eadf6d34e0afc161e839230bf3640b9d7a8e0566d2cc0673e7950c664',
    'native-current-skill-data-and-gs-beginplay-v1.json': '8582f6b3e73c9a06bdf6435de0de87666ea2d58c2a48991924a5f9af136e5e17',
    'native-current-skill-data-register-and-gs-local-init-v1.json': '4cb7360c38c538790bf1af1b3902fd759d48a1f2cc9383a65eaa38930087d954',
    'native-current-skill-data-system-on-gs-init-replay-v1.json': '28af75435e11aa3da350fe68a22e7d165e967d6a949e5dbc35b6f8e173a5d01e',
    'native-current-skill-dfm-gs-context-init-hook-v1.json': 'aafda9614dbf5caa8a5953f4e059c31cba0f5ec4e6516892ba9ff65daa695762',
    'native-current-skill-gs-no-template-row-fill-v1.json': 'cb35aadd427f4a216ca7051a5067267f400292b84e7807085db63555c59f40d7',
    'native-current-skill-context-type-write-bodies-v1.json': '4bacd044829b085bfd7f205e39e24d1d08a8072c217a260b10bf8b88f1b031d6',
    'native-current-skill-gs-create-ability-template-v1.json': 'db3200ff1efaddb9a716570c1fff795a53eb8baed63d80bc08d4df40ce6b6056',
    'native-current-skill-gs-template-setup-context-v1.json': 'e6f1c5b49c2c3c85b4f8547562e380a71ebdc25cabf543e5ebd572951e35d298',
}
OUTPUT = FOLDER+'native-current-skill-gs-dynamic-component-schema-v2.json'


def build_schema():
    docs, sources = {}, []
    for name, expected in PINS.items():
        raw = (ROOT/FOLDER/name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('The GS skill native source changed: '+name)
        docs[name] = json.loads(raw)
        sources.append(dict(relative_path=FOLDER+name, sha256=expected))
    factory = docs['native-current-skill-game-state-factory-sources-v1.json']
    for package in ('gs_cooked_package','config_table_package'):
        sources.extend(factory[package]['source_files'])
    registry = docs['native-current-skill-gs-config-registry-row-v1.json']
    registry_row = registry['rows']['DFMAbilityConfig']
    if (registry_row['serialized_uexp_offset'] != 61391 or
            registry_row['fields']['DefaultPath'] != '/Game/DataTables/Ability/DFMAbilityConfig.DFMAbilityConfig' or
            registry_row['fields']['MatchModeIdToDataTables'] or
            registry_row['fields']['bReplaceDefaultPathWithMatchModeId']):
        raise ValueError('The actual config table registry route differs')
    for extension in ('uasset','uexp'):
        path = Path(registry['source_'+extension])
        sources.append(dict(relative_path=path.as_posix(),sha256=registry['source_'+extension+'_sha256']))
    for source in sources:
        if hashlib.sha256((ROOT/source['relative_path']).read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('The decoded installed skill asset changed')
    target = factory['selected_row']['resolved_proxy_class']
    if target != '/Script/DFMAbility.DFMAbilityGameStateComponent':
        raise ValueError('The actual ProxyClass is not the source DFM ability component')
    if any('AbilityGameStateComponent' in str(e['class_path']) for e in factory['gs_cooked_package']['exports']):
        raise ValueError('The cooked component source boundary changed')
    pins = []
    for name, addresses in {
        'native-current-skill-gs-ability-field-assignment-v1.json': (
            '0xb89ccc9', '0xb89ccdd', '0xb89cce3', '0xb89cd12', '0xb89cda6',
            '0xb89ce77', '0xb89ced4', '0xb89cee0', '0xb89cee5', '0xb89cef7', '0xb89cf07', '0xb89cf13'),
        'native-current-skill-dynamic-subobject-receive-header-v1.json': (
            '0x12863e3b', '0x12863e3e', '0x12863f48', '0x12863f4b', '0x12863f52',
            '0x128645dd', '0x1286460f', '0x12864698', '0x128646e7', '0x128647d6',
            '0x128647de', '0x128647f5', '0x12864809', '0x1286482b'),
        'native-current-skill-gs-created-from-replication-body-v1.json': (
            '0x125bcabd', '0x125bcae3', '0x125bcae8', '0x125bcaed'),
        'native-current-skill-component-register-and-beginplay-v1.json': (
            '0x1270cbc4', '0x1270cbd4', '0x1270cc03', '0x1270cd0e', '0x1270cd24', '0x1270cd47'),
        'native-current-skill-data-and-gs-beginplay-v1.json': (
            '0x7ebc5ef', '0x7ebc61c', '0x7ebc625', '0x7ebc664', '0x7ebc66d'),
        'native-current-skill-data-system-on-gs-init-replay-v1.json': ('0x351f969',),
        'native-current-skill-context-type-write-bodies-v1.json': (
            '0x3518145','0x3518156','0x35181e9','0x35181f1'),
    }.items():
        instructions = {x['rva']:x for f in docs[name]['functions'] for x in f['instructions']}
        for address in addresses:
            instruction = instructions[address]
            pins.append(dict(source_relative_path=FOLDER+name, rva=address,
                bytes=instruction['bytes'], mnemonic=instruction['mnemonic'], operands=instruction['operands']))
    declarations = docs['native-current-skill-gs-component-declarations-v1.json']
    fields = [dict(declaring_class='DFMAbilityGameStateComponent' if c['static_class_getter_rva']=='0x80820f0'
        else 'GPAbilityGameStateComponent', **f) for c in declarations['classes'] for f in c['net_property_records']]
    return dict(kind='source_qualified_gs_ability_dynamic_component_creation_v1',
        client_sha256=factory['client_sha256'], cache_manifest_sha256=factory['cache_manifest_sha256'],
        connection_network_version=13, archive_network_version=13,
        component=dict(class_path=target, authority_name='GameStateAbilityComponent',
            client_replication_creation_name=None, default_subobject=False,
            creation_method='authority_dynamic_instance_component', outer='existing_channel_GameState_actor',
            source_table='/Game/DataTables/Ability/DFMAbilityConfig', source_row='GSAbilityComponent',
            source_row_uexp_offset=45, native_net_fields_without_wire_handles=fields),
        header=dict(has_rep_layout=True, actor_selector=False, stably_named=False,
            fields=['has_rep_layout_1bit','actor_selector_1bit','packed_object_guid',
                'stably_named_1bit','packed_class_guid','packed_payload_bits','payload_exact_bits'],
            client_new_object_name=None, client_new_object_outer='channel_actor',
            component_register_hook='0x125bcab0', empty_rep_layout_bits=9),
        sources=sources, instruction_pins=pins,
        normal_lifecycle=dict(owner_binding_constructor_rva='0x126f4670',
            register_with_world_rva='0x1270ca30',
            beginplay_if_owner_begun_and_component_not_begun_rva='0x1270cd47',
            dfm_component_beginplay_rva='0x7ebc540',
            local_ability_systems_init_rva='0x7ee4ca0',
            game_state_init_delegate_offset='0x938',
            data_system_replay_existing_contexts_rva='0x351f890',
            context_config_fill_rva='0x3517ba0',
            source_skill_state_type_load_rva='0x35181e9',
            source_skill_state_type_store_rva='0x35181f1',
            gs_field_lazy_find_getter_rva='0xb8ab8d0',
            gs_field_is_non_net=True, gs_field_may_stay_null_until_native_lazy_getter=True,
            data_system_is_not_created_by_this_network_content=True,
            before_owner_state='Existing GS Open and class export ACKs; native registration and BeginPlay use normal world/owner conditions',
            after_creation='Native GS ability class with current GS Outer must be strictly observed; actual name is not forced'),
        remaining_gates=['actual current component/owner/registered/begunplay values',
            'existing SkillSubsystem.DataSystem and valid typed context owner/component references',
            'actual driver RepLayout handles and serializers for six declared native net fields',
            'AbilityTemplateRepData and AbilityIndexRam gameplay replication where required',
            'global Blackboard skill permission reasons remain independently blocked in the latest log'],
        process_access=False, native_methods_invoked=False, runtime_component_observed=False,
        skills_initialized_claimed=False, wire_property_handles_qualified=False,
        local_policy='Only empty creation content; actual GS layout and state require a later strict observation',
        source_table_is_baseline=True, later_override_absence_claimed=False)


if __name__ == '__main__':
    result = build_schema()
    raw = (json.dumps(result, indent=2, sort_keys=True)+'\n').encode()
    with (ROOT/OUTPUT).open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=OUTPUT, sha256=hashlib.sha256(raw).hexdigest())))
