"""Build a source-backed, control-only diagnostic profile for Shipping79fb7b10.

Reads exact current shadow PAK entries and sealed offline native qualifications.
No client launch, process access, account mutation, runtime metadata collection,
old profile rewrite, shared launcher edit, or gameplay compatibility claim.
"""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

from research_updated_content_resources import access
from research_updated_map_rule_sources import fields_table
from recover_economy_pak_access import (
    pak_footer, validate_index, directory_index, entry_offset, decode_entry,
)
from scan_weapon_tables import parse_entry
import oodle_payload_reader
from local_game_paths import game_paths


ROOT = Path(__file__).resolve().parent.parent
SHADOW = game_paths()[1]
CLIENT_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
PROFILE = ROOT/'outputs/df-local-server/protocol/native_ds_control_profile_79fb7b10.json'
EVIDENCE = ROOT/'work/evidence/updated-control-profile-sources-79fb7b10.json'
REPORTS = {
    'work/evidence/updated-control-contract-79fb7b10.json':
        'e176ef7d2d33771d1f2573331f64bbfd8797e76242f9c0d1af3827ea61e6d40b',
    'work/research_updated_transport_profile_79fb7b10.json':
        '2e55c4989ddb28f7ae75a6ddfd62e92f50d77bc523a99aebbf84ffd65ccd43c8',
    'work/research_updated_transport_79fb7b10.json':
        'd127c9b551192ba1a126f3b5f5e2c90f9a9a6a0e6d4ff806b6d037941fb73e92',
    'work/research_updated_stateless_handshake_79fb7b10.json':
        'eb77c89cd90717df7f49f18c0e47610460933d32b474cf7168c1742a9025330c',
    'work/evidence/updated-subworld-79fb7b10.json':
        '0ea823df0e5b3aae0d348310888a3b25b351e4a99eb1a780c4ff652c7afc1544',
}
MAP_BASE = '../../../DeltaForce/Content/R13N/Common/Base/DataTables/MapConfig'
SUBWORLD_BASE = '../../../DeltaForce/Content/DataTables/SubWorld/DT_SubWorldConfig_Iris_Entry'
ASSETS = {
    MAP_BASE+'.uasset': ('pak-0-0-pakchunk2-WindowsClient.pak',141472,49543168,9603,
        'e41784765610dfde36cbd23d99c37f26c42448af2f43b6482bb845da0459d372'),
    MAP_BASE+'.uexp': ('pak-0-0-pakchunk2-WindowsClient.pak',141496,49548361,398086,
        '5486a2b773a5a387b8d835f2693be17ca4b21eebf1444282a0734cb110590221'),
    SUBWORLD_BASE+'.uasset': ('pak-0-1-pakchunk73-WindowsClient.pak',23328,14882816,9053,
        '78103cc76430791b6d40e19116d9878d16ba2f149049f246482b177bc965cfcf'),
    SUBWORLD_BASE+'.uexp': ('pak-0-1-pakchunk73-WindowsClient.pak',23352,14885641,53266,
        '8f55c19e62c061f0427b172b32175dedd53b41bbbabccb2eea5ebd1deaf49199'),
}
INDEX_PINS = {
    'pak-0-0-pakchunk2-WindowsClient.pak':
        '6203f02e04093d563cc4b1f158bb349bca6aff6943d3047d4c6fef1f0ecf3ba1',
    'pak-0-1-pakchunk73-WindowsClient.pak':
        '3c0ea9f5e7872e73074adc6741d287f09dcd81377754ad8b5ea6a11fb2d02fe3',
}
HOTFIX = '1.101.37117.36.14_WindowsNoEditor_37131_P.pak'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def serialized(doc):
    return (json.dumps(doc,indent=2,sort_keys=True)+'\n').encode('ascii')


def pinned_reports():
    docs,pins = {},[]
    for relative,expected in REPORTS.items():
        raw = (ROOT/relative).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Sealed current native qualification changed: '+relative)
        doc = json.loads(raw)
        if doc.get('client_sha256') != CLIENT_SHA:
            raise ValueError('Current native qualification has a different client')
        docs[relative] = doc
        pins.append(dict(relative_path=relative,sha256=expected,bytes=len(raw)))
    control = docs['work/evidence/updated-control-contract-79fb7b10.json']
    transport = docs['work/research_updated_transport_profile_79fb7b10.json']
    subworld = docs['work/evidence/updated-subworld-79fb7b10.json']
    hello = control['updated_captured_hello']
    if (hello['message_id'],hello['endian'],hello['network_version_u32'],hello['trailing_string_units']) != (0,1,1077088301,0):
        raise ValueError('Exact current captured Hello is required')
    if (not control['codec_reuse']['production_codecs_need_no_field_grammar_edit'] or
            transport['archive_version_proof']['engine_default_file_value'] != 13 or
            transport['cap_proof']['ordinary_zero_or_gt1024_request_becomes'] != 1024 or
            not any(r['name']=='Control' and r['hardcoded_index']==255 for r in transport['hardcoded_names'])):
        raise ValueError('Current native Control/archive/packet profile qualification is incomplete')
    if (subworld['contract']['current_native_redirect_subworld_consumer_qualified'] is not True or
            subworld['contract']['redirect_option_key']!='SubWorld' or
            subworld['contract']['redirect_key_value_separator']!='=' or
            subworld['engine_loadmap_binding']['slot']!='0x448' or
            subworld['engine_loadmap_binding']['target_rva']!='0x49bca80'):
        raise ValueError('Current native Welcome RedirectURL SubWorld consumer is not qualified')
    for key in ('capture','report'):
        path,expected = hello[key],hello[key+'_sha256']
        raw = (ROOT/path).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Current captured Hello source changed')
        pins.append(dict(relative_path=path,sha256=expected,bytes=len(raw)))
    return docs,pins


def current_tables(shadow):
    executable = shadow/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with executable.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest() != CLIENT_SHA:
            raise ValueError('Current profile requires the exact updated immutable shadow')
    oodle_payload_reader.PATH = shadow/'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    keys,provenance = access()
    decoded,archives = {},[]
    for filename in [*INDEX_PINS,HOTFIX]:
        path = shadow/'DeltaForce/Content/Paks'/filename
        footer = pak_footer(path)
        public = clear = key = None
        for candidate in keys:
            public,clear,key = validate_index(path,footer,{footer['guid']:candidate})
            if clear is not None:
                break
        if clear is None or not public['index_sha1_valid']:
            raise ValueError('Current archive index validation failed: '+filename)
        public.pop('registered_guid_found',None)
        if filename in INDEX_PINS and public['decoded_index_sha256'] != INDEX_PINS[filename]:
            raise ValueError('Exact current archive directory changed: '+filename)
        directory,files,encoded = directory_index(path,footer,clear,key)
        witnesses = []
        with path.open('rb') as stream:
            for name,location in files:
                if name not in ASSETS:
                    continue
                if filename == HOTFIX:
                    raise ValueError('A current hotfix overrides the selected MapConfig/SubWorld source')
                wanted_pak,wanted_location,wanted_offset,wanted_bytes,wanted_sha = ASSETS[name]
                offset = entry_offset(encoded,location)
                if (filename,location,offset) != (wanted_pak,wanted_location,wanted_offset):
                    raise ValueError('Current map source entry moved or is duplicated')
                entry = parse_entry(stream,offset,footer['offset'],variant='observed_permutation')
                raw,valid = decode_entry(stream,offset,entry,footer['methods'],key)
                if valid is not True or len(raw) != wanted_bytes or sha(raw) != wanted_sha:
                    raise ValueError('Current map source payload identity failed')
                if name in decoded:
                    raise ValueError('Ambiguous selected current map source')
                decoded[name] = raw
                witnesses.append(dict(asset=name,encoded_offset=location,entry_offset=offset,
                    decoded_bytes=len(raw),decoded_sha256=sha(raw),archive_payload_sha1_valid=True))
        archives.append(dict(archive=filename,path=str(path),validation=public,directory=directory,
            selected_entries=witnesses,
            selected_entries_absent=(filename==HOTFIX)))
    if set(decoded)!=set(ASSETS):
        raise ValueError('Current packaged map table source is incomplete')
    mapcfg = fields_table(decoded[MAP_BASE+'.uasset'],decoded[MAP_BASE+'.uexp'],{'2201'},
        {'MapID','LevelName','SubWorldName','LevelFullPath','bStreamingLevel','MaxMatchDuration'})
    subworld = fields_table(decoded[SUBWORLD_BASE+'.uasset'],decoded[SUBWORLD_BASE+'.uexp'],{'Dam_Iris_Level1'},
        {'MapType','Category'})
    row = mapcfg['rows']['2201']
    expected = dict(MapID=2201,LevelName='Dam_Iris_Level1',SubWorldName='Dam_Iris_Level1',
        LevelFullPath='/Game/Maps/Iris_Entry/Iris_Entry',bStreamingLevel=True,MaxMatchDuration=1800)
    if (mapcfg['row_count']!=640 or row['fields']!=expected or row['serialized_uexp_offset']!=71931 or
            row['serialized_sha256']!='75f33acecea3d1f0733695114e57f2bc96ea9fff92cb9401628361d770abbe7b' or
            subworld['row_count']!=81 or subworld['rows']['Dam_Iris_Level1']['serialized_uexp_offset']!=2673 or
            subworld['rows']['Dam_Iris_Level1']['serialized_sha256']!='f4c3d295195cb6a9a89b6afb8aeceeb6f427455e3c8f0f61acbec73635d86fc1'):
        raise ValueError('Current packaged Dam map/subworld row changed')
    values = dict(level=expected['LevelFullPath'].rsplit('/',1)[1],game='',
        redirect='SubWorld='+expected['SubWorldName'])
    return values,dict(executable=dict(path=str(executable),sha256=CLIENT_SHA),
        archive_scope='Exact current chunk2/chunk73 entries and absence of these four entries from the selected current _P hotfix; all other mounted archives/runtime replacements are not resolved',
        archive_reports=archives,map_config=mapcfg,subworld_config=subworld,
        key_provenance=provenance,keys_disclosed=False,
        derivation=dict(level='leaf of current MapConfig2201.LevelFullPath',
            redirect_value='current MapConfig2201.SubWorldName, also a current DT_SubWorldConfig_Iris_Entry row',
            redirect_option_key='Current full native engine49bca80 and seamless4961250 bodies split FURL.RedirectURL by space and equals and select the exact SubWorld key; see sealed updated-subworld report',
            game='explicit empty optional Welcome Game string; no GameMode path is inferred'))


def portable_source_locations(source):
    """Keep verified content identities, recording locations relative to the game."""
    result = copy.deepcopy(source)
    result['executable']['path'] = 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    for archive in result['archive_reports']:
        name = archive['archive']
        if '/' in name or '\\' in name or ':' in name or not name.endswith('.pak'):
            raise ValueError('An ordinary archive filename is required')
        relative = 'DeltaForce/Content/Paks/'+name
        archive['path'] = relative
        archive['validation']['pak'] = relative
    return result


def derive(shadow=SHADOW):
    docs,pins = pinned_reports()
    maps,current = current_tables(Path(shadow))
    current = portable_source_locations(current)
    control = docs['work/evidence/updated-control-contract-79fb7b10.json']
    transport = docs['work/research_updated_transport_profile_79fb7b10.json']
    subworld = docs['work/evidence/updated-subworld-79fb7b10.json']
    scope = dict(kind='control_only_diagnostic',selected_map_id=2201,observation_seconds=1800,
        shipping_shadow='DF_LOCAL_SHADOW_GAME',game_server_probe=True,ds_control_probe=True,
        disable_device_seamless=True,required_entry_flag='--disable-device-seamless',
        required_entry_setting='[ConsoleVariables]\nGame.DisableDeviceSeamless=1',
        startup_subworld_override=False,
        replication_metadata_export=False,initial_actor_bootstrap=False,
        actor_associations=False,actor_content=False,world_settings_channel=False,
        native_metadata_getters=False,account_or_inventory_mutation=False,
        native_protocol_compatibility_verified=False,playable_map_verified=False)
    helper_paths = ['work/build_updated_control_profile.py','work/research_updated_content_resources.py',
        'work/research_updated_map_rule_sources.py','work/recover_economy_pak_access.py',
        'work/scan_weapon_tables.py','work/oodle_payload_reader.py','work/research_updated_subworld.py']
    evidence = dict(kind='source_backed_updated_control_profile_evidence',client_sha256=CLIENT_SHA,
        status='source_backed_diagnostic',native_protocol_compatibility_verified=False,
        native_challenge_acceptance_verified=False,native_connection_completed=False,playable_map_verified=False,
        process_accessed=False,client_launched=False,packets_emitted=False,
        current_packaged_map_sources=current,control_welcome_maps={'2201':maps},
        current_native_control=control['notify_contract'],
        current_native_subworld=subworld['contract'],
        current_engine_loadmap_binding=subworld['engine_loadmap_binding'],
        hello=control['updated_captured_hello'],archive_version=transport['archive_version_proof'],
        maximum_packet_bytes=dict(value=1024,basis='explicit diagnostic setting matching current ordinary wrapper default',
            native_universal_maximum=False,actual_runtime_connection_cap_observed=False),
        source_pins=pins,launch_scope=scope,
        generator_and_parser_sources=[dict(relative_path=p,sha256=sha((ROOT/p).read_bytes())) for p in helper_paths],
        residuals=[
            'Current source qualification is not a current native LoadMap observation or a new Welcome/Join acceptance trial.',
            'The third Welcome FString to FURL.RedirectURL+38 and concrete updated engine/seamless SubWorld option parsers are qualified; actual current engine/WorldSettings instances and loading results remain unobserved.',
            'Game.DisableDeviceSeamless native name/default/getter are qualified. The required launch flag requests value1; effective application and entry-mode effect must be verified in the owned client log.',
            'Archive version13 is the current native file-backed default, not an observed live connection value.',
            'No actor, replication schema, GameMode, pawn, WorldSettings, map authority, or playable gameplay is authorized by this control-only profile.',
            'The selected archive sources are validated independently. All mount priority, DLC/optional replacement, and runtime hot-replacement behavior remain unobserved.',
        ])
    raw = serialized(evidence)
    profile = dict(kind='local_native_ds_wire_profile',client_sha256=CLIENT_SHA,
        status='source_backed_diagnostic',diagnostic_scope='updated_client_control_only',
        hello_net_version=1077088301,archive_version=13,
        archive_version_qualification='Current native file-backed engine archive default13; live connection value not observed.',
        maximum_packet_bytes=1024,
        maximum_packet_bytes_qualification='Explicit control-only diagnostic setting; current ordinary wrapper defaults zero or oversized requests to1024; not a universal maximum.',
        archive_profile='ordinary non-swapped packed channel index and name; engine archive default13',
        observed_routing_prefix_bytes=8,observed_adjacent_handler_terminators=True,
        native_packet_handler_envelope_fully_recovered=False,control_name_hardcoded_index=255,
        control_welcome_maps={'2201':maps},
        welcome_map_evidence_relative_to_project_root=EVIDENCE.relative_to(ROOT).as_posix(),
        welcome_map_evidence_sha256=sha(raw),
        welcome_map_qualification='Current packaged MapConfig2201 LevelFullPath leaf and SubWorld table row, plus full current native FURL.RedirectURL SubWorld key consumers; no current native Welcome or map acceptance.',
        subworld_consumer_evidence_relative_to_project_root='work/evidence/updated-subworld-79fb7b10.json',
        subworld_consumer_evidence_sha256=REPORTS['work/evidence/updated-subworld-79fb7b10.json'],
        native_subworld_redirect_consumer_qualified=True,
        hello_evidence_relative_to_project_root='work/evidence/updated-control-contract-79fb7b10.json',
        hello_evidence_sha256=REPORTS['work/evidence/updated-control-contract-79fb7b10.json'],
        native_protocol_compatibility_verified=False,native_challenge_acceptance_verified=False,
        native_connection_completed=False,playable_map_verified=False,launch_scope=scope)
    return profile,evidence


def verify_loader(profile_path):
    # Extract only the existing pure validator; importing either launcher would
    # parse arguments and enter trial setup. No launcher top-level code executes.
    for relative in ['work/verify_local_provider_client.py','work/run_native_elevated_trial.py']:
        tree = ast.parse((ROOT/relative).read_text(encoding='utf-8'))
        fn = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='load_control_trial_profile')
        module = ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
        namespace = dict(Path=Path,json=json,hashlib=hashlib)
        exec(compile(module,relative,'exec'),namespace)
        loaded = namespace['load_control_trial_profile'](profile_path,ROOT,CLIENT_SHA,2201)
        if loaded['launch_scope']['kind']!='control_only_diagnostic':
            raise ValueError('Pure profile validator changed the diagnostic scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write',action='store_true')
    mode.add_argument('--check',action='store_true')
    parser.add_argument('--shadow',type=Path,default=SHADOW)
    args = parser.parse_args()
    profile,evidence = derive(args.shadow)
    for path,doc in [(EVIDENCE,evidence),(PROFILE,profile)]:
        raw = serialized(doc)
        if args.check:
            if path.read_bytes()!=raw:
                raise ValueError('Generated diagnostic artifact is stale: '+str(path.relative_to(ROOT)))
        else:
            path.write_bytes(raw)
    verify_loader(PROFILE)
    print(json.dumps(dict(profile=PROFILE.relative_to(ROOT).as_posix(),profile_sha256=sha(PROFILE.read_bytes()),
        evidence=EVIDENCE.relative_to(ROOT).as_posix(),evidence_sha256=sha(EVIDENCE.read_bytes()),
        current_map_id=2201,control_only=True,pure_launcher_validators_passed=True,
        native_protocol_compatibility_verified=False,client_launched=False)))


if __name__=='__main__':
    main()
