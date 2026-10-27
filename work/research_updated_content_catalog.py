"""Generate an independent source-qualified Raven client configuration catalog."""
import argparse
import hashlib
import json
from pathlib import Path

from research_updated_content_table_diff import ROOT

REPORT = ROOT / 'work/evidence/research_updated_content_raven_79fb7b10_v4.json'
REPORT_SHA = '7eb907cc30bf9e826318ba228417da75f085f8378a783afe2f8e9c7da95d7d27'
DEFAULT_OUTPUT = ROOT / 'outputs/df-local-server/protocol/native_raven_catalog.json'


def checked_json(path, expected=None):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected and expected != digest:
        raise ValueError('Pinned Raven source changed: ' + path.name)
    return json.loads(raw), digest


def derive():
    report, digest = checked_json(REPORT, REPORT_SHA)
    resources = {}
    witnesses = []
    for name, expected in report['extraction_witnesses'].items():
        witness_path = ROOT / 'work/evidence' / name
        witness, observed = checked_json(witness_path, expected)
        witnesses.append(dict(path=witness_path.relative_to(ROOT).as_posix(), sha256=observed))
        for archive in witness['archives']:
            for entry in archive['matches']:
                path = ROOT / entry['output']
                if hashlib.sha256(path.read_bytes()).hexdigest() != entry['decoded_sha256']:
                    raise ValueError('Extracted Raven source differs from current archive witness')
                if entry['archive_payload_sha1_valid'] is not True:
                    raise ValueError('Raven source payload hash was not verified')
                key = entry['asset'].split('/Content/', 1)[1]
                resources[key] = dict(archive=archive['archive'], asset=entry['asset'],
                    pak_entry_offset=entry['entry_offset'], decoded_bytes=entry['decoded_bytes'],
                    decoded_sha256=entry['decoded_sha256'],
                    archive_payload_sha1_valid=True,
                    archive_index_sha1_valid=archive['validation']['index_sha1_valid'],
                    decoded_primary_index_sha256=archive['validation']['decoded_index_sha256'])

    def source(stem):
        return {suffix[1:]: resources[stem + suffix] for suffix in ('.uasset', '.uexp')}

    actor_stem = 'BluePrints/Interact/SingleItemContainer/BP_Interactor_SingleItemContainer_HalloweenRaven'
    table_root = 'R13N/Common/Base/DataTables/'
    sources = dict(actor=source(actor_stem),
        holiday_table=source(table_root + 'ItemExchangeActivityTable'),
        cluster_table=source(table_root + 'ItemsClusterTable'),
        drop_mapping_table=source(table_root + 'SkuDropMappingTable'),
        gameitem=source(table_root + 'GameItem'),
        raven_localization=resources['StringTables/STForMaps/Common/Base/LOC_MAPS_OtherBP.ustbin'])
    holidays = {str(row['fields']['HolidayId']['value']): row
        for row in report['exchange_table']['linked_rows']}
    clusters = {str(row['fields']['ClusterID']['value']): row for row in report['linked_clusters']['rows']}
    mappings = {str(row['fields']['DropMappingId']['value']): row for row in report['linked_drop_mappings']['rows']}
    if len(holidays) != 3 or len(clusters) != 45 or len(mappings) != 180:
        raise ValueError('Qualified Raven row count changed')
    for row in holidays.values():
        if any(str(i) not in clusters for i in row['fields']['ClusterIdList']['value']):
            raise ValueError('Raven holiday references an unavailable source cluster')
        if any(str(i) not in mappings for i in row['fields']['DropMappingIdList']['value']):
            raise ValueError('Raven holiday references an unavailable source drop mapping')
    for row in mappings.values():
        if str(row['fields']['ClusterId']['value']) not in clusters:
            raise ValueError('Raven drop mapping references an unavailable source cluster')

    protocol = ROOT / 'outputs/df-local-server/protocol'
    fields, fields_sha = checked_json(protocol / 'generated_codec_fields.json')
    classes, classes_sha = checked_json(protocol / 'generated_class_metadata.json')
    class_rows = {row['name']: row for row in classes['messages']}
    selected = {'CSActivityGetReq', 'CSActivityGetRes', 'CSActivityGetCurrencyReq', 'CSActivityGetCurrencyRes',
        'CSActivityExchangeReq', 'CSActivityExchangeRes', 'CSActivityPropExchangeReq', 'CSActivityPropExchangeRes',
        'CSActivityFocusExchangeReq', 'CSActivityFocusExchangeRes', 'CSActivityChangeExchangePlanReq',
        'CSActivityChangeExchangePlanRes', 'CSActivityCurrencyChangeNtf', 'ActivityCurrencyInfo',
        'ActivityInfo', 'ActivityExchangeProp', 'ActivityExchangePlan', 'CSActivityExchange'}
    contracts = {}
    for row in fields['messages']:
        if row['name'] not in selected:
            continue
        if (row['source'] != '@cs_activity_editor_pb.lua'
                or row['source_sha256'] != '279087d858cce5cf2fe3779e17e7dc1fc50fe0ed805e78014475310e2bda6cad'
                or row['all_observed_field_calls_matched'] is not True):
            raise ValueError('Activity contract source changed')
        declaration = class_rows[row['name']]
        if declaration.get('source') != '@cs_activity_pb.lua' or declaration.get('service') != 'activity':
            raise ValueError('Activity service declaration changed')
        contracts[row['name']] = dict(row, declared_service=declaration['service'],
            class_declaration_source=declaration['source'])
    if set(contracts) != selected:
        raise ValueError('Incomplete selected current activity contracts')
    lua, lua_sha = checked_json(ROOT / 'work/evidence/research_updated_content_lua_activity_editor_79fb7b10_v1.json',
        '9c154343f645f9d6339bdbd06a15994b01fcc157e5675ed640a4bdeda2c5aef8')
    current_editor = lua['sources'][0]
    if current_editor['current_sha256'] != next(iter(contracts.values()))['source_sha256']:
        raise ValueError('Selected activity metadata differs from current installed Lua')

    helpers = [Path(__file__), ROOT / 'work/research_updated_content_raven.py',
        ROOT / 'work/research_updated_content_table_diff.py', ROOT / 'work/research_updated_content_resources.py']
    return dict(kind='source_qualified_raven_client_configuration', schema_version=1,
        client_sha256='79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203',
        provenance=dict(research_report=dict(path=REPORT.relative_to(ROOT).as_posix(), sha256=digest),
            extraction_witnesses=witnesses,
            generators={p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in helpers}),
        sources=sources,
        actor=dict(package_path=report['actor']['package'][0],
            component_export=report['actor']['component_export'], component=report['actor']['component'],
            component_uexp_offset=report['actor']['component_uexp_offset'], component_size=report['actor']['component_size'],
            fields=report['actor']['fields']),
        holiday_configurations=holidays, input_clusters=clusters, drop_mappings=mappings,
        localized_interaction_tips=dict(decoded_source_sha256=report['raven_localization_source']['decoded_sha256'],
            rows=report['raven_tips']),
        server_activity_contracts=dict(metadata_source_sha256=fields_sha,
            class_declarations_sha256=classes_sha, current_installed_lua_evidence_sha256=lua_sha,
            actual_lua_sha256=current_editor['current_sha256'], archive=current_editor['archive'],
            entry_offset=current_editor['entry_offset'], lua_offset=current_editor['lua_offset'],
            messages=contracts),
        server_delivered_stock=dict(status='not_recovered', entries=[],
            missing=['ActivityInfo.actv_id', 'activity currency identifier', 'exchange identifiers',
                     'exchange plans and costs', 'award counts and limits', 'active event schedule'],
            holiday_ids_are_not_server_activity_ids=True),
        acceptance=dict(local_configuration_source_verified=True, native_gameplay_accepted=False,
            original_server_roll_weights_recovered=False, token_award_rules_recovered=False,
            token_store_prices_recovered=False, catalog_enables_no_runtime_handler=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / 'outputs/df-local-server/protocol'):
        parser.error('Independent protocol catalog output required')
    report = derive()
    raw = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')
    if args.check:
        if output.read_bytes() != raw:
            raise ValueError('Independent Raven catalog differs from source-qualified generation')
    else:
        with output.open('xb') as stream:
            stream.write(raw)
    print(json.dumps(dict(output=str(output), sha256=hashlib.sha256(raw).hexdigest(),
        holidays=len(report['holiday_configurations']), clusters=len(report['input_clusters']),
        drop_mappings=len(report['drop_mappings']), activity_contracts=len(report['server_activity_contracts']['messages']),
        check=args.check)))
