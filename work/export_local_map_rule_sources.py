"""Export actual Dam candidates without assigning official activation policies."""
import argparse
import hashlib
import json
import math
from pathlib import Path

from parse_economy_installed_tables import parse_table

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT/'work/evidence/map-system-audit-20261018'
ITEMS = 'outputs/df-local-server/protocol/game_item_catalog.json'
ITEMS_SHA = '5b30d2179d77e62294e71d7510c21e03aa664f97c9c1c07399e911f8c91376e8'
REPORTS = {
    'mandelbrickseamlessmapinfotable': '03d1aec87b841384f629b3788a789fc36eb095cff73b03f2c528501a8146dee7',
    'highvalueboxseamlessmapinfotable': 'afeb852196e46ab67dfadf1aa275373cdfa72eaaefb21a14f672201e9a6da4b2',
    'blueprintplunderdroppool': '3b4d1f4f0908db450393a86f2d7fa63871c58ac1b638879b151d4f8439858674',
    'mandelbrickdatatable': '8992c8131db7b6f70895f7ab0c132c39d9f22ec86bbadcae76e9809661522e91',
    'randomhighvalueroomtable': '4b3ff0f9591199d72ac956d17a0c01a4dde5b6cebc040bc87fa5c14ce5a2d28b',
    'highvalueroomexpectationtable': '36467fd1bd31b358e0c8af7219dfb2be05ed84eabe3f6fdb72309f15792b844a',
    'highvaluelootboxprop': '9853d7f826374ff02b640365de6f22f5a23676025e3f40ebe4eb03b2c080450e',
    'economy-intro-event': '45ab81871fb31dea47350ce8c65708145bb61bf7882a9b1b17453c996231eaf7',
    'economy-preview-tod-config': '41f998dd6bd492893f2dfebedfdf2d917938f547ee1a1db00546024c45cafe02',
}
NATIVE_REPORTS = {
    'native-economy-event-map-level-consumer-scope.json': 'ece3d11ea521c0f06a62c7c08d6f4da1ad55fabadf8f4e71a1170eb48b2872a1',
    'native-economy-intro-event-world-loader-body.json': '745e9edcfeb25a502ff1695fc7ed12a39619999f54d5c52641b01ade8438260b',
    'native-economy-mandel-prejoin-join-protobuf-codecs.json': 'b732e2f1d06ecd5ad7ee24d22e517caaf90ebe8ad8721045275f43f282765a86',
    'native-economy-mandel-lua-input-closed.json': '247ea07058c7d98808e978660b5e31d7c1bcd41764a1db30f38e9422a220a043',
    'native-economy-mandel-map2201-association-contract.json': '631cef7b77f09fdfd4b40daea971d04b4053ea08f8702916db91ab794cf5c2b2',
    'native-economy-iris-tod-event-getter-qualified.json': '32e863870d59c2815aa075d4598ad176cd42707eb5306b48b0e82ecf0928743b',
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def relative(path):
    return path.resolve(strict=True).relative_to(ROOT).as_posix()


def xyz(vector):
    assert set(vector) == {'X', 'Y', 'Z'}
    result = [vector[k] for k in ('X', 'Y', 'Z')]
    assert all(type(n) in (int, float) and math.isfinite(n) for n in result)
    return result


def derive():
    docs, pins, summaries = {}, [], []
    for key, expected in REPORTS.items():
        report = EVIDENCE/('native-'+key+'-actual-rows.json')
        raw = report.read_bytes()
        if digest(raw) != expected:
            raise ValueError('Pinned parsed source changed: '+report.name)
        doc = json.loads(raw)
        asset, export = (ROOT/Path(doc[k]) for k in ('source_uasset', 'source_uexp'))
        reparsed = parse_table(asset, export, doc['selected_pattern'])
        assert all(reparsed[k] == v for k, v in doc.items() if k not in ('source_uasset', 'source_uexp'))
        assert doc['complete_row_coverage'] is True
        pins.append(dict(relative_path=relative(report), sha256=expected))
        for path, kind in ((asset, 'uasset'), (export, 'uexp')):
            assert digest(path.read_bytes()) == doc['source_'+kind+'_sha256']
            pins.append(dict(relative_path=relative(path), sha256=doc['source_'+kind+'_sha256']))
        docs[key] = doc
        summaries.append(dict(table=doc['source_table'], row_count=doc['row_count'],
                              parsed_report=relative(report), all_rows_consumed=True))
    item_raw = (ROOT/ITEMS).read_bytes()
    assert digest(item_raw) == ITEMS_SHA
    items = json.loads(item_raw)
    pins.append(dict(relative_path=ITEMS, sha256=ITEMS_SHA))

    def reference(doc, row, field):
        return dict(table=doc['source_table'], row=row,
                    serialized_uexp_row_offset=doc['rows'][row]['serialized_uexp_offset'], field=field)

    mandel_doc = docs['mandelbrickseamlessmapinfotable']
    mandel_fields = mandel_doc['rows']['2201']['fields']
    assert mandel_fields['MapId'] == 2201
    generators = []
    for index, entry in enumerate(mandel_fields['GeneratorStructMap']):
        value = entry['value']
        assert entry['key'] == value['GeneratorId'] == index
        assert len(value['DecipherLocArr']) == len(value['DecipherNameArr']) == 2
        generators.append(dict(generator_id=index, source_spawn_weight=value['SpawnWeight'],
            actor_name=value['SpawnerName'], ds_location_xyz=xyz(value['SpawnerLoc']),
            coordinate_field='SpawnerLoc', source=reference(mandel_doc, '2201', 'GeneratorStructMap['+str(index)+']'),
            decipher_points=[dict(source_index=i, actor_name=name, ds_location_xyz=xyz(loc),
                                  coordinate_field='DecipherLocArr['+str(i)+']')
                             for i, (name, loc) in enumerate(zip(value['DecipherNameArr'], value['DecipherLocArr']))]))
    assert len(generators) == 8
    high_doc = docs['highvalueboxseamlessmapinfotable']
    high_fields = high_doc['rows']['2201']['fields']
    assert high_fields['MapId'] == 2201
    events, boxes = high_fields['EventIDForSpawnArray'], high_fields['HighValueBoxInfoArray']
    assert len(events) == len(boxes) == 32
    points = []
    for index, (event, box) in enumerate(zip(events, boxes)):
        assert box['bHighValueBox'] is True
        assert all(item in items['rows'] for item in box['HighValueItemList'])
        points.append(dict(source_index=index, event_id=event, actor_name=box['IconName'],
            ds_location_xyz=xyz(box['DSLoc']), coordinate_field='DSLoc',
            source_high_value_items=box['HighValueItemList'],
            source=reference(high_doc, '2201', 'HighValueBoxInfoArray['+str(index)+']'),
            event_source_field='EventIDForSpawnArray['+str(index)+']'))
    assert len(set(events)) == 8 and all(events.count(event) == 4 for event in set(events))
    pools, pool_doc = {}, docs['blueprintplunderdroppool']
    for row, record in pool_doc['rows'].items():
        assert record['fields']['DropPoolID'] == row
        entries = record['fields']['BlueprintPlunderDropWeightList']
        assert entries and all(e['MandelBrickID'] in items['rows'] and type(e['Weight']) is int and e['Weight'] > 0
                               for e in entries)
        pools[row] = dict(source=reference(pool_doc, row, 'BlueprintPlunderDropWeightList'),
            items=[dict(item_id=e['MandelBrickID'], weight=e['Weight']) for e in entries])
    event_doc, intro_events = docs['economy-intro-event'], {}
    for row, state in (('2201', 'MandelBrickOccur'), ('2202', 'MandelBrickNotOccur')):
        fields = event_doc['rows'][row]['fields']
        assert fields['EventId'] == row and fields['EventState'] == 'ESOLEventState::'+state
        assert fields['MapLevelName'] == 'Dam_Iris_Long3'
        intro_events[row] = dict(event_id=int(row), state=fields['EventState'],
            source_map_level_name=fields['MapLevelName'],
            dynamic_request_ld_dir=fields['DynamicRequestLDLevelDirName'],
            server_nav_level=fields['SeverRequestNavLevelName'],
            source=reference(event_doc, row, 'EventId/EventState/MapLevelName/DynamicRequestLDLevelDirName'))
    for name, expected in NATIVE_REPORTS.items():
        path = EVIDENCE/name
        assert digest(path.read_bytes()) == expected
        pins.append(dict(relative_path=relative(path), sha256=expected))
    tod_doc = docs['economy-preview-tod-config']
    tod_fields = tod_doc['rows']['2']['fields']
    assert tod_doc['row_count'] == 29
    assert (tod_fields['TODId'], tod_fields['WeatherId'], tod_fields['EventId']) == (2, 703, 0)
    getter_name = 'native-economy-iris-tod-event-getter-qualified.json'
    getter = json.loads((EVIDENCE/getter_name).read_bytes())['qualified_module_methods']['GetTODConfig']
    assert getter['function_id'] == '0.43'
    assert "0014 LOADK      R3 K6=2" in getter['listing']
    tod_policy = dict(tod_info=dict(tod_id=tod_fields['TODId']),
        message='CSPrepareMapBoardRes', policy_origin='explicit_local_policy_using_client_GetTODConfig_fallback',
        source=reference(tod_doc, '2', 'TODId/WeatherId/EventId'),
        source_fields={k: tod_fields[k] for k in ('TODId', 'WeatherId', 'EventId')},
        getter_proof=dict(relative_path=relative(EVIDENCE/getter_name), sha256=NATIVE_REPORTS[getter_name],
                          source_module='IrisSafeHouseModule.lua', function_id=getter['function_id']),
        tod_info_required=True, zero_tod_id_uses_client_fallback_2=True,
        official_server_map_TOD_policy_recovered=False)
    return dict(kind='client_derived_local_map_rule_sources_v1', map_id=2201,
        client_sha256='4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0',
        source_files=pins, source_tables=summaries,
        item_catalog=dict(relative_path=ITEMS, sha256=ITEMS_SHA, table=items['source_table'],
                          row_count=items['row_count'], source_uasset_sha256=items['source_uasset_sha256'],
                          source_uexp_sha256=items['source_uexp_sha256']),
        mandel_generators=generators, high_value_points=points, blueprint_drop_pools=pools,
        mandel_intro_events=intro_events,
        local_map_board_tod_policy={'2201': tod_policy},
        native_prepare_contract=dict(message='CSPrepareJoinMatchNtf', box_event_field=12,
            iris_event_ids_field=15, box_event_semantics='Mandel_generator_IDs',
            iris_event_ids_semantics='actual_SOLEvent_IDs', join_message_carries_these_fields=False,
            lua_consumer='_OnCSPrepareJoinMatchNtf',
            event_world_loader_rvas=['0xd41d1f0', '0xd41ca80', '0xd43e060', '0xd43f360'],
            level_scope='current_world_existing_levels_filtered_by_config_LDDir',
            source_MapLevelName_used_as_target_path_prefix=False),
        limitations=dict(official_activation_or_drop_probabilities_recovered=False,
            official_map_to_blueprint_pool_binding_recovered=False,
            mandel_generator_to_high_value_event_binding_recovered=False,
            attached_random_loot_world_transforms_qualified=False,
            ds_coordinates_are_table_values=True, runtime_world_placement_verified=False,
            source_item_lists_are_not_official_drop_distributions=True,
            mandel_intro_event_reuse_for_Level1_is_explicit_local_policy=True,
            official_Level1_to_Long3_event_binding_recovered=False,
            blueprint_pool_to_mandel_definition_join_complete=False,
            native_interaction_or_inventory_grants_verified=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-sha256', help='Explicit SHA of the owned public schema being regenerated')
    args = parser.parse_args()
    raw = (json.dumps(derive(), sort_keys=True, indent=2)+'\n').encode()
    target = ROOT/'outputs/df-local-server/protocol/local-map-rules/sources.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.read_bytes() != raw:
            if args.previous_sha256 is None or digest(target.read_bytes()) != args.previous_sha256:
                raise ValueError('Refusing to overwrite public sources without their exact previous SHA')
            target.write_bytes(raw)
    else:
        with target.open('xb') as stream:
            stream.write(raw)
    print(json.dumps(dict(relative_path=relative(target), sha256=digest(raw), bytes=len(raw))))
