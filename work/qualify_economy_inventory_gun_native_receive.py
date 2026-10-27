"""Seal complete saved GunDesc/owner receive against the exact admission snapshot."""
import argparse
import hashlib
import json
from pathlib import Path

import qualify_economy_inventory_native_receive as previous
from dfserver.legacy_ds_inventory_gun_desc import from_snapshot_prop

ROOT=previous.ROOT
CAPTURE='work/native-client-tests/1792314937287546900/'
PINS={
    CAPTURE+'economy-inventory-gun-receive.json':
        '418cfa23919f61aeaf5feb4bf7cd0142371b8dc900c1c58c9839b91b4f3adf13',
    CAPTURE+'economy-inventory-receive.json':
        'ae1f5390ef7cfc0e079d5dd03d6ba54807c533b883f04622641e5ea56f5c1398',
    CAPTURE+'admitted-loadout-snapshot.json':
        'b73cbdcfb004cc1ae1fbb07cd82801c163543d1698a5d6b91686d7cd8da119c9',
    CAPTURE+'owned-gameplay-metadata.json':
        '399d896dda740b768feb8e9e7bad40eab8d2798d27806731577a708704ca2873',
    CAPTURE+'client-alerts.log':
        '77ee32109750f4eb03f29344bbfe14a124b64617250311d87a56635e4a7a4033',
}


def compare_guns(receive,snapshot):
    mandatory=previous.compare(receive,snapshot)
    expected={p['gid']:from_snapshot_prop(p) for p in json.loads(snapshot)['props'] if p.get('weapon')}
    values=receive['received']
    actual=values['gun_descriptions']
    differences=[]
    rows=[]
    if len(actual)!=len(expected) or {g['item_gid'] for g in actual}!=set(expected):
        differences.append(dict(field='gun_gids_or_count'))
    for gun in actual:
        original=expected.get(gun['item_gid'])
        if original is None:
            continue
        wanted=dict(nodes=[dict(index=n.index,item_id=n.item_id,gid=n.gid,parent_index=n.parent_index,
                parent_socket_id=n.parent_socket_id) for n in original.rows],
            ammo=[dict(item_id=a.item_id,gid=a.gid,num=a.num) for a in original.ammo],
            skin=dict(skin_id=original.skin.skin_id,skin_gid=original.skin.skin_gid,skin_appearance_id=0),
            modify_timestamp=original.modify_revision,attr_modify_timestamp=original.attr_modify_revision,
            rows_count=len(original.rows))
        for field,value in wanted.items():
            if gun.get(field)!=value:
                differences.append(dict(item_gid=gun['item_gid'],field=field,expected=value,actual=gun.get(field)))
        rows.append(dict(item_gid=gun['item_gid'],receiver=original.rows[0].item_id,
            original_node_count=len(original.rows),received_node_count=gun['rows_count'],
            original_ammo=wanted['ammo'],received_ammo=gun['ammo'],received_skin=gun['skin'],
            received_description_revision=gun['modify_timestamp'],
            received_attribute_revision=gun['attr_modify_timestamp']))
    owner=values['owner_character']
    owner_ok=(owner.get('status')=='typed_existing_reference' and owner.get('points_to_current_pawn') is True and
        owner.get('native_property_type')=='FEncryptedObjectProperty' and owner.get('declared_native_class')=='DFMCharacter' and
        owner.get('identity',{}).get('address')==receive['current_pawn']['address'])
    return dict(mandatory=mandatory,all_complete_gun_fields_equal_to_frozen_projection=not differences,
        gun_field_differences=differences,guns=rows,owner_character_is_typed_current_pawn=owner_ok,
        owner_outer_flag_is_not_the_character_binding_gate='outer_is_selected_owner false is expected for Pawn outered to its Level; exact typed field target equals current Pawn')


def qualify():
    pins=dict(PINS)
    for name,digest in pins.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('Saved current native source changed '+name)
    raw=(ROOT/(CAPTURE+'admitted-loadout-snapshot.json')).read_bytes()
    gun=json.loads((ROOT/(CAPTURE+'economy-inventory-gun-receive.json')).read_bytes())
    ordinary=json.loads((ROOT/(CAPTURE+'economy-inventory-receive.json')).read_bytes())
    if any(r['snapshot_sha256']!=hashlib.sha256(raw).hexdigest() for r in (gun,ordinary)):
        raise ValueError('Actual admission snapshot differs from either receive capture')
    result=compare_guns(gun,raw)
    other=previous.compare(ordinary,raw)
    if (not result['mandatory']['all_observed_mandatory_fields_equal_to_frozen_projection'] or
            not other['all_observed_mandatory_fields_equal_to_frozen_projection'] or
            not result['all_complete_gun_fields_equal_to_frozen_projection'] or
            not result['owner_character_is_typed_current_pawn']):
        raise ValueError('Current full native inventory differs: '+repr(result))
    log=(ROOT/(CAPTURE+'client-alerts.log')).read_text(encoding='utf8')
    pins.update(previous.adapter.source_pins())
    for name in ('work/qualify_economy_inventory_gun_native_receive.py',
            'work/qualify_economy_inventory_native_receive.py',
            'work/observe_economy_inventory_spaces.py','work/test_observe_economy_inventory_spaces.py'):
        pins[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    return dict(kind='source_qualified_actual_full_inventory_and_gun_receive_v1',
        client_sha256=gun['client_sha256'],source_pins=pins,comparison=result,
        independent_mandatory_capture_also_matches=True,
        native_observed_at_utc=gun['observed_at_utc'],native_fields_and_values_rechecked=True,
        original_process_pointer_reused=False,process_opened_by_this_audit=False,client_launched=False,
        filtered_log_desc_invalid_occurrences=log.count('GetNodesFromeDesc Faild: Desc Invalid'),
        filtered_log_absence_is_not_complete_ui_validation=True,
        confirmed_revision_fix='Both native GunDesc ModifyTimeStamp and AttrModifyTimeStamp are now1 and all original nodes/ammo/skins survive deserialization',
        remaining_observation_gap='Derived native SpaceMap/ItemSpace interval arrays and Lua slot cache were not captured by this cohort; transmitted RepData geometry itself exactly matches',
        new_reader='work/observe_economy_inventory_spaces.py',
        new_reader_scope='Exact native int32 key lookup into owning SpaceMap/SpecialSpaceMap/FashionSpaceMap; current typed ItemSpace declarations and bounded uint64 interval arrays from cached c1cd5c0 parser',
        new_reader_not_run='Owned report became record_complete with observation_limit_reached before the new reader was ready; no additional process read attempted',
        ui_display_verified=False,weapon_actor_lifecycle_verified_by_inventory=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Use a fresh evidence output')
    result=qualify()
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf8')
    print(json.dumps(dict(output=str(args.output),sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
        original_item_count=result['comparison']['mandatory']['native_item_count'],
        guns_match=result['comparison']['all_complete_gun_fields_equal_to_frozen_projection'],
        owner_matches=result['comparison']['owner_character_is_typed_current_pawn'])))


if __name__=='__main__':
    main()
