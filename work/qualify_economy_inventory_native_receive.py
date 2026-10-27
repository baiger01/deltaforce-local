"""Compare saved native receive values with the exact frozen admission snapshot.

No process is opened and no protocol data is sent. Unobserved derived caches and
optional native fields remain unobserved even when the local codec roundtrips.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

import portable_map_inventory as adapter
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem


ROOT=adapter.ROOT
CAPTURE='work/native-client-tests/1792311694804456800/'
PINNED={
    CAPTURE+'economy-inventory-receive.json':
        '883be78d4225aa644f27cbab136a780d93155a6faa6d36a9c1aea5d2f54d4f8d',
    CAPTURE+'admitted-loadout-snapshot.json':
        'b73cbdcfb004cc1ae1fbb07cd82801c163543d1698a5d6b91686d7cd8da119c9',
    CAPTURE+'client-alerts.log':
        '467bdb61f4f476bc7b11580a561f3ade5cb5648a910d9dd7e39e82da65b44cc7',
    'work/evidence/map-system-audit-20261018/native-economy-initial-desc-cache-installed-lua.json':
        '906797e2c00259c9019120b9bb551468bd2bc6c78931ecb1ab0fe91f87215251',
    'work/evidence/map-system-audit-20261018/native-economy-gun-desc-lua-binding-and-cache-converter.json':
        'a42fcd1eacd1a8bc6bb28b5753725dd531a93f7e87d4d03191c5282527f89405',
    'work/evidence/map-system-audit-20261018/native-economy-gun-desc-invalid-ui-bodies.json':
        '6fdc3bf0f1714c2f69985afdf3a792aa02d955bdc752266bc076df421f52c5fe',
}


def _count(item):
    while hasattr(item,'item'):
        if type(item) is StackedInventoryItem:
            return item.stack.item_count,item.stack.item_num_max
        item=item.item
    return item.item_count,item.item_num_max


def compare(receive,snapshot):
    if (receive.get('status')!='observed' or receive.get('client_sha256')!=
            '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0' or
            receive.get('identities_and_fields_rechecked') is not True or
            receive.get('process_identity_rechecked') is not True or
            receive.get('received',{}).get('values_rechecked') is not True):
        raise ValueError('Qualified stable native receive report required')
    projection=adapter.build(snapshot,value_fields=(0,0,0,0,0,0,0),owner_player_id=101)
    received=receive['received']
    expected={}
    for element in projection.items:
        base=adapter.base_item(element.item)
        quantity,maximum=_count(element.item)
        expected[base.item_gid]=dict(item_gid=base.item_gid,template_id=base.template_id,
            item_count=quantity,item_num_max=maximum,attach_position=base.attach_position,
            location=asdict(base.location),element_id=element.element_id)
    rows=received['items']
    actual={row['item_gid']:row for row in rows}
    differences=[]
    for gid,wanted in expected.items():
        if gid not in actual:
            differences.append(dict(gid=gid,field='missing'))
            continue
        for field,value in wanted.items():
            if actual[gid].get(field)!=value:
                differences.append(dict(gid=gid,field=field,expected=value,actual=actual[gid].get(field)))
    extra=sorted(set(actual)-set(expected))
    duplicates=len(rows)-len(actual)
    expected_spaces=[]
    for space in projection.repdata.spaces:
        grids=[]
        for grid in space.grids:
            row=asdict(grid)
            row['id']=row.pop('grid_id')
            grids.append(row)
        expected_spaces.append(dict(space_type=space.space_type,server_update_count=space.server_update_count,
            grid_count=len(grids),grids=grids))
    rep=received['repdata']
    spaces_equal=rep['spaces']==expected_spaces
    values_equal=rep['raw_value_fields']==[0]*7
    initialized=rep['initialized'] is True
    all_equal=not differences and not extra and not duplicates and spaces_equal and values_equal and initialized
    return dict(all_observed_mandatory_fields_equal_to_frozen_projection=all_equal,
        initialized=initialized,space_count=rep['spaces_count'],grid_count=rep['grids_count'],
        spaces_and_all_transmitted_grid_fields_equal=spaces_equal,
        all_space_versions=sorted(set(s['server_update_count'] for s in rep['spaces'])),
        raw_valuation_fields_equal_explicit_zero_policy=values_equal,
        expected_item_count=len(expected),native_item_count=len(rows),
        original_quantity_sum=sum(r['item_count'] for r in rows),
        all_original_gids_templates_quantities_maxima_locations_and_element_ids_equal=not(differences or extra or duplicates),
        field_differences=differences,unexpected_gids=extra,duplicate_gid_count=duplicates)


def qualify():
    pins=dict(PINNED)
    for relative,digest in pins.items():
        if hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()!=digest:
            raise ValueError('Changed saved native inventory evidence '+relative)
    raw=(ROOT/(CAPTURE+'admitted-loadout-snapshot.json')).read_bytes()
    receive=json.loads((ROOT/(CAPTURE+'economy-inventory-receive.json')).read_bytes())
    if receive['snapshot_sha256']!=hashlib.sha256(raw).hexdigest():
        raise ValueError('Saved receive snapshot differs from admission')
    comparison=compare(receive,raw)
    if not comparison['all_observed_mandatory_fields_equal_to_frozen_projection']:
        raise ValueError('Native mandatory receive differs from frozen projection: '+repr(comparison))
    pins.update(adapter.source_pins())
    for name in ('work/qualify_economy_inventory_native_receive.py','work/observe_economy_inventory_gun_receive.py',
            'work/test_observe_economy_inventory_gun_receive.py'):
        pins[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    return dict(kind='saved_native_inventory_receive_and_description_cache_gap_audit_v1',
        client_sha256=receive['client_sha256'],source_pins=pins,
        saved_native_observed_at_utc=receive['observed_at_utc'],comparison=comparison,
        original_process_pointer_reused=False,client_launched=False,process_opened=False,
        original_game_or_account_written=False,
        proven_receive='Native InventoryManager.RepData initialized and all serialized spaces/grids plus all 52 item identities, quantities and locations match the frozen admission snapshot',
        unobserved=dict(owner_character='InventoryManager.OwnerCharacter+0x218 was omitted by the original observer',
            gun_description='Original observer reads only item[0:128]; GunDescInfo starts at item+0x90',
            ammo_and_skin='Nested GunDescInfo AmmoContext and SkinInfo were outside the original read scope',
            derived_space_description='Only 22 serialized bytes of each 96-byte SpaceGrid were read; derived native SpaceDesc and Lua cache contents were not captured',
            onrep_execution='Read values do not record callback execution',ui_display='No complete item/grid UI success was proven'),
        confirmed_description_cache_block=dict(
            ctor='ItemBase.lua function0.2 instructions58/59 initialize descCount and descAttrCount to zero',
            getter='c05d020 reads item+0xf8; c05cfc0 reads item+0x100; these are GunDescInfo ModifyTimeStamp+0x68 and AttrModifyTimeStamp+0x70 low int32 values',
            branch='ItemBase.lua function0.38 instructions102..107 skip GetItemExtraInfoData/SetRawDescObjOnly/Desc_To_PropInfo when same identity and both cached counters are unchanged',
            historical_local_producer='Both native uint64 version fields were encoded as zero',
            ui_error='GetNodesFromeDesc Faild: Desc Invalid at client-alerts.log lines800/801 after Tab opened; native eaabd10/eac5d20 use this text for null or invalid desc UObject, not the separate zero-row branch',
            fixed_local_policy='New initial match descriptions use explicit positive local revision1 for both fields; no official timestamp or activation probability is claimed',
            native_fix_validation='Not yet observed in a new native trial'),
        next_readonly_validation=['Current typed InventoryManager.OwnerCharacter references the selected current Pawn',
            'Both exact original firearm GIDs contain all native nodes, 20 original loaded rounds on the second gun, both original skins and nonzero description versions',
            'Derived SpaceDesc and Lua slot cache initialization need separate evidence if ordinary grids remain absent'],
        supplement_attempt='Active-owned-trial preflight refused after the owned process exited; no process handle was opened and no supplemental native report was produced')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Use a fresh output path')
    result=qualify()
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf8')
    print(json.dumps(dict(output=str(args.output),sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
        comparison=result['comparison'])))


if __name__=='__main__':
    main()
