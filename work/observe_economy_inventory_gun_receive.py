"""Supplement the current owned inventory with typed owner and two GunDesc trees.

Only an already active project-owned shadow trial is accepted. No client is
started, no object getter/native method is called, and no packets are sent.
"""
import argparse
import ctypes
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import struct

from observe_owned_gameplay_metadata import (address,owned_trial_identity,typed_declarations,
    BindingObservation,write_exclusive_report)
from observe_portable_map_runtime import (ROOT,SHIPPING_SHA256,Win32MetadataReader,
    MetadataSession,validate_source,discover_roots,observe_first_player_state,request_elevation)
from native_metadata_paths import object_path

MAX_ITEMS=52
SCHEMA='outputs/df-local-server/protocol/portable-map-spawn/inventory-schema.json'
SOURCE_PINS={
    SCHEMA:'c0ff0436a36ee6e1c0e66c7a69039a4f3375eabe9308353116dcc23a41e63ad7',
    'work/evidence/map-system-audit-20261018/native-economy-inventory-fastarray-item-fields.json':
        '05b7366c8863e01fe0d03ac8074e5b2887909c41af00f7a89b65438a8625ae86',
    'work/native-client-tests/1792297548603201600/owned-gameplay-metadata-recheck.json':
        'a53833a56b5e31978fa6dbc17d996f6fc2b3d6358c55186d3d0bd0bfeab26e11',
    'work/native-client-tests/1792311694804456800/owned-gameplay-metadata.json':
        '407649e4d323bf8ca17f929c86798f2e3b3ca0e9ce585ce00fc1e94b84a1cc24',
    'work/evidence/map-system-audit-20261018/native-economy-gun-desc-fields.json':
        '75eabe37c3e421f779337c7fcf682b26723c590c33a06eafa4ffd149334b5e10',
    'work/evidence/map-system-audit-20261018/native-economy-gun-desc-nested-fields.json':
        'c0d32be38245e479fb095dfe647e4d9f438a852341bbebea18bba959835d3c7e',
    'work/evidence/map-system-audit-20261018/native-economy-gun-desc-ammo-item-fields.json':
        '7cbe2ec226b2b7364150d15510da3220f897cc526c3b7661ef84d9c877ac6076',
    'work/evidence/map-system-audit-20261018/native-economy-gun-desc-ammo-context-fields.json':
        'eed554d52a06e20d7f6faff106012c133578839bbb0ad6d17e0e0ce203f607bf',
}


def sources():
    pins=dict(SOURCE_PINS)
    for name,digest in pins.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('Changed inventory receive source '+name)
    for name in ('work/observe_economy_inventory_gun_receive.py','work/observe_owned_gameplay_metadata.py',
            'work/observe_portable_map_runtime.py','work/observe_map_component_sources.py',
            'work/export_native_replication_metadata.py','work/native_metadata_objects.py',
            'work/native_metadata_paths.py','work/native_metadata_names.py','work/native_replication_metadata_core.py'):
        pins[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    return pins


def expected_items(raw):
    document=json.loads(raw)
    if document.get('kind')!='local_account_carried_loadout_v1' or type(document.get('props')) is not list:
        raise ValueError('Frozen actual carried snapshot required')
    props=list(document['props'])
    if document.get('selected_melee'):
        props.append(document['selected_melee'])
    if not 1<=len(props)<=MAX_ITEMS:
        raise ValueError('Frozen inventory exceeds the 52-item observation scope')
    result={}
    for prop in props:
        gid,item,count=prop.get('gid'),prop.get('template_id'),prop.get('quantity')
        if (type(gid) is not int or not 1<=gid<(1<<64) or gid in result or
                type(item) is not int or not 1<=item<(1<<64) or type(count) is not int or not 1<=count<(1<<31)):
            raise ValueError('Invalid or repeated frozen carried identity')
        result[gid]=(item,count)
    return result


def _array(raw,offset,limit):
    pointer,count,capacity=struct.unpack_from('<Qii',raw,offset)
    if not 0<=count<=limit or not count<=capacity<=4096:
        raise ValueError('Native array exceeds the bounded observation scope')
    if count:
        address(pointer)
    return pointer,count,capacity


def read_inventory_values(session,manager,expected):
    """Pure bounded reads from a separately qualified current native component."""
    reads={}
    def stable(at,size):
        raw=session.stable(at,size)
        reads[(at,size)]=raw
        return raw

    rep=stable(manager+0x298,88)
    if rep[24] not in (0,1):
        raise ValueError('Noncanonical native initialized bool')
    pointer,count,capacity=_array(rep,8,64)
    spaces=[]
    for index in range(count):
        raw=stable(pointer+index*32,32)
        kind,update=struct.unpack_from('<ii',raw)
        grid_pointer,grid_count,_=_array(raw,8,64)
        grids=[]
        for grid_index in range(grid_count):
            grid=stable(grid_pointer+grid_index*96,22)
            identity,x,y,length,height,half_x,half_y=struct.unpack('<5ibb',grid)
            grids.append(dict(id=identity,start_x=x,start_y=y,length=length,height=height,
                logic_half_unit_x=half_x,logic_half_unit_y=half_y))
        spaces.append(dict(space_type=kind,server_update_count=update,grid_count=grid_count,grids=grids))
    array=stable(manager+0x2f0+0x108,16)
    item_pointer,item_count,item_capacity=_array(array,0,MAX_ITEMS)
    rows=[]
    for index in range(item_count):
        raw=stable(item_pointer+index*0x800,128)
        element_id,rep_key,recent=struct.unpack_from('<3i',raw)
        category,sequence=struct.unpack_from('<II',raw,0x10)
        gid,=struct.unpack_from('<Q',raw,0x28)
        quantity,maximum=struct.unpack_from('<ii',raw,0x38)
        position,=struct.unpack_from('<i',raw,0x70)
        rows.append(dict(array_index=index,element_id=element_id,replication_key=rep_key,
            most_recent_array_replication_key=recent,item_gid=gid,template_id=category*10000+sequence,
            item_count=quantity,item_num_max=maximum,attach_position=position,
            location=dict(x=raw[0x74],y=raw[0x75],length=raw[0x76],height=raw[0x77],
                rotated=bool(raw[0x78]),grid_index=raw[0x79])))
    present={row['item_gid'] for row in rows}
    duplicates=sorted(gid for gid in present if sum(row['item_gid']==gid for row in rows)>1)
    mismatched=[]
    for row in rows:
        if row['item_gid'] in expected:
            item,quantity=expected[row['item_gid']]
            if (row['template_id'],row['item_count'])!=(item,quantity):
                mismatched.append(dict(item_gid=row['item_gid'],actual_template_id=row['template_id'],
                    actual_count=row['item_count'],expected_template_id=item,expected_count=quantity))
    missing=sorted(set(expected)-present)
    unexpected=sorted(present-set(expected))
    return dict(repdata=dict(initialized=bool(rep[24]),spaces_count=count,spaces_capacity=capacity,
            grids_count=sum(s['grid_count'] for s in spaces),spaces=spaces,
            raw_value_fields=list(struct.unpack_from('<6qi',rep,0x20))),
        items_count=item_count,items_capacity=item_capacity,items=rows,expected_count=len(expected),
        missing_gids=missing,unexpected_gids=unexpected,duplicate_gids=duplicates,mismatched_items=mismatched,
        all_expected_gids_and_quantities_received=not(missing or unexpected or duplicates or mismatched),
        values_rechecked=False),reads


def recheck_values(session,reads):
    for (at,size),before in reads.items():
        if session.stable(at,size)!=before:
            raise ValueError('Native inventory value or array changed during observation')


def _field(metadata,name,declaring,offset,size,*,vtable=None,rep_index=None):
    matches=[dict(f,declaring_class=c['class_name']) for c in metadata['declarations']
        for f in c['fields'] if f['name']==name]
    if len(matches)!=1:
        raise ValueError('One exact current inventory field required: '+name)
    row=matches[0]
    if (row['declaring_class'],row['storage_offset'],row['element_bytes'],row['array_dimension'])!=(declaring,offset,size,1):
        raise ValueError('Current inventory declaration differs: '+name)
    if vtable is not None and row.get('field_vtable_rva')!=vtable:
        raise ValueError('Current inventory property type differs: '+name)
    if rep_index is not None and row.get('declared_rep_index')!=rep_index:
        raise ValueError('Current native RepIndex differs: '+name)
    return row


def read_guns(session,manager,snapshot,reads):
    from dfserver.legacy_ds_inventory_gun_desc import from_snapshot_prop
    expected={p['gid']:from_snapshot_prop(p) for p in json.loads(snapshot)['props'] if p.get('weapon')}
    if len(expected)!=2:
        raise ValueError('This supplement is limited to the exact two frozen firearms')
    def stable(at,size):
        raw=session.stable(at,size)
        reads[(at,size)]=raw
        return raw
    pointer,count,_=_array(stable(manager+0x2f0+0x108,16),0,52)
    result=[]
    for index in range(count):
        item=pointer+index*0x800
        gid,=struct.unpack('<Q',stable(item+0x28,8))
        if gid not in expected:
            continue
        desc=stable(item+0x90,336)
        rows_pointer,rows_count,rows_capacity=_array(desc,0,64)
        nodes=[]
        for ordinal in range(rows_count):
            row=stable(rows_pointer+ordinal*136,136)
            nodes.append(dict(index=struct.unpack_from('<H',row,0x20)[0],
                item_id=struct.unpack_from('<Q',row,0x28)[0],gid=struct.unpack_from('<Q',row,0x30)[0],
                parent_index=struct.unpack_from('<H',row,0x38)[0],
                parent_socket_id=struct.unpack_from('<I',row,0x3c)[0]))
        ammo_pointer,ammo_count,_=_array(desc,0x40,32)
        ammo=[]
        for ordinal in range(ammo_count):
            raw=stable(ammo_pointer+ordinal*56,56)
            ammo.append(dict(item_id=struct.unpack_from('<Q',raw,0)[0],
                gid=struct.unpack_from('<Q',raw,8)[0],num=struct.unpack_from('<i',raw,16)[0]))
        original=expected[gid]
        original_nodes=[dict(index=n.index,item_id=n.item_id,gid=n.gid,parent_index=n.parent_index,
            parent_socket_id=n.parent_socket_id) for n in original.rows]
        original_ammo=[dict(item_id=a.item_id,gid=a.gid,num=a.num) for a in original.ammo]
        skin=dict(skin_gid=struct.unpack_from('<Q',desc,0x80)[0],
            skin_id=struct.unpack_from('<Q',desc,0x88)[0],
            skin_appearance_id=struct.unpack_from('<Q',desc,0x90)[0])
        result.append(dict(item_gid=gid,nodes=nodes,ammo=ammo,skin=skin,
            rows_count=rows_count,rows_capacity=rows_capacity,
            modify_timestamp=struct.unpack_from('<Q',desc,0x68)[0],
            attr_modify_timestamp=struct.unpack_from('<Q',desc,0x70)[0],
            original_nodes_match=nodes==original_nodes,original_ammo_match=ammo==original_ammo,
            original_skin_match=(skin['skin_id'],skin['skin_gid'])==(original.skin.skin_id,original.skin.skin_gid)))
    if len(result)!=2:
        raise ValueError('Both exact frozen firearm GIDs must be present')
    return result


def observe(game_root,trial_report,snapshot):
    trial_raw=trial_report.read_bytes()
    snapshot_raw=snapshot.read_bytes()
    import sys
    sys.path.insert(0,str(ROOT/'outputs/df-local-server'))
    expected=expected_items(snapshot_raw)
    pid,created=owned_trial_identity(json.loads(trial_raw),game_root)
    pins=sources()
    executable,size=validate_source(game_root)
    reader=Win32MetadataReader(executable,size,pid,created,maximum_seconds=150)
    try:
        session=MetadataSession(reader.read_exact)
        session.module_sha256,session.module_size=SHIPPING_SHA256,size
        base,sink=reader.module_base,{}
        roots=discover_roots(session,base,connection_binding_only=True,first_player_state=True,
            _binding_identity_sink=sink,unpublished_batch_retry=True)
        identity=sink['callback']
        candidates=[r for r in roots['connection_binding_observations']['player_controllers']
            if r.get('status')=='observed' and r.get('identity_and_fields_rechecked') is True
            and r.get('driver_primary_matches_original_connection') is True and r.get('local_player_index_field')==0]
        if len(candidates)!=1:
            raise ValueError('One current primary owned controller required')
        pc=candidates[0]
        binding=observe_first_player_state(session,base,driver_address=address(pc['driver']),
            connection_address=address(pc['connection']),pc_address=address(pc['address']),object_identity=identity)
        pawn=binding.get('pc_pawn_reference',{})
        if binding.get('status')!='observed' or pawn.get('status')!='typed_existing_reference':
            raise ValueError('Current owned Pawn unavailable')
        cache={}
        def metadata(pointer,expected_base):
            obj=identity(pointer,expected_base)
            klass=address(obj['class_address'])
            if klass not in cache:
                cache[klass]=dict(declarations=typed_declarations(session,base,klass,identity))
            return cache[klass]
        observation=BindingObservation(session,base,identity,metadata)
        pawn_pointer=address(pawn['address'])
        pawn_identity=observation.identify(pawn_pointer,'Pawn')
        field=_field(metadata(pawn_pointer,'Pawn'),'InventoryManager','DFMPlayerCharacter',0x3928,8)
        if field.get('declared_native_class')!='InventoryManager':
            raise ValueError('Current Pawn InventoryManager declared class differs')
        component=observation.reference(pawn_pointer,field,expected_base='ActorComponent')
        if component.get('status')!='typed_existing_reference' or component.get('outer_is_selected_owner') is not True:
            raise ValueError('Current owning InventoryManager reference unavailable')
        component_identity=component['identity']
        pointer=address(component_identity['address'])
        if (component_identity['name']!='InventoryManager' or component_identity['is_cdo'] is not False or
                component_identity['class_ancestry'][0]!='InventoryManager'):
            raise ValueError('Current default InventoryManager Name/Class differs')
        path=object_path(session.read,base,address(component_identity['class_address']))
        if path!='/Script/DFMGameplay.InventoryManager':
            raise ValueError('Current InventoryManager class package differs')
        current=metadata(pointer,'ActorComponent')
        _field(current,'RepData','InventoryManager',0x298,88,vtable=0x15a86f40,rep_index=6)
        _field(current,'RepItemArray','InventoryManager',0x2f0,288,vtable=0x15a86f40,rep_index=7)
        owner_field=_field(current,'OwnerCharacter','InventoryManager',0x218,8,vtable=0x1ab613b0)
        if (owner_field.get('native_property_type')!='FEncryptedObjectProperty' or
                owner_field.get('declared_native_class_path')!='/Script/DFMGameplay.DFMCharacter'):
            raise ValueError('Inventory OwnerCharacter differs from its qualified encrypted DFMCharacter property')
        owner=observation.reference(pointer,owner_field,expected_base='Pawn')
        if owner.get('status')=='typed_existing_reference':
            owner['points_to_current_pawn']=address(owner['identity']['address'])==pawn_pointer
        values,reads=read_inventory_values(session,pointer,expected)
        values['gun_descriptions']=read_guns(session,pointer,snapshot_raw,reads)
        values['owner_character']=owner
        recheck_values(session,reads)
        observation.finish()
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module()!=base or sources()!=pins or snapshot.read_bytes()!=snapshot_raw:
            raise ValueError('Inventory source, module, or frozen snapshot changed')
        values['values_rechecked']=True
        return dict(kind='owned_current_inventory_gun_and_owner_native_receive_values',status='observed',
            client_sha256=SHIPPING_SHA256,pid=pid,created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),snapshot_sha256=hashlib.sha256(snapshot_raw).hexdigest(),
            primary_connection_binding=pc,first_player_binding=binding,current_pawn=pawn_identity,
            inventory_manager=component,inventory_class_path=path,received=values,
            read_calls=session.calls,read_bytes=session.bytes_read,identities_and_fields_rechecked=True,
            selected_roots_rechecked=True,process_identity_rechecked=True,process_memory_written=False,
            native_methods_invoked=False,native_layouts_constructed=False,packets_sent=False,
            code_sampled=False,historical_process_pointers_reused=False,snapshot_atomic=False,
            ui_display_verified=False,onrep_callback_execution_observed=False)
    finally:
        reader.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root',type=Path,required=True)
    parser.add_argument('--trial-report',type=Path,required=True)
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--request-uac',action='store_true')
    args=parser.parse_args()
    output=args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/'work'):
        parser.error('Use an exclusive fresh project work output')
    owned_trial_identity(json.loads(args.trial_report.read_bytes()),args.game_root)
    expected_items(args.snapshot.read_bytes())
    sources()
    import sys
    sys.path.insert(0,str(ROOT/'outputs/df-local-server'))
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B',str(Path(__file__).resolve()),'--game-root',str(args.game_root.resolve()),
            '--trial-report',str(args.trial_report.resolve()),'--snapshot',str(args.snapshot.resolve()),'--output',str(output)],output)
        report=json.loads(output.read_bytes())
    else:
        try:
            report=observe(args.game_root,args.trial_report,args.snapshot)
        except Exception as error:
            report=dict(status='refused',reason=str(error),error_type=type(error).__name__,
                process_memory_written=False,native_methods_invoked=False,packets_sent=False,
                native_layouts_constructed=False,code_sampled=False,historical_process_pointers_reused=False)
        write_exclusive_report(output,report)
    received=report.get('received',{})
    print(json.dumps(dict(status=report['status'],reason=report.get('reason'),output=str(output),
        initialized=received.get('repdata',{}).get('initialized'),items_count=received.get('items_count'),
        all_received=received.get('all_expected_gids_and_quantities_received'))))


if __name__=='__main__':
    main()
