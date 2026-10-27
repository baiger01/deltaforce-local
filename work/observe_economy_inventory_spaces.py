"""Read existing derived native spaces in an active owned shadow trial only.

Exact int32 keys use cached e489e0's bucket/chain branch. No sparse free slots
are enumerated, methods called, layouts constructed, or game started.
"""
import argparse
import ctypes
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import struct

from observe_economy_inventory_gun_receive import _field,expected_items,read_inventory_values,recheck_values
from observe_owned_gameplay_metadata import address,owned_trial_identity,typed_declarations,BindingObservation,write_exclusive_report
from observe_portable_map_runtime import ROOT,SHIPPING_SHA256,Win32MetadataReader,MetadataSession,validate_source,discover_roots,observe_first_player_state,request_elevation,direct_root_reference
from native_metadata_paths import object_path

PINS={
    'work/evidence/map-system-audit-20261018/native-economy-character-uin-native-interface-body-v1.json':
        'a628066f86c68f9a4e1bfede6cadb9a95886e63ed2b5c7b7e4cc8a2f5f8f5d53',
    'work/evidence/map-system-audit-20261018/native-economy-dfm-setpawn-and-engine-super-v1.json':
        '9e41ba9d9afc9d1b4381033edd0c21c8ffadebf9f0b9bf41c707864a1e485b92',
    'work/evidence/map-system-audit-20261018/native-economy-local-ready-delegate-qualified-consumers-v1.json':
        '80c589ce99ca456897e9854a0b61f0bb55c06597dc4524aec4827600860f9a81',
    'work/evidence/map-system-audit-20261018/native-economy-getallinventory-item-validity-v1.json':
        'f805626be2bc85ba35ff9ceb9a8ee87f093e8688ad9dba20b3ee0aa45d320b33',
    'work/evidence/map-system-audit-20261018/native-economy-onrep-item-config-initializer-v1.json':
        '3340fc1979cb326002da8729c64d056863299aaa4945e6467c354a8d8bec88bf',
    'work/evidence/map-system-audit-20261018/native-economy-getallinventory-array-iterator-v1.json':
        '07ba7a6e4df0ba6bf22139bf536c9d18f7f44ce31d673193e3fe1e1cb46e9051',
    'work/evidence/map-system-audit-20261018/native-economy-owning-inventory-creation-id-conversion-and-onrep.json':
        'f7af4ef55252ed747b5897edbade0b8293883115a85ae04911fc0607cb273996',
    'work/evidence/map-system-audit-20261018/native-economy-lootbox-grid-derived-state-consumer.json':
        'a259949de632ae79cd05410a7506a373e5121387cfd689d6b4ede3545d4dd664',
    'work/evidence/map-system-audit-20261018/native-economy-space-initializer-authority-gate-v1.json':
        'd495cc923d3b75e63f633bcb861aa11c05b1b762c3603e7d2e8cb53c51cec0e1',
    'work/evidence/map-system-audit-20261018/native-economy-inventory-slot-binding-installed-lua-v2.json':
        '82ed2c947a96bae458b2c9fd7378b629a280569e9fd424b3cd6fe10eda6830e7',
    'work/evidence/map-system-audit-20261018/native-economy-space-map-key-lookup-and-class-v1.json':
        'c9018ed73d6aca0792ff897ecd831b40b08a83c186858ed339fe4da2e89db0fc',
    'work/evidence/map-system-audit-20261018/native-economy-space-map-value-class-and-shape-parser-v1.json':
        'e903eca46dfd90d44afffe7d4384d49a7af15f7af46ed4d72b1e50d38b4867fa',
    'work/evidence/map-system-audit-20261018/native-economy-space-initialize-by-type.json':
        '0ff2583b761f3b5d7af48e954cf0d2ef92ab4bcca49e6d496899207264045ada',
    'work/evidence/map-system-audit-20261018/native-economy-native-itemspace-initialize-body.json':
        'c35e00e68093df7bb5fd4da824b4584e38858def1b334df5c35fe1e5f6fa4728',
    'work/evidence/map-system-audit-20261018/native-economy-grid-string-parser-and-simple-space.json':
        '5a999a1c7896c3c85cfa1459063db6099a818fff4e97089f7d9c675a253fa7ab',
    'work/native-client-tests/1792314937287546900/owned-gameplay-metadata.json':
        '399d896dda740b768feb8e9e7bad40eab8d2798d27806731577a708704ca2873',
}


def sources():
    result=dict(PINS)
    for name,digest in result.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('Changed derived space source '+name)
    for name in ('work/observe_economy_inventory_spaces.py','work/observe_economy_inventory_gun_receive.py',
            'work/observe_owned_gameplay_metadata.py','work/observe_portable_map_runtime.py',
            'work/observe_map_component_sources.py','work/native_metadata_paths.py',
            'work/native_metadata_objects.py','work/native_metadata_names.py'):
        result[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    return result


def map_header(session,at,reads):
    raw=session.stable(at,80)
    reads[(at,80)]=raw
    data,count,capacity=struct.unpack_from('<Qii',raw)
    free,=struct.unpack_from('<i',raw,0x34)
    buckets,=struct.unpack_from('<i',raw,0x48)
    if not 0<=free<=count<=capacity<=256:
        raise ValueError('Derived space map exceeds bounded slot counts')
    return raw,dict(slot_count=count,free_slots=free,used_entries=count-free,bucket_count=buckets)


def lookup_space(session,at,key,reads):
    """Only e489e0's exact selected-key branch; value+8, next+16, stride24."""
    if type(key) is not int or not -(1<<31)<=key<(1<<31):
        raise ValueError('A native int32 space key is required')
    raw,header=map_header(session,at,reads)
    if not header['used_entries']:
        return header,None
    buckets=header['bucket_count']
    if not 1<=buckets<=512 or buckets&(buckets-1):
        raise ValueError('Derived space bucket count is invalid')
    data=address(struct.unpack_from('<Q',raw)[0])
    storage=struct.unpack_from('<Q',raw,0x40)[0]
    if not storage:
        if buckets>2:
            raise ValueError('Null external buckets exceed native inline capacity')
        storage=at+0x38
    else:
        address(storage)
    bucket_at=storage+(key&(buckets-1))*4
    bucket=session.stable(bucket_at,4)
    reads[(bucket_at,4)]=bucket
    index,=struct.unpack('<i',bucket)
    visited=set()
    while index!=-1:
        if index in visited or not 0<=index<header['slot_count'] or len(visited)>=64:
            raise ValueError('Derived space map chain is invalid or exceeds local bound')
        visited.add(index)
        entry=session.stable(data+index*24,24)
        reads[(data+index*24,24)]=entry
        found,=struct.unpack_from('<i',entry)
        if found==key:
            value,=struct.unpack_from('<Q',entry,8)
            return header,dict(key=key,slot_index=index,value=direct_root_reference(value))
        index,=struct.unpack_from('<i',entry,16)
    return header,None


def read_intervals(session,pointer,reads):
    """c1d2420 outputs at+38/+50; c1cd5c0 appends uint64 interval pairs."""
    result=[]
    for offset in (0x38,0x50):
        at=pointer+offset
        raw=session.stable(at,16)
        reads[(at,16)]=raw
        storage,count,capacity=struct.unpack('<Qii',raw)
        if not 0<=count<=capacity<=128 or count%2:
            raise ValueError('Native interval array is invalid or over budget')
        if count:
            address(storage)
            values=session.stable(storage,count*8)
            reads[(storage,count*8)]=values
            values=struct.unpack('<'+'Q'*count,values)
        else:
            values=()
        result.append(dict(native_offset=hex(offset),value_count=count,
            interval_pairs=[list(values[i:i+2]) for i in range(0,count,2)]))
    return result


def read_received_ui_geometry(session,manager,expected_types,reads):
    """c21e0f0 receive-derived fields inside native 32/96-byte structs."""
    header_at=manager+0x2a0
    header=session.stable(header_at,16)
    reads[(header_at,16)]=header
    storage,count,capacity=struct.unpack('<Qii',header)
    if not 0<=count<=capacity<=128 or count!=len(expected_types):
        raise ValueError('Received UI space identity/count changed')
    if not count:
        return []
    address(storage)
    raw=session.stable(storage,count*32)
    reads[(storage,count*32)]=raw
    result=[]
    for index,key in enumerate(expected_types):
        row=raw[index*32:(index+1)*32]
        actual,revision,grids,grid_count,grid_capacity=struct.unpack_from('<iiQii',row)
        if actual!=key or not 0<=grid_count<=grid_capacity<=64:
            raise ValueError('Received UI space identity/grid count changed')
        if grid_count:
            address(grids)
            data=session.stable(grids,grid_count*96)
            reads[(grids,grid_count*96)]=data
        else:
            data=b''
        decoded=[]
        for number in range(grid_count):
            grid=data[number*96:(number+1)*96]
            gid,start_x,start_y,length,height,half_x,half_y=struct.unpack_from('<5i2b',grid)
            edges=list(struct.unpack_from('<4i',grid,0x4c))
            decoded.append(dict(id=gid,start_x=start_x,start_y=start_y,length=length,height=height,
                logic_half_unit_x=half_x,logic_half_unit_y=half_y,
                derived_half_offset_bytes=list(struct.unpack_from('<2b',grid,0x16)),
                edge_bounds_native_int32=edges,
                edge_bounds_match_receive_recompute=edges==[half_x-length,half_x+length,half_y-height,half_y+height]))
        result.append(dict(space_type=actual,server_update_count=revision,
            derived_root_tail_hex=row[0x18:0x20].hex(),length_native_byte=row[0x18],
            height_native_byte=row[0x19],origin_native_signed_bytes=list(struct.unpack_from('<4b',row,0x1a)),
            capacity_native_uint16=struct.unpack_from('<H',row,0x1e)[0],grids=decoded))
    return result


def read_item_visibility_state(session,manager,expected,reads):
    """Observe source-qualified OnRep effects, never invoke IsValid/InitConfig."""
    def stable(at,size):
        raw=session.stable(at,size)
        reads[(at,size)]=raw
        return raw
    flag=stable(manager+0x920,1)[0]
    if flag not in (0,1):
        raise ValueError('Noncanonical native first item notification flag')
    pointer,count,capacity=struct.unpack('<Qii',stable(manager+0x3f8,16))
    if count!=len(expected) or not 0<=count<=capacity<=128:
        raise ValueError('Native visibility item count differs from exact admitted scope')
    if count:
        address(pointer)
    rows=[]
    for index in range(count):
        at=pointer+index*0x800
        prefix=stable(at,0x30)
        category,sequence,cached_name=struct.unpack_from('<IIQ',prefix,0x10)
        gid=struct.unpack_from('<Q',prefix,0x28)[0]
        if gid not in expected or expected[gid][0]!=category*10000+sequence:
            raise ValueError('Native visibility item identity changed')
        config=struct.unpack('<Q',stable(at+0x650,8))[0]
        if config:
            address(config)
        rows.append(dict(item_gid=gid,template_id=category*10000+sequence,
            cached_item_fname_is_none=cached_name==0,native_config_pointer_nonnull=bool(config)))
    if len({r['item_gid'] for r in rows})!=count:
        raise ValueError('Repeated native visibility item identity')
    return dict(first_onrep_item_array_flag=bool(flag),items_count=count,
        config_bound_items=sum(r['native_config_pointer_nonnull'] for r in rows),items=rows,
        config_pointers_followed=False,native_is_valid_invoked=False,
        source_filter='c05c490 additionally requires valid ItemID, GID and config+650')


def observe(game_root,trial_report,snapshot):
    trial_raw,snapshot_raw=trial_report.read_bytes(),snapshot.read_bytes()
    pid,created=owned_trial_identity(json.loads(trial_raw),game_root)
    pins=sources()
    expected=expected_items(snapshot_raw)
    executable,size=validate_source(game_root)
    reader=Win32MetadataReader(executable,size,pid,created,maximum_seconds=150)
    try:
        session=MetadataSession(reader.read_exact)
        session.module_sha256,session.module_size=SHIPPING_SHA256,size
        base,sink=reader.module_base,{}
        roots=discover_roots(session,base,connection_binding_only=True,first_player_state=True,
            _binding_identity_sink=sink,unpublished_batch_retry=True)
        identity=sink['callback']
        candidates=[p for p in roots['connection_binding_observations']['player_controllers']
            if p.get('status')=='observed' and p.get('identity_and_fields_rechecked') is True and
            p.get('driver_primary_matches_original_connection') is True and p.get('local_player_index_field')==0]
        if len(candidates)!=1:
            raise ValueError('One current primary owning controller required')
        pc=candidates[0]
        binding=observe_first_player_state(session,base,driver_address=address(pc['driver']),
            connection_address=address(pc['connection']),pc_address=address(pc['address']),object_identity=identity)
        pawn=binding.get('pc_pawn_reference',{})
        if binding.get('status')!='observed' or pawn.get('status')!='typed_existing_reference':
            raise ValueError('Current owning Pawn unavailable')
        cache={}
        def metadata(pointer,expected_base):
            obj=identity(pointer,expected_base)
            klass=address(obj['class_address'])
            if klass not in cache:
                cache[klass]=dict(declarations=typed_declarations(session,base,klass,identity))
            return cache[klass]
        observer=BindingObservation(session,base,identity,metadata)
        pawn_pointer=address(pawn['address'])
        field=_field(metadata(pawn_pointer,'Pawn'),'InventoryManager','DFMPlayerCharacter',0x3928,8)
        if field.get('declared_native_class_path')!='/Script/DFMGameplay.InventoryManager':
            raise ValueError('Current InventoryManager declaration differs')
        component=observer.reference(pawn_pointer,field,expected_base='ActorComponent')
        if component.get('status')!='typed_existing_reference' or component.get('outer_is_selected_owner') is not True:
            raise ValueError('Owning InventoryManager unavailable')
        component_identity=component['identity']
        pointer=address(component_identity['address'])
        if component_identity['name']!='InventoryManager' or component_identity['is_cdo'] is not False:
            raise ValueError('Actual InventoryManager Name/CDO differs')
        if object_path(session.read,base,address(component_identity['class_address']))!='/Script/DFMGameplay.InventoryManager':
            raise ValueError('Actual InventoryManager class package differs')
        current=metadata(pointer,'ActorComponent')
        _field(current,'RepData','InventoryManager',0x298,88,vtable=0x15a86f40,rep_index=6)
        values,reads=read_inventory_values(session,pointer,expected)
        keys=tuple(s['space_type'] for s in values['repdata']['spaces'])
        received_ui_geometry=read_received_ui_geometry(session,pointer,keys,reads)
        visibility_state=read_item_visibility_state(session,pointer,expected,reads)
        pc_pointer=address(pc['address'])
        pc_character_field=_field(metadata(pc_pointer,'PlayerController'),'GPCharacter',
            'GPPlayerController',0x870,8)
        pc_character=observer.reference(pc_pointer,pc_character_field,expected_base='Pawn')
        pc_character['matches_current_owning_pawn']=(pc_character.get('status')=='typed_existing_reference' and
            address(pc_character['identity']['address'])==pawn_pointer)
        pawn_state_field=_field(metadata(pawn_pointer,'Pawn'),'PlayerState','Pawn',0x390,8)
        pawn_state=observer.reference(pawn_pointer,pawn_state_field,expected_base='PlayerState')
        if pawn_state.get('status')=='typed_existing_reference':
            state_pointer=address(pawn_state['identity']['address'])
            _field(metadata(state_pointer,'PlayerState'),'Uin','BasePlayerState',0x498,8)
            uin_raw=session.stable(state_pointer+0x498,8)
            reads[(state_pointer+0x498,8)]=uin_raw
            pawn_state['native_uin']=struct.unpack('<Q',uin_raw)[0]
            pawn_state['lua_get_uin_nonzero_gate']=pawn_state['native_uin']!=0
            current_pc_state=binding.get('pc_player_state_reference',{})
            pawn_state['matches_controller_player_state']=(current_pc_state.get('status')=='typed_existing_reference' and
                state_pointer==address(current_pc_state['address']))
        maps=[]
        for name,offset in (('SpaceMap',0x650),('SpecialSpaceMap',0x6a0),('FashionSpaceMap',0x6f0)):
            _field(current,name,'InventoryManager',offset,80,vtable=0x1ab61bf0)
            _,header=map_header(session,pointer+offset,reads)
            objects=[]
            for key in keys:
                _,match=lookup_space(session,pointer+offset,key,reads)
                if match is None:
                    objects.append(dict(key=key,status='not_found'))
                    continue
                space=address(match['value'])
                space_identity=observer.identify(space,'Object')
                if (space_identity['class_ancestry'][0]!='ItemSpace' or space_identity['is_cdo'] is not False or
                        int(space_identity['outer_address'],16)!=pointer or
                        object_path(session.read,base,address(space_identity['class_address']))!='/Script/DFMGameplay.ItemSpace'):
                    raise ValueError('Map value is not an existing owning native ItemSpace')
                declarations=metadata(space,'Object')
                _field(declarations,'SpaceType','ItemSpace',0x30,4)
                kind=session.stable(space+0x30,4)
                reads[(space+0x30,4)]=kind
                if struct.unpack('<i',kind)[0]!=key:
                    raise ValueError('Native ItemSpace.SpaceType differs from exact map key')
                row=dict(key=key,status='typed_existing_space',identity=space_identity,
                    declarations=declarations['declarations'],native_interval_arrays=read_intervals(session,space,reads))
                # c1ee770 stores a nested ItemSpace at+68 for equipment spaces.
                # Follow only a current reflected object property, and only once.
                links=[dict(f,declaring_class=c['class_name']) for c in declarations['declarations']
                    for f in c['fields'] if f['storage_offset']==0x68]
                row['nested_space']=dict(status='current_typed_link_not_available')
                if (len(links)==1 and links[0].get('declared_native_class_path')=='/Script/DFMGameplay.ItemSpace' and
                        links[0].get('element_bytes')==8 and links[0].get('array_dimension')==1 and
                        links[0].get('native_property_type') in ('FObjectProperty','FEncryptedObjectProperty')):
                    linked=observer.reference(space,links[0],expected_base='Object')
                    row['nested_space']=linked
                    if linked.get('status')=='typed_existing_reference':
                        child=address(linked['identity']['address'])
                        child_meta=metadata(child,'Object')
                        _field(child_meta,'SpaceType','ItemSpace',0x30,4)
                        if (linked['identity']['class_ancestry'][0]!='ItemSpace' or linked['identity']['is_cdo'] is not False or
                                int(linked['identity']['outer_address'],16)!=pointer or
                                object_path(session.read,base,address(linked['identity']['class_address']))!='/Script/DFMGameplay.ItemSpace'):
                            raise ValueError('Nested space is not the existing owning native ItemSpace')
                        child_kind=session.stable(child+0x30,4)
                        reads[(child+0x30,4)]=child_kind
                        linked.update(space_type=struct.unpack('<i',child_kind)[0],
                            declarations=child_meta['declarations'],native_interval_arrays=read_intervals(session,child,reads))
                objects.append(row)
            maps.append(dict(field_name=name,native_offset=hex(offset),header=header,selected_spaces=objects))
        recheck_values(session,reads)
        observer.finish()
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module()!=base or sources()!=pins or snapshot.read_bytes()!=snapshot_raw:
            raise ValueError('Derived space module/source/snapshot changed')
        return dict(kind='owned_current_inventory_derived_space_values',status='observed',
            client_sha256=SHIPPING_SHA256,pid=pid,created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),source_pins=pins,
            snapshot_sha256=hashlib.sha256(snapshot_raw).hexdigest(),
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),current_pawn=pawn,
            inventory_manager=component,repdata=values['repdata'],derived_maps=maps,
            received_ui_geometry=received_ui_geometry,native_space_maps_are_authority_initialized=True,
            native_item_visibility_state=visibility_state,
            controller_gp_character_binding=pc_character,pawn_player_state_binding=pawn_state,
            current_fields_and_identities_rechecked=True,process_identity_rechecked=True,
            process_memory_written=False,native_methods_invoked=False,packets_sent=False,
            native_layouts_constructed=False,code_sampled=False,historical_process_pointers_reused=False,
            ui_display_verified=False,lua_slot_cache_read=False)
    finally:
        reader.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('game-root','trial-report','snapshot','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--request-uac',action='store_true')
    args=parser.parse_args()
    output=args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/'work'):
        parser.error('Use an exclusive fresh project work output')
    # Reject completed trials before creating any process reader or UAC helper.
    owned_trial_identity(json.loads(args.trial_report.read_bytes()),args.game_root)
    sources()
    expected_items(args.snapshot.read_bytes())
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B',str(Path(__file__).resolve()),'--game-root',str(args.game_root.resolve()),
            '--trial-report',str(args.trial_report.resolve()),'--snapshot',str(args.snapshot.resolve()),
            '--output',str(output)],output)
        result=json.loads(output.read_bytes())
    else:
        try:
            result=observe(args.game_root,args.trial_report,args.snapshot)
        except Exception as error:
            result=dict(status='refused',reason=str(error),error_type=type(error).__name__,
                process_memory_written=False,native_methods_invoked=False,packets_sent=False)
        write_exclusive_report(output,result)
    print(json.dumps(dict(status=result['status'],reason=result.get('reason'),output=str(output))))


if __name__=='__main__':
    main()
