"""Bounded read-only current-world door, container, exit and owner discovery.

Run only against the separately authorized owned shadow trial. It follows the
actual current Pawn World's reflected Levels array, then selects two nearest
doors/containers and up to eight actual source exits. No native method,
layout construction, process write, packet, or executable-code read occurs.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import struct

import export_native_replication_metadata as exporter
from observe_owned_gameplay_metadata import (address, owned_trial_identity,
    typed_declarations, BindingObservation, write_exclusive_report, label_existing)
from observe_portable_map_runtime import (ROOT, SHIPPING_SHA256, Win32MetadataReader,
    MetadataSession, validate_source, discover_roots, observe_first_player_state,
    object_name, request_elevation)
from native_metadata_objects import validate_object_record
from native_metadata_paths import object_path
from observe_economy_loaded_interactors import actor_open_hook, sources as actor_sources

GATE_SOURCE = 'work/evidence/map-system-audit-20261018/native-economy-interactor-current-cancheck-override.json'
EXIT_SOURCE = 'work/evidence/map-system-audit-20261018/native-economy-exit-and-ai-blueprint-exports-v1.json'
POSITION_SOURCE = 'work/evidence/map-system-audit-20261018/native-economy-current-world-root-location-source-v1.json'
SOURCE_REPORTS = {
    GATE_SOURCE: '8d034bbd71e97e41321415b03c47ebb23d7b15c895fd47524bc5d1da7e15a9fc',
    EXIT_SOURCE: 'a693cd981c65cf723c246738ffc687b8c3d30a9d8b3fc04a0fd6f0f740317527',
    'work/native-client-tests/1792328560808149500/owned-gameplay-metadata.json':
        '18fcdea26eba57403bc94e712e07906aef38e5a641e8a140012d2d4504233a31',
    'work/evidence/map-system-audit-20261018/native-economy-container-inventory-rep-struct-fields.json':
        '8956c0b53df51bb4054619932af21d0782e989a45a92a7ae2f99301e8b5d081b',
    POSITION_SOURCE: 'd490f62fd60d1e49ba8023b410e1777dc8664ed31b3c8e5ee9bf602b4b632e7c',
}
CLASS_ANCHORS = {
    'BP_Interactor_RotateDoorBase_C': ('door',
        '/Game/BluePrints/Interact/Door/BaseNew/BP_Interactor_RotateDoorBase.BP_Interactor_RotateDoorBase_C'),
    'InventoryPickup_OpenBox': ('container', '/Script/DFMGameplay.InventoryPickup_OpenBox'),
    'BP_PlayerExitNormalNew_C': ('exit',
        '/Game/BluePrints/Exit/BP_PlayerExitNormalNew.BP_PlayerExitNormalNew_C'),
    'BP_PlayerExitDam_C': ('exit', '/Game/BluePrints/Exit/BP_PlayerExitDam.BP_PlayerExitDam_C'),
}
MAX_CLASSES = 25000
MAX_REGISTRY_CANDIDATES = 4096
MAX_CURRENT_LEVEL_ACTORS = 2048
CATEGORY_LIMITS = dict(door=2,container=2,exit=8)
MAX_DISTANCE_CM = 250000
MAX_COMPONENTS = 24

FOCUS_REFERENCES = ('GPOwner', 'OwnerPawn', 'CurScanInteractor',
    'CurrentInteractingObject', 'CachedShowingHUDInteractor_HD', 'CurrentHookPotentialInteractor')
FOCUS_ARRAYS = ('AllConsiderableSingleInteractors', 'MostPotentialAllInteractors',
    'MostPotentialWhiteDotInteractors', 'CurrentPotentialInteractors',
    'CurrIndepViewPotnInteractors', 'CustomPotentialInteractors_HD',
    'AllPotentialHUDInteractableProxies', 'AllPotentialInteractors',
    'MostPotentialGlowInteractors', 'AllPotentialOutlineInteractors',
    'GridInteractorArr', 'MovableGridInteractorArr', 'ClientOverlapInteractorArr')
FOCUS_BOOLS = ('bNeedTick', 'bUseCheckCannotTick', 'bUseCheckOwnerIsSelf',
    'bWhitelistEnable', 'bUseCheckActiveInMaxDis')
ACTOR_VALUES = ('bIsEmpty', 'bSceneEquipContainer', 'bIsOpened', 'bIsOpening',
    'bHasOpened', 'bHasInterlayer', 'bIsInterlayerOpenBox', 'bSwitcherState',
    'OpeningPlayerId', 'SafeBoxUin', 'LastLootingPlayer', 'LastPlayerLootingTime',
    'BaseBoxSearchTime', 'BaseItemSearchTime', 'PlayerExitId', 'PlayerExitState',
    'ExitState', 'CountDownTime', 'CurrentCountDown', 'bActive', 'bEnable',
    'LootBoxRepData', 'SwitcherStateWithContext')
ACTOR_ARRAYS = ('CurrentSearchingPlayers', 'AllowPutInItemGids',
    'CurrentLootingPlayers', 'SearchDonePlayer')
def sources():
    pins = actor_sources()[1]
    for relative, expected in SOURCE_REPORTS.items():
        raw = (ROOT/relative).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if expected is not None and digest != expected:
            raise ValueError('World interaction source changed: '+relative)
        pins[relative] = digest
    position = json.loads((ROOT/POSITION_SOURCE).read_bytes())
    anchors = {(row['rva'],row['mnemonic'],row['operands'])
        for function in position['functions'] for row in function['instructions']}
    if (position.get('client_sha256')!=SHIPPING_SHA256 or
            position.get('process_access') is not False or
            not {('0xe36ac5','mov','rdi, qword ptr [rcx + 0x180]'),
                 ('0x131945b6','movups','xmm1, xmmword ptr [rdx + 0x220]'),
                 ('0x131945bd','mov','eax, 0xffff'),
                 ('0x131945c2','add','rdx, 0x240')} <= anchors):
        raise ValueError('The current-world root/location consumer qualification changed')
    for relative in ('work/observe_world_interaction_lifecycle.py',):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def array_header(raw, stride, limit=512):
    if type(raw) is not bytes or len(raw) != 16 or stride < 1:
        raise ValueError('A bounded native array header is required')
    data, count, capacity = struct.unpack('<Qii', raw)
    if (not 0 <= count <= capacity <= limit or capacity and not data or
            data and (not 0x10000 <= data < 1 << 47 or data & 7) or
            count and data+count*stride >= 1 << 47):
        raise ValueError('The current native array exceeds its declared bound')
    return data, count, capacity


def nearest_candidates(rows, levels, origin):
    if len(rows) > MAX_CURRENT_LEVEL_ACTORS or len(set(levels)) > 512:
        raise ValueError('The current world candidate scope exceeds its bound')
    if len(origin)!=3 or not all(math.isfinite(v) for v in origin):
        raise ValueError('The current owned origin must be finite')
    seen, selected = set(), []
    for row in rows:
        if row['address'] in seen:
            raise ValueError('A duplicate published candidate is ambiguous')
        seen.add(row['address'])
        if row['category'] not in ('door', 'container', 'exit'):
            raise ValueError('A candidate class family is outside scope')
        if row['level'] not in levels or row['is_cdo'] or not row['initialized']:
            continue
        xyz = row['position_xyz']
        if len(xyz)!=3 or not all(math.isfinite(v) for v in xyz):
            raise ValueError('A candidate position is nonfinite')
        distance = math.dist(origin, xyz)
        if distance <= MAX_DISTANCE_CM:
            selected.append(dict(row, distance_cm=distance))
    return [row for category in ('door', 'container', 'exit')
        for row in sorted((r for r in selected if r['category']==category),
                          key=lambda r:(r['distance_cm'],r['address']))[:CATEGORY_LIMITS[category]]]


class Facts:
    def __init__(self, session):
        self.session, self.reads = session, {}

    def keep(self, at, size):
        raw = self.session.stable(at, size)
        key = (at, size)
        if key in self.reads and self.reads[key] != raw:
            raise ValueError('A selected world field changed during observation')
        self.reads[key] = raw
        return raw

    def finish(self):
        for (at, size), raw in self.reads.items():
            if self.session.stable(at, size) != raw:
                raise ValueError('A selected world field changed before publication')


class Fields:
    def __init__(self, session, base, identity, facts):
        self.session, self.base, self.identity, self.facts = session, base, identity, facts
        self.cache = {}

    def properties(self, klass):
        if klass in self.cache:
            return self.cache[klass]
        rows, classes, nodes, cursor = [], set(), set(), klass
        while cursor:
            cursor = address(cursor)
            if cursor in classes or len(classes)>=32:
                raise ValueError('The current declaring class chain is cyclic or oversized')
            classes.add(cursor)
            before = self.identity(cursor, 'Struct')
            parent, = struct.unpack('<Q', self.facts.keep(cursor+0x48, 8))
            node, = struct.unpack('<Q', self.facts.keep(cursor+0x70, 8))
            while node:
                node = address(node)
                if node in nodes or len(nodes)>=4096:
                    raise ValueError('The current declaring property chain is cyclic or oversized')
                nodes.add(node)
                raw = self.facts.keep(node, 0x60)
                table, owner = struct.unpack_from('<QQ', raw)
                if owner != cursor or not raw[0x10] or not self.base <= table < self.base+536408064:
                    raise ValueError('A current property has a foreign owner or image')
                rows.append(dict(name=object_name(self.session.read,self.base,node,field_representation=0).display_text,
                    declaring_class=before['name'], descriptor_address=node,
                    storage_offset=struct.unpack_from('<i',raw,0x54)[0],
                    element_bytes=struct.unpack_from('<i',raw,0x40)[0],
                    array_dimension=struct.unpack_from('<i',raw,0x3c)[0],
                    property_flags=hex(struct.unpack_from('<Q',raw,0x48)[0]),
                    field_vtable_rva=table-self.base))
                node, = struct.unpack_from('<Q', raw, 0x18)
            if self.identity(cursor,'Struct')!=before:
                raise ValueError('The declaring class changed')
            cursor = parent
        self.cache[klass] = rows
        return rows

    def one(self, klass, name):
        rows = [r for r in self.properties(klass) if r['name']==name]
        if len(rows)!=1:
            raise ValueError('One exact current declaration is required: '+name)
        row = rows[0]
        if row['array_dimension']!=1 or not 0<=row['storage_offset']<131072 or not 0<row['element_bytes']<=4096:
            raise ValueError('The current declaration has an unsupported extent: '+name)
        return row

    def hook(self, field):
        value = exporter.observed_virtual_method(self.session,self.base,field['descriptor_address'],0x90)
        exporter.recheck_virtual_method(self.session,self.base,field['descriptor_address'],value)
        if value.get('inside_pinned_image') is not True:
            raise ValueError('The current serializer is outside its pinned image')
        return value

    def reference_array(self, pointer, klass, name, expected_class):
        field = self.one(klass,name)
        if (field['element_bytes'],field['field_vtable_rva'])!=(16,0x1ab5b730):
            raise ValueError('The current level membership is not a declared array')
        inner = address(struct.unpack('<Q',self.facts.keep(field['descriptor_address']+0x90,8))[0])
        raw = self.facts.keep(inner,0x60)
        if struct.unpack_from('<ii',raw,0x3c)!=(1,8) or struct.unpack_from('<i',raw,0x54)[0]!=0:
            raise ValueError('The actual level-array element is not an eight-byte reference')
        inner_field = dict(descriptor_address=inner)
        if self.hook(inner_field).get('target_rva')!=0x10e8ed20:
            raise ValueError('The actual level-array element serializer is not object reference')
        declared = address(struct.unpack('<Q',self.facts.keep(inner+0x90,8))[0])
        declared_identity = self.identity(declared,'Class')
        if (declared_identity['name']!=expected_class or
                object_path(self.session.read,self.base,declared)!='/Script/Engine.'+expected_class):
            raise ValueError('The actual world membership array has a foreign declared class')
        header = self.facts.keep(pointer+field['storage_offset'],16)
        data,count,capacity = array_header(header,8)
        payload = self.facts.keep(data,count*8) if count else b''
        values = []
        for at in range(0,len(payload),8):
            value, = struct.unpack_from('<Q',payload,at)
            if value:
                value = address(value)
                self.identity(value,expected_class)
                values.append(value)
        if len(values)!=len(set(values)):
            raise ValueError('The current world membership array contains duplicate Levels')
        return dict(field=field,count=count,capacity=capacity,typed_level_addresses=values)

    def value(self, pointer, klass, name):
        field = self.one(klass,name)
        hook = self.hook(field)
        result = dict(field=field,serializer_hook=hook)
        size, at = field['element_bytes'],pointer+field['storage_offset']
        if field['field_vtable_rva']==0x1ab5b730 and size==16:
            data,count,capacity = array_header(self.facts.keep(at,16),1,4096)
            return dict(result,status='observed_array_header',count=count,capacity=capacity,
                        data_pointer_nonnull=bool(data),elements_read=False)
        target = hook.get('target_rva')
        if target==0x10e8ebe0 and size==1:
            masks = self.facts.keep(field['descriptor_address']+0x8a,3)
            offset,byte_mask,field_mask = masks
            if offset or not byte_mask or byte_mask&(byte_mask-1) or field_mask not in (byte_mask,255):
                raise ValueError('The current bool mask has an unsupported extent')
            raw = self.facts.keep(at,1)
            return dict(result,status='observed',value=bool(raw[0]&field_mask),raw_hex=raw.hex(),
                        byte_offset=offset,byte_mask=byte_mask,field_mask=field_mask)
        if target==0x10e5ce20 and field['field_vtable_rva']==0x15a86700 and size==4:
            raw = self.facts.keep(at,4)
            value, = struct.unpack('<f',raw)
            if not math.isfinite(value):
                raise ValueError('The current declared float is nonfinite')
            return dict(result,status='observed',raw_hex=raw.hex(),value=value)
        if target==0x10e5ce20 and size in (1,2,4,8):
            raw = self.facts.keep(at,size)
            return dict(result,status='observed',raw_hex=raw.hex(),
                integer_unsigned=int.from_bytes(raw,'little'),integer_signed=int.from_bytes(raw,'little',signed=True))
        if target in (0x10e8ec50,0x10e29fa0) and size in (1,2,4,8):
            raw = self.facts.keep(at,size)
            return dict(result,status='observed',raw_hex=raw.hex(),enum_numeric=int.from_bytes(raw,'little'))
        if name in ('LootBoxRepData','SwitcherStateWithContext') and size<=64:
            raw = self.facts.keep(at,size)
            nested = address(struct.unpack('<Q',self.facts.keep(field['descriptor_address']+0x90,8))[0])
            nested_identity = self.identity(nested,'ScriptStruct')
            return dict(result,status='observed_typed_struct_raw',raw_hex=raw.hex(),
                        struct_identity=nested_identity,semantic_fields_decoded=False)
        return dict(result,status='unsupported_declared_value_representation',instance_value_read=False)


def observe(game_root, trial_report):
    trial_raw = trial_report.read_bytes()
    pid,created = owned_trial_identity(json.loads(trial_raw),game_root)
    pins = sources()
    executable,size = validate_source(game_root)
    reader = Win32MetadataReader(executable,size,pid,created,maximum_seconds=180)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256,session.module_size = SHIPPING_SHA256,size
        base,sink,candidates,class_cache = reader.module_base,{},[],{}
        original_iterator = exporter.iter_object_records
        scan_facts = Facts(session)

        def category(klass):
            if klass in class_cache:
                return class_cache[klass]
            chain,seen,cursor,selected = [],set(),klass,None
            while cursor:
                cursor = address(cursor)
                if cursor in seen or len(seen)>=32:
                    raise ValueError('A published registry class chain is cyclic or oversized')
                if cursor in class_cache:
                    selected = class_cache[cursor]
                    break
                if len(class_cache)+len(chain)>=MAX_CLASSES:
                    raise ValueError('Published class selection exceeds its bound')
                seen.add(cursor)
                record = validate_object_record(session.read,base,cursor)
                name = object_name(session.read,base,cursor).display_text
                chain.append(cursor)
                if name in CLASS_ANCHORS:
                    wanted,path = CLASS_ANCHORS[name]
                    if object_path(session.read,base,cursor)!=path:
                        raise ValueError('A source class family has a foreign actual package identity')
                    selected = wanted
                    break
                parent, = struct.unpack('<Q',scan_facts.keep(cursor+0x48,8))
                if validate_object_record(session.read,base,cursor)!=record:
                    raise ValueError('A published registry class changed during selection')
                cursor = parent
            for item in chain:
                class_cache[item] = selected
            return selected

        def registry(read,module_base,**options):
            for record in original_iterator(read,module_base,**options):
                if record.class_address is None:
                    raise ValueError('A published Class pointer is required')
                kind = category(record.class_address)
                if kind:
                    if len(candidates)>=MAX_REGISTRY_CANDIDATES:
                        raise ValueError('Published world-family candidates exceed their bound')
                    candidates.append(dict(address=record.object_address,object_index=record.index,
                        serial=record.serial,category=kind))
                yield record

        try:
            exporter.iter_object_records = registry
            roots = discover_roots(session,base,connection_binding_only=True,first_player_state=True,
                _binding_identity_sink=sink,unpublished_batch_retry=True)
        finally:
            exporter.iter_object_records = original_iterator
        identity = sink['callback']
        pcs = [r for r in roots['connection_binding_observations']['player_controllers']
            if r.get('status')=='observed' and r.get('identity_and_fields_rechecked') is True
            and r.get('driver_primary_matches_original_connection') is True and r.get('local_player_index_field')==0]
        if len(pcs)!=1:
            raise ValueError('One current owned primary controller is required')
        pc = pcs[0]
        binding = observe_first_player_state(session,base,driver_address=address(pc['driver']),
            connection_address=address(pc['connection']),pc_address=address(pc['address']),object_identity=identity)
        pawn = binding.get('pc_pawn_reference',{})
        if binding.get('status')!='observed' or pawn.get('status')!='typed_existing_reference':
            raise ValueError('One current owned Pawn is required')
        facts,metadata_cache,checked = Facts(session),{},[]

        def metadata(pointer,expected):
            value = identity(pointer,expected)
            klass = address(value['class_address'])
            if klass not in metadata_cache:
                metadata_cache[klass] = dict(declarations=typed_declarations(session,base,klass,identity),
                    existing_driver_class=label_existing(session,base,address(pc['driver']),klass))
            return metadata_cache[klass]

        observation = BindingObservation(session,base,identity,metadata)
        fields = Fields(session,base,observation.identify,facts)

        def describe(pointer,expected):
            before = observation.identify(pointer,expected)
            path = object_path(session.read,base,pointer)
            checked.append((pointer,expected,before,path))
            return dict(identity=before,object_path=path,
                class_path=object_path(session.read,base,address(before['class_address'])))

        def ref(pointer,name,expected='Object'):
            declared = [dict(f,declaring_class=c['class_name'])
                for c in metadata(pointer,'Object')['declarations'] for f in c['fields'] if f['name']==name]
            if len(declared)!=1:
                return dict(field_name=name,status='declaration_unavailable',instance_value_read=False)
            return observation.reference(pointer,declared[0],expected_base=expected)

        def position(pointer):
            klass = address(observation.identify(pointer,'Actor')['class_address'])
            root_field = fields.one(klass,'RootComponent')
            if (root_field['declaring_class'],root_field['storage_offset'],root_field['element_bytes'])!=('Actor',0x180,8):
                raise ValueError('The current Actor root declaration differs from the pinned root consumer')
            root = ref(pointer,'RootComponent','SceneComponent')
            if root.get('status')!='typed_existing_reference':
                raise ValueError('The current Actor root has no supported typed reference')
            scene = address(root['identity']['address'])
            tag = facts.keep(scene+0x240,4)
            if struct.unpack_from('<H',tag)[0]!=65535:
                raise ValueError('The current Actor translation requires an unsupported decoder')
            xyz = struct.unpack_from('<3f',facts.keep(scene+0x220,16))
            if not all(math.isfinite(v) for v in xyz):
                raise ValueError('The current Actor translation is nonfinite')
            return xyz

        pawn_pointer = address(pawn['address'])
        pawn_row = describe(pawn_pointer,'Pawn')
        pawn_level = address(pawn_row['identity']['outer_address'])
        level_row = describe(pawn_level,'Level')
        world_pointer = address(level_row['identity']['outer_address'])
        world_row = describe(world_pointer,'World')
        world_class = address(world_row['identity']['class_address'])
        membership = fields.reference_array(world_pointer,world_class,'Levels','Level')
        levels = set(membership['typed_level_addresses'])
        if pawn_level not in levels:
            raise ValueError('The current owned Pawn Level is absent from its actual World Levels')
        origin = position(pawn_pointer)
        exit_source = json.loads((ROOT/EXIT_SOURCE).read_bytes())
        source_exits = {row['name'] for package in exit_source['packages']
            for row in package['selected_exports']
            if row['class_name'] in ('BP_PlayerExitNormalNew_C','BP_PlayerExitDam_C')}
        if len(source_exits)!=8:
            raise ValueError('The eight qualified cooked exit Actor names changed')
        exit_package_prefix = '/Game/Maps/Dam_Iris_Level1/GameplayConfig/Dam_Iris_Level1_GameplayConfig.'
        scoped,refused_positions = [],[]
        for candidate in candidates:
            try:
                before = observation.identify(candidate['address'],'Actor')
                level = address(before['outer_address'])
                if level not in levels or before['is_cdo'] or not before['serial']:
                    continue
                if candidate['category']=='exit' and (before['name'] not in source_exits or
                        not object_path(session.read,base,candidate['address']).startswith(exit_package_prefix)):
                    continue
                if len(scoped)>=MAX_CURRENT_LEVEL_ACTORS:
                    raise ValueError('Current-level actors exceed the explicit observation bound')
                xyz = position(candidate['address'])
                scoped.append(dict(candidate,level=level,position_xyz=xyz,initialized=True,is_cdo=False))
            except (ValueError,OSError) as error:
                if len(refused_positions)>=64:
                    raise ValueError('More than 64 current-world candidates could not be qualified')
                refused_positions.append(dict(object_index=candidate['object_index'],reason=str(error)))
        selected = nearest_candidates(scoped,levels,origin)
        interactor = ref(pawn_pointer,'InteractorComponent','ActorComponent')
        focus = dict(status='current_interactor_reference_unavailable')
        if interactor.get('status')=='typed_existing_reference':
            pointer = address(interactor['identity']['address'])
            if (interactor['identity']['name']!='InteractorComponent' or
                    address(interactor['identity']['outer_address'])!=pawn_pointer or
                    'SOLInteractorComponent' not in interactor['identity']['class_ancestry']):
                raise ValueError('The current default Interactor name, Outer or native ancestry differs')
            klass = address(interactor['identity']['class_address'])
            focus = dict(status='observed',object=describe(pointer,'ActorComponent'),
                existing_driver_class=metadata(pointer,'ActorComponent')['existing_driver_class'],
                owner_references=[ref(pointer,name) for name in FOCUS_REFERENCES],
                arrays=[],booleans=[])
            for link in focus['owner_references']:
                if link.get('status')=='typed_existing_reference':
                    link['points_to_current_pawn'] = address(link['identity']['address'])==pawn_pointer
            for group,names in (('arrays',FOCUS_ARRAYS),('booleans',FOCUS_BOOLS)):
                for name in names:
                    try:
                        focus[group].append(dict(name=name,**fields.value(pointer,klass,name)))
                    except ValueError as error:
                        focus[group].append(dict(name=name,status='refused',reason=str(error)))
        actors = []
        for candidate in selected:
            pointer = candidate['address']
            actor = describe(pointer,'Actor')
            klass = address(actor['identity']['class_address'])
            actor.update(category=candidate['category'],distance_cm=candidate['distance_cm'],
                position_xyz=list(candidate['position_xyz']),
                level=describe(candidate['level'],'Level'),
                level_is_actual_current_world_member=True,
                existing_driver_class=metadata(pointer,'Actor')['existing_driver_class'],
                actor_open_hook=actor_open_hook(session,base,size,pointer),values=[],components=[])
            declared = metadata(pointer,'Actor')['declarations']
            components = [dict(f,declaring_class=c['class_name']) for c in declared for f in c['fields']
                if f.get('native_property_type') in ('FObjectProperty','FEncryptedObjectProperty')
                and any(token in (f['name']+' '+f.get('declared_native_class','')).lower()
                        for token in ('switch','process','interact','trigger','search','pickup','password'))]
            if len(components)>MAX_COMPONENTS:
                raise ValueError('Selected Actor typed interaction component scope exceeds 24')
            for field in components:
                link = observation.reference(pointer,field)
                if link.get('status')=='typed_existing_reference' and 'ActorComponent' in link['identity']['class_ancestry']:
                    component = address(link['identity']['address'])
                    link.update(object=describe(component,'ActorComponent'),
                        existing_driver_class=metadata(component,'ActorComponent')['existing_driver_class'],values=[])
                    component_class = address(link['identity']['class_address'])
                    for name in ('SwitcherStateWithContext','bSwitcherState','OptSwitcherType',
                            'bActive','bEnable','bInitialized'):
                        if any(f['name']==name for f in fields.properties(component_class)):
                            try:
                                link['values'].append(dict(name=name,**fields.value(component,component_class,name)))
                            except ValueError as error:
                                link['values'].append(dict(name=name,status='refused',reason=str(error)))
                actor['components'].append(link)
            for name in ACTOR_VALUES+ACTOR_ARRAYS:
                if not any(f['name']==name for f in fields.properties(klass)):
                    continue
                try:
                    actor['values'].append(dict(name=name,**fields.value(pointer,klass,name)))
                except ValueError as error:
                    actor['values'].append(dict(name=name,status='refused',reason=str(error)))
            item_fields = [f for f in fields.properties(klass) if f['name']=='RepItemArray']
            if item_fields:
                field = fields.one(klass,'RepItemArray')
                if field['element_bytes']!=288 or field['field_vtable_rva']!=0x15a86f40:
                    raise ValueError('The container does not use the source-qualified ItemArray')
                raw = facts.keep(pointer+field['storage_offset']+0x108,16)
                data,count,capacity = array_header(raw,0x800,256)
                actor['item_array'] = dict(field=field,count=count,capacity=capacity,
                    data_pointer_nonnull=bool(data),items_read=False,
                    no_activated_contents_inferred_from_config_candidates=True)
            actors.append(actor)
        blackboard = ref(pawn_pointer,'Blackboard')
        facts.finish()
        scan_facts.finish()
        observation.finish()
        for actor in actors:
            if actor_open_hook(session,base,size,address(actor['identity']['address']))!=actor['actor_open_hook']:
                raise ValueError('A selected existing Actor open hook changed before publication')
        for pointer,expected,before,path in checked:
            if (identity(pointer,expected)!=before or object_path(session.read,base,pointer)!=path):
                raise ValueError('A published world object identity or path changed')
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module()!=base or sources()!=pins:
            raise ValueError('The source/module identity changed during world observation')
        return dict(kind='owned_current_world_interaction_lifecycle_observation',status='observed',
            client_sha256=SHIPPING_SHA256,pid=pid,created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc,first_player_binding=binding,current_pawn=pawn_row,
            pawn_blackboard=blackboard,current_pawn_position_xyz=list(origin),
            current_pawn_level=level_row,current_world=world_row,world_levels=membership,
            registry_scan=roots['registry_scan'],published_family_candidates=len(candidates),
            current_world_positioned_candidates=len(scoped),refused_positions=refused_positions,
            selection_policy=dict(maximum_per_category=CATEGORY_LIMITS,
                maximum_distance_cm=MAX_DISTANCE_CM,distance_is_local_diagnostic_policy=True),
            source_exit_actor_names=sorted(source_exits),
            source_exit_names_not_selected=sorted(source_exits-
                {a['identity']['name'] for a in actors if a['category']=='exit'}),
            interactor=interactor,focus=focus,actors=actors,
            existing_actor_references_only=True,identities_and_fields_rechecked=True,
            read_calls=session.calls,read_bytes=session.bytes_read,
            process_memory_written=False,native_methods_invoked=False,native_layouts_constructed=False,
            packets_sent=False,code_sampled=False,historical_process_pointers_reused=False,snapshot_atomic=False)
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root',type=Path,required=True)
    parser.add_argument('--trial-report',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--request-uac',action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/'work'):
        parser.error('Use an exclusive new project work output')
    owned_trial_identity(json.loads(args.trial_report.read_bytes()),args.game_root)
    sources()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B',str(Path(__file__).resolve()),'--game-root',str(args.game_root.resolve()),
            '--trial-report',str(args.trial_report.resolve()),'--output',str(output)],output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root,args.trial_report)
        except Exception as error:
            report = dict(status='refused',reason=str(error),error_type=type(error).__name__,
                process_memory_written=False,native_methods_invoked=False,native_layouts_constructed=False,
                packets_sent=False,code_sampled=False,historical_process_pointers_reused=False)
        write_exclusive_report(output,report)
    print(json.dumps(dict(status=report['status'],reason=report.get('reason'),output=str(output))))


if __name__=='__main__':
    main()
