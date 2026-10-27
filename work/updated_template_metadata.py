"""Callback-only current cached CDO and implemented-interface metadata.

The supplied UpdatedMetadata owns qualified registry/name/path resolution and
its backend. This module opens no process and calls no native function. Method
RVAs are observations, not approved sender bindings. No CDO payload is read.
"""
import hashlib
import json
from pathlib import Path
import struct
from types import MappingProxyType

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
PROOF = 'work/evidence/updated-template-metadata-79fb7b10.json'
PROOF_SHA256 = '9031b077b0f6dadcd59212057cfc2c8974f50e922142742f6e314eb67f03bc56'
IMAGE_BYTES = 536408064
ACCESSOR_CELL_RVA = 0x1d59de88
ACCESSOR_RVA = 0xd968f0
INTERFACE_CELL_RVA = 0x1de5c888
INTERFACE_PATH = '/Script/GPGameplay.NetRepActorInterface'
MAX_ANCESTORS = 64
MAX_INTERFACES = 128
MAX_DIRECT_READ_CALLS = 8192
MAX_DIRECT_READ_BYTES = 1024*1024
MAX_METADATA_CALLS = 16384
SUPPORTED_CLASS_PATHS = MappingProxyType({
    'BP_DFMPlayerController_C': '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C',
    'BP_DFMCharacter_C': '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C',
    'BP_GameState_PVPVE_C': '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C',
    'BP_SOLPlayerState_C': '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C',
})


class TemplateMetadataError(ValueError):
    pass


def source_pins():
    """Own proof/module only; transitive historical code is not activated here."""
    raw = (ROOT/PROOF).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROOF_SHA256:
        raise TemplateMetadataError('Updated template metadata proof SHA changed')
    doc = json.loads(raw)
    if (doc.get('kind') != 'offline_updated_existing_template_metadata_qualification'
            or doc.get('client_sha256') != SOURCE_SHA256
            or doc.get('native_called') is not False
            or doc['cdo_contract']['class_existing_cdo_pointer_offset'] != '0x140'
            or doc['interface_contract']['array_class_offset'] != '0x200'
            or doc['interface_contract']['entry_bytes'] != 16
            or doc['net_rep_actor_interface']['existing_singleton_cell_rva'] != '0x1de5c888'):
        raise TemplateMetadataError('Updated template metadata proof scope changed')
    return {PROOF:PROOF_SHA256,'work/updated_template_metadata.py':
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def _span(address,size):
    if (type(address) is not int or type(size) is not int or
            not 0x10000 <= address < (1<<47) or not 0 < size <= 8192 or
            address+size > (1<<47)):
        raise TemplateMetadataError('Invalid bounded template metadata address')


class _Observation:
    def __init__(self,metadata):
        self.metadata = metadata
        self.base = getattr(metadata,'base',None)
        _span(self.base,8)
        if self.base+IMAGE_BYTES >= (1<<47) or not callable(getattr(metadata,'backend',None)):
            raise TemplateMetadataError('Qualified current metadata reader/backend required')
        for name in ('record','name','path'):
            if not callable(getattr(metadata,name,None)):
                raise TemplateMetadataError('Qualified current metadata reader required')
        self.backend = metadata.backend
        self.saved,self.objects,self.classes = {},{},set()
        self.calls = self.bytes = self.metadata_calls = 0

    def read(self,address,size,*,image_slot=False):
        _span(address,size)
        if self.calls >= MAX_DIRECT_READ_CALLS or self.bytes+size > MAX_DIRECT_READ_BYTES:
            raise TemplateMetadataError('Template metadata direct read budget exhausted')
        in_image = self.base <= address < self.base+IMAGE_BYTES
        if not in_image and address<self.base+IMAGE_BYTES and address+size>self.base:
            raise TemplateMetadataError('Unqualified template image global boundary read')
        if in_image:
            global_cell = (address-self.base,size) in ((ACCESSOR_CELL_RVA,8),(INTERFACE_CELL_RVA,8))
            if not (image_slot and size==8 or global_cell) or address+size > self.base+IMAGE_BYTES:
                raise TemplateMetadataError('Unqualified template image global read')
        elif image_slot:
            raise TemplateMetadataError('Template method table outside current image')
        self.calls += 1
        self.bytes += size
        try:
            value = self.backend(address,size)
        except Exception as error:
            raise TemplateMetadataError('Unavailable template metadata read') from error
        if type(value) is not bytes or len(value) != size:
            raise TemplateMetadataError('Incomplete template metadata callback read')
        return value

    def keep(self,address,size,*,image_slot=False):
        raw=self.read(address,size,image_slot=image_slot)
        key=(address,size,image_slot)
        if key in self.saved and self.saved[key]!=raw:
            raise TemplateMetadataError('Template metadata bytes changed during observation')
        self.saved[key]=raw
        return raw

    def ptr(self,address,*,image_slot=False):
        return struct.unpack('<Q',self.keep(address,8,image_slot=image_slot))[0]

    def call(self,name,address):
        if self.metadata_calls >= MAX_METADATA_CALLS:
            raise TemplateMetadataError('Template metadata identity-call budget exhausted')
        self.metadata_calls += 1
        try:
            return getattr(self.metadata,name)(address)
        except Exception as error:
            raise TemplateMetadataError('Unavailable or changed template object '+name) from error

    def identity(self,address):
        _span(address,8)
        if self.base <= address < self.base+IMAGE_BYTES:
            raise TemplateMetadataError('Template UObject metadata unexpectedly inside image')
        record=self.call('record',address)
        name,path=str(self.call('name',address)),self.call('path',address)
        if (getattr(record,'object_address',None)!=address or
                type(record.index) is not int or not 0<=record.index<(1<<31) or
                type(record.serial) is not int or not 0<=record.serial<(1<<32) or
                type(path) is not str or not name or not name.isascii() or '?' in name or
                not path or not path.isascii() or '?' in path):
            raise TemplateMetadataError('Incomplete or ambiguous template object identity')
        value=(record,name,path)
        if address in self.objects and self.objects[address]!=value:
            raise TemplateMetadataError('Template object identity/name/path changed')
        self.objects[address]=value
        return dict(name=name,path=path,object_index=record.index,serial=record.serial)

    def klass(self,address):
        row=self.identity(address)
        if address in self.classes:
            return row
        cursor=self.ptr(address+8)
        seen=set()
        while cursor:
            if cursor in seen or len(seen)>=MAX_ANCESTORS:
                raise TemplateMetadataError('Template metaclass ancestry cycle or bound')
            seen.add(cursor)
            meta=self.identity(cursor)
            if meta['path']=='/Script/CoreUObject.Class' and meta['name']=='Class':
                self.classes.add(address)
                return row
            cursor=self.ptr(cursor+0x48)
        raise TemplateMetadataError('Template descriptor has wrong type; Class ancestry required')

    def method(self,object_address,slot):
        table=self.ptr(object_address)
        if not self.base<=table<=self.base+IMAGE_BYTES-slot-8:
            raise TemplateMetadataError('Template vtable outside current image')
        target=self.ptr(table+slot,image_slot=True)
        if not self.base<=target<self.base+IMAGE_BYTES:
            raise TemplateMetadataError('Template method target outside current image')
        return dict(vtable_rva=table-self.base,slot=slot,target_rva=target-self.base,
            target_approved=False,function_called=False,function_body_verified=False)

    def depth(self,address):
        depth=struct.unpack('<i',self.keep(address+0x38,4))[0]
        if not 0<=depth<MAX_ANCESTORS:
            raise TemplateMetadataError('Interface ancestry depth exceeds bound')
        return depth

    def finish(self):
        # Separate full passes expose mutations made by a later read callback.
        # This is a stable bounded observation, never an atomic process snapshot.
        for _ in range(2):
            if self.metadata.base!=self.base or self.metadata.backend is not self.backend:
                raise TemplateMetadataError('Supplied template metadata backend/base changed')
            for address,(record,name,path) in tuple(self.objects.items()):
                if (self.call('record',address)!=record or
                        str(self.call('name',address))!=name or self.call('path',address)!=path):
                    raise TemplateMetadataError('Template object identity/name/path changed during recheck')
            for (address,size,image_slot),expected in tuple(self.saved.items()):
                if self.read(address,size,image_slot=image_slot)!=expected:
                    raise TemplateMetadataError('Template metadata bytes changed during recheck')


def _unavailable(reason):
    return dict(status='not_available',reason=reason)


def observe_template_metadata(metadata,class_address):
    """Observe one exact supported current class through metadata.backend/base.

    metadata supplies record/name/path and a qualified exact-read backend, as an
    UpdatedMetadata instance does. Its caller owns process/source identity and
    bounded underlying read deadlines. Returned rows contain RVAs and current
    object indices/serials, never process addresses. Missing cached CDO/interface
    singleton pointers are explicit not_available; invalid/changing data raises.
    """
    pins=source_pins()
    ob=_Observation(metadata)
    selected=ob.klass(class_address)
    if SUPPORTED_CLASS_PATHS.get(selected['name'])!=selected['path']:
        raise TemplateMetadataError('Only four exact supported current template class paths are allowed')
    class_outer=ob.ptr(class_address+0x10)
    outer=ob.identity(class_outer)
    cdo=ob.ptr(class_address+0x140)
    cdo_row=_unavailable('cached_class_default_object_pointer_is_null')
    if cdo:
        cdo_row=ob.identity(cdo)
        actual_class=ob.ptr(cdo+8)
        actual_outer=ob.ptr(cdo+0x10)
        if (actual_class!=class_address or cdo_row['name']!='Default__'+selected['name'] or
                actual_outer not in (class_address,class_outer)):
            raise TemplateMetadataError('Cached CDO class/name/Outer does not match selected class')
        actual_outer_row=ob.identity(actual_outer)
        separator=':' if actual_outer==class_address else '.'
        if cdo_row['path']!=actual_outer_row['path']+separator+cdo_row['name']:
            raise TemplateMetadataError('Cached CDO exact path does not match current Outer')
        flags=struct.unpack('<I',ob.keep(cdo+0x18,4))[0]
        cdo_row.update(status='observed',class_path=selected['path'],outer_path=actual_outer_row['path'],
            raw_uobject_flags32=flags,class_default_pointer_offset=0x140,
            actor_channel_open_hook=ob.method(cdo,0x3d8),native_getter_called=False)
    if ob.ptr(ob.base+ACCESSOR_CELL_RVA)!=ob.base+ACCESSOR_RVA:
        raise TemplateMetadataError('Current interface array accessor is unqualified')
    singleton=ob.ptr(ob.base+INTERFACE_CELL_RVA)
    requested=None
    if singleton:
        requested=ob.klass(singleton)
        flags=struct.unpack('<I',ob.keep(singleton+0xd4,4))[0]
        if (requested['name']!='NetRepActorInterface' or requested['path']!=INTERFACE_PATH or
                flags & ((1<<14)|(1<<7)) != ((1<<14)|(1<<7))):
            raise TemplateMetadataError('Existing interface singleton has wrong type/path/flags')
        requested['base_chain_depth']=ob.depth(singleton)
    ancestors,matches,seen,total=[],[],set(),0
    cursor=class_address
    while cursor:
        if cursor in seen or len(seen)>=MAX_ANCESTORS:
            raise TemplateMetadataError('Template Class ancestry cycle or bound')
        seen.add(cursor)
        row=ob.klass(cursor)
        data,count,capacity=struct.unpack('<Qii',ob.keep(cursor+0x200,16))
        if not 0<=count<=capacity<=MAX_INTERFACES or capacity and not data:
            raise TemplateMetadataError('Implemented interface array count/capacity/pointer exceeds bound')
        total+=count
        if total>MAX_INTERFACES:
            raise TemplateMetadataError('Implemented interface total exceeds bound')
        raw=ob.keep(data,count*16) if count else b''
        entries=[]
        for index in range(count):
            interface,adjustment,script=struct.unpack_from('<QiB',raw,index*16)
            entry=ob.klass(interface)
            item=dict(entry_index=index,**entry,pointer_adjustment=adjustment,
                      implemented_by_script_byte=script)
            entries.append(item)
            if requested is not None and script==0:
                depth=ob.depth(interface)
                requested_depth=requested['base_chain_depth']
                if requested_depth<=depth:
                    chain=ob.ptr(interface+0x30)
                    if not chain:
                        raise TemplateMetadataError('Native interface base-chain pointer is null')
                    if ob.ptr(chain+requested_depth*8)==singleton+0x30:
                        matches.append(dict(declaring_class_path=row['path'],**item))
        row.update(interface_count=count,interface_capacity=capacity,interfaces=entries)
        ancestors.append(row)
        cursor=ob.ptr(cursor+0x48)
    if ancestors[-1]['path']!='/Script/CoreUObject.Object':
        raise TemplateMetadataError('Selected template ancestry does not end at Object')
    if len(matches)>1:
        raise TemplateMetadataError('Native NetRepActorInterface binding is ambiguous')
    interface_row=_unavailable('no_eligible_native_interface_entry')
    if not singleton:
        interface_row=_unavailable('existing_interface_singleton_pointer_is_null')
    elif not cdo:
        interface_row=_unavailable('cached_class_default_object_pointer_is_null')
    elif matches:
        match=matches[0]
        secondary=cdo+match['pointer_adjustment']
        _span(secondary,8)
        interface_row=dict(status='observed',interface_class=requested,**match,
            method=ob.method(secondary,0x10),native_method_called=False)
    ob.finish()
    if source_pins()!=pins:
        raise TemplateMetadataError('Template source proof/module changed during observation')
    return dict(kind='updated_existing_template_metadata_observation',client_sha256=SOURCE_SHA256,
        **{'class':selected},class_outer_path=outer['path'],ancestors=ancestors,cdo=cdo_row,
        net_rep_actor_interface=interface_row,source_pins=pins,
        identities_and_fields_rechecked=True,snapshot_atomic=False,
        native_function_called=False,process_memory_written=False,cdo_payload_read=False,
        method_targets_are_observations_only=True,read_calls=ob.calls,read_bytes=ob.bytes,
        metadata_method_calls=ob.metadata_calls,
        read_accounting_scope='Direct metadata/header/vtable reads here; supplied reader owns its internal registry/name/path read accounting and deadline.')
