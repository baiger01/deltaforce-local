"""Callback-only exact manifest Actor membership/visibility observation.

The caller owns a freshly selected PC/Pawn binding and read-only process/image
identity. Supply at most the four source Actor paths, never addresses from an
old report. final_recheck must revalidate that binding and process. No process
is opened, code sampled, coordinate decoded, native getter called or packet sent.

This closes scene membership only. It does not establish PackageMap/ActorChannel
binding, BeginPlay, interaction permissions or readiness. Reported visibility
RPCs and transport ACKs are intentionally absent from these predicates.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

from native_replication_metadata_core import MetadataSession


ROOT = Path(__file__).resolve().parent.parent
SHIPPING_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
IMAGE_SIZE = 536408064
EVIDENCE = 'work/evidence/live-world-streaming-research-20261020-v1/'
SCHEMA = 'outputs/df-local-server/protocol/portable-map-spawn/level-actors-schema.json'
PINS = {
    SCHEMA: '322d3c79d316e1c4bd854da12e6ef9faf9364d29df1968c3a64397e2dc6fc12b',
    EVIDENCE+'native-world-class-declaration.json': '9455cbe682b0f036c12cf8219230594729286bdae19b0dc19d7360642a447f32',
    EVIDENCE+'native-level-class-declaration.json': '1f0bfc2ca327d2fadc5f3804d1bb5c234aa689e6d50887d35685050eb2ca1dcd',
    EVIDENCE+'native-streaming-class-declaration.json': '4d02266c36b272f172939564a9638c1334bb4e0805490b2ade0ea4ef0f3cab27',
    EVIDENCE+'native-level-loaded-visible-getters.json': 'ebd2bd069d7bd05de6f58e2f0ce59a819676fdfc2a0072925d13b7c5b5230f44',
    EVIDENCE+'native-streaming-functions-owners.json': '6d8a82e07e3d2cd60c6ab4d1d7c3df0925f5014d50e4114e4d5c573b3e07bb81',
    EVIDENCE+'native-level-streaming-class-identity.json': '656b71011a83f9e0b00e331f8a39d1bf4d5d45d042c2561c04543c3486de3bc0',
}
MAX_ARRAY_COUNT, MAX_ARRAY_CAPACITY = 512, 1024
MAX_READ_BYTES, MAX_READ_CALLS = 128*1024, 4096


@dataclass(frozen=True)
class ActorCandidate:
    address: int
    actor_path: str


def _pointer(value, *, null=False):
    if type(value) is str:
        value = int(value, 16)
    if null and value == 0:
        return 0
    if type(value) is not int or not 0x10000 <= value < 1 << 47 or value & 7:
        raise ValueError('Only an unchanged plain aligned current object reference is supported')
    return value


def _qualified():
    documents = {}
    for relative, digest in PINS.items():
        raw = (ROOT/relative).read_bytes()
        if not 0 < len(raw) <= 512*1024 or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Current-world source seal changed')
        documents[relative] = json.loads(raw)
    for relative in PINS.keys()-{SCHEMA}:
        if documents[relative]['client_sha256'] != SHIPPING_SHA256 or documents[relative]['process_access'] is not False:
            raise ValueError('The current-world sources must remain offline same-build evidence')
    world, = documents[EVIDENCE+'native-world-class-declaration.json']['declarations']
    level, = documents[EVIDENCE+'native-level-class-declaration.json']['declarations']
    streaming, = documents[EVIDENCE+'native-streaming-class-declaration.json']['classes']
    def field(rows, name, offset, gen):
        matches = [row for row in rows if row['name']==name and row.get('native_member_offset')==offset
                   and row['native_gen_flags']==gen]
        if len(matches) != 1:
            raise ValueError('The fixed native class field declaration changed')
    for name, offset, gen in (('Levels','0x158','0x16'),('StreamingLevels','0x90','0x16'),
                              ('PersistentLevel','0xf8','0x23')):
        field(world['selected_fields'], name, offset, gen)
    field(level['selected_fields'],'OwningWorld','0xa8','0x12')
    field(streaming['declared_property_records'],'LoadedLevel','0x128','0x12')
    code = documents[EVIDENCE+'native-level-loaded-visible-getters.json']
    anchors = {(i['rva'],i['mnemonic'],i['operands']) for f in code['functions'] for i in f['instructions']}
    if not {('0x12ab4880','mov','rax, qword ptr [rcx + 0x128]'),
            ('0x12ab488c','test','byte ptr [rax + 0x1e4], 0x20'),
            ('0x1336a8a5','mov','rax, qword ptr [rcx + 0x128]')} <= anchors:
        raise ValueError('The fixed loaded-level and actual-visible consumers changed')
    schema = documents[SCHEMA]
    if schema['client_sha256'] != SHIPPING_SHA256 or len(schema['actors']) != 4:
        raise ValueError('The fixed exact Actor path scope changed')
    return schema


def qualified_actor_paths():
    return tuple(dict(row) for row in _qualified()['actors'])


def source_pins():
    _qualified()
    pins = dict(PINS)
    for relative in ('work/observe_current_world_actor_membership_scope.py',
                     'work/native_replication_metadata_core.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    if pins['work/observe_current_world_actor_membership_scope.py'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('The scoped reader was imported from another checkout')
    return pins


def observe(*, session, pc_address, pawn_address, actor_candidates, object_identity,
            object_path, final_recheck, source_pins):
    """Read actual World membership before any optional Actor position producer.

    The exact fixed World arrays have a 512-element read bound and separate
    1024-slot allocation bound. A larger StreamingLevels array is reported as
    partial and cannot yield a positive loaded-visible member witness. The
    encrypted PersistentLevel field is accepted only in its raw canonical
    pointer subset; no masking or callback decoding is attempted.
    """
    pins = globals()['source_pins']()
    if type(source_pins) is not dict or any(source_pins.get(k)!=v for k,v in pins.items()):
        raise ValueError('The exact current-world reader source seal is required')
    bindings = {row['actor_path']:row for row in qualified_actor_paths()}
    if (not isinstance(session, MetadataSession) or type(actor_candidates) is not tuple or
            len(actor_candidates)>4 or any(type(row) is not ActorCandidate or row.actor_path not in bindings
            for row in actor_candidates) or
            len({row.address for row in actor_candidates})!=len(actor_candidates) or
            len({row.actor_path for row in actor_candidates})!=len(actor_candidates) or
            any(not callable(cb) for cb in (object_identity,object_path,final_recheck))):
        raise ValueError('An exact bounded current typed Actor scope and mandatory rechecks are required')
    read_start,call_start = session.bytes_read,session.calls
    scoped_bytes,scoped_calls = 0,0
    facts,identities,paths = {},{},{}
    report = dict(kind='exact_current_world_actor_membership_observation',status='refused',actors=[],
        source_pins=pins,process_opened_by_this_module=False,process_memory_written=False,
        native_methods_invoked=False,packets_sent=False,coordinates_read=False,
        native_actor_binding_verified=False,interaction_ready_verified=False,
        reported_visibility_or_ack_used_as_scene_proof=False,
        historical_pointers_usable_as_bindings=False)
    def stable(at,size):
        nonlocal scoped_bytes,scoped_calls
        calls=2*((size+8191)//8192)
        if scoped_bytes+size*2>MAX_READ_BYTES or scoped_calls+calls>MAX_READ_CALLS:
            raise ValueError('The exact member read scope exceeds its budget')
        scoped_bytes+=size*2
        scoped_calls+=calls
        return session.stable(at,size)
    def read(at,size):
        raw=stable(at,size)
        if (at,size) in facts and facts[(at,size)]!=raw:
            raise ValueError('Current-world fields changed')
        facts[(at,size)]=raw
        return raw
    def path_of(pointer):
        path=object_path(pointer)
        if type(path) is not str or not path or len(path)>4096:
            raise ValueError('A bounded current typed object path is required')
        if paths.setdefault(pointer,path)!=path:
            raise ValueError('A current typed object path changed')
        return path
    def identify(pointer,base):
        pointer=_pointer(pointer)
        value=object_identity(pointer,base)
        if (type(value) is not dict or base not in value['class_ancestry'] or
                type(value['serial']) is not int or value['serial']<=0 or value['is_cdo'] is not False or
                _pointer(value['address'])!=pointer):
            raise ValueError('An initialized current typed object is required')
        previous=identities.setdefault((pointer,base),value)
        if previous!=value:
            raise ValueError('Current-world object identity changed')
        path_of(pointer)
        return value
    def pointer(at,*,null=False):
        return _pointer(struct.unpack('<Q',read(at,8))[0],null=null)
    def array(owner,offset,base):
        raw=read(owner+offset,16)
        data,count,capacity=struct.unpack('<Qii',raw)
        if not 0<=count<=capacity<=MAX_ARRAY_CAPACITY or count>MAX_ARRAY_COUNT or capacity and not data:
            raise ValueError('The current reference-array count or capacity exceeds the fixed bound')
        _pointer(data,null=True)
        payload=read(data,count*8) if count else b''
        values=tuple(_pointer(v) for (v,) in struct.iter_unpack('<Q',payload) if v)
        if len(values)!=len(set(values)):
            raise ValueError('A current reference array contains duplicate objects')
        for value in values:identify(value,base)
        return values,dict(count=count,capacity=capacity,elements_read=True,field_offset=offset)
    try:
        if (getattr(session,'module_sha256',None)!=SHIPPING_SHA256 or
                getattr(session,'module_size',None)!=IMAGE_SIZE or final_recheck() is not True):
            raise ValueError('The owning process, image or actual PC/Pawn root recheck is unavailable')
        pc,pawn=_pointer(pc_address),_pointer(pawn_address)
        pc_identity,pawn_identity=identify(pc,'PlayerController'),identify(pawn,'Pawn')
        pc_level=_pointer(pc_identity['outer_address'])
        if _pointer(pawn_identity['outer_address'])!=pc_level:
            raise ValueError('The selected current PC and Pawn do not share a qualified Level')
        level_identity=identify(pc_level,'Level')
        world=_pointer(level_identity['outer_address'])
        identify(world,'World')
        persistent=pointer(world+0xf8)
        identify(persistent,'Level')
        if persistent!=pc_level or pointer(persistent+0xa8)!=world:
            raise ValueError('The actual PersistentLevel/PC/Pawn/OwningWorld relationship differs')
        levels,report['world_levels']=array(world,0x158,'Level')
        if persistent not in levels:
            raise ValueError('The actual PersistentLevel is absent from current World.Levels')
        loaded={}
        try:
            streams,report['streaming_levels']=array(world,0x90,'LevelStreaming')
            for stream in streams:
                identity=identify(stream,'LevelStreaming')
                if _pointer(identity['outer_address'])!=world:
                    continue
                level=pointer(stream+0x128,null=True)
                if level:
                    identify(level,'Level')
                    loaded.setdefault(level,[]).append(paths[stream])
        except (ValueError,OSError,KeyError):
            loaded={}
            report['status']='partial'
            report['streaming_levels']=dict(elements_read=False,reason='streaming_scope_refused',maximum_count=MAX_ARRAY_COUNT)
        actors=[]
        for candidate in actor_candidates:
            row=dict(actor_path=candidate.actor_path,level_in_current_world_levels=False,
                level_owning_world_matches_current=False,loaded_by_current_world_streaming=False,
                level_visible_bit=False,current_loaded_visible_level_membership_observed=False)
            try:
                actor=identify(candidate.address,'Actor')
                if paths[candidate.address]!=candidate.actor_path or path_of(_pointer(actor['class_address']))!=bindings[candidate.actor_path]['class_path']:
                    raise ValueError('The actual selected Actor path or class differs')
                level=_pointer(actor['outer_address'])
                identify(level,'Level')
                row.update(level_path=paths[level],level_in_current_world_levels=level in levels)
                if level in levels:
                    row.update(level_owning_world_matches_current=pointer(level+0xa8)==world,
                        loaded_by_current_world_streaming=level in loaded,
                        level_visible_bit=bool(read(level+0x1e4,1)[0]&0x20),
                        matching_streaming_paths=tuple(loaded.get(level,())))
                    row['current_loaded_visible_level_membership_observed']=all(row[key] is True for key in (
                        'level_in_current_world_levels','level_owning_world_matches_current',
                        'loaded_by_current_world_streaming','level_visible_bit'))
            except (ValueError,OSError,KeyError):
                row['reason']='selected_actor_context_refused'
            actors.append(row)
        if final_recheck() is not True:
            raise ValueError('The final process and current-root check refused')
        for (at,size),raw in facts.items():
            if stable(at,size)!=raw:
                raise ValueError('A current-world source field changed before publication')
        for (at,base),value in identities.items():
            if object_identity(at,base)!=value or object_path(at)!=paths[at]:
                raise ValueError('A current-world identity or path changed before publication')
        for at,path in paths.items():
            if object_path(at)!=path:
                raise ValueError('A current-world object or class path changed before publication')
        if globals()['source_pins']()!=pins or getattr(session,'module_sha256',None)!=SHIPPING_SHA256 or getattr(session,'module_size',None)!=IMAGE_SIZE:
            raise ValueError('The image or reader source changed before publication')
        report.update(status='partial' if report['status']=='partial' else 'observed',actors=actors,
            current_world_path=paths[world],actual_persistent_level_path=paths[persistent],
            identity_fields_roots_and_process_rechecked=True,snapshot_is_atomic=False,
            scoped_field_read_bytes=scoped_bytes,scoped_field_read_calls=scoped_calls,
            read_calls=session.calls-call_start,read_bytes=session.bytes_read-read_start)
        return report
    except (ValueError,OSError,KeyError,TypeError):
        return dict(report,status='refused',actors=[],reason='current_world_read_or_final_recheck_refused',
            identity_fields_roots_and_process_rechecked=False,
            scoped_field_read_bytes=scoped_bytes,scoped_field_read_calls=scoped_calls,
            read_calls=session.calls-call_start,read_bytes=session.bytes_read-read_start)
