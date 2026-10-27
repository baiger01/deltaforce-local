"""Bounded authenticated binary-pipe messages for one original reader worker.

The key travels only through the owning Popen stdin pipe. A signed HELLO is
issued after the collector's typed native selector supplies a registered live
context. This module grants no native identity merely from files or a PID.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import queue
import secrets
import struct
import threading
import time

MAX_FRAME=32768
MAX_MESSAGES=128
_CLIENT_ISSUER=object()
_ADMISSION_ISSUER=object()
OWNER_KEYS=frozenset(('join_nonce','owner_digest','complete_namespace_digest','selected_hero_id',
    'pawn_channel','pawn_guid','component_guid','association_reliable_sequence'))

def require(value,reason):
    if not value:raise ValueError(reason)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def sha(value):return hashlib.sha256(value).hexdigest()
def hex64(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)
def uint(value,low,high):return type(value) is int and low<=value<=high
def finite(value):return type(value) in (int,float) and math.isfinite(value) and value>=0

def owner_anchor(value):
    require(type(value) is dict and set(value)==OWNER_KEYS and
        all(hex64(value.get(k)) for k in ('join_nonce','owner_digest','complete_namespace_digest')) and
        uint(value.get('selected_hero_id'),1,(1<<63)-1) and uint(value.get('pawn_channel'),2,65535) and
        uint(value.get('pawn_guid'),2,0xffffffff) and uint(value.get('component_guid'),2,0xffffffff) and
        value['component_guid']!=value['pawn_guid'] and uint(value.get('association_reliable_sequence'),0,1023),
        'fixed_original_join_anchor_required')
    return json.loads(canonical(value))

def read_frame(stream):
    def exact(size):
        parts=[]
        while size:
            raw=stream.read(size)
            require(type(raw) is bytes and 0<len(raw)<=size,'original_duplex_eof_or_partial_frame')
            parts.append(raw);size-=len(raw)
        return b''.join(parts)
    size=struct.unpack('<I',exact(4))[0]
    require(1<=size<=MAX_FRAME,'bounded_original_duplex_frame_required')
    raw=exact(size)
    value=json.loads(raw.decode('ascii'),parse_constant=lambda value:(_ for _ in ()).throw(ValueError('nonfinite_json')))
    require(type(value) is dict and canonical(value)==raw,'canonical_original_duplex_frame_required')
    return value

def write_frame(stream,value):
    raw=canonical(value);require(1<=len(raw)<=MAX_FRAME,'bounded_original_duplex_frame_required')
    frame=struct.pack('<I',len(raw))+raw
    # Buffered stdio normally returns the complete count; partial writes refuse.
    require(stream.write(frame)==len(frame),'original_duplex_partial_write')
    stream.flush()

def signed(message,key):
    require(type(key) is bytes and len(key)==32,'private_duplex_key_required')
    require(type(message) is dict and 'mac' not in message,'unsigned_original_message_required')
    return {**message,'mac':hmac.new(key,canonical(message),hashlib.sha256).hexdigest()}

def authenticated(raw,key):
    require(type(raw) is dict and len(canonical(raw))<=MAX_FRAME,'bounded_authenticated_frame_required')
    message=dict(raw);mac=message.pop('mac',None)
    require(hex64(mac) and hmac.compare_digest(mac,hmac.new(key,canonical(message),hashlib.sha256).hexdigest()),
        'original_duplex_authentication_refused')
    return message

class BinaryInbox:
    """One daemon reader; no native calls and no reset of the caller deadline."""
    def __init__(self,stream):
        self.stream=stream;self.messages=queue.Queue(maxsize=8);self.stopped=False
        self.thread=threading.Thread(target=self._read,daemon=True,name='fashion-original-pipe-inbox')
        self.thread.start()
    def _read(self):
        try:
            for _ in range(MAX_MESSAGES):
                value=read_frame(self.stream)
                require(not self.stopped,'original_inbox_closed')
                self.messages.put_nowait(value)
            raise ValueError('original_pipe_message_budget_exhausted')
        except Exception as error:
            self.stopped=True
            try:self.messages.put_nowait(error)
            except queue.Full:pass
    def receive(self,deadline,*,clock=time.monotonic):
        require(finite(deadline),'unchanged_original_deadline_required')
        remaining=deadline-clock();require(remaining>0,'original_session_deadline_exhausted')
        try:value=self.messages.get(timeout=remaining)
        except queue.Empty:raise ValueError('original_session_deadline_exhausted') from None
        if isinstance(value,Exception):raise value
        return value

@dataclass(frozen=True,eq=False)
class CurrentDeclarationAdmission:
    """Identity only; registry lookup supplies all facts, never its attributes."""
    opaque_token: str=field(repr=False)
    issuer: object=field(repr=False)

class OriginalWorkerAdmissionAuthority:
    def __init__(self,client):
        require(type(client) is RetainedWorkerClient and client._issuer is _CLIENT_ISSUER,
            'owned_original_worker_client_required')
        self.client=client;self._entries={};self._used=set()
        self._export_receipts={}
    def register_previous_own_export_receipt(self,receipt,binding):
        from dfserver.replication.legacy_ds_fashion_owned_phase import OwnExportReceipt
        from dfserver.replication.legacy_ds_fashion_async_bridge import _Binding
        require(type(receipt) is OwnExportReceipt and type(binding) is _Binding and
            binding.channel.client is self.client and binding.validate_export_receipt(receipt),
            'actual_original_phase_export_receipt_required')
        self._export_receipts[id(receipt)]=(receipt,binding,receipt.receipt_digest)
    def verify_previous_own_export_receipt(self,receipt,*,owner_binding,component_guid,expected_fingerprint):
        self.client.assert_live();row=self._export_receipts.get(id(receipt))
        require(row is not None and row[0] is receipt and row[1].validate_export_receipt(receipt) and
            component_guid==receipt.component_guid and expected_fingerprint==row[2]==receipt.receipt_digest and
            owner_binding.get('join_nonce')==receipt.trigger_nonce and
            owner_binding.get('owner_digest')==receipt.owner_digest and
            owner_binding.get('previous_reliable_sequence')==receipt.reliable_sequence and
            owner_binding.get('previous_own_export_receipt_digest')==receipt.receipt_digest,
            'registered_own_export_body_handoff_required')
        return True
    def register_authenticated_declaration(self,response,*,owner_binding):
        self.client.assert_live()
        require(type(response) is dict and response.get('phase')=='body_prepare' and
            response.get('result')=='ready' and hex64(response.get('opaque_token')) and
            hex64(response.get('declaration_fingerprint')) and type(response.get('facts')) is dict and
            response.get('owner_binding')==owner_binding and response['opaque_token'] not in self._used,
            'authenticated_current_declaration_issuance_required')
        # Only the client's authenticated request/reply registry can issue.
        require(self.client._accepted.get(response.get('request_id')) is response,
            'registered_original_duplex_response_required')
        token=CurrentDeclarationAdmission(response['opaque_token'],_ADMISSION_ISSUER)
        self._entries[id(token)]=(token,json.loads(canonical(response)),json.loads(canonical(owner_binding)))
        self._used.add(response['opaque_token']);return token
    def current_declaration_descriptor(self,token):
        self.client.assert_live();row=self._entries.get(id(token))
        require(row is not None and row[0] is token and token.issuer is _ADMISSION_ISSUER,
            'retained_registered_declaration_token_required')
        response=row[1];now=time.monotonic()
        require(response['verified_at']<=now<response['expires_at']<=self.client.deadline and
            now-response['verified_at']<=.1,'fresh_original_declaration_admission_required')
        return {'declaration_fingerprint':response['declaration_fingerprint'],
            'owner_binding':json.loads(canonical(row[2])),'facts':json.loads(canonical(response['facts']))}
    def consume_current_declaration_admission(self,token,*,expected_fingerprint,owner_binding,phase='body_prepare'):
        descriptor=self.current_declaration_descriptor(token)
        require(phase=='body_prepare' and expected_fingerprint==descriptor['declaration_fingerprint'] and
            owner_binding==descriptor['owner_binding'],'current_phase_declaration_binding_required')
        del self._entries[id(token)]
        return {'fingerprint':descriptor['declaration_fingerprint'],'facts':descriptor['facts']}
    def describe_current_declaration_admission(self,token,*,owner_binding,phase='body_prepare'):
        descriptor=self.current_declaration_descriptor(token)
        require(phase=='body_prepare' and owner_binding==descriptor['owner_binding'],
            'current_phase_declaration_binding_required')
        return {'fingerprint':descriptor['declaration_fingerprint'],'facts':descriptor['facts']}

class RetainedWorkerClient:
    """Only policy's actual Popen handle and authenticated typed HELLO bind it."""
    def __init__(self,*args,**kwargs):raise ValueError('owned_popen_original_worker_binder_required')
    @classmethod
    def start_owned_popen(cls,process,*,key,anchor,source_digest,expected_game_identity,source_check,launch_policy):
        # Called by the sealed policy immediately after its own Popen, never by
        # a saved tuple reader. HELLO must attest the actual child PID/birth.
        import subprocess
        import native_local_trial_appearance_observer as policy
        require(type(process) is subprocess.Popen and type(launch_policy) is policy.AutomaticAppearanceObserver and
            launch_policy.process is process and launch_policy.config.get('retain_original_fashion_worker') is True and
            process.args==launch_policy._retained_command and process.args[2]==launch_policy.config['bridge_path'] and
            process.args[-1]=='--retained-fashion-pipe','sealed_policy_own_actual_Popen_required')
        require(type(key) is bytes and len(key)==32 and callable(source_check) and hex64(source_digest) and
            hasattr(process,'stdin') and hasattr(process,'stdout') and uint(process.pid,1,0xffffffff),
            'owned_binary_popen_required')
        self=object.__new__(cls);self._issuer=_CLIENT_ISSUER;self.process=process
        self.key=key;self.anchor=owner_anchor(anchor);self.source_digest=source_digest
        self.game_identity=expected_game_identity;self.source_check=source_check
        self._accepted={};self._serial=0;self._io_lock=threading.Lock();self.state='awaiting_typed_original_context'
        self._birth=None;self.deadline=None;self.session_id=None;self.capture_digest=None
        self.inbox=BinaryInbox(process.stdout)
        write_frame(process.stdin,{'kind':'retained_fashion_original_init_v1','key':key.hex(),
            'anchor':self.anchor,'source_digest':source_digest})
        return self
    def bind_authenticated_hello_outside_lock(self,*,maximum_wait_deadline):
        require(self.state=='awaiting_typed_original_context','one_original_context_binding_required')
        raw=self.inbox.receive(maximum_wait_deadline)
        message=authenticated(raw,self.key)
        expected={'kind','session_id','worker_pid','worker_created_at','game_pid','game_created_at',
            'original_deadline','original_started_at','original_duration','source_digest','capture_digest',
            'anchor_digest','calls','bytes','max_calls','max_bytes'}
        require(set(message)==expected and message['kind']=='retained_fashion_original_live_hello_v1' and
            message['worker_pid']==self.process.pid and type(message['worker_pid']) is int and
            finite(message['worker_created_at']) and hex64(message['session_id']) and hex64(message['capture_digest']) and
            message['source_digest']==self.source_digest and message['anchor_digest']==sha(canonical(self.anchor)) and
            (message['game_pid'],message['game_created_at'])==self.game_identity and
            finite(message['original_deadline']) and finite(message['original_started_at']) and
            uint(message['original_duration'],1,180) and
            message['original_deadline']==message['original_started_at']+message['original_duration'] and
            time.monotonic()<message['original_deadline'] and
            uint(message['calls'],0,message['max_calls']) and uint(message['bytes'],0,message['max_bytes']),
            'actual_live_original_session_hello_required')
        # PID creation time comes from the owning handle's actual process.
        import psutil
        require(psutil.Process(self.process.pid).create_time()==message['worker_created_at'],
            'own_popen_birth_changed')
        self.source_check();self._birth=message['worker_created_at']
        self.deadline=message['original_deadline'];self.session_id=message['session_id']
        self.capture_digest=message['capture_digest'];self._initial=message
        self.state='original_live_retained';self.authority=OriginalWorkerAdmissionAuthority(self)
        return self
    def assert_live(self):
        require(self._issuer is _CLIENT_ISSUER and self.state=='original_live_retained' and
            not self.inbox.stopped and finite(self.deadline) and time.monotonic()<self.deadline,
            'live_original_session_required')
    def exchange_outside_lock(self,message):
        self.assert_live();self.source_check()
        with self._io_lock:
            self.assert_live()
            envelope={'kind':'retained_fashion_original_request_envelope_v1','session_id':self.session_id,
                'message':message}
            write_frame(self.process.stdin,signed(envelope,self.key))
            response=authenticated(self.inbox.receive(self.deadline),self.key)
            require(response.get('session_id',self.session_id)==self.session_id and
                response.get('worker_pid')==self.process.pid and response.get('worker_created_at')==self._birth,
                'original_worker_response_identity_changed')
            # Source checks finish before IPC/native verification starts. The
            # worker verifies its original closure before stamping freshness;
            # filesystem work after the response would spend the 100ms permit.
            self.assert_live()
            return response
    def declaration_outside_lock(self,*,owner_binding,previous_own_receipt=None,connection_driven_transport=False):
        require(type(connection_driven_transport) is bool,'explicit_connection_transport_policy_required')
        self.assert_live();self._serial+=1
        require(self._serial<=64,'original_declaration_request_budget_exhausted')
        previous=None
        if previous_own_receipt is not None:
            require(self.authority.verify_previous_own_export_receipt(previous_own_receipt,
                owner_binding=owner_binding,component_guid=self.anchor['component_guid'],
                expected_fingerprint=owner_binding['previous_own_export_receipt_digest']),
                'exact_registered_own_export_receipt_before_BODY_request_required')
            previous=previous_own_receipt.wire_receipt()
        message={'kind':'retained_fashion_declaration_request_v1','phase':'body_prepare','request_id':self._serial,
            'challenge':secrets.token_hex(32),'owner_binding':owner_binding,'previous_own_export_receipt':previous,
            'requested_at':time.monotonic()}
        if connection_driven_transport:
            require(previous is not None,'connection_transport_requires_registered_export_receipt')
            message['connection_driven_transport']=True
        response=self.exchange_outside_lock(message)
        require(response.get('request_id')==message['request_id'] and response.get('challenge')==message['challenge'] and
            response.get('phase')=='body_prepare' and response.get('owner_binding')==owner_binding and
            response.get('result')=='ready' and finite(response.get('verified_at')) and finite(response.get('expires_at')) and
            message['requested_at']<response['verified_at']<=time.monotonic()<response['expires_at']<=
                min(self.deadline,response['verified_at']+.1),'fresh_bound_original_declaration_response_required')
        self._accepted[message['request_id']]=response
        return self.authority.register_authenticated_declaration(response,owner_binding=owner_binding)
    def export_preparation_outside_lock(self,*,owner_binding):
        self.assert_live();self._serial+=1
        require(self._serial<=64,'original_export_request_budget_exhausted')
        message={'kind':'retained_fashion_export_preparation_v1','phase':'export_prepare','request_id':self._serial,
            'challenge':secrets.token_hex(32),'owner_binding':owner_binding,'requested_at':time.monotonic()}
        response=self.exchange_outside_lock(message)
        require(response.get('request_id')==message['request_id'] and response.get('challenge')==message['challenge'] and
            response.get('phase')=='export_prepare' and response.get('owner_binding')==owner_binding and
            response.get('result')=='ready' and finite(response.get('verified_at')) and finite(response.get('expires_at')) and
            message['requested_at']<response['verified_at']<=time.monotonic()<response['expires_at']<=
                min(self.deadline,response['verified_at']+.1),'fresh_bound_original_export_preparation_required')
        require(type(response.get('facts')) is dict and type(response['facts'].get('component_name')) is str and
            1<=len(response['facts']['component_name'])<=256,'current_private_component_Name_required')
        self._accepted[message['request_id']]=response
        return response
    def close_outside_lock(self):
        self.state='refused'
        # Only the owning pipe is closed; never terminate another process.
        try:self.process.stdin.close()
        except OSError:pass
