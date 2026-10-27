"""Pure default-off asynchronous Fashion permit FSM; no I/O/native reads.

Slow IPC/native/source verification is performed by the original retained
worker outside GameServerProbe._lock. Locked methods only inspect small frozen
records. Pending worker work never reserves a cursor, increments a retry, or
clears the queued outbox. SEND and ACK are separate one-use authorities.
"""
from dataclasses import dataclass, field, replace
from copy import copy
import hashlib
import hmac
import json
import math
import secrets
import threading
from functools import wraps

from dfserver.legacy_ds_wire_codec import WireBunch, WirePacket, decode_observed_application
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_even_component_guid_exports import (EvenComponentBinding,EvenComponentExportProfile,
    read_even_component_guid_exports)

MASK, HALF = 0x3fff, 0x2000
CORE_FREEZE_SHA = 'f694a8fc70d91e555531655b7201438c8b66c24440de84e7881d16d22a46d895'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def uint(value, low, high):return type(value) is int and low <= value <= high
def sha(raw):return hashlib.sha256(raw).hexdigest()
def hex64(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)
def clock(value):return type(value) in (int,float) and math.isfinite(value) and value>=0
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def authority_locked(method):
    """Bounded pure inbox lock; never wraps native work or IPC transport."""
    @wraps(method)
    def call(self,*args,**kwargs):
        with self._lock:
            return method(self,*args,**kwargs)
    return call


@dataclass(frozen=True, eq=False)
class OwnerView:
    """Short caller snapshot under the existing lock; no native pointers."""
    coordinator: object = field(repr=False)
    ticket: object = field(repr=False)
    transport: object = field(repr=False)
    generation: object = field(repr=False)
    source_revision: object = field(repr=False)
    original_worker: object = field(repr=False)
    join_nonce: str = field(repr=False)
    owner_digest: str = field(repr=False)
    complete_namespace_digest: str
    source_seal_digest: str
    capture_digest: str
    worker_session_id: str = field(repr=False)
    worker_pid: int
    worker_created_at: float
    worker_deadline: float
    selected_hero_id: int
    pawn_channel: int
    pawn_guid: int
    component_guid: int
    association_reliable_sequence: int
    admission_state: str
    worker_state: str
    out_sequence: int
    in_sequence: int
    acknowledged_out_sequence: int
    history: int
    reply_count: int
    current_outbox: object = field(default=None, repr=False)
    previous_own_reliable_sequence: int | None = None
    own_export_receipt_digest: str | None = None

    def owner_key(self):
        return (id(self.coordinator),id(self.ticket),id(self.transport),id(self.generation),
            id(self.source_revision),id(self.original_worker),self.join_nonce,self.owner_digest,
            self.complete_namespace_digest,self.source_seal_digest,self.capture_digest,self.worker_session_id,
            self.worker_pid,self.worker_created_at,self.worker_deadline,self.selected_hero_id,
            self.pawn_channel,self.pawn_guid,self.component_guid,self.association_reliable_sequence,
            self.admission_state,self.worker_state,self.previous_own_reliable_sequence,self.own_export_receipt_digest)

    def wire_owner(self):
        # No addresses, weak keys, names or new native selectors cross IPC.
        result={key:getattr(self,key) for key in ('join_nonce','owner_digest','complete_namespace_digest',
            'source_seal_digest','capture_digest','worker_session_id','worker_pid','worker_created_at',
            'worker_deadline','selected_hero_id','pawn_channel','pawn_guid','component_guid','association_reliable_sequence')}
        if self.previous_own_reliable_sequence is not None:
            result.update(previous_own_reliable_sequence=self.previous_own_reliable_sequence,
                own_export_receipt_digest=self.own_export_receipt_digest)
        return result


@dataclass(frozen=True)
class FrozenRecipe:
    """Preflighted body/bunch from the frozen pure factory, prepared outside lock."""
    bunch: WireBunch = field(repr=False)
    body_sha256: str
    bunch_sha256: str
    selected_hero_id: int
    source_seal_digest: str
    reviewed_core_freeze_sha256: str
    phase_kind: str = 'LEGACY_BODY'
    declaration_fingerprint: str | None = None
    export_name: str | None = None


@dataclass(frozen=True, eq=False)
class SendProposal:
    application_payload: bytes = field(repr=False)
    packet_sequence: int
    source_header: tuple
    application_sha256: str


@dataclass(frozen=True, eq=False)
class PendingRequest:
    request_id: int
    challenge: str = field(repr=False)
    phase: str
    binding: dict = field(repr=False)
    binding_digest: str
    requested_at: float
    deadline: float

    def wire_request(self):
        return {'kind':'retained_fashion_permit_request_v1','request_id':self.request_id,
            'challenge':self.challenge,'phase':self.phase,'binding':dict(self.binding),
            'binding_digest':self.binding_digest,'requested_at':self.requested_at,'deadline':self.deadline}


@dataclass(frozen=True, eq=False)
class _Permit:
    request: PendingRequest = field(repr=False)
    opaque_worker_token: str = field(repr=False)
    verified_at: float
    expires_at: float
    fingerprint: tuple


class RetainedWorkerAuthority:
    """Pure authenticated inbox/opaque token authority; transport is absent.

    The duplex private key is established with the original live worker by the
    separate IPC adapter. Tests use a Fake key. Accepting an HMAC proves only
    mailbox origin: reviewed worker code must produce READY only after fresh
    retained identity/source checks within the unchanged original budget.
    """
    def __init__(self, *, original_owner, duplex_key, freshness_seconds=0.1, maximum_requests=64):
        require(type(original_owner) is OwnerView and type(duplex_key) is bytes and len(duplex_key)==32 and
            type(freshness_seconds) in (int,float) and math.isfinite(freshness_seconds) and
            0 < freshness_seconds <= 0.25 and uint(maximum_requests,1,128), 'sealed_authority_policy_required')
        self.owner=original_owner
        self._owner_key=original_owner.owner_key()
        self._key=duplex_key
        self.freshness=freshness_seconds
        self.maximum=maximum_requests
        self._lock=threading.RLock()
        self._serial=0;self._entries={};self._work=[];self._used_worker_tokens=set()

    @authority_locked
    def request(self, phase, binding, *, now):
        require(phase in ('SEND','ACK','BODY_SEND','BODY_ACK','EXPORT_SEND','EXPORT_ACK') and type(binding) is dict and clock(now) and
            now < self.owner.worker_deadline and self._serial < self.maximum,
            'original_worker_request_deadline_or_budget_refused')
        owner_fields=self.owner.wire_owner()
        logical=binding.get('logical_native_authorization') is True
        extra={'logical_native_authorization','declaration_fingerprint'} if logical else set()
        require(self.owner.owner_key()==self._owner_key and set(binding)==set(owner_fields)|extra|{
            'phase','body_sha256','bunch_sha256','reliable_sequence','proposed_packet_sequence',
            'application_sha256','receipt_candidate_sha256'} and
            all(type(binding.get(key)) is type(value) and binding[key]==value for key,value in owner_fields.items()) and
            binding.get('phase')==phase and all(hex64(binding.get(key)) for key in ('body_sha256','bunch_sha256')) and
            (binding.get('application_sha256') is None and binding.get('proposed_packet_sequence') is None
                if logical and phase.endswith('SEND') else hex64(binding.get('application_sha256')) and
                uint(binding.get('proposed_packet_sequence'),0,MASK)) and
            (not logical or binding.get('declaration_fingerprint') is None or hex64(binding.get('declaration_fingerprint'))) and
            uint(binding.get('reliable_sequence'),0,1023) and
            (binding.get('receipt_candidate_sha256') is None if phase.endswith('SEND') else
                hex64(binding.get('receipt_candidate_sha256'))), 'fixed_retained_lease_request_no_native_selectors_required')
        self._serial+=1
        frozen=json.loads(canonical(binding))
        request=PendingRequest(self._serial,secrets.token_hex(32),phase,frozen,sha(canonical(frozen)),
            now,self.owner.worker_deadline)
        self._entries[request.request_id]={'request':request,'frozen':canonical(request.wire_request()),
            'status':'pending','permit':None}
        self._work.append(request)
        return request

    @authority_locked
    def drain_work_outside_lock(self):
        """Caller sends these messages outside the backend lock; no I/O here."""
        work=tuple(request for request in self._work if self._entry(request)['status']=='pending')
        self._work=[]
        return work

    def _entry(self, request):
        row=self._entries.get(getattr(request,'request_id',None))
        require(row is not None and row['request'] is request and
            canonical(request.wire_request())==row['frozen'], 'original_request_identity_required')
        return row

    @authority_locked
    def accept_authenticated_response_outside_lock(self, request, raw_response, *, now):
        row=self._entry(request)
        if row['status']!='pending':return False
        require(type(raw_response) is dict and clock(now), 'authenticated_response_shape_required')
        allowed={'kind','request_id','challenge','phase','binding_digest','worker_session_id','worker_pid',
            'worker_created_at','result','opaque_token','verified_at','expires_at','mac','refusal_reason'}
        if not set(raw_response)<=allowed or len(canonical(raw_response))>8192:
            row['diagnostic']='response_shape_refused';row['status']='refused';return False
        message=dict(raw_response);mac=message.pop('mac',None)
        expected=hmac.new(self._key,canonical(message),hashlib.sha256).hexdigest()
        if not hex64(mac) or not hmac.compare_digest(mac,expected):
            row['diagnostic']='response_mac_refused';row['status']='refused';return False
        verified,expiry=message.get('verified_at'),message.get('expires_at')
        if (message.get('kind')!='retained_fashion_permit_response_v1' or
                message.get('request_id')!=request.request_id or type(message.get('request_id')) is not int or
                message.get('challenge')!=request.challenge or message.get('phase')!=request.phase or
                message.get('binding_digest')!=request.binding_digest or
                message.get('worker_session_id')!=self.owner.worker_session_id or
                message.get('worker_pid')!=self.owner.worker_pid or type(message.get('worker_pid')) is not int or
                message.get('worker_created_at')!=self.owner.worker_created_at or
                type(message.get('worker_created_at')) not in (int,float) or
                message.get('result') not in ('ready','refused')):
            row['diagnostic']='response_binding_refused';row['status']='refused';return False
        if message['result']=='refused':
            row['diagnostic']='native_phase_refused';row['status']='refused';return True
        token=message.get('opaque_token')
        if (not hex64(token) or token in self._used_worker_tokens or not clock(verified) or not clock(expiry) or
                not request.requested_at<verified<=now<expiry<=min(self.owner.worker_deadline,verified+self.freshness) or
                now-verified>self.freshness):
            row['diagnostic']='response_freshness_or_token_refused'
            row['response_age_ms']=(int((now-verified)*1000) if clock(verified) else None)
            row['status']='refused';return False
        self._used_worker_tokens.add(token)
        fingerprint=(request.request_id,request.challenge,request.phase,request.binding_digest,verified,expiry,token)
        row['permit']=_Permit(request,token,verified,expiry,fingerprint)
        row['status']='ready'
        return True

    @authority_locked
    def state(self, request, *, now):
        row=self._entry(request)
        if now>=request.deadline or (row['permit'] is not None and now>=row['permit'].expires_at):
            row['diagnostic']='permit_or_worker_deadline_expired';row['status']='refused'
        return row['status']

    @authority_locked
    def diagnostic(self, request):
        row=self._entry(request)
        return {key:row.get(key) for key in ('diagnostic','response_age_ms')}

    @authority_locked
    def revoke(self, request):
        self._entry(request)['status']='refused'

    @authority_locked
    def consume_locked(self, request, *, phase, binding_digest, now):
        """Only compares frozen records; consumes BEFORE socket/ACK commit."""
        row=self._entry(request)
        if self.state(request,now=now)!='ready':return None
        permit=row['permit']
        expected=(request.request_id,request.challenge,request.phase,request.binding_digest,
            permit.verified_at,permit.expires_at,permit.opaque_worker_token)
        if phase!=request.phase or binding_digest!=request.binding_digest or expected!=permit.fingerprint:
            row['status']='refused';return None
        row['status']='consumed'
        return permit


@dataclass(frozen=True, eq=False)
class _ConnectionRequest:
    request_id: int
    challenge: str = field(repr=False)
    phase: str
    binding: dict = field(repr=False)
    binding_digest: str
    requested_at: float

    def wire_request(self):
        # Internal correlation only; never sent to the native reader.
        return {'kind':'connection_fashion_operation_v1','request_id':self.request_id,
            'challenge':self.challenge,'phase':self.phase,'binding':dict(self.binding),
            'binding_digest':self.binding_digest,'requested_at':self.requested_at}


@dataclass(frozen=True, eq=False)
class _ConnectionPermit:
    request: _ConnectionRequest = field(repr=False)


class ConnectionRecipeAuthority:
    """Connection-owned operations for an already source-qualified recipe.

    Source/schema and stable-object preparation still happen before publication.
    Once published, actual send journaling and positive receipts drive progress;
    no per-packet native observation, IPC response or reader lifetime is needed.
    The outbox and bridge independently recheck the live connection owner before
    every send/ACK commit. This object alone never marks a recipe delivered.
    """
    def __init__(self, *, original_owner, maximum_requests=128):
        require(type(original_owner) is OwnerView and
            original_owner.worker_state=='connection_recipe' and uint(maximum_requests,1,128),
            'prepared_connection_recipe_owner_required')
        self.owner=original_owner;self._owner_key=original_owner.owner_key()
        self.maximum=maximum_requests;self._serial=0;self._entries={}
        self._lock=threading.RLock()

    @authority_locked
    def request(self, phase, binding, *, now):
        require(phase in ('SEND','ACK','BODY_SEND','BODY_ACK','EXPORT_SEND','EXPORT_ACK') and
            type(binding) is dict and clock(now) and self._serial<self.maximum,
            'connection_operation_shape_or_budget_refused')
        owner_fields=self.owner.wire_owner()
        logical=binding.get('logical_native_authorization') is True
        extra={'logical_native_authorization','declaration_fingerprint'} if logical else set()
        require(self.owner.owner_key()==self._owner_key and set(binding)==set(owner_fields)|extra|{
            'phase','body_sha256','bunch_sha256','reliable_sequence','proposed_packet_sequence',
            'application_sha256','receipt_candidate_sha256'} and
            all(type(binding.get(key)) is type(value) and binding[key]==value for key,value in owner_fields.items()) and
            binding.get('phase')==phase and all(hex64(binding.get(key)) for key in ('body_sha256','bunch_sha256')) and
            (binding.get('application_sha256') is None and binding.get('proposed_packet_sequence') is None
                if logical and phase.endswith('SEND') else hex64(binding.get('application_sha256')) and
                uint(binding.get('proposed_packet_sequence'),0,MASK)) and
            (not logical or binding.get('declaration_fingerprint') is None or hex64(binding.get('declaration_fingerprint'))) and
            uint(binding.get('reliable_sequence'),0,1023) and
            (binding.get('receipt_candidate_sha256') is None if phase.endswith('SEND') else
                hex64(binding.get('receipt_candidate_sha256'))),
            'exact_prepared_connection_operation_required')
        self._serial+=1
        frozen=json.loads(canonical(binding))
        request=_ConnectionRequest(self._serial,secrets.token_hex(32),phase,frozen,sha(canonical(frozen)),now)
        self._entries[request.request_id]={'request':request,'frozen':canonical(request.wire_request()),
            'status':'ready','permit':_ConnectionPermit(request)}
        return request

    def _entry(self, request):
        row=self._entries.get(getattr(request,'request_id',None))
        require(type(request) is _ConnectionRequest and row is not None and row['request'] is request and
            canonical(request.wire_request())==row['frozen'], 'original_connection_operation_required')
        return row

    def drain_work_outside_lock(self):
        return ()

    @authority_locked
    def state(self, request, *, now):
        require(clock(now) and now>=request.requested_at,'monotonic_connection_operation_required')
        return self._entry(request)['status']

    @authority_locked
    def diagnostic(self, request):
        return {'authority':'prepared_connection_recipe','status':self._entry(request)['status']}

    @authority_locked
    def revoke(self, request):
        self._entry(request)['status']='refused'

    @authority_locked
    def consume_locked(self, request, *, phase, binding_digest, now):
        row=self._entry(request)
        if self.state(request,now=now)!='ready':return None
        if phase!=request.phase or binding_digest!=request.binding_digest:
            row['status']='refused';return None
        row['status']='consumed'
        return row['permit']


@dataclass(frozen=True, eq=False)
class SendAttempt:
    proposal: SendProposal = field(repr=False)
    permit: _Permit | _ConnectionPermit = field(repr=False)
    owner_key: tuple = field(repr=False)
    attempted_at: float
    proposal_fingerprint: tuple = field(repr=False)


@dataclass(frozen=True, eq=False)
class _FullSend:
    attempt: SendAttempt = field(repr=False)
    sequence: int
    sent_at: float


@dataclass(frozen=True, eq=False)
class _ReceiptCandidate:
    packet: WirePacket = field(repr=False)
    pre_cursor: tuple
    full_send: _FullSend = field(repr=False)
    packet_digest: str
    candidate_digest: str
    observed_at: float


class AsyncFashionPermitOutbox:
    def __init__(self, *, enabled=False, owner=None, recipe=None, authority=None,
            max_attempts=16, max_replies=128, allow_forward_gap=False, max_packet_bytes=1492, logical_authorization=False):
        require(type(enabled) is bool and type(allow_forward_gap) is bool, 'explicit_boolean_required')
        require(type(logical_authorization) is bool,'explicit_logical_authorization_policy_required')
        self.logical_authorization=logical_authorization
        self.enabled=enabled;self.cancelled=False;self.delivered=False
        self.last_refusal=None
        self._pending_send=None;self._pending_ack=None
        self._attempts=[];self._finished=[];self._successful=[];self._receipt_digests=set()
        self._last_committed_candidate=None;self._last_ack_permit=None
        if not enabled:return
        require(type(owner) is OwnerView and type(recipe) is FrozenRecipe and
            type(authority) in (RetainedWorkerAuthority,ConnectionRecipeAuthority) and authority.owner is owner and
            uint(max_attempts,1,64) and uint(max_replies,1,128) and uint(max_packet_bytes,1,1492),
            'typed_frozen_owner_recipe_authority_required')
        b=recipe.bunch
        require(recipe.phase_kind in ('LEGACY_BODY','BODY','EXPORT'),'reviewed_phase_recipe_kind_required')
        export=recipe.phase_kind=='EXPORT'
        previous=owner.association_reliable_sequence if owner.previous_own_reliable_sequence is None else owner.previous_own_reliable_sequence
        require(uint(previous,0,1023) and (owner.previous_own_reliable_sequence is None or
            hex64(owner.own_export_receipt_digest)),'own_previous_phase_receipt_required')
        require(type(b) is WireBunch and b.reliable is True and b.channel_index==owner.pawn_channel and
            uint(owner.association_reliable_sequence,0,1023) and
            b.channel_sequence==((previous+1)&1023) and b.package_exports is export and all(getattr(b,key) is False for key in
                ('open','close','partial','must_be_mapped')) and
            type(b.payload) is bytes and uint(b.payload_bits,1,8192 if export else 512) and len(b.payload)==(b.payload_bits+7)//8 and
            recipe.bunch_sha256==sha(repr(b).encode('utf-8')) and
            hex64(recipe.body_sha256) and recipe.selected_hero_id==owner.selected_hero_id and
            recipe.source_seal_digest==owner.source_seal_digest and recipe.reviewed_core_freeze_sha256==CORE_FREEZE_SHA,
            'frozen_pawn_recipe_required')
        # Small immutable wire grammar only. Source-qualified metadata/body
        # preparation remains outside the lock and outside this FSM.
        if export:
            # Actual consumer-compatible Name/Outer export recipe was prepared
            # outside lock. Exact immutable bunch/body hash remains the authority.
            require(owner.component_guid%2==0 and recipe.body_sha256==sha(b.payload) and
                type(recipe.export_name) is str and 1<=len(recipe.export_name)<=256,
                'owned_even_export_recipe_required')
            profile=EvenComponentExportProfile(owner.pawn_guid,(EvenComponentBinding(owner.component_guid,
                recipe.export_name,owner.pawn_guid),),True,True,True,True,True,True,True,
                lambda:authority.owner is owner and authority.owner.owner_key()==owner.owner_key())
            export_reader=BitReader(b.payload,bit_count=b.payload_bits)
            nodes=read_even_component_guid_exports(export_reader,enabled=True,profile=profile)
            require(len(nodes)==1 and nodes[0].guid==owner.component_guid and export_reader.remaining==0,
                'exact_single_owned_even_Name_Outer_export_required')
        else:
            reader=BitReader(b.payload,bit_count=b.payload_bits)
            require(reader.read_bool() is True and reader.read_bool() is False and
                reader.read_packed_int()==owner.component_guid and reader.read_bool() is True and
                reader.read_packed_int()==81,'resolved_stable_fashion_envelope_required')
            body_payload=reader.read_payload(81)
            require(reader.remaining==0 and sha(body_payload)==recipe.body_sha256,'exact_frozen_body_hash_required')
            body_reader=BitReader(body_payload,bit_count=81)
            require(body_reader.read_bool() is False and body_reader.read_packed_int()==4 and
                int.from_bytes(body_reader.read_payload(64),'little')==owner.selected_hero_id and
                body_reader.read_packed_int()==0 and body_reader.remaining==0,'current_ticket_hero_body_required')
        require(all(ref is not None for ref in (owner.coordinator,owner.ticket,owner.transport,owner.generation,
            owner.source_revision,owner.original_worker)) and all(hex64(value) for value in (
                owner.join_nonce,owner.owner_digest,owner.complete_namespace_digest,owner.source_seal_digest,
                owner.capture_digest,owner.worker_session_id)) and
            uint(owner.worker_pid,1,0xffffffff) and clock(owner.worker_created_at) and clock(owner.worker_deadline) and
            uint(owner.selected_hero_id,1,(1<<63)-1) and uint(owner.pawn_channel,2,65535) and
            uint(owner.pawn_guid,2,0xffffffff) and uint(owner.component_guid,2,0xffffffff) and
            owner.pawn_guid!=owner.component_guid,'exact_owned_retained_worker_lease_required')
        self.owner=owner;self.recipe=recipe;self.authority=authority
        self._owner_key=owner.owner_key();self._recipe_key=(sha(repr(b).encode('utf-8')),recipe.body_sha256,recipe.bunch_sha256,
            recipe.selected_hero_id,recipe.source_seal_digest,recipe.reviewed_core_freeze_sha256,recipe.phase_kind,
            recipe.declaration_fingerprint,recipe.export_name)
        self._limit=max_attempts;self._reply_limit=max_replies;self._gap=allow_forward_gap
        self._packet_maximum=max_packet_bytes

    def _current(self, view, now):
        require(clock(now),'finite_monotonic_time_required')
        valid=(self.enabled and not self.cancelled and type(view) is OwnerView and
            view.current_outbox is self and
            self._recipe_key==(sha(repr(self.recipe.bunch).encode('utf-8')),self.recipe.body_sha256,
                self.recipe.bunch_sha256,self.recipe.selected_hero_id,self.recipe.source_seal_digest,
                self.recipe.reviewed_core_freeze_sha256,self.recipe.phase_kind,self.recipe.declaration_fingerprint,
                self.recipe.export_name) and
            view.owner_key()==self._owner_key and view.admission_state=='joined_active' and
            (view.worker_state=='connection_recipe' if type(self.authority) is ConnectionRecipeAuthority else
                view.worker_state=='original_live_retained' and now<view.worker_deadline) and
            type(getattr(view.ticket,'selected_hero_id',None)) is int and
            view.ticket.selected_hero_id==view.selected_hero_id and
            all(uint(getattr(view,key),0,MASK) for key in ('out_sequence','in_sequence','acknowledged_out_sequence')) and
            uint(view.history,0,0xffffffff) and
            uint(view.reply_count,0,self._reply_limit))
        if not valid:
            if self.last_refusal is None:
                self.last_refusal={'stage':'owner_snapshot','reason':'current_owner_snapshot_refused'}
                if type(view) is OwnerView:
                    self.last_refusal.update(reply_count=view.reply_count,reply_limit=self._reply_limit,
                        worker_deadline_expired=now>=view.worker_deadline,
                        same_owner_key=view.owner_key()==self._owner_key,
                        same_current_outbox=view.current_outbox is self)
            self.cancelled=True
        return valid

    def _phase(self, action):
        return action if self.recipe.phase_kind=='LEGACY_BODY' else self.recipe.phase_kind+'_'+action

    def _binding(self, phase, packet_sequence, payload_digest, receipt_digest=None):
        result={**self.owner.wire_owner(),'phase':phase,'body_sha256':self.recipe.body_sha256,
            'bunch_sha256':self.recipe.bunch_sha256,'reliable_sequence':self.recipe.bunch.channel_sequence,
            'proposed_packet_sequence':packet_sequence,'application_sha256':payload_digest,
            'receipt_candidate_sha256':receipt_digest}
        if self.logical_authorization:
            result.update(logical_native_authorization=True,declaration_fingerprint=self.recipe.declaration_fingerprint)
            if phase.endswith('SEND'):
                result.update(proposed_packet_sequence=None,application_sha256=None)
        return result

    @staticmethod
    def _proposal_key(proposal):
        return (proposal.packet_sequence,proposal.source_header,proposal.application_sha256,
            sha(proposal.application_payload))

    def begin_send_locked(self, proposal, view, *, now):
        if not self.enabled:return 'disabled'
        if not self._current(view,now):return 'refused'
        if self.delivered:return 'delivered'
        require(type(proposal) is SendProposal and type(proposal.application_payload) is bytes and
            1<=len(proposal.application_payload)<=self._packet_maximum and proposal.application_sha256==sha(proposal.application_payload) and
            proposal.packet_sequence==view.out_sequence and proposal.source_header==(
                view.out_sequence,view.in_sequence,view.acknowledged_out_sequence,view.reply_count,view.history),
            'exact_current_unreserved_packet_proposal_required')
        packet=decode_observed_application(proposal.application_payload,max_packet_bytes=self._packet_maximum,received_by_server=False)
        require(packet.sequence==view.out_sequence and packet.acknowledged_sequence==view.in_sequence and
            packet.history==(view.history,) and len(packet.bunches)==1 and
            replace(packet.bunches[0],header_start_bit=None,payload_start_bit=None)==self.recipe.bunch,
            'exact_frozen_bunch_application_required')
        if self._pending_send is not None:
            if self.logical_authorization:
                # Only the proposed packet/header changes. The frozen native
                # body/owner request and challenge stay exact and single-use.
                self._pending_send=(proposal,self._pending_send[1],self._proposal_key(proposal))
            return 'pending'
        if len(self._attempts)>=self._limit or view.reply_count>=self._reply_limit:return 'exhausted'
        phase=self._phase('SEND')
        binding=self._binding(phase,proposal.packet_sequence,proposal.application_sha256)
        request=self.authority.request(phase,binding,now=now)
        self._pending_send=(proposal,request,self._proposal_key(proposal))
        return 'pending'

    def consume_send_permit_locked(self, view, *, now):
        if not self.enabled:return 'disabled',None
        if not self._current(view,now):return 'refused',None
        if self._pending_send is None:return 'unqueued',None
        proposal,request,fingerprint=self._pending_send
        if self._proposal_key(proposal)!=fingerprint:
            self.authority.revoke(request);self._pending_send=None
            return 'refused',None
        if proposal.source_header!=(view.out_sequence,view.in_sequence,view.acknowledged_out_sequence,view.reply_count,view.history):
            self.authority.revoke(request);self._pending_send=None
            return 'pending_reissue_current_packet',None
        status=self.authority.state(request,now=now)
        if status=='pending':return 'pending',None
        if status!='ready':
            self.last_refusal={'stage':'send_permit','reason':'send_permit_refused',
                **self.authority.diagnostic(request)}
            self._pending_send=None;return 'refused',None
        permit=self.authority.consume_locked(request,phase=self._phase('SEND'),binding_digest=request.binding_digest,now=now)
        if permit is None:return 'refused',None
        attempt=SendAttempt(proposal,permit,self._owner_key,now,fingerprint)
        self._attempts.append(attempt);self._pending_send=None
        # Caller now reserves exactly this packet/reply cursor and attempts the
        # socket send immediately under the SAME lock. No slow callback here.
        return 'ready',attempt

    def finish_socket_attempt_locked(self, attempt, view, *, payload, bytes_sent, now):
        if not self._current(view,now):return False
        require(any(old is attempt for old in self._attempts) and
            not any(old is attempt for old in self._finished),'own_unused_socket_attempt_token_required')
        self._finished.append(attempt)
        if (self._proposal_key(attempt.proposal)!=attempt.proposal_fingerprint or
                type(payload) is not bytes or payload!=attempt.proposal.application_payload or
                not uint(bytes_sent,0,1492) or bytes_sent!=len(payload) or not clock(now) or now<attempt.attempted_at or
                view.out_sequence!=((attempt.proposal.packet_sequence+1)&MASK) or
                view.reply_count!=attempt.proposal.source_header[3]+1):
            return False
        self._successful.append(_FullSend(attempt,attempt.proposal.packet_sequence,now))
        return True

    def observe_accepted_receipt_locked(self, packet, view, *, now):
        """Before global cursor mutation; only store/request, never deliver/replay."""
        if not self.enabled or not self._current(view,now) or self.delivered:return False
        if (type(packet) is not WirePacket or not uint(packet.sequence,0,MASK) or
                not uint(packet.acknowledged_sequence,0,MASK) or type(packet.history) is not tuple or
                not 1<=len(packet.history)<=8 or any(not uint(word,0,0xffffffff) for word in packet.history) or
                type(packet.bunches) is not tuple or len(packet.bunches)>64 or
                any(type(b) is not WireBunch or b.close is not False or type(b.payload) is not bytes or
                    not uint(b.payload_bits,0,1492*8) or len(b.payload)!=(b.payload_bits+7)//8 for b in packet.bunches) or
                sum(len(b.payload) for b in packet.bunches)>1492):
            return False
        delta=(packet.sequence-view.in_sequence)&MASK
        sent=(view.out_sequence-view.acknowledged_out_sequence)&MASK
        ack=(packet.acknowledged_sequence-view.acknowledged_out_sequence)&MASK
        if not (0<sent<HALF and ack<sent and (1<=delta<=32 or self._gap and 32<delta<HALF)):
            return False
        matched=next((record for record in self._successful if record.attempt.owner_key==view.owner_key() and
            0<((view.out_sequence-record.sequence)&MASK)<HALF and
            (packet.acknowledged_sequence-record.sequence)&MASK < len(packet.history)*32 and
            (packet.history[((packet.acknowledged_sequence-record.sequence)&MASK)//32] >>
                (((packet.acknowledged_sequence-record.sequence)&MASK)%32))&1),None)
        if matched is None or self._pending_ack is not None:return False
        packet_digest=sha(repr(packet).encode('utf-8'))
        pre_cursor=(view.in_sequence,view.out_sequence,view.acknowledged_out_sequence)
        candidate_digest=sha(canonical({'packet':packet_digest,'pre_cursor':pre_cursor,
            'own_full_send_sequence':matched.sequence,'own_send_challenge':matched.attempt.permit.request.challenge}))
        if candidate_digest in self._receipt_digests:return False
        self._receipt_digests.add(candidate_digest)
        candidate=_ReceiptCandidate(packet,pre_cursor,matched,packet_digest,candidate_digest,now)
        request=self.authority.request(self._phase('ACK'),self._binding(self._phase('ACK'),matched.sequence,
            matched.attempt.proposal.application_sha256,candidate_digest),now=now)
        self._pending_ack=(candidate,request)
        return True

    def consume_ack_permit_locked(self, view, *, now):
        if not self.enabled:return 'disabled'
        if not self._current(view,now):return 'refused'
        if self.delivered:return 'delivered'
        if self._pending_ack is None:return 'no_own_receipt_candidate'
        candidate,request=self._pending_ack
        if (sha(repr(candidate.packet).encode('utf-8'))!=candidate.packet_digest or
                not any(record is candidate.full_send for record in self._successful) or
                not 0<((view.out_sequence-candidate.full_send.sequence)&MASK)<HALF):
            self.authority.revoke(request);self._pending_ack=None;return 'refused'
        status=self.authority.state(request,now=now)
        if status=='pending':return 'pending'
        if status!='ready':self._pending_ack=None;return 'refused'
        permit=self.authority.consume_locked(request,phase=self._phase('ACK'),binding_digest=request.binding_digest,now=now)
        if permit is None:return 'refused'
        self._last_committed_candidate=candidate;self._last_ack_permit=permit
        self._pending_ack=None;self.delivered=True
        return 'own_transport_receipt_committed'

    def clone(self):
        clone=copy(self)
        clone._attempts=list(self._attempts);clone._finished=list(self._finished)
        clone._successful=list(self._successful);clone._receipt_digests=set(self._receipt_digests)
        return clone

    def summary(self):
        return {'status':'disabled' if not self.enabled else 'cancelled' if self.cancelled else
            'transport_receipt_committed' if self.delivered else 'queued',
            'pending_send':self._pending_send is not None,'pending_ack':self._pending_ack is not None,
            'transport_authority':('prepared_connection_recipe' if
                type(getattr(self,'authority',None)) is ConnectionRecipeAuthority else 'retained_worker'),
            'last_refusal':dict(self.last_refusal) if self.last_refusal is not None else None,
            'socket_attempt_count':len(self._attempts),'actual_full_send_count':len(self._successful),
            'packet_cursor_mutated':False,'reliable_cursor_mutated':False,
            'source_or_native_io_performed':False,'socket_send_performed':False,
            'repnotify_execution_verified':False,'model_initialized':False}
