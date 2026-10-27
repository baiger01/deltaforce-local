"""Default-off actual transport hooks plus bounded asynchronous worker handoff.

No native backend is implemented here. The production channel constructor and
binder refuse. A snapshot/SourceJson, saved tuple, callable or boolean cannot
create a channel. Pure tests construct a private fake channel to exercise the
real queue/poll/send/receipt hooks; that is never native eligibility evidence.
"""
from dataclasses import dataclass, field, replace
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import secrets

from dfserver.replication.legacy_ds_fashion_async_permit import OwnerView, FrozenRecipe, SendProposal, RetainedWorkerAuthority, ConnectionRecipeAuthority, AsyncFashionPermitOutbox, sha, canonical, hex64, clock, uint, MASK
from dfserver.replication.legacy_ds_fashion_runtime import RuntimeSourceSeal, JoinedFashionOwnerContract, _current, namespace, namespace_digest, digest, require, SHIPPING_SHA256
from dfserver.replication.legacy_ds_actor_manifest import ActorManifest
from dfserver.transport.native.legacy_ds_wire_codec import WirePacket, WireBunch, ChannelName, encode_observed_application
from dfserver.replication import legacy_ds_fashion_retained_protocol as retained
from dfserver.replication.legacy_ds_fashion_owned_phase import PhaseNamespaceLease, OwnExportReceipt, issue_phase_lease, allocate_component_guid, validate_owned_export_receipt, _RECEIPT_ISSUER
from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_even_component_guid_exports import EvenComponentBinding, EvenComponentExportNode, EvenComponentExportProfile, ExistingPawnOuterReference, write_even_component_guid_exports

EVENT = 'actor_content_fashion_async_send_prepared'
_CHANNEL_ISSUER = object()
_PREPARED_ISSUER = object()
MAX_BINDINGS = 8


class NativeBackendUnsupported(ValueError):
    pass


@dataclass(frozen=True)
class _SealedExportSources:
    source_revision: str

class _RemoteOriginalSession:
    def __init__(self,client):
        self.original_deadline=client.deadline
    def read(self,*args):
        raise NativeBackendUnsupported('native_reads_belong_only_to_original_worker')

@dataclass(frozen=True)
class RetainedFashionPreparationRequest:
    contract: JoinedFashionOwnerContract = field(repr=False)
    source_seal: RuntimeSourceSeal = field(repr=False)
    schema_source: object = field(repr=False)
    native_catalog_source: object = field(repr=False)
    phase: str = 'EXPORT'

class RetainedOriginalSessionChannel:
    """Opaque actual policy Popen plus authenticated living typed-worker HELLO."""
    def __init__(self,client=None):
        if type(client) is not retained.RetainedWorkerClient or client._issuer is not retained._CLIENT_ISSUER:
            raise NativeBackendUnsupported('owned_live_original_worker_client_required')
        client.assert_live()
        self._issuer=_CHANNEL_ISSUER;self.client=client
        self.original_session=_RemoteOriginalSession(client);self.deadline=client.deadline
        self.session_id=client.session_id;self.source_digest=client.source_digest
        self.capture_digest=client.capture_digest;self.pid=client.process.pid;self.created_at=client._birth
        self.duplex_key=client.key;self.state=client.state
        # The reader qualifies the component/schema at preparation boundaries.
        # Published recipes use the live server connection for transport progress.
        self.connection_driven_transport=True
        self._prepare=self._prepare_native;self._exchange=self._exchange_native

    def _valid(self):
        require(getattr(self,'_issuer',None) is _CHANNEL_ISSUER and
            callable(getattr(self.original_session,'read',None)) and
            getattr(self.original_session,'original_deadline',None) == self.deadline and
            all(hex64(getattr(self,k,None)) for k in ('session_id','source_digest','capture_digest')) and
            uint(self.pid,1,0xffffffff) and clock(self.created_at) and clock(self.deadline) and
            type(self.duplex_key) is bytes and len(self.duplex_key)==32,
            'genuine_retained_original_session_channel_required')
        client=getattr(self,'client',None)
        if client is not None:
            require(type(client) is retained.RetainedWorkerClient and client.state=='original_live_retained' and
                not client.inbox.stopped and
                (client.session_id,client.deadline,client.source_digest,client.capture_digest,client._birth)==
                (self.session_id,self.deadline,self.source_digest,self.capture_digest,self.created_at),
                'original_worker_channel_identity_changed')

    def prepare_outside_lock(self, probe, map_id, request):
        self._valid()
        return self._prepare(probe,map_id,request)

    def exchange_outside_lock(self, request):
        self._valid()
        response=self._exchange(request.wire_request())
        self._valid()
        return response

    def _exchange_native(self,message):
        return retained.signed(self.client.exchange_outside_lock(message),self.duplex_key)

    def _prepare_native(self,probe,map_id,request):
        require(type(request) is RetainedFashionPreparationRequest and
            type(request.contract) is JoinedFashionOwnerContract and request.contract.probe is probe and
            request.contract.ticket.map_id==map_id and request.phase in ('EXPORT','BODY'),
            'typed_original_contract_and_source_preparation_request_required')
        contract=request.contract
        # Prequalify all slow source/body dependencies before asking for a fresh
        # native response. No file I/O follows the <=100ms admission response.
        import native_fashion_declaration_body as factory
        if request.phase=='EXPORT':
            from pathlib import Path
            from dfserver.replication import legacy_ds_even_component_guid_exports as codec
            sealed=request.source_seal.verify()
            require(digest(Path(codec.__file__).read_bytes())==
                '5d0ad3a6f5479111fc56e87b43758625d8a543fba1759f9ddd67b668e038098b',
                'frozen_consumer_export_codec_changed')
            sources=_SealedExportSources(digest(canonical(sealed)))
        else:
            sources=factory.prepare_current_declaration_sources(source_seal=request.source_seal,
                schema_source=request.schema_source,native_catalog_source=request.native_catalog_source)
        anchor={key:value for key,value in self.client.anchor.items() if key!='component_guid'}
        if request.phase=='EXPORT':
            previous=next(b.channel_sequence for ch,_,b in contract.content_namespace if ch==contract.pawn_channel)
            expected={'join_nonce':contract.nonce,'owner_digest':contract.owner_digest,
                'complete_namespace_digest':namespace_digest((contract.actor_namespace,contract.content_namespace,
                    contract.export_namespace,contract.reserved_guids)),
                'source_seal_digest':sources.source_revision,'selected_hero_id':contract.ticket.selected_hero_id,
                'native_catalog_hero_id':contract.ticket.selected_hero_id,'pawn_channel':contract.pawn_channel,
                'pawn_guid':contract.pawn_guid,'association_reliable_sequence':previous,
                'previous_reliable_sequence':previous,'previous_own_export_receipt_digest':None}
        else:
            expected={**factory.owner_binding_for_body(contract,sources)}
        require(all(expected.get(k)==value for k,value in anchor.items()),'original_Join_nonce_namespace_changed')
        with probe._lock:
            require(_current(probe,contract),'current_original_Join_changed_during_source_preflight')
        component_guid=self.client.anchor['component_guid']
        lease=issue_phase_lease(contract,self,component_guid)
        if request.phase=='EXPORT':
            require(component_guid%2==0 and contract.pawn_guid==2 and contract.pawn_channel==4,
                'own_LOCAL_missing_mapping_even_GUID_and_Pawn2_channel4_required')
            response=self.client.export_preparation_outside_lock(owner_binding=expected)
            facts=response['facts']
            writer=BitWriter(maximum_bits=contract.connection.max_packet_bytes*8)
            profile=EvenComponentExportProfile(contract.pawn_guid,(EvenComponentBinding(component_guid,
                facts['component_name'],contract.pawn_guid),),True,True,True,True,True,True,True,
                lambda: self.client._accepted.get(response['request_id']) is response and
                    time.monotonic()<response['expires_at'] and _current(probe,contract))
            write_even_component_guid_exports(writer,(EvenComponentExportNode(component_guid,
                facts['component_name'],ExistingPawnOuterReference(contract.pawn_guid)),),enabled=True,profile=profile)
            previous=self.client.anchor['association_reliable_sequence']
            bunch=WireBunch(contract.pawn_channel,writer.to_bytes(),writer.bit_count,reliable=True,
                channel_sequence=(previous+1)&1023,channel_name=ChannelName(hardcoded_index=102),package_exports=True)
            recipe=FrozenRecipe(bunch,sha(bunch.payload),sha(repr(bunch).encode()),contract.ticket.selected_hero_id,
                sources.source_revision,retained_core_freeze(),'EXPORT',None,facts['component_name'])
            return _PreparedQueue(contract,recipe,component_guid,self,sources,_PREPARED_ISSUER,
                lease,None,request,facts['native_identity_digest'])
        admission=self.client.declaration_outside_lock(owner_binding=expected)
        body=factory.prepare_bound_current_fashion_recipe(authority=self.client.authority,admission=admission,
            contract=contract,previous_own_receipt=None,source_seal=sources)
        recipe=replace(body.recipe,phase_kind='BODY',declaration_fingerprint=body.declaration_fingerprint)
        require(body.component_guid==component_guid,'actual_current_component_GUID_changed')
        return _PreparedQueue(contract,recipe,component_guid,self,sources,_PREPARED_ISSUER,
            lease,None,request,None)

    def prepare_body_after_export_outside_lock(self,prepared,receipt):
        import native_fashion_declaration_body as factory
        sources=factory.prepare_current_declaration_sources(source_seal=prepared.preparation_request.source_seal,
            schema_source=prepared.preparation_request.schema_source,
            native_catalog_source=prepared.preparation_request.native_catalog_source)
        owner=factory.owner_binding_for_body(prepared.contract,sources,previous_own_receipt=receipt)
        admission=self.client.declaration_outside_lock(owner_binding=owner,previous_own_receipt=receipt,
            connection_driven_transport=getattr(self,'connection_driven_transport',False))
        body=factory.prepare_bound_current_fashion_recipe(authority=self.client.authority,admission=admission,
            contract=prepared.contract,previous_own_receipt=receipt,source_seal=sources)
        recipe=replace(body.recipe,phase_kind='BODY',declaration_fingerprint=body.declaration_fingerprint)
        require(body.component_guid==prepared.recipe_component_guid and
            recipe.bunch.channel_sequence==receipt.next_body_reliable_sequence,'own_export_to_body_sequence_binding_required')
        return _PreparedQueue(prepared.contract,recipe,body.component_guid,self,sources,_PREPARED_ISSUER,
            prepared.lease,receipt,prepared.preparation_request,prepared.native_identity_digest)

def retained_core_freeze():
    from dfserver.replication.legacy_ds_fashion_async_permit import CORE_FREEZE_SHA
    return CORE_FREEZE_SHA

def bind_original_session_channel(client=None):
    if type(client) is not retained.RetainedWorkerClient:
        raise NativeBackendUnsupported('actual_policy_Popen_live_original_session_required')
    return RetainedOriginalSessionChannel(client)


@dataclass(frozen=True,eq=False)
class _PreparedQueue:
    """Only a retained channel's reviewed preflight may issue this private frame."""
    contract: JoinedFashionOwnerContract = field(repr=False)
    recipe: FrozenRecipe = field(repr=False)
    recipe_component_guid: int
    channel: RetainedOriginalSessionChannel = field(repr=False)
    source_revision: object = field(repr=False)
    issuer: object = field(repr=False)
    lease: object = field(default=None,repr=False)
    previous_receipt: object = field(default=None,repr=False)
    preparation_request: object = field(default=None,repr=False)
    native_identity_digest: str | None = None


def _snapshot_owner_locked(probe, map_id, sealed):
    require(probe._handshake is not None and probe._admissions is not None and probe.listening,
        'active_local_owner_required')
    c = probe._handshake.packet_ack_probe
    records = [r for r in probe._registered_bootstraps.values() if r['ticket'].map_id == map_id]
    require(len(records) == 1, 'one_current_registered_owner_required')
    r = records[0]; ticket = r['ticket']; peer = r['peer']
    state, t = c.control_peers.get(peer), c.peers.get(peer)
    configured = probe._initial_actor_profiles.get(map_id)
    require(configured is not None and state is not None and t is not None, 'current_profile_and_transport_required')
    fields = deepcopy(tuple(r['actor_fields']))
    actor_guids = tuple(sorted(f['actor_guid'] for f in fields))
    require(len(actor_guids) == len(set(actor_guids)) and
        set(state.actor_opens) == {f['channel_index'] for f in fields}, 'complete_actor_namespace_required')
    pawn_channels = [f['channel_index'] for f in fields
        if f.get('actor_guid') == state.pc_restart_pawn_guid]
    require(len(pawn_channels) == 1 and pawn_channels[0] == state.pc_restart_pawn_channel and
        pawn_channels[0] in state.actor_contents, 'exact_owned_pawn_association_required')
    pawn_manifests = [m for m in configured['manifests'] if type(m) is ActorManifest and
        m.actor_guid == state.pc_restart_pawn_guid and m.channel_index == pawn_channels[0]]
    require(len(pawn_manifests) == 1 and pawn_manifests[0].client_sha256 == SHIPPING_SHA256 and
        pawn_manifests[0].class_path == '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C' and
        pawn_manifests[0].references_resolvable is True and
        sealed.get(pawn_manifests[0].source_relative_path) == pawn_manifests[0].source_sha256,
        'source_qualified_typed_current_pawn_manifest_required')
    reserved = set(actor_guids)
    for f in fields:
        for root in f['exports']:
            node = root; depth = 0
            while node is not None:
                depth += 1
                require(depth <= 32, 'bounded_complete_export_namespace_required')
                reserved.add(node.guid); node = node.outer
    # Actor.exports is the BASE's additional owner namespace; never just inspect
    # the Pawn's references or an old profile subset.
    reserved.update(state.actor_exports)
    nonce = secrets.token_hex(32)
    binding = digest((nonce + ticket.cookie + repr((actor_guids, state.pc_restart_pawn_guid))).encode())
    contract = JoinedFashionOwnerContract(probe, c, configured, r, ticket, r['generation'], t, fields,
        namespace(state.actor_opens), namespace(state.actor_contents),
        deepcopy(tuple(sorted(state.actor_exports.items()))), deepcopy(tuple(configured['manifests'])), tuple(sorted(reserved)),
        pawn_channels[0], state.pc_restart_pawn_guid, nonce, binding, time.monotonic())
    require(_current(probe, contract), 'current_joined_owner_required')
    return contract


def capture_join_owner(probe, map_id, source_seal):
    """All source/file verification outside lock; only bounded owner snapshot inside."""
    require(type(source_seal) is RuntimeSourceSeal,'runtime_source_seal_required')
    sealed=source_seal.verify()
    with probe._lock:
        return _snapshot_owner_locked(probe,map_id,sealed)


class _Binding:
    def __init__(self, bridge, prepared):
        self.bridge=bridge;self.prepared=prepared
        self.contract=prepared.contract;self.channel=prepared.channel
        self.connection_driven_transport=getattr(self.channel,'connection_driven_transport',False) is True
        self.original_session=self.channel.original_session
        self.original_deadline=self.channel.deadline
        self._original_channel_key=(self.channel.session_id,self.channel.source_digest,self.channel.capture_digest,
            self.channel.pid,self.channel.created_at,self.channel.deadline,self.channel.duplex_key)
        self.source_revision=prepared.source_revision
        self.last_attempt_at=None;self.active_attempt=None;self.cancelled=False
        self.lease=prepared.lease;self.previous_receipt=prepared.previous_receipt
        self._export_receipt=None;self._export_proof_box=None;self._export_receipt_fingerprint=None
        self._export_receipt_registered=False;self._export_receipt_registration_failure=None
        self._transition_pending=False;self._transition_failed=False;self._transition_failure=None
        self._jobs_lock=threading.Lock();self._jobs=[];self._future=None
        self._executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='fashion-retained-ipc')
        owner=self._view(None)
        self.authority=self._new_authority(owner)
        c=self.contract.connection
        self.box=AsyncFashionPermitOutbox(enabled=True,owner=owner,recipe=prepared.recipe,
            authority=self.authority,max_attempts=c.max_transmissions,max_replies=c.max_replies,
            allow_forward_gap=c.qualified_receipt_forward_gaps,max_packet_bytes=c.max_packet_bytes,logical_authorization=True)

    def _new_authority(self, owner):
        if self.connection_driven_transport:
            return ConnectionRecipeAuthority(original_owner=owner)
        return RetainedWorkerAuthority(original_owner=owner,duplex_key=self.channel.duplex_key)

    def _view(self, current_box, *, prepared=None, previous_receipt=None):
        # Build a prospective phase without publishing it on this binding. The
        # authority/outbox constructors can reject and must leave EXPORT intact.
        if prepared is None:
            prepared=self.prepared;source_revision=self.source_revision
            previous_receipt=self.previous_receipt
        else:
            source_revision=prepared.source_revision
        contract=self.contract;t=contract.transport;ch=self.channel
        return OwnerView(contract.connection,contract.ticket,t,contract.generation,source_revision,ch,
            contract.nonce,contract.owner_digest,
            namespace_digest((contract.actor_namespace,contract.content_namespace,
                contract.export_namespace,contract.reserved_guids)),
            prepared.recipe.source_seal_digest,ch.capture_digest,ch.session_id,ch.pid,ch.created_at,ch.deadline,
            contract.ticket.selected_hero_id,contract.pawn_channel,contract.pawn_guid,
            prepared.recipe_component_guid,
            next(b.channel_sequence for channel,_,b in contract.content_namespace if channel==contract.pawn_channel),
            'joined_active',('connection_recipe' if self.connection_driven_transport else
                'original_live_retained' if ch.state=='original_live_retained' else 'refused'),
            t.out_sequence,t.in_sequence,t.acknowledged_out_sequence,t.history,t.replies,current_box,
            previous_receipt.reliable_sequence if previous_receipt is not None else None,
            previous_receipt.receipt_digest if previous_receipt is not None else None)

    @staticmethod
    def _phase_failure(stage, error, fallback):
        reason=error.args[0] if len(error.args)==1 and type(error.args[0]) is str else None
        if not (reason and reason.isascii() and reason.isidentifier() and len(reason)<=96):reason=None
        return {'stage':stage,'reason':reason or fallback,'error_type':type(error).__name__}

    def current_locked(self):
        try:
            if not self.connection_driven_transport:self.channel._valid()
            else:
                require(type(self.channel) is RetainedOriginalSessionChannel and
                    self.channel._issuer is _CHANNEL_ISSUER and
                    self.channel.connection_driven_transport is True,
                    'original_prepared_connection_channel_required')
        except (ValueError,AttributeError) as error:
            self.box.last_refusal={'stage':'retained_channel','reason':'retained_channel_not_live',
                'error_type':type(error).__name__}
            self.cancelled=True;self.box.cancelled=True
            return False
        contract=self.contract;c=contract.connection
        peer=c.ticket_peers.get(contract.ticket.cookie)
        state=c.control_peers.get(peer)
        valid=(not self.cancelled and (self.connection_driven_transport or
                self.channel.state=='original_live_retained' and self.bridge.clock()<self.channel.deadline) and
            self._original_channel_key==(self.channel.session_id,self.channel.source_digest,self.channel.capture_digest,
                self.channel.pid,self.channel.created_at,self.channel.deadline,self.channel.duplex_key) and
            self.channel.original_session is self.original_session and
            self.original_session.original_deadline==self.original_deadline==self.channel.deadline and
            _current(self.bridge.probe,contract) and
            state is not None and state.fashion_async_binding is self and state.fashion_subobject_outbox is None and
            (self.lease is None or state.fashion_phase_lease is self.lease and
                self.lease.contract is contract and self.lease.channel is self.channel and
                self.lease.component_guid==self.prepared.recipe_component_guid and
                self.lease.original_reserved_guids==contract.reserved_guids) and
            c.max_packet_bytes==self.box._packet_maximum and
            self.prepared.recipe.bunch.channel_sequence ==
                (((self.previous_receipt.reliable_sequence if self.previous_receipt is not None else
                    state.actor_contents[contract.pawn_channel].bunch.channel_sequence)+1)&1023) and
            (self.previous_receipt is None or self.validate_export_receipt(self.previous_receipt)) and
            all(c._actor_own_full_send_positive_receipt(state,item,ticket=contract.ticket,
                transport=contract.transport,generation=contract.generation) for item in
                (state.actor_opens[contract.pawn_channel],state.actor_contents[contract.pawn_channel])))
        if not valid:
            if self.box.last_refusal is None:
                self.box.last_refusal={'stage':'binding_owner','reason':'binding_owner_recheck_refused',
                    'worker_deadline_expired':self.bridge.clock()>=self.channel.deadline,
                    'reply_count':contract.transport.replies,'reply_limit':self.box._reply_limit}
            self.cancelled=True;self.box.cancelled=True
        return valid

    def view_locked(self):
        if not self.current_locked():return None
        return self._view(self.box)

    def validate_export_receipt(self,receipt):
        return (type(receipt) is OwnExportReceipt and receipt is self._export_receipt and
            receipt.authority is self and receipt.issuer is _RECEIPT_ISSUER and
            canonical(receipt.wire_receipt())==self._export_receipt_fingerprint and
            self._export_proof_box is not None and self._export_proof_box.delivered and
            self._export_proof_box._last_committed_candidate is not None and
            self._export_proof_box._last_committed_candidate.candidate_digest==receipt.positive_candidate_sha256 and
            _current(self.bridge.probe,self.contract) and not self.cancelled)

    def publish_export_receipt_locked(self):
        if self._export_receipt is None:
            require(self.box.recipe.phase_kind=='EXPORT' and self.box.delivered and self.lease is not None,
                'delivered_owned_export_phase_required')
            candidate=self.box._last_committed_candidate;send=candidate.full_send
            require(send in self.box._successful and self.box._last_ack_permit is not None,
                'own_export_full_send_positive_ACK_candidate_required')
            receipt=OwnExportReceipt(self.prepared.recipe_component_guid,self.contract.pawn_guid,
                self.contract.pawn_channel,self.box.recipe.bunch.channel_sequence,send.sequence,
                send.attempt.proposal.application_sha256,self.contract.owner_digest,self.contract.nonce,
                self.prepared.native_identity_digest,self.channel.capture_digest,self.box.recipe.source_seal_digest,
                candidate.candidate_digest,self,_RECEIPT_ISSUER)
            # Registry validation calls back into this proof. Retain the same
            # candidate across a failed registration, including a failure after
            # the registry has stored it; retry is then idempotent by identity.
            self._export_receipt=receipt;self._export_proof_box=self.box
            self._export_receipt_fingerprint=canonical(receipt.wire_receipt())
        receipt=self._export_receipt
        if not self._export_receipt_registered:
            try:
                client=getattr(self.channel,'client',None)
                if client is not None:client.authority.register_previous_own_export_receipt(receipt,self)
            except Exception as error:
                failure=self._phase_failure('export_receipt_registration',error,'own_export_registration_refused')
                self._export_receipt_registration_failure=failure
                self.box.last_refusal={**failure,'retryable':True}
                self._transition_pending=False
                return None
            self._export_receipt_registered=True
            if self.box.last_refusal is not None and self.box.last_refusal.get('stage')=='export_receipt_registration':
                self.box.last_refusal=None
        self._transition_pending=True
        return receipt

    def _transition_outside_lock(self):
        stage='body_preparation'
        try:
            prepared=self.channel.prepare_body_after_export_outside_lock(self.prepared,self._export_receipt)
            with self.bridge.probe._lock:
                stage='body_handoff'
                require(self.current_locked() and type(prepared) is _PreparedQueue and
                    prepared.contract is self.contract and prepared.channel is self.channel and
                    prepared.lease is self.lease and prepared.previous_receipt is self._export_receipt and
                    self._export_receipt_registered and prepared.recipe.phase_kind=='BODY',
                    'same_original_phase_lease_body_handoff_required')
                owner=self._view(None,prepared=prepared,previous_receipt=self._export_receipt)
                stage='body_authority'
                authority=self._new_authority(owner)
                c=self.contract.connection
                stage='body_outbox'
                box=AsyncFashionPermitOutbox(enabled=True,owner=owner,recipe=prepared.recipe,
                    authority=authority,max_attempts=c.max_transmissions,max_replies=c.max_replies,
                    allow_forward_gap=c.qualified_receipt_forward_gaps,max_packet_bytes=c.max_packet_bytes,
                    logical_authorization=True)
                self.prepared,self.source_revision,self.previous_receipt,self.authority,self.box=(
                    prepared,prepared.source_revision,self._export_receipt,authority,box)
                self.last_attempt_at=None;self._transition_pending=False
        except Exception as error:
            # No body proposal/cursor exists until a fresh mapping/schema
            # admission succeeds. Failure remains an explicit closed branch.
            with self.bridge.probe._lock:
                self._transition_failure=self._phase_failure(stage,error,'owned_body_transition_refused')
                self.box.last_refusal=dict(self._transition_failure)
                self._transition_failed=True;self._transition_pending=False
        self.bridge.wake_outside_lock()

    def _run(self, request):
        # This entry is submitted only by pump_outside_lock. No probe lock is
        # acquired around native/IPC/source work. The original worker is retained.
        try:
            preflight=self.prepared.preparation_request
            if type(preflight) is RetainedFashionPreparationRequest:
                sealed=preflight.source_seal.verify()
                require(digest(canonical(sealed))==self.prepared.recipe.source_seal_digest,
                    'prepared_BASE_runtime_source_changed_before_native_request')
            response=self.channel.exchange_outside_lock(request)
            self.authority.accept_authenticated_response_outside_lock(request,response,now=self.bridge.clock())
        except Exception as error:
            reason=error.args[0] if len(error.args)==1 and type(error.args[0]) is str else None
            if not (reason and reason.isascii() and reason.isidentifier() and len(reason)<=96):reason=None
            self.box.last_refusal={'stage':'native_exchange','reason':reason or 'controlled_native_exchange_refused',
                'error_type':type(error).__name__}
            self.authority.revoke(request)
        # Wake the existing transport poll promptly, without waiting for UDP's
        # 200ms timeout to consume a <=100ms fresh permit.
        self.bridge.wake_outside_lock()

    def pump_outside_lock(self):
        with self._jobs_lock:
            self._jobs.extend(self.authority.drain_work_outside_lock())
            require(len(self._jobs)<=128,'bounded_original_worker_dispatch_required')
            if self._future is not None and self._future.done():self._future=None
            if self._transition_pending and self._future is None and not self._jobs:
                self._future=self._executor.submit(self._transition_outside_lock)
            while self._jobs and self._future is None:
                request=self._jobs.pop(0)
                if self.cancelled:
                    self.authority.revoke(request);continue
                if self.authority.state(request,now=self.bridge.clock())!='pending':continue
                self._future=self._executor.submit(self._run,request)

    def close_outside_lock(self):
        self.cancelled=True
        self._executor.shutdown(wait=False,cancel_futures=True)
        client=getattr(self.channel,'client',None)
        if client is not None:client.close_outside_lock()


class AsyncFashionTransportBridge:
    def __init__(self, probe):
        self.probe=probe;self.clock=time.monotonic
        self.bindings=[];self._wake_lock=threading.Lock()

    def install_locked(self, prepared):
        require(type(prepared) is _PreparedQueue and prepared.issuer is _PREPARED_ISSUER and
            type(prepared.channel) is RetainedOriginalSessionChannel and
            type(prepared.contract) is JoinedFashionOwnerContract and type(prepared.recipe) is FrozenRecipe and
            prepared.contract.probe is self.probe and prepared.source_revision is not None and
            len(self.bindings)<MAX_BINDINGS,'original_channel_preflight_frame_required')
        prepared.channel._valid()
        contract=prepared.contract;c=contract.connection
        require(_current(self.probe,contract),'original_join_changed_during_native_preflight')
        peer=c.ticket_peers[contract.ticket.cookie];state=c.control_peers[peer]
        require(state.fashion_async_binding is None and state.fashion_subobject_outbox is None,
            'one_current_fashion_channel_reservation_required')
        require(prepared.recipe_component_guid not in contract.reserved_guids,
            'complete_owned_namespace_component_collision')
        require(all(c._actor_own_full_send_positive_receipt(state,item,ticket=contract.ticket,
            transport=contract.transport,generation=contract.generation) for item in
            (state.actor_opens[contract.pawn_channel],state.actor_contents[contract.pawn_channel])),
            'each_pawn_prerequisite_own_full_send_positive_receipt_required')
        binding=_Binding(self,prepared)
        # Publication does not mutate a transport/reliable cursor or producer.
        state.fashion_async_binding=binding
        if prepared.lease is not None:state.fashion_phase_lease=prepared.lease
        c._fashion_async_bridge=self
        self.bindings.append(binding)
        return 'queued'

    def poll_locked(self, connection, now):
        result=[]
        for binding in self.bindings:
            try:
                if binding.contract.connection is not connection:continue
                view=binding.view_locked()
                if view is None:continue
                ack_status=binding.box.consume_ack_permit_locked(view,now=self.clock())
                if ack_status=='refused':
                    binding.cancelled=True;binding.box.cancelled=True
                    continue
                if binding.box.delivered:
                    if binding.box.recipe.phase_kind=='EXPORT' and not binding._transition_failed:
                        binding.publish_export_receipt_locked()
                    continue
                if binding.box.cancelled:continue
                # A positive candidate is already being checked by this owner.
                # Wait for that result instead of starting a competing SEND.
                # Without a candidate, normal bounded retransmission continues.
                if ack_status=='pending':continue
                if (binding.last_attempt_at is not None and now-binding.last_attempt_at<connection.retry_interval):continue
                raw=encode_observed_application(WirePacket(view.out_sequence,view.in_sequence,(view.history,),
                    False,0,None,(binding.box.recipe.bunch,),0),
                    max_packet_bytes=connection.max_packet_bytes,received_by_server=False)
                proposal=SendProposal(raw,view.out_sequence,(view.out_sequence,view.in_sequence,
                    view.acknowledged_out_sequence,view.reply_count,view.history),sha(raw))
                binding.box.begin_send_locked(proposal,view,now=self.clock())
                pending=binding.box._pending_send
                if pending is None:continue
                token,request,_=pending
                if token.source_header!=proposal.source_header:
                    binding.box.consume_send_permit_locked(view,now=self.clock())
                    continue
                status=binding.authority.state(request,now=self.clock())
                if status=='refused':
                    binding.box.consume_send_permit_locked(view,now=self.clock())
                    binding.cancelled=True;binding.box.cancelled=True
                elif status=='ready':
                    peer=connection.ticket_peers[binding.contract.ticket.cookie]
                    result.append((peer,EVENT,token.application_payload))
            except (ValueError, TypeError, KeyError, OSError, AttributeError):
                # Exhaustion/drift belongs to this optional Fashion outbox.
                # Keep the existing normal producers/header/liveness running.
                binding.cancelled=True;binding.box.cancelled=True
        return result

    def before_socket_locked(self, peer, payload):
        c=self.probe._handshake.packet_ack_probe;state=c.control_peers.get(peer)
        binding=getattr(state,'fashion_async_binding',None)
        if binding not in self.bindings:return False
        view=binding.view_locked()
        pending=binding.box._pending_send
        if view is None or pending is None or pending[0].application_payload!=payload:return False
        status,attempt=binding.box.consume_send_permit_locked(view,now=self.clock())
        if status!='ready':return False
        binding.active_attempt=attempt
        t=binding.contract.transport
        t.out_sequence=(t.out_sequence+1)&MASK;t.replies+=1
        binding.last_attempt_at=time.perf_counter()-self.probe._started_at
        return True

    def finish_socket_locked(self, peer, payload, bytes_sent):
        c=self.probe._handshake.packet_ack_probe;state=c.control_peers.get(peer)
        binding=getattr(state,'fashion_async_binding',None)
        if binding not in self.bindings or binding.active_attempt is None:return False
        attempt=binding.active_attempt;binding.active_attempt=None
        view=binding.view_locked()
        if view is None:return False
        # A full return also needs the existing actual-send journal produced by
        # the owning GameProbe hook. Prepared or short sends cannot create it.
        full=(type(bytes_sent) is int and bytes_sent==len(payload))
        if full:
            contract=binding.contract
            full=any(record.sequence==attempt.proposal.packet_sequence and
                record.ticket is contract.ticket and record.transport is contract.transport and
                record.generation is contract.generation and record.bunches==(binding.box.recipe.bunch,)
                for record in state.actual_application_sends)
        return binding.box.finish_socket_attempt_locked(attempt,view,payload=payload,
            bytes_sent=bytes_sent if full else 0,now=self.clock())

    def observe_header_locked(self, connection, peer, packet, generation):
        state=connection.control_peers.get(peer);binding=getattr(state,'fashion_async_binding',None)
        if binding not in self.bindings or generation is not binding.contract.generation:return False
        view=binding.view_locked()
        return view is not None and binding.box.observe_accepted_receipt_locked(packet,view,now=self.clock())

    def pump_outside_lock(self):
        # Short snapshot; all dispatch/exchange/authentication happens after release.
        with self.probe._lock:bindings=tuple(self.bindings)
        for binding in bindings:binding.pump_outside_lock()

    def wake_outside_lock(self):
        if self.probe._stop.is_set() or not self._wake_lock.acquire(False):return
        try:self.probe._send_control_retries()
        finally:self._wake_lock.release()

    def close_outside_lock(self):
        with self.probe._lock:
            bindings=tuple(self.bindings)
            for binding in bindings:
                binding.cancelled=True;binding.box.cancelled=True
                for pending in (binding.box._pending_send,binding.box._pending_ack):
                    if pending is not None:binding.authority.revoke(pending[1])
        for binding in bindings:binding.close_outside_lock()


def queue_current_fashion_async(probe, map_id, *, channel=None, request=None):
    # Refuse snapshots/callables/flags before any producer, cursor or native work.
    if type(channel) is not RetainedOriginalSessionChannel:
        raise NativeBackendUnsupported('genuine_retained_original_session_native_ipc_backend_required')
    channel._valid()
    prepared=channel.prepare_outside_lock(probe,map_id,request)
    require(type(prepared) is _PreparedQueue and prepared.channel is channel and
        prepared.issuer is _PREPARED_ISSUER,'original_channel_preflight_frame_required')
    with probe._lock:
        bridge=getattr(probe,'_fashion_async_bridge',None)
        if bridge is None:
            bridge=AsyncFashionTransportBridge(probe)
            probe._fashion_async_bridge=bridge
        return bridge.install_locked(prepared)

