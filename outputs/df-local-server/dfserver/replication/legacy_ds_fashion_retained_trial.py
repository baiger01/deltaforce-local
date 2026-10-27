"""One default-off owned trial hook; source/IPC work never holds probe lock."""
from dataclasses import dataclass
import hashlib
import importlib
import json
from pathlib import Path
import threading

from dfserver.replication.legacy_ds_fashion_runtime import RuntimeSourceSeal, RUNTIME_MODULES, SOURCE_PINS, FIXED_BASE_PATH, FIXED_REPOSITORY_PATH, HERO_CATALOG_SHA, SELECTED_HERO_EVIDENCE, SELECTED_HERO_EVIDENCE_SHA, namespace_digest, require
from dfserver.replication.legacy_ds_fashion_async_bridge import capture_join_owner, RetainedFashionPreparationRequest, queue_current_fashion_async
from dfserver.replication.legacy_ds_fashion_owned_phase import allocate_component_guid
from native_fashion_hero_content import SourceJson,SourcePin

REPO_STATIC_SOURCE_PATHS=frozenset((
    'work/staging-ds-receipt-fix-20261009/fashion-hero-property-body/candidate_native_fashion_hero_content.py',
    'work/staging-ds-receipt-fix-20261009/resolved-stable-subobject-content/candidate_legacy_ds_actor_content.py'))

class RetainedSourcePreflightError(ValueError):
    """A bounded source identifier/path; never arbitrary exception text."""
    def __init__(self,reason,root_name,relative):
        super().__init__(reason)
        self.reason=reason;self.root_name=root_name;self.relative=relative
    def safe_diagnostics(self):
        if (self.reason not in ('qualified_retained_source_missing','qualified_retained_source_path_or_hash_changed') or
                self.root_name not in ('BASE','REPO') or type(self.relative) is not str or
                not 1<=len(self.relative)<=512 or not self.relative.isascii() or ':' in self.relative or
                '\\' in self.relative or self.relative.startswith('/') or '..' in self.relative.split('/')):
            return {'phase':'pre_native_source_preparation','reason':'controlled_source_preflight_refused'}
        return {'phase':'pre_native_source_preparation','reason':self.reason,
            'source_root':self.root_name,'source_relative':self.relative}

@dataclass(frozen=True)
class PreparedRetainedTrial:
    request: RetainedFashionPreparationRequest
    anchor: dict

def prepare_retained_trial(probe,map_id,*,base_root,repository_root,additional_sources):
    base=Path(base_root).resolve(strict=True);repo=Path(repository_root).resolve(strict=True)
    require(base==Path(FIXED_BASE_PATH).resolve(strict=True) and repo==Path(FIXED_REPOSITORY_PATH).resolve(strict=True),
        'fixed_owner_BASE_and_REPO_required')
    # This is called before Popen/native work. Load every executing source now.
    for name in RUNTIME_MODULES:importlib.import_module(name)
    import native_fashion_declaration_body as factory
    expected={};locations={}
    def add(relative,pin,root):
        require(type(relative) is str and 1<=len(relative)<=512 and ':' not in relative and
            '\\' not in relative and not relative.startswith('/') and '..' not in relative.split('/'),
            'relative_qualified_source_path_required')
        root_name='BASE' if root==base else 'REPO'
        try:
            path=(root/relative).resolve(strict=True)
            raw=path.read_bytes()
        except FileNotFoundError:
            raise RetainedSourcePreflightError('qualified_retained_source_missing',root_name,relative) from None
        if not path.is_relative_to(root) or hashlib.sha256(raw).hexdigest()!=pin:
            raise RetainedSourcePreflightError('qualified_retained_source_path_or_hash_changed',root_name,relative)
        require(relative not in expected or expected[relative]==pin,'retained_source_namespace_collision')
        expected[relative]=pin;locations[relative]=path
    # Exactly two immutable historical source artifacts belong to REPO. Four
    # executing destinations and every RUNTIME module remain BASE-only.
    require(REPO_STATIC_SOURCE_PATHS<=SOURCE_PINS.keys(),'fixed_static_source_classification_changed')
    for relative,pin in SOURCE_PINS.items():
        add(relative,pin,repo if relative in REPO_STATIC_SOURCE_PATHS else base)
    for name,relative in RUNTIME_MODULES.items():
        module=importlib.import_module(name)
        path=Path(module.__file__).resolve(strict=True)
        require(path==(base/relative).resolve(strict=True),'parent_BASE_executing_namespace_required')
        add(relative,hashlib.sha256(path.read_bytes()).hexdigest(),base)
    require(type(additional_sources) is dict and len(additional_sources)<=384,'bounded_original_bootstrap_sources_required')
    for relative,pin in additional_sources.items():
        # Source-backed Actor/association namespaces are sealed in the original
        # BASE bootstrap. Only explicitly pinned immutable static profiles may
        # come from the fixed REPO source closure.
        add(relative,pin,base if (base/relative).is_file() else repo)
    schema_path=(repo/factory.SCHEMA_RELATIVE).resolve(strict=True)
    raw=schema_path.read_bytes();require(hashlib.sha256(raw).hexdigest()==factory.SCHEMA_SHA,'current_schema_source_changed')
    schema=SourceJson(SourcePin(factory.SCHEMA_RELATIVE,factory.SCHEMA_SHA),raw)
    add(factory.SCHEMA_RELATIVE,factory.SCHEMA_SHA,repo)
    for relative,pin in json.loads(raw)['source_pins'].items():add(relative,pin,repo)
    # The pinned selected-Hero derivation is immutable REPO evidence. The
    # executing factory and current catalog remain qualified in BASE.
    add(SELECTED_HERO_EVIDENCE,SELECTED_HERO_EVIDENCE_SHA,repo)
    catalog_relative='outputs/df-local-server/protocol/hero_customization_catalog.json'
    add(catalog_relative,HERO_CATALOG_SHA,base)
    catalog=SourceJson(SourcePin(catalog_relative,HERO_CATALOG_SHA),locations[catalog_relative].read_bytes())
    require(len(expected)<=512,'retained_BASE_source_pin_bound_exceeded')
    def recheck():
        return {relative:hashlib.sha256(path.read_bytes()).hexdigest() for relative,path in locations.items()}
    source=RuntimeSourceSeal(expected,recheck)
    contract=capture_join_owner(probe,map_id,source)
    previous=next(b.channel_sequence for ch,_,b in contract.content_namespace if ch==contract.pawn_channel)
    guid=allocate_component_guid(contract)
    anchor={'join_nonce':contract.nonce,'owner_digest':contract.owner_digest,
        'complete_namespace_digest':namespace_digest((contract.actor_namespace,contract.content_namespace,
            contract.export_namespace,contract.reserved_guids)),'selected_hero_id':contract.ticket.selected_hero_id,
        'pawn_channel':contract.pawn_channel,'pawn_guid':contract.pawn_guid,'component_guid':guid,
        'association_reliable_sequence':previous}
    return PreparedRetainedTrial(RetainedFashionPreparationRequest(contract,source,schema,catalog,'EXPORT'),anchor)

class RetainedTrialQueue:
    """Actual owned observer HELLO to actual GameProbe async queue, off-lock."""
    def __init__(self,observer,probe,prepared):
        require(type(prepared) is PreparedRetainedTrial,'prepared_original_retained_trial_required')
        self.observer=observer;self.probe=probe;self.prepared=prepared
        self._lock=threading.Lock();self._status={'status':'awaiting_original_live_context',
            'model_verified':False,'local_RepLayout_observed':False}
        self.thread=threading.Thread(target=self._run,name='fashion-trial-bind',daemon=True)
    def start(self):
        self.thread.start();return self
    def _run(self):
        try:
            channel=self.observer.bind_retained_channel_outside_lock()
            status=queue_current_fashion_async(self.probe,self.prepared.request.contract.ticket.map_id,
                channel=channel,request=self.prepared.request)
            with self._lock:self._status['status']=status
        except Exception as error:
            with self._lock:
                self._status.update(status='refused',error_type=type(error).__name__)
    def summary(self):
        with self._lock:row=dict(self._status)
        contract=self.prepared.request.contract
        with self.probe._lock:
            peer=contract.connection.ticket_peers.get(contract.ticket.cookie)
            state=contract.connection.control_peers.get(peer)
            binding=getattr(state,'fashion_async_binding',None)
            if binding is not None and binding.contract is contract:
                box=binding.box
                row.update(phase=box.recipe.phase_kind,delivery=box.summary(),
                    own_export_receipt_issued=binding._export_receipt is not None,
                    native_body_HeroID_recheck_confirmed=box.recipe.phase_kind=='BODY' and box.delivered,
                    body_transition_refused=binding._transition_failed)
        return row
