"""Pure original-Join namespace lease and immutable own async export receipt."""
from dataclasses import dataclass, field
from dfserver.replication.legacy_ds_fashion_retained_protocol import require, uint, sha, canonical, hex64

_LEASE_ISSUER=object()
_RECEIPT_ISSUER=object()

@dataclass(frozen=True,eq=False)
class PhaseNamespaceLease:
    contract: object=field(repr=False)
    channel: object=field(repr=False)
    component_guid: int
    original_reserved_guids: tuple
    issuer: object=field(repr=False)

@dataclass(frozen=True,eq=False)
class OwnExportReceipt:
    component_guid: int
    pawn_guid: int
    pawn_channel: int
    reliable_sequence: int
    packet_sequence: int
    export_payload_sha256: str
    owner_digest: str
    trigger_nonce: str
    native_identity_digest: str
    capture_sha256: str
    source_revision: str
    positive_candidate_sha256: str
    authority: object=field(repr=False)
    issuer: object=field(repr=False)
    @property
    def next_body_reliable_sequence(self):return (self.reliable_sequence+1)&1023
    def wire_receipt(self):
        return {key:getattr(self,key) for key in ('component_guid','pawn_guid','pawn_channel','reliable_sequence',
            'packet_sequence','export_payload_sha256','owner_digest','trigger_nonce','native_identity_digest',
            'capture_sha256','source_revision','positive_candidate_sha256')}
    @property
    def receipt_digest(self):return sha(canonical(self.wire_receipt()))

def allocate_component_guid(contract):
    reserved=contract.reserved_guids
    require(type(reserved) is tuple and len(reserved)<=4096 and len(set(reserved))==len(reserved) and
        all(uint(value,2,0xffffffff) for value in reserved),'complete_original_namespace_required')
    guid=next((value for value in range(2,2*(len(reserved)+2),2) if value not in reserved),None)
    require(guid is not None and guid!=contract.pawn_guid,'disjoint_owned_even_component_GUID_required')
    return guid

def issue_phase_lease(contract,channel,component_guid):
    require(uint(component_guid,2,0xffffffff) and component_guid not in contract.reserved_guids and
        component_guid!=contract.pawn_guid,'exact_disjoint_component_reservation_required')
    return PhaseNamespaceLease(contract,channel,component_guid,contract.reserved_guids,_LEASE_ISSUER)

def validate_owned_export_receipt(receipt,*,contract,lease):
    require(type(receipt) is OwnExportReceipt and receipt.issuer is _RECEIPT_ISSUER and
        type(lease) is PhaseNamespaceLease and lease.issuer is _LEASE_ISSUER and lease.contract is contract and
        receipt.trigger_nonce==contract.nonce and receipt.owner_digest==contract.owner_digest and
        (receipt.component_guid,receipt.pawn_guid,receipt.pawn_channel)==
            (lease.component_guid,contract.pawn_guid,contract.pawn_channel) and
        callable(getattr(receipt.authority,'validate_export_receipt',None)) and
        receipt.authority.validate_export_receipt(receipt),'original_registered_own_export_receipt_required')
    return receipt
