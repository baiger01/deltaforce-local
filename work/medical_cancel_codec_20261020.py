"""Source-qualified ordinary cancellation parameter codec; offline only.

No component routing, admission, socket, timer, item mutation or medical result
is implemented. Source qualification reads pinned PE/cache files once. This
grammar accepts only the 22 explicitly installed reason values; native enum
bit decoding alone does not enforce that local semantic restriction.
"""
from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache

from research_medical_contract_20261020 import reflection_contract


@lru_cache(maxsize=1)
def _source_schema():
    result = reflection_contract()
    return dict(result, supported_field_index=13,
                supported_class_path='/Script/DFMGameplay.InventoryUseItemManager',
                class_cache_exclusive_maximum=19, field_checksum=3477101170,
                parameter_scope='ordinary non-export reflected parameter body only',
                reason_explicit_range=[0, 21], absent_body_bits=1, present_body_bits=6,
                semantic_out_of_range_rejection_is_local_subset=True,
                owning_component_header_or_binding_qualified=False,
                generated_fixtures_are_native_captures=False,
                production_runtime_integrated=False)


def source_schema():
    return deepcopy(_source_schema())


@dataclass(frozen=True)
class CancelRequest:
    reason: int
    reason_present: bool


def encode_cancel(reason, *, reason_present=True):
    _source_schema()
    if type(reason) is not int or not 0 <= reason <= 21 or type(reason_present) is not bool:
        raise ValueError('An installed cancel reason and explicit bool presence are required')
    if not reason_present:
        if reason:
            raise ValueError('An omitted reason retains the native zero default')
        return b'\0', 1
    return bytes((1 | reason << 1,)), 6


def decode_cancel(payload, bit_count):
    _source_schema()
    if (type(payload) is not bytes or type(bit_count) is not int or bit_count not in (1, 6)
            or len(payload) != 1 or payload[0] >> bit_count):
        raise ValueError('One exact cancellation parameter bit slice is required')
    present = bool(payload[0] & 1)
    if not present:
        if bit_count != 1:
            raise ValueError('Cancellation parameters contain trailing bits after an omitted reason')
        return CancelRequest(0, False)
    if bit_count != 6:
        raise ValueError('Cancellation reason is truncated')
    reason = payload[0] >> 1
    if reason > 21:
        raise ValueError('The enum value is outside the explicitly installed local subset')
    return CancelRequest(reason, True)
