"""Ordinary followup of an already created dynamic main FSM instance.

The pinned ReadContentBlockHeader source (SHA256027ef34cb7fce8aa76a8e663b0e4e8ff
e7486bae51fee5934d72742ee286770c) consumes class GUID on stable=false, then its
128646e7/128646ec branch reuses an existing object. No instance Name export or
second object allocation is needed. The caller must retain the exact creation
binding and enforce the creation's real delivery ACK before sending this tail.
Property semantics are qualified separately by the producer.
"""
from dataclasses import dataclass
import re

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.replication.legacy_ds_dynamic_object_creation import CLASS_PATH


@dataclass(frozen=True)
class DynamicObjectUpdate:
    actor_guid: int
    guid: int
    class_guid: int
    class_path: str
    source_sha256: str
    payload: bytes
    payload_bit_count: int

    @property
    def name(self):
        return None


def write_update(writer, update, *, actor_guids, object_bindings):
    if (type(writer) is not BitWriter or type(update) is not DynamicObjectUpdate or
            type(actor_guids) is not tuple or not 1 <= len(actor_guids) <= 128 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in actor_guids) or
            len(set(actor_guids)) != len(actor_guids) or type(object_bindings) is not tuple or
            not 1 <= len(object_bindings) <= 128 or any(type(b) is not tuple or len(b) != 4
                for b in object_bindings) or len({b[0] for b in object_bindings}) != len(object_bindings)):
        raise ValueError('A bounded existing Actor and dynamic creation binding are required')
    if (any(type(g) is not int or not 2 <= g <= UINT32_MAX
            for g in (update.actor_guid, update.guid, update.class_guid)) or
            update.actor_guid not in actor_guids or update.guid in actor_guids or
            update.actor_guid & 1 or update.guid & 1 or not update.class_guid & 1 or
            update.class_path != CLASS_PATH or
            (update.guid, update.actor_guid, update.class_guid, update.class_path) not in object_bindings or
            type(update.source_sha256) is not str or
            re.fullmatch('[0-9a-f]{64}', update.source_sha256) is None or
            type(update.payload) is not bytes or type(update.payload_bit_count) is not int or
            not 1 <= update.payload_bit_count <= 8192 or
            len(update.payload) != (update.payload_bit_count + 7) // 8 or
            int.from_bytes(update.payload, 'little') >> update.payload_bit_count):
        raise ValueError('The exact existing main FSM identity and canonical property body are required')
    BitReader(update.payload, bit_count=update.payload_bit_count)
    staged = BitWriter(maximum_bits=writer.maximum_bits)
    staged.write_bool(True)
    staged.write_bool(False)
    staged.write_packed_int(update.guid)
    staged.write_bool(False)
    staged.write_packed_int(update.class_guid)
    staged.write_packed_int(update.payload_bit_count)
    staged.write_payload(update.payload, update.payload_bit_count)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count
