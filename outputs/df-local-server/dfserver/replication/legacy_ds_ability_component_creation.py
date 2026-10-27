"""The source-qualified empty dynamic GS ability creation subset.

ReadContentBlockHeader 12863600 consumes selector0, object GUID, stable0,
class GUID, packed content length and exact content. Its normal creation hook
125bcab0 registers the ActorComponent. The class comes from DFMAbilityConfig
row GSAbilityComponent. The sealed source is
work/evidence/model-init-chain-20261018/native-current-skill-gs-dynamic-component-schema-v2.json.
No native methods, reflected property handles or local GameState pointers are
sent here. A prepared message is not proof of component or skill readiness.
"""
from dataclasses import dataclass

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter, UINT32_MAX


CLASS_PATH = '/Script/DFMAbility.DFMAbilityGameStateComponent'
SOURCE_SHA256 = '3893210b7c72243bed6d358faaca21ad5bbab984848e88dfbd8194049f499109'


@dataclass(frozen=True)
class AbilityComponentCreation:
    actor_guid: int
    guid: int
    class_guid: int
    source_sha256: str

    @property
    def name(self):
        # The normal receiver chooses the instance Name; it is not a default.
        return None


def write_creation(writer, update, *, actor_guids, exported_class_guids):
    if (type(writer) is not BitWriter or type(update) is not AbilityComponentCreation or
            type(actor_guids) is not tuple or type(exported_class_guids) is not tuple or
            any(type(value) is not int or not 2 <= value <= UINT32_MAX
                for value in (update.actor_guid, update.guid, update.class_guid)) or
            update.actor_guid not in actor_guids or update.guid in actor_guids or
            update.actor_guid & 1 or update.guid & 1 or not update.class_guid & 1 or
            update.class_guid not in exported_class_guids or
            update.source_sha256 != SOURCE_SHA256):
        raise ValueError('A qualified current GS Actor, actual class export and fresh ability GUID are required')
    staged = BitWriter(maximum_bits=256)
    staged.write_bool(True)
    staged.write_bool(False)
    staged.write_packed_int(update.guid)
    staged.write_bool(False)
    staged.write_packed_int(update.class_guid)
    staged.write_packed_int(9)
    staged.write_bits(0, 9)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count
