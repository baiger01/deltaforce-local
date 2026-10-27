"""Explicit existing GS ability subobject values for qualified local producers."""
from dataclasses import dataclass


@dataclass(frozen=True)
class SkillTemplateUpdate:
    actor_guid: int
    guid: int
    class_guid: int
    class_path: str
    source_sha256: str
    payload: bytes
    payload_bit_count: int
    plan: object
    allocated_guids: tuple

    @property
    def name(self):
        return None


def write_followup(writer, update, *, actor_guids, object_bindings):
    # Only the explicitly configured native map producer needs this qualified
    # codec. Ordinary service users do not import the optional research runtime.
    from skill_template_replication import write_followup as qualified_write
    return qualified_write(writer, update, actor_guids=actor_guids,
        object_bindings=object_bindings, creation_acknowledged=True)
