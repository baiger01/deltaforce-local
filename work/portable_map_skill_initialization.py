"""Pure source-qualified skill initialization values for a frozen room ticket.

The installed Hero/Expert rows determine these values. They do not determine
RepLayout handles, dynamic ability identities or authoritative health values.
No packet, process read, UObject construction or native call occurs here.
"""
import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path


CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SCHEMA_PATH = 'outputs/df-local-server/protocol/portable-map-spawn/skill-initialization-source-schema-v2.json'
SCHEMA_SHA256 = '6eaec3810b1c8af29ed21522a7580461a12f71ed8600fed1049e2a20dd8dfac8'
SOURCE_FIELD_ORDER = ('SOLUltimateSkillID', 'SOLSupportSkillID', 'SOLPassiveSkillID',
                      'SOLActiveSkillID', 'SOLCommonPassiveSkillID', 'SOLCommonSkillID')


class UnqualifiedInitializationWire(ValueError):
    """Real client fields exist, but their required wire/object binding is absent."""


def qualify_schema(schema):
    if type(schema) is not dict:
        raise ValueError('The pinned initialization value schema is required')
    raw = (json.dumps(schema, indent=2, sort_keys=True) + '\n').encode()
    if (hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256 or
            schema.get('kind') != 'client_source_derived_skill_initialization_values' or
            schema.get('client_sha256') != CLIENT_SHA256):
        raise ValueError('The pinned initialization value schema is required')


def load_schema(root):
    root = Path(root).resolve()
    raw = (root / SCHEMA_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('Initialization value schema file changed')
    schema = json.loads(raw)
    qualify_schema(schema)
    for row in schema['sources']:
        source = (root / row['relative_path']).resolve()
        if not source.is_relative_to(root):
            raise ValueError('Initialization source escapes the repository')
        if hashlib.sha256(source.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('Initialization source changed: ' + row['relative_path'])
    return schema


@dataclass(frozen=True)
class SkillInitializationValues:
    """Replayable service state; all nested public views are independent copies."""
    hero_id: int
    expert_id: int
    can_sliding_tackle: bool
    source_skill_fields: tuple
    missing_skill_config_ids: tuple
    _snapshot_json: str

    @property
    def skill_detail_assignments(self):
        return (('SkillDetailInfo.ExpertId', self.expert_id),
                ('SkillDetailInfo.CanSlidingTackle', self.can_sliding_tackle))

    @property
    def skill_source_rows(self):
        return tuple(self.to_dict()['skill_source_rows'])

    @property
    def wire_ready(self):
        return False

    @property
    def snapshot_sha256(self):
        return hashlib.sha256(self._snapshot_json.encode()).hexdigest()

    def to_dict(self):
        return json.loads(self._snapshot_json)


def resolve_skill_initialization(schema, *, hero_id):
    """Resolve a real hero to exact expert values without selecting a fallback.

    SkillDataConfig uses the explicit installed baseline/combined source scope
    in the schema. Runtime redirect selection is still unqualified. Additional
    skill lists remain evidence and are never converted to runtime grants.
    """
    qualify_schema(schema)
    if type(hero_id) is not int or not 0 < hero_id < 2**64:
        raise ValueError('A real numeric uint64 HeroId is required')
    key = str(hero_id)
    if key in schema['unsupported_hero_bindings']:
        reason = schema['unsupported_hero_bindings'][key]['reason']
        raise ValueError('Unsupported HeroId binding: ' + key + ' (' + reason + ')')
    binding = schema['hero_bindings'].get(key)
    if binding is None:
        raise ValueError('No source HeroId binding: ' + key)
    expert = binding['expert_id']
    source_fields = binding['source_SOL_skill_fields']
    frozen_fields = tuple((name, tuple(source_fields[name]) if type(source_fields[name]) is list
                          else source_fields[name]) for name in SOURCE_FIELD_ORDER)
    requested = []
    for name in SOURCE_FIELD_ORDER:
        ids = source_fields[name] if name == 'SOLCommonSkillID' else [source_fields[name]]
        for skill_id in ids:
            if skill_id != 0 and skill_id not in requested:
                requested.append(skill_id)
    rows, missing = [], []
    for skill_id in requested:
        row = schema['skill_config_rows'].get(str(skill_id))
        if row is None or row['SkillID'] != skill_id:
            missing.append(skill_id)
        else:
            rows.append(copy.deepcopy(row))
    snapshot = dict(kind='frozen_source_skill_initialization_values',
        source_schema_relative_path=SCHEMA_PATH, source_schema_sha256=SCHEMA_SHA256,
        client_sha256=CLIENT_SHA256, hero_id=hero_id, expert_id=expert,
        skill_detail_info=dict(ExpertId=expert, CanSlidingTackle=binding['can_sliding_tackle']),
        hero_row_source=copy.deepcopy(binding['hero_row_source']),
        expert_row_source=copy.deepcopy(binding['expert_row_source']),
        source_SOL_skill_fields=copy.deepcopy(source_fields), skill_source_rows=rows,
        missing_skill_config_ids=missing, wire_ready=False,
        configured_skill_ids_are_runtime_instance_ids=False,
        additional_skill_lists_are_runtime_grants=False,
        runtime_redirect_selection_qualified=False)
    encoded = json.dumps(snapshot, sort_keys=True, separators=(',', ':'))
    return SkillInitializationValues(hero_id, expert, binding['can_sliding_tackle'],
        frozen_fields, tuple(missing), encoded)


def require_wire_targets(schema, *targets):
    """Reject absent observed layout/creation contracts before packet production.

    No ClassNetCache index or in-memory struct offset is accepted as a handle.
    This version intentionally has no wire-ready target. A later source export
    must add its real layout/serializer/object proof before encoding is enabled.
    """
    qualify_schema(schema)
    if not targets or any(type(name) is not str or name not in schema['wire_targets'] for name in targets):
        raise ValueError('Explicit source-declared initialization targets are required')
    missing = []
    for name in targets:
        target = schema['wire_targets'][name]
        if target['qualified'] is not True:
            missing.append(name + ': ' + '; '.join(target['missing']))
    if missing:
        raise UnqualifiedInitializationWire(' | '.join(missing))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hero-id', type=int, required=True)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    state = resolve_skill_initialization(load_schema(args.root), hero_id=args.hero_id)
    print(json.dumps(dict(snapshot=state.to_dict(), snapshot_sha256=state.snapshot_sha256), indent=2))
