"""Qualified PlayerState/Movement templates for the explicit local Actor trial."""
import hashlib
import json
from pathlib import Path

from native_actor_bootstrap import build_initial_actor_bootstrap, CLIENT_SHA256

SPEC_PATH = 'work/evidence/map-entry-next-20261006/additional-initial-actor-sources.json'
ROLES = ('PlayerState', 'MovementReplicationActor')


def _read(root, relative, expected=None):
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Additional initial Actor source is missing or outside its bound')
    raw = path.read_bytes(); digest = hashlib.sha256(raw).hexdigest()
    if expected is not None and digest != expected:
        raise ValueError('Additional initial Actor source SHA256 mismatch')
    return raw, digest


def qualified_additional_initial_role_sources(root):
    root = Path(root).resolve(strict=True)
    raw, digest = _read(root, SPEC_PATH)
    document = json.loads(raw)
    if (document.get('kind') != 'qualified_additional_initial_actor_templates' or
            document.get('client_sha256') != CLIENT_SHA256 or document.get('roles') != list(ROLES)):
        raise ValueError('Additional Actor specification does not match the observed client roles')
    pins = {SPEC_PATH: digest}
    metadata, metadata_sha = _read(root, document['metadata_relative_path'], document['metadata_sha256'])
    pins[document['metadata_relative_path']] = metadata_sha
    interfaces, interface_sha = _read(root, document['interfaces_relative_path'], document['interfaces_sha256'])
    pins[document['interfaces_relative_path']] = interface_sha
    observations = json.loads(interfaces)
    if observations.get('client_sha256') != CLIENT_SHA256:
        raise ValueError('Initial template interface snapshot belongs to another client')
    roots = json.loads(metadata).get('roots', {})
    for role, cls in (('PlayerState', 'BP_SOLPlayerState_C'), ('MovementReplicationActor', 'MovementReplicationActor')):
        candidates = [r for r in roots.get('named_template_candidates', []) if r.get('class_name') == cls]
        members = [r for r in observations.get('observations', []) if r.get('class_name') == cls]
        if (len(candidates) != 1 or len(members) != 1 or
                members[0].get('candidate_path') != candidates[0]['asset_path'] or
                members[0].get('identity_and_fields_rechecked') is not True or
                members[0].get('status') != 'observed_absent_interface' or
                members[0].get('implements_netrep_actor_interface') is not False or
                members[0].get('actor_open_tail_empty') is not True):
            # An implemented writer requires its own recovered header grammar.
            raise ValueError(role + ' requires a qualified interface-free Actor-open profile')
        hook = candidates[0].get('actor_channel_open_hook', {})
        if (hook.get('identity_rechecked') is not True or hook.get('inside_pinned_image') is not True or
                hook.get('target_rva') != members[0].get('actor_open_target_rva')):
            raise ValueError(role + ' has an unqualified Actor-channel open tail')
    for relative in ('work/native_additional_initial_roles.py', 'work/native_actor_bootstrap.py'):
        _, actual = _read(root, relative); pins[relative] = actual
    if pins['work/native_additional_initial_roles.py'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('Additional Actor factory was imported from another checkout')
    return pins


def prepare_additional_initial_roles(root, source_pins, *, common_arguments):
    root = Path(root).resolve(strict=True)
    pins = qualified_additional_initial_role_sources(root)
    if any(source_pins.get(path) != digest for path, digest in pins.items()):
        raise ValueError('Additional initial Actor sources are outside the launch seal')
    document = json.loads(_read(root, SPEC_PATH, pins[SPEC_PATH])[0])
    raw, digest = _read(root, document['metadata_relative_path'], document['metadata_sha256'])
    prepared = {}
    # These are distinct local allocations, not IDs taken from the official match.
    for role, allocated in (('PlayerState', (27, 29, 31, 8, 5)),
                            ('MovementReplicationActor', (33, 35, 37, 10, 6))):
        package, cls, template, actor, channel = allocated
        prepared[role] = build_initial_actor_bootstrap(raw, role=role,
            source_relative_path=document['metadata_relative_path'], source_sha256=digest,
            package_guid=package, class_guid=cls, archetype_guid=template,
            actor_guid=actor, channel_index=channel, **common_arguments)
    if qualified_additional_initial_role_sources(root) != pins:
        raise ValueError('Additional Actor sources changed during preparation')
    return prepared
