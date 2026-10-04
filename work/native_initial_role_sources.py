"""Pinned, offline PC/GameState source selection for property-free bootstrap.

Archived reports qualify paths and identities only within their own document.
They are not current-process object identities or evidence of native acceptance.
The current report wins. An archive is considered only when a Class or named
template is absent; malformed, duplicate or unsupported current data is refused.
No process, native callback, network endpoint or game installation is accessed.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import MappingProxyType

from native_actor_bootstrap import (
    CLIENT_SHA256, MAX_METADATA_REPORT_BYTES, ROLE_CLASSES,
    InitialActorBootstrap,
    _identity, _invalid_constant, _json_object, _metadata_actor, _report,
    _rows, _source_pin,
)


INITIAL_ROLE_CONFIG_RELATIVE_PATH = 'outputs/df-local-server/protocol/local_initial_role_sources.json'
INITIAL_ROLE_CONFIG_SHA256 = '56b2db68a950c56c9bef692932b2310fa08dec5b05dabf961f5bbf825dac404c'
ARCHIVE_ROLES = ('PlayerController', 'GameState')
MAX_CONFIG_BYTES = 32 * 1024


@dataclass(frozen=True)
class ArchivedRoleSource:
    metadata_report: bytes
    source_relative_path: str
    source_sha256: str


@dataclass(frozen=True)
class InitialRoleSources:
    config_relative_path: str
    config_sha256: str
    roles: MappingProxyType


@dataclass(frozen=True)
class InitialRoleSource:
    role: str
    metadata_report: bytes
    source_relative_path: str
    source_sha256: str
    provenance: str
    fallback_reason: str | None
    bootstrap: InitialActorBootstrap

    def summary(self):
        return {
            'role': self.role,
            'source_relative_path': self.source_relative_path,
            'source_sha256': self.source_sha256,
            'provenance': self.provenance,
            'fallback_reason': self.fallback_reason,
            'current_process_identity_claimed': self.provenance == 'current_process_metadata',
            'native_acceptance': False,
            'possession_verified': False,
        }


def _role(role):
    if type(role) is not str or role not in ARCHIVE_ROLES:
        raise ValueError('Only PlayerController and GameState archive roles are supported')


def _read_pinned(project_root, relative_path, sha256, *, max_bytes):
    _source_pin(relative_path, sha256, verified=False)
    root = Path(project_root).resolve(strict=True)
    path = (root / relative_path).resolve(strict=True)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError('Pinned source must resolve inside the project root') from error
    if not path.is_file():
        raise ValueError('Pinned source must be a regular file')
    with path.open('rb') as stream:
        raw = stream.read(max_bytes + 1)
    if not 0 < len(raw) <= max_bytes:
        raise ValueError('Pinned source exceeds its explicit byte budget or is empty')
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError('Pinned source bytes disagree with the sealed SHA256')
    return raw


def load_initial_role_sources(project_root, *, config_relative_path, config_sha256):
    """Read a sealed config and bounded same-build archived reports once.

    The caller must pin the config and report files in its own source sealing.
    These immutable byte copies remain qualified even if a later process has
    different addresses. No archive object address is exposed for live access.
    """
    raw = _read_pinned(project_root, config_relative_path, config_sha256,
                       max_bytes=MAX_CONFIG_BYTES)
    try:
        config = json.loads(raw, object_pairs_hook=_json_object,
                            parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError('Initial role source config is malformed or ambiguous') from error
    if (type(config) is not dict or set(config) != {'kind', 'client_sha256', 'roles'} or
            config['kind'] != 'pinned_initial_role_metadata_sources' or
            config['client_sha256'] != CLIENT_SHA256):
        raise ValueError('An exact config for the pinned Shipping build is required')
    roles = config['roles']
    if (type(roles) is not dict or not roles or
            any(type(role) is not str or role not in ARCHIVE_ROLES for role in roles)):
        raise ValueError('Config may contain only explicit PlayerController/GameState sources')
    sources, documents = {}, {}
    for role, row in roles.items():
        if (type(row) is not dict or
                set(row) != {'source_relative_path', 'source_sha256'}):
            raise ValueError('Every role source needs an exact relative path and SHA256')
        relative_path, sha256 = row['source_relative_path'], row['source_sha256']
        _source_pin(relative_path, sha256, verified=False)
        identity = (relative_path, sha256)
        if identity not in documents:
            report_raw = _read_pinned(project_root, relative_path, sha256,
                                      max_bytes=MAX_METADATA_REPORT_BYTES)
            roots = _report(report_raw, sha256)
            documents[identity] = (report_raw, roots)
        report_raw, roots = documents[identity]
        # Each role must be uniquely qualified wholly within this source report.
        # The PC open-hook is additionally checked by the existing factory at
        # selection time, with the caller's explicit proven tail profile.
        _metadata_actor(roots, role)
        sources[role] = ArchivedRoleSource(report_raw, relative_path, sha256)
    return InitialRoleSources(config_relative_path, config_sha256,
                              MappingProxyType(sources))


def _missing_role_reason(roots, role):
    name = ROLE_CLASSES[role]
    classes = [row for row in _rows(roots, 'classes') if row.get('name') == name]
    named = _rows(roots, 'named_template_candidates')
    if len(classes) > 1:
        raise ValueError('Ambiguous current Class metadata cannot be replaced by an archive')
    if not classes:
        if any(row.get('class_name') == name for row in named):
            raise ValueError('Current template has no matching Class metadata')
        return 'missing_class'
    klass = classes[0]
    _identity(klass)
    path = klass.get('asset_path')
    if (type(path) is not str or not path.startswith('/') or path.count('.') != 1 or
            ':' in path or not path.endswith('.' + name)):
        raise ValueError('Current Class path is not a complete observed package Class path')
    candidates = [row for row in named if row.get('class_name') == name or
                  row.get('class_address') == klass['address']]
    if len(candidates) > 1:
        raise ValueError('Ambiguous current template metadata cannot be replaced by an archive')
    return 'missing_template' if not candidates else None


def select_initial_role_source(current_metadata_report, *, role,
        current_source_relative_path, current_source_sha256, factory_arguments,
        archive_sources=None):
    """Select one complete source and preflight it through the existing factory.

    ``factory_arguments`` is the caller's explicit GUID/Level/network/tail
    argument dict excluding role, metadata bytes and metadata source pins. All
    current data is validated first. Only absent Class/template permits fallback;
    any duplicate, wrong hook, invalid path, binding or factory failure propagates.
    """
    _role(role)
    _source_pin(current_source_relative_path, current_source_sha256, verified=True)
    roots = _report(current_metadata_report, current_source_sha256)
    if type(factory_arguments) is not dict or any(key in factory_arguments for key in (
            'role', 'metadata_report', 'source_relative_path', 'source_sha256')):
        raise ValueError('Factory arguments must exclude role and metadata source fields')
    if archive_sources is not None and type(archive_sources) is not InitialRoleSources:
        raise ValueError('Archive sources must be the sealed loader result')
    reason = _missing_role_reason(roots, role)
    if reason is None:
        raw, path, sha = (current_metadata_report, current_source_relative_path,
                          current_source_sha256)
        provenance = 'current_process_metadata'
    else:
        if archive_sources is None or role not in archive_sources.roles:
            raise ValueError('Current ' + role + ' metadata is absent and no sealed source is configured')
        source = archive_sources.roles[role]
        raw, path, sha = source.metadata_report, source.source_relative_path, source.source_sha256
        if reason == 'missing_template':
            archive_roots = _report(raw, sha)
            _, archive_class_path, _, _, _, _ = _metadata_actor(archive_roots, role)
            current_class = next(row for row in roots['classes']
                                 if row.get('name') == ROLE_CLASSES[role])
            if current_class['asset_path'] != archive_class_path:
                raise ValueError('Archive Class path disagrees with the observed current Class path')
        provenance = 'archive_same_build_not_current_process'
    # Resolve the factory at call time so runner integration may replace the
    # construction call without replacing this module's report validation.
    import native_actor_bootstrap
    bootstrap = native_actor_bootstrap.build_initial_actor_bootstrap(raw, role=role,
        source_relative_path=path, source_sha256=sha, **factory_arguments)
    return InitialRoleSource(role, raw, path, sha, provenance, reason, bootstrap)
