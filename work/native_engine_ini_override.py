"""Reversible, launch-only shadow Engine.ini overrides for proved native CVars.

Token contents are opaque. Only private backups contain original file bytes.
No process is opened and writing the INI never proves a runtime CVar changed.
"""
from pathlib import Path
import codecs
import hashlib
import json
import os
import re
import tempfile
import uuid


RELATIVE_PATH = Path('DeltaForce/Saved/Config/WindowsClient/Engine.ini')
MAX_CONFIG_BYTES = 1024 * 1024
REPARSE = 0x400


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _paths(source_root, shadow_root):
    shadow_root = Path(shadow_root)
    if shadow_root.exists() and (shadow_root.is_symlink() or
            getattr(shadow_root.lstat(), 'st_file_attributes', 0) & REPARSE):
        raise ValueError('Engine override refuses a redirected shadow root')
    source_root, shadow_root = Path(source_root).resolve(), shadow_root.resolve()
    if source_root == shadow_root or shadow_root.is_relative_to(source_root):
        raise ValueError('Engine override requires an independent shadow root')
    lexical = shadow_root / RELATIVE_PATH
    target = lexical.resolve()
    if not target.is_relative_to(shadow_root) or target != lexical:
        raise ValueError('Engine override target escaped or redirected from the shadow root')
    # A replace must affect this exact directory entry, never a junction target.
    for path in (shadow_root, *reversed(lexical.parents[:-1]), lexical):
        if path.is_relative_to(shadow_root) and path.exists():
            stat = path.lstat()
            if path.is_symlink() or getattr(stat, 'st_file_attributes', 0) & REPARSE:
                raise ValueError('Engine override refuses redirected shadow path components')
    source = (source_root / RELATIVE_PATH).resolve()
    if target == source or target.is_relative_to(source_root):
        raise ValueError('Engine override would address the source installation')
    return source_root, shadow_root, source, target


def _file(path):
    if not path.exists():
        if path.is_symlink():
            raise ValueError('Engine configuration is a dangling link')
        return {'exists': False}, None
    before = path.stat()
    if not path.is_file() or before.st_size > MAX_CONFIG_BYTES:
        raise ValueError('Engine configuration is not a bounded regular file')
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink)
    if identity(before) != identity(after) or len(raw) != after.st_size:
        raise ValueError('Engine configuration changed during precondition capture')
    return {'exists': True, 'sha256': _digest(raw), 'bytes': len(raw),
            'identity': list(identity(after))}, raw


def capture_engine_ini_precondition(source_root, shadow_root, *,
                                    disable_device_seamless=False,
                                    disable_dynamic_address_switch=False,
                                    enable_sol_map_entry_loading=False):
    if any(type(flag) is not bool for flag in (disable_device_seamless,
            disable_dynamic_address_switch, enable_sol_map_entry_loading)):
        raise ValueError('Engine override requests must be explicit booleans')
    if not (disable_device_seamless or disable_dynamic_address_switch or enable_sol_map_entry_loading):
        return None
    source_root, shadow_root, source, target = _paths(source_root, shadow_root)
    source_file, _ = _file(source)
    target_file, _ = _file(target)
    return {'kind': 'shadow_engine_ini_precondition_v1', 'source_root': str(source_root),
            'shadow_root': str(shadow_root), 'target_relative_path': RELATIVE_PATH.as_posix(),
            'source_file': source_file, 'target_file': target_file,
            'disable_device_seamless': disable_device_seamless,
            'disable_dynamic_address_switch': disable_dynamic_address_switch,
            'enable_sol_map_entry_loading': enable_sol_map_entry_loading}


def _render(raw, values, section_name='ConsoleVariables'):
    if raw.startswith(codecs.BOM_UTF8):
        encoding = 'utf-8-sig'
    elif raw.startswith(codecs.BOM_UTF16_LE):
        encoding = 'utf-16-le'
    elif raw.startswith(codecs.BOM_UTF16_BE):
        encoding = 'utf-16-be'
    else:
        encoding = 'utf-8'
    bom = raw[:2] if encoding.startswith('utf-16-') else b''
    body = raw[2:] if bom else raw
    try:
        text = body.decode(encoding, 'strict')
    except UnicodeError as error:
        raise ValueError('Engine configuration encoding is not source-safe UTF text') from error
    if '\x00' in text:
        raise ValueError('Engine configuration has an unsupported text representation')
    newline = '\r\n' if '\r\n' in text else '\n'
    result, active = [], False
    # Remove only the requested keys from the selected native settings section;
    # append one final section. All opaque Token and unrelated lines stay intact.
    for line in text.splitlines(keepends=True):
        section = re.fullmatch(r'\s*\[([^\]\r\n]+)\]\s*', line.rstrip('\r\n'))
        if section:
            active = section.group(1).casefold() == section_name.casefold()
        key = re.match(r'\s*([^;#=\r\n]+)\s*=', line) if active else None
        if key and key.group(1).strip().casefold() in {name.casefold() for name in values}:
            continue
        result.append(line)
    text = ''.join(result)
    if text and not text.endswith(('\r', '\n')):
        text += newline
    text += newline + '[' + section_name + ']' + newline
    text += ''.join(name + '=' + str(value) + newline for name, value in values.items())
    return bom + text.encode(encoding), encoding, newline


def _replace(path, raw):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.codex-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Replacement of the directory entry deliberately detaches hard links.
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class ShadowEngineIniOverride:
    def __init__(self, source_root, shadow_root, backup_folder, *, expected_precondition,
                 disable_device_seamless=False, disable_dynamic_address_switch=False,
                 enable_sol_map_entry_loading=False):
        self.flags = {'disable_device_seamless': disable_device_seamless,
                      'disable_dynamic_address_switch': disable_dynamic_address_switch,
                      'enable_sol_map_entry_loading': enable_sol_map_entry_loading}
        self.source_root, self.shadow_root, self.source, self.target = _paths(source_root, shadow_root)
        self.expected = expected_precondition
        if self.expected is None or self._capture() != self.expected:
            raise ValueError('Engine configuration precondition changed before launch')
        self.folder = Path(backup_folder)
        self.original = self.written = self.written_signature = None
        self.lock = self.target.with_name(self.target.name + '.codex-trial.lock')
        self.lock_bytes = json.dumps({'helper_pid': os.getpid(), 'nonce': uuid.uuid4().hex}).encode('ascii')
        self.locked = self.applied = False
        self.report = {'status': 'not_applied', 'helper_pid': os.getpid(),
                       'target_relative_path': RELATIVE_PATH.as_posix(),
                       'shadow_root': str(self.shadow_root), 'source_file_written': False,
                       'runtime_cvar_effect_verified': False, 'original_bytes_restored': False,
                       'process_owned_root_conflict': False, 'modified_fields': []}

    def _capture(self):
        return capture_engine_ini_precondition(self.source_root, self.shadow_root, **self.flags)

    def _save(self):
        if self.folder.is_dir():
            _replace(self.folder / 'manifest.json', (json.dumps(self.report, indent=2) + '\n').encode('utf-8'))

    def _check_source(self):
        observed = _file(self.source)[0]
        expected = self.expected['source_file']
        # Replacing the shadow directory entry can lower the source's link count
        # when both initially shared an inode. Its bytes/inode/mtime must not change.
        if observed.get('exists') and expected.get('exists'):
            observed, expected = dict(observed), dict(expected)
            observed['identity'] = observed['identity'][:4]
            expected['identity'] = expected['identity'][:4]
        if observed != expected:
            raise ValueError('Source configuration identity changed; source is never overwritten')

    def apply(self):
        self.target.parent.mkdir(parents=True, exist_ok=True)
        _paths(self.source_root, self.shadow_root)
        try:
            with self.lock.open('xb') as stream:
                stream.write(self.lock_bytes)
            self.locked = True
        except FileExistsError as error:
            self.report.update(status='refused', process_owned_root_conflict=True)
            raise ValueError('Another process-owned Engine override lock exists') from error
        try:
            if self._capture() != self.expected:
                raise ValueError('Engine configuration precondition changed before replacement')
            signature, raw = _file(self.target)
            self.original = raw
            values = {}
            if self.flags['disable_device_seamless']:
                values['Game.DisableDeviceSeamless'] = 1
            if self.flags['disable_dynamic_address_switch']:
                values['dualChannel.EnableSwitchIpAddressDynamic'] = 0
            self.written, encoding, newline = _render(raw or b'', values)
            if self.flags['enable_sol_map_entry_loading']:
                # The first ConsoleVariables trial remained at native value 0.
                # This build's SystemSettings loader 0x1301ab80 -> 0x1301b600
                # -> 0x1301cef0 -> 0x10ad6340 applies the existing native CVar.
                # It does not alter a guessed numeric map type or process memory.
                sol_values = {'r.Loading.EnableSOLMapEntryLoading': 1}
                self.written, encoding, newline = _render(self.written, sol_values, 'SystemSettings')
                values.update(sol_values)
            self.folder.mkdir(parents=True, exist_ok=False)
            if raw is not None:
                with (self.folder / 'Engine.ini.original.bin').open('xb') as stream:
                    stream.write(raw)
            self.report.update(original_exists=raw is not None,
                original_sha256=signature.get('sha256'), original_bytes=signature.get('bytes', 0),
                written_sha256=_digest(self.written), written_bytes=len(self.written),
                encoding=encoding, newline='CRLF' if newline == '\r\n' else 'LF',
                original_link_count=signature.get('identity', [None]*5)[4],
                modified_fields=list(values), status='backed_up_before_replace')
            self._save()
            if self._capture() != self.expected:
                raise ValueError('Engine configuration changed while backing it up')
            _replace(self.target, self.written)
            self.applied = True
            self.written_signature = _file(self.target)[0]
            if self.written_signature.get('sha256') != _digest(self.written):
                raise ValueError('Written shadow configuration changed immediately')
            self._check_source()
            self.report['status'] = 'shadow_override_written_runtime_unverified'
            self._save()
            return dict(self.report)
        except Exception:
            self.report['status'] = 'apply_failed'
            self._save()
            raise

    def restore(self):
        try:
            was_applied = self.applied
            if self.applied:
                _paths(self.source_root, self.shadow_root)
                current_signature, current_raw = _file(self.target)
                original_already_present = self.original is not None and current_raw == self.original
                if current_signature != self.written_signature and not original_already_present:
                    self.report.update(status='restore_refused_external_change',
                                       process_owned_root_conflict=True)
                    raise ValueError('Shadow Engine configuration changed; private backup retained')
                if self.original is not None and (self.folder / 'Engine.ini.original.bin').read_bytes() != self.original:
                    raise ValueError('Private Engine configuration backup changed')
                if original_already_present:
                    # Startup may restore the exact opaque file itself. Do not rewrite it.
                    self._check_source()
                    self.report['restoration_action'] = 'no_write_original_already_present'
                elif self.original is None:
                    self.target.unlink()
                    self.report['restoration_action'] = 'remove_created_file'
                else:
                    _replace(self.target, self.original)
                    self.report['restoration_action'] = 'atomic_replace_original_bytes'
                self.applied = False
                if _file(self.target)[1] != self.original:
                    raise ValueError('Shadow Engine configuration exact-byte restoration failed')
                self._check_source()
            if self.locked:
                if self.lock.read_bytes() != self.lock_bytes:
                    raise ValueError('Process-owned Engine override lock changed')
                self.lock.unlink()
                self.locked = False
            self.report.update(status=('restored_exact_original_bytes' if was_applied else 'no_override_was_applied'),
                               original_bytes_restored=was_applied)
            self._save()
            return dict(self.report)
        except Exception:
            if self.report['status'] != 'restore_refused_external_change':
                self.report.update(status='restore_refused', process_owned_root_conflict=True)
            self._save()
            raise
