"""Explicit local normal SafeBox rule over qualified sources and durable SQL state.

Native SafeBoxPwd is empty, but a separate native component generates a password.
The required local rule selects unlocked local normal boxes; it does not claim a
native passwordless default or modify that component. Callers must authenticate
the current admission and validate live references and accepted range separately.
All methods that read or change box authority require the caller's SQL transaction.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

import portable_loot_box_codec as boxes
from portable_world_session import SessionCredential, _json


ROOT = Path(__file__).resolve().parent.parent
SOURCE = 'work/evidence/normal-box-policy-research-20261020-v1/normal-box-policy-contract-v2.json'
SOURCE_SHA256 = '5713991afd4e0baac684fe82f2093e60a1b6361bee19a94047f7660b29703fa5'
LOCAL_NORMAL_UNLOCK_V1 = 'local_normal_unlocked_v1'
SCHEMA = '''
CREATE TABLE IF NOT EXISTS durable_normal_box_state_v1 (
 room_id TEXT NOT NULL, path TEXT NOT NULL, contract_sha256 TEXT NOT NULL,
 local_rule TEXT NOT NULL, baseline_provenance_json TEXT NOT NULL,
 opened INTEGER NOT NULL, opening_player_id TEXT NOT NULL,
 password_required INTEGER NOT NULL, loot_limit_type INTEGER NOT NULL,
 revision INTEGER NOT NULL, PRIMARY KEY(room_id,path));
'''
_PROTECTED = frozenset(('bIsKeyBox', 'bIsOpened', 'bIsOpening', 'OpeningPlayerId',
    'bUseRandomSafeBoxPwd', 'SafeBoxPwd', 'RealSafeBoxPwd', 'LootLimit'))
_CDOS = {
    'BP_InventoryPickupOpenBoxBase': 2,
    'BP_InteractorContainer_BoxBase': 15,
    'BP_Interactor_ContainerBoxBase': 2,
    'BP_Interact_AnimSwitcherContainer': 16,
    'BP_Interactor_Container_SafeBox': 8,
}


def _sources():
    raw = (ROOT / SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError('The qualified normal box source contract changed')
    document = json.loads(raw)
    pins = {SOURCE: SOURCE_SHA256}
    for row in document['source_pins']:
        relative = row['path'].replace('\\', '/')
        data = (ROOT / relative).read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('The qualified normal box source changed: ' + relative)
        pins[relative] = row['sha256']
    qualification = document['qualification']
    if (document['client_sha256'] != boxes.CLIENT_SHA256 or document['process_access'] is not False or
            document['client_launched'] is not False or
            qualification['native_SafeBoxPwd_empty_default'] is not True or
            qualification['native_component_VerifyPassword_state_present'] is not True or
            qualification['native_fully_passwordless_box_claim'] is not False or
            qualification['explicit_local_unlock_rule_required'] is not True):
        raise ValueError('The source qualification must retain the native password component caveat')
    enum = document['loot_limit_enum']
    if [(row['name'].rsplit('_', 1)[-1], row['value']) for row in enum['entries']] != [
            ('Both', 0), ('OnlySource', 1), ('OnlyTarget', 2), ('None', 3)] or enum['lock_state'] is not False:
        raise ValueError('The actual LootLimit transfer direction enum changed')
    for package, export_id in _CDOS.items():
        matches = [row for source in document['packages'] if source['package'] == package
            for row in source['exports'] if row['name'] == 'Default__' + package + '_C']
        if len(matches) != 1 or matches[0]['export'] != export_id or _PROTECTED & matches[0]['serialized_properties'].keys():
            raise ValueError('A qualified normal box inherited policy default changed')
        if package == 'BP_Interactor_Container_SafeBox':
            normal = matches[0]['serialized_properties']['bIsNormalSafeBox']
            if normal['serialized_kind'] != 'BoolProperty' or normal['value'] is not True:
                raise ValueError('The selected source class is not the qualified normal SafeBox')
    return document, pins


def source_pins():
    _, pins = _sources()
    pins['work/portable_normal_box_policy.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return pins


@dataclass(frozen=True)
class QualifiedNormalBoxPolicy:
    unlock_rule: str

    def __post_init__(self):
        if self.unlock_rule != LOCAL_NORMAL_UNLOCK_V1:
            raise ValueError('The explicit versioned local normal box unlock rule is required')
        _sources()

    @property
    def contract_sha256(self):
        return hashlib.sha256(_json(dict(source_contract_sha256=SOURCE_SHA256,
            local_rule=self.unlock_rule)).encode()).hexdigest()

    def source_pins(self):
        return source_pins()

    def qualify_binding(self, binding):
        boxes.qualify_binding(binding)
        document, _ = _sources()
        name = binding.object_path.rsplit(':PersistentLevel.', 1)[-1]
        matches = [row for package in document['packages'] for row in package['exports']
            if row['name'] == name and row['class_name'] == boxes.SAFE_CLASS]
        if (len(matches) != 1 or matches[0]['export'] not in (50, 51, 69) or
                (_PROTECTED | {'bIsNormalSafeBox'}) & matches[0]['serialized_properties'].keys()):
            raise ValueError('The actual selected normal box has no qualified unchanged cooked policy')
        return binding

    def _provenance(self, binding):
        return _json(dict(source_contract=SOURCE, source_contract_sha256=SOURCE_SHA256,
            source_class=boxes.SAFE_CLASS, object_path=binding.object_path,
            local_rule=self.unlock_rule, passwordless_is_local_rule=True,
            native_component_VerifyPassword_state_present=True,
            native_fully_passwordless_box_claim=False))

    def _scope(self, connection, credential, binding):
        if not connection.in_transaction or type(credential) is not SessionCredential:
            raise ValueError('An authenticated durable dispatch SQL transaction is required')
        self.qualify_binding(binding)
        return str(credential.room_id), binding.object_path

    def initialize(self, connection, credential, binding, *, allow_create):
        room, path = self._scope(connection, credential, binding)
        row = connection.execute('SELECT 1 FROM durable_normal_box_state_v1 WHERE room_id=? AND path=?',
            (room, path)).fetchone()
        if row is None:
            opened = connection.execute('SELECT 1 FROM world_open_v1 o JOIN world_session_v1 s '
                'ON s.admission_id=o.admission_id WHERE s.room_id=? AND o.path=?', (room, path)).fetchone()
            previous_profiles = connection.execute('SELECT d.profile_json FROM durable_world_admission_v1 d '
                'JOIN world_session_v1 s ON s.admission_id=d.admission_id '
                'WHERE s.room_id=? AND d.admission_id<>?', (room, credential.admission_id))
            previously_initialized = False
            for previous in previous_profiles:
                profile = json.loads(previous['profile_json'])
                if profile.get('normal_box_policy') is not None and any(
                        value['object_path'] == path for value in profile['bindings'].values()):
                    previously_initialized = True
                    break
            if allow_create is not True or opened is not None or previously_initialized:
                raise ValueError('The persisted normal box state is missing; it cannot be reset')
            connection.execute('INSERT INTO durable_normal_box_state_v1 VALUES (?,?,?,?,?,0,?,0,0,1)',
                (room, path, self.contract_sha256, self.unlock_rule, self._provenance(binding), '0'))
        return self._state(connection, credential, binding)

    def _state(self, connection, credential, binding):
        room, path = self._scope(connection, credential, binding)
        row = connection.execute('SELECT * FROM durable_normal_box_state_v1 WHERE room_id=? AND path=?',
            (room, path)).fetchone()
        if row is None:
            raise ValueError('The persisted normal box state is missing')
        owner = row['opening_player_id']
        if (row['contract_sha256'] != self.contract_sha256 or row['local_rule'] != self.unlock_rule or
                row['baseline_provenance_json'] != self._provenance(binding) or
                type(row['opened']) is not int or row['opened'] not in (0, 1) or
                type(row['password_required']) is not int or row['password_required'] not in (0, 1) or
                type(owner) is not str or not owner.isascii() or not owner.isdecimal() or
                not 0 <= int(owner) < 1 << 64 or str(int(owner)) != owner or
                type(row['loot_limit_type']) is not int or row['loot_limit_type'] not in (0, 1, 2, 3) or
                type(row['revision']) is not int or not 1 <= row['revision'] < 1 << 31):
            raise ValueError('The actual durable normal box policy identity or state is invalid')
        return row

    def authorize(self, connection, credential, binding, *, operation):
        if operation not in ('open', 'browse', 'source_transfer', 'target_transfer'):
            raise ValueError('An implemented explicit normal box operation is required')
        row = self._state(connection, credential, binding)
        owner = int(row['opening_player_id'])
        if row['password_required']:
            raise ValueError('The actual normal box password requirement rejects this operation')
        if owner and (not row['opened'] or owner != credential.player_id):
            raise ValueError('The actual normal box opening owner rejects this operation')
        if operation != 'open' and not row['opened']:
            raise ValueError('The actual normal source box has not been opened')
        if operation == 'source_transfer' and row['loot_limit_type'] not in (0, 1):
            raise ValueError('The actual normal box source transfer direction rejects this operation')
        if operation == 'target_transfer' and row['loot_limit_type'] not in (0, 2):
            raise ValueError('The actual normal box target transfer direction rejects this operation')
        return row

    def mark_open(self, connection, credential, binding):
        row = self.authorize(connection, credential, binding, operation='open')
        if not row['opened']:
            if row['revision'] == (1 << 31) - 1:
                raise ValueError('The durable normal box state revision is exhausted')
            changed = connection.execute('UPDATE durable_normal_box_state_v1 SET opened=1,opening_player_id=?, '
                'revision=revision+1 WHERE room_id=? AND path=? AND revision=? AND opened=0 '
                'AND opening_player_id=? AND password_required=0',
                ('0', str(credential.room_id), binding.object_path, row['revision'], '0')).rowcount
            if changed != 1:
                raise ValueError('The durable normal box opening claim changed')
        return True

    def opened(self, connection, credential, binding):
        return bool(self._state(connection, credential, binding)['opened'])
