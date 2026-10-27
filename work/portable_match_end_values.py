"""Source-qualified PlayerMatchInfo values for a committed local match result.

The caller owns terminal-condition validation, persistence, the admitted owning
PlayerState channel, and actual ACK ordering. A digest is a result identity;
this pure codec cannot prove that its caller committed a result. It neither
ends a match nor sends a packet. Native packet acceptance remains unverified.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter


ROOT = Path(__file__).resolve().parent.parent
CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MANIFEST_SHA256 = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
CLASS_PATH = '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C'
EVIDENCE = 'work/evidence/map-system-audit-20261018/'
CAPTURE = 'work/native-client-tests/1792343957590810500/portable-runtime-after-possession.json'
FIXED_PINS = {
    CAPTURE: 'ba74858b94c8983a06ddc2b0be361ab68c31a180664071eb1664566afa6758de',
    EVIDENCE + 'native-economy-world-rpc-struct-ops-records-v2.json':
        '6a01a8fa7b6e41dabbf90b8413088fd67c7f497e844a33563d40efe7c5cdf9c4',
    EVIDENCE + 'native-economy-tag-netserialize-and-player-end-bodies-v1.json':
        '65796850e9b3bc3e131aa066b8dfb9028f9067ec5b6d11dd302fd94010843d25',
    EVIDENCE + 'native-economy-match-end-enum-and-delegate-class-v1.json':
        '9340c43aee1aac740f2d7b81129b1177218588dd959389379cc322f8019fc595',
}
REASONS = dict(zip(('Escaped', 'Dead', 'TimeOver', 'Quit', 'GiveUp',
    'Complete', 'Fail', 'MatchEnd', 'BlastingRedScreenQuit'), range(9)))


@dataclass(frozen=True)
class CommittedTerminalResult:
    room_id: int
    player_id: int
    result_sha256: str
    reason_name: str


def _sources():
    result = {}
    for relative, expected in FIXED_PINS.items():
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Changed match-end source: ' + relative)
        result[relative] = json.loads(raw)
    return result


def source_pins():
    """Validate exact native metadata and expose only portable file identities."""
    docs = _sources()
    actual = docs[CAPTURE]['primary_controller_views'][0]['player_state_replication_metadata']
    if (actual['class_asset_path'] != CLASS_PATH or
            actual['layout_status'] != 'exported_existing' or
            actual['native_getter_invoked'] is not False):
        raise ValueError('The observed owning PlayerState receiver changed')
    commands = actual['layout']['commands']
    for name, handle, opcode, offset, target in (
            ('bMatchOver', 170, 21, 0xba8, 0x10e8ebe0),
            ('MatchOverReason', 171, 6, 0xba9, 0x10e29fa0)):
        rows = [row for row in commands if row.get('descriptor_name') == name]
        if len(rows) != 1:
            raise ValueError('The match-end property is missing or ambiguous')
        row = rows[0]
        hook = row['property_serializer_hook']
        if ((row['relative_handle'], row['dispatch_opcode'], row['data_offset'],
                row['parent_index'], hook['target_rva']) !=
                (handle, opcode, offset, 86, target) or
                hook['target_module_sha256'] != CLIENT_SHA256 or
                hook['identity_rechecked'] is not True):
            raise ValueError('The actual match-end property serializer changed')
    enum_doc = docs[EVIDENCE + 'native-economy-world-rpc-struct-ops-records-v2.json']
    recovered = {row['name'].split('::')[-1]: row['value']
        for row in enum_doc['match_over_enum']['entries']}
    if (enum_doc['client_sha256'] != CLIENT_SHA256 or enum_doc['process_access'] is not False or
            recovered != REASONS):
        raise ValueError('The immutable native match-end enum changed')
    for name in ('native-economy-tag-netserialize-and-player-end-bodies-v1.json',
            'native-economy-match-end-enum-and-delegate-class-v1.json'):
        doc = docs[EVIDENCE + name]
        if (doc['client_sha256'] != CLIENT_SHA256 or
                doc['cache_manifest_sha256'] != MANIFEST_SHA256 or
                doc['process_access'] is not False or doc['client_launched'] is not False):
            raise ValueError('The cached native match-end code identity changed')
    body = docs[EVIDENCE + 'native-economy-tag-netserialize-and-player-end-bodies-v1.json']
    notify = next(row for row in body['functions'] if row['requested_rva'] == '0xb576e80')
    anchors = {(row['rva'], row['mnemonic'], row['operands']) for row in notify['instructions']}
    if not {('0xb576eea', 'cmp', 'byte ptr [rdi + 0xba8], 0'),
            ('0xb5770c7', 'call', '0x73fee20'),
            ('0xb5770d1', 'lea', 'rcx, [rax + 0xb0]'),
            ('0xb5770d8', 'movzx', 'eax, byte ptr [rdi + 0xba9]'),
            ('0xb5770e3', 'call', '0xd96400')} <= anchors:
        raise ValueError('The native match-end notification path changed')
    pins = dict(FIXED_PINS)
    for relative in ('work/portable_match_end_values.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
            'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return pins


def schema_binding():
    pins = source_pins()
    return {'class_path': CLASS_PATH, 'network_version': 13,
        'parent_name': 'PlayerMatchInfo', 'parent_index': 86,
        'match_over_handle': 170, 'reason_handle': 171, 'reason_bits': 4,
        'reasons': dict(REASONS), 'native_notify_rva': '0xb576e80',
        'native_delegate_class': '/Script/DFMGameplay.DFMGameplayDelegates',
        'native_delegate_member_offset': 0xb0,
        'native_packet_acceptance_verified': False, 'source_pins': pins}


def _identity(value):
    return type(value) is int and 0 < value < 1 << 64


def build_match_over_content(terminal, *, admitted_room_id, admitted_player_id):
    """Encode a saved terminal result for its exact admitted room and player."""
    source_pins()
    if (type(terminal) is not CommittedTerminalResult or
            not all(_identity(value) for value in (terminal.room_id, terminal.player_id,
                admitted_room_id, admitted_player_id)) or
            terminal.room_id != admitted_room_id or terminal.player_id != admitted_player_id or
            type(terminal.result_sha256) is not str or
            re.fullmatch('[0-9a-fA-F]{64}', terminal.result_sha256) is None or
            type(terminal.reason_name) is not str or terminal.reason_name not in REASONS):
        raise ValueError('A saved actual terminal result for the admitted room/player is required')
    writer = BitWriter(maximum_bits=46)
    writer.write_bool(False)
    writer.write_packed_int(170)
    writer.write_bool(True)
    writer.write_packed_int(171)
    # Version 13 enum serialization uses ceil(log2(native maximum + 1)).
    # Both the nine declared values and UE's optional generated MAX fit 4 bits.
    writer.write_bits(REASONS[terminal.reason_name], 4)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)
