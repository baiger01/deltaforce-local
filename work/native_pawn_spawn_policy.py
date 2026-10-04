"""One local, autonomous Pawn policy, resolved only after its ticket joins.

These are server-owned initial conditions, not replayed official state. The
connection starts with no primary/focus Actor references. Control/possession
is a subsequent step, not a consequence of serializing this initial flag byte.
"""
import hashlib
import json
from pathlib import Path

POLICY_PATH = 'outputs/df-local-server/protocol/local_pawn_spawn_policy.json'
INTERFACE_PATH = 'work/official-interface-observations/1791043432995-pid243608/result.json'
INTERFACE_SHA256 = 'dd5a951133d77361d2bb791a5aba5fa12d764acff4cef9127f204708b862462d'
CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
STATE_SOURCE = 'work/evidence/native-spawn-role-and-connection-semantics.json'
STATE_SOURCE_SHA256 = 'd5d0b0f6ee99928980095650f35641346707062872ffdf95305e0d7c8d2234ba'


def _sealed_bytes(root, relative, pins):
    path = (Path(root).resolve() / relative).resolve()
    if not path.is_relative_to(Path(root).resolve()) or not 0 < path.stat().st_size <= 1024 * 1024:
        raise ValueError('Local Pawn source must remain inside the bounded project')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pins.get(relative):
        raise ValueError('Local Pawn source changed after preparation')
    return raw


def load_local_pawn_policy(root, pins):
    policy = json.loads(_sealed_bytes(root, POLICY_PATH, pins))
    if (type(policy) is not dict or policy.get('kind') != 'local_owned_initial_pawn_policy' or
            policy.get('client_sha256') != CLIENT_SHA256 or
            type(policy.get('map_id')) is not int or policy['map_id'] != 2201 or
            type(policy.get('actor_guid')) is not int or policy['actor_guid'] != 2 or
            type(policy.get('remote_role')) is not int or policy['remote_role'] != 2 or
            policy.get('replication_enabled') is not True or
            policy.get('owner_policy') != 'admitted_ticket_player' or
            policy.get('connection_actor_guid', 'missing') is not None or
            policy.get('connection_focus_target_guids') != [] or
            policy.get('state_origin') != 'local_server_configuration_not_official_packet_values' or
            policy.get('native_spawn_verified') is not False or
            policy.get('interface_source') != {'relative_path': INTERFACE_PATH, 'sha256': INTERFACE_SHA256}):
        raise ValueError('Unsupported local initial Pawn state/connection policy')
    raw = _sealed_bytes(root, INTERFACE_PATH, pins)
    if hashlib.sha256(raw).hexdigest() != INTERFACE_SHA256:
        raise ValueError('Local Pawn interface observation does not match its source')
    if hashlib.sha256(_sealed_bytes(root, STATE_SOURCE, pins)).hexdigest() != STATE_SOURCE_SHA256:
        raise ValueError('Local Pawn role semantics do not match their source')
    return policy


def build_local_pawn_resolver(root, pins, metadata_raw, pawn_arguments, expected_policy):
    from native_actor_bootstrap import QualifiedGameSpawnProfile, build_pawn_actor_bootstrap
    from dfserver.legacy_ds_match_admission import LocalMatchTicket

    policy = load_local_pawn_policy(root, pins)
    if policy != expected_policy:
        raise ValueError('Local Pawn policy changed between launch and preparation')
    interface_raw = _sealed_bytes(root, INTERFACE_PATH, pins)
    arguments = dict(pawn_arguments)
    if arguments.get('actor_guid') != policy['actor_guid']:
        raise ValueError('The local Pawn policy must name the actual allocated Actor')

    def resolve(joined_ticket, actor_fields):
        # The caller has verified this exact admission, Join and generation.
        if type(joined_ticket) is not LocalMatchTicket or joined_ticket.map_id != policy['map_id']:
            raise ValueError('Pawn policy requires the exact local map ticket')
        if (type(actor_fields) is not tuple or any(type(row) is not dict or
                type(row.get('actor_guid')) is not int or row['actor_guid'] <= 0 for row in actor_fields)):
            raise ValueError('The admitted bootstrap requires complete Actor field dictionaries')
        if sum(row.get('actor_guid') == policy['actor_guid']
                                                 for row in actor_fields) != 1:
            raise ValueError('The admitted bootstrap needs exactly one allocated Pawn')
        owner_ticket = joined_ticket  # This local server assigns its new Pawn to this player.
        profile = QualifiedGameSpawnProfile(interface_report=interface_raw,
            source_relative_path=INTERFACE_PATH, source_sha256=INTERFACE_SHA256,
            original_state_u8=policy['remote_role'], actor_byte93_mask20=policy['replication_enabled'],
            owner_connection_match=owner_ticket is joined_ticket, connection_present=True,
            actor_is_connection_actor=policy['actor_guid'] == policy['connection_actor_guid'],
            actor_in_connection_actor_array=policy['actor_guid'] in policy['connection_focus_target_guids'])
        prepared = build_pawn_actor_bootstrap(metadata_raw, **arguments, game_spawn_profile=profile)
        # This policy supports only the first owned autonomous spawn. It cannot
        # silently discard a state transition required by another observer.
        if prepared.game_spawn_result.effective_state_u8 != policy['remote_role']:
            raise ValueError('A state transition needs an explicit persistent Actor model')
        result = []
        for row in actor_fields:
            if row['actor_guid'] != policy['actor_guid']:
                result.append(dict(row))
                continue
            new_fields = dict(prepared.preflight.actor_fields)
            old_fields = dict(row)
            for fields in (old_fields, new_fields):
                fields.pop('game_replication_flags', None)
            if old_fields != new_fields:
                raise ValueError('Pawn policy cannot change the registered export graph or Actor fields')
            result.append(dict(prepared.preflight.actor_fields))
        return tuple(result)

    return resolve
