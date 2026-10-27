"""Freeze source-derived skill rows and persistent IDs for one actual admission."""
import hashlib
import json

from dfserver.legacy_ds_match_admission import LocalMatchTicket
from portable_map_skill_player_index import InitialSkillPlayerAssignment
from skill_entity_id_ledger import SkillEntityIdLedger
from skill_initial_state_values import freeze_initial_grant, required_entity_id_count


def prepare_grant(schema, *, ticket, assignment, ledger):
    if (type(ticket) is not LocalMatchTicket or type(assignment) is not InitialSkillPlayerAssignment
            or type(ledger) is not SkillEntityIdLedger
            or type(ticket.cookie) is not str or not 0 < len(ticket.cookie) <= 256
            or type(ticket.loadout_snapshot) is not bytes
            or not 0 < len(ticket.loadout_snapshot) <= 1024*1024
            or any(type(value) is not int or not 0 < value < 1 << 64
                   for value in (ticket.room_id, ticket.player_id))
            or assignment.room_id != str(ticket.room_id)
            or assignment.participant_uid != ticket.player_id):
        raise ValueError('The actual frozen admission, roster and service ID ledger are required')
    snapshot = json.loads(ticket.loadout_snapshot)
    if (type(snapshot) is not dict or snapshot.get('selected_hero_id') != ticket.selected_hero_id
            or snapshot.get('selected_fashion_id') != ticket.selected_fashion_id):
        raise ValueError('Skill grants and carried appearance must share the frozen admission')
    # Validate the complete source plan and roster before consuming any IDs.
    freeze_initial_grant(schema, assignment=assignment, hero_id=ticket.selected_hero_id,
                         first_entity_unique_id=1)
    count = required_entity_id_count(schema, ticket.selected_hero_id)
    context = dict(schema_sha256=hashlib.sha256(
        (json.dumps(schema, sort_keys=True, indent=2)+'\n').encode()).hexdigest(),
        room_id=ticket.room_id, participant_uid=ticket.player_id, map_id=ticket.map_id,
        match_mode_id=ticket.match_mode_id, hero_id=ticket.selected_hero_id,
        snapshot_sha256=hashlib.sha256(ticket.loadout_snapshot).hexdigest())
    first = ledger.reserve(hashlib.sha256(ticket.cookie.encode()).hexdigest(),
        hashlib.sha256(json.dumps(context, sort_keys=True, separators=(',', ':')).encode()).hexdigest(), count)
    return freeze_initial_grant(schema, assignment=assignment,
        hero_id=ticket.selected_hero_id, first_entity_unique_id=first)
