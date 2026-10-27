"""Bind switch authority to the exact final frozen weapon initialization graph."""
import hashlib

from dfserver.legacy_ds_owner_switch import OwnerSwitchProfile, OwnerSwitchDecision
from portable_carried_weapon_selection import select, binding as selection_binding
from portable_modular_weapon_initialization import initialize, schema_binding
from portable_modular_weapon_recipe import build as build_recipes
from portable_weapon_equipment_position import project_equipment_positions
from portable_weapon_switch_timeline import build as build_timeline, source_pins as timeline_sources
from portable_weapon_switch_runtime import (OwnerSwitchRuntimeBinding, seed_from_initial_timeline,
    source_generation_digest, receive_admitted, source_pins as runtime_sources)
from weapon_native_default_slot import native_default_slot_policy
from weapon_switch_timeline_codec import LocalInitialSwitchClock, ROOT
from portable_source_guard import SourceGuard


def source_pins():
    pins = timeline_sources()
    for name, digest in runtime_sources().items():
        if name in pins and pins[name] != digest:
            raise ValueError('The initial weapon graph and switch authority sources disagree')
        pins[name] = digest
    for name in ('work/portable_owner_switch_profile.py', 'work/portable_source_guard.py',
                 'outputs/df-local-server/dfserver/legacy_ds_owner_switch.py'):
        pins[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    return pins


def make_profile(ticket, manifests, plans, *, pawn_guid, empty_hand_guid, initial_policy, clock_policy):
    pins = tuple(sorted(source_pins().items()))
    parent, = [p for p in plans if p['actor_guid'] == pawn_guid]
    components = {u.name: u for u in parent.get('default_subobjects', ())}
    manager, replicate = (components[n] for n in ('WeaponManager', 'WeaponReplicate'))
    guns = select(ticket).guns
    from portable_melee_weapon import select as select_melee
    melee = select_melee(ticket)
    melee_actors = () if melee is None else tuple(m for m in manifests if m.class_path == melee.class_path)
    if melee is not None and len(melee_actors) != 1:
        raise ValueError('The selected melee Actor must be present in the complete owner switch graph')
    modular = schema_binding()['actor']['class_path']
    physical = tuple(m for m in manifests if m.class_path == modular)
    if len(physical) != len(guns):
        raise ValueError('The owner switch graph must contain the whole admitted equipped gun set')
    allocations = tuple((gun.inventory_gid, manifest.actor_guid) for gun, manifest in zip(guns, physical))
    slots = selection_binding()['business_slots']
    chosen = next((gun for name in initial_policy['priority'] for gun in guns
        if gun.business_position == slots[name]), None)
    initialized = initialize(ticket, pawn_guid=pawn_guid, empty_hand_guid=empty_hand_guid,
        gun_allocations=allocations, manager_component_guid=manager.guid,
        replicate_component_guid=replicate.guid, pawn_open_acknowledged=True,
        weapon_opens_acknowledged=True, initial_state_is_fresh=True,
        manager_binding_snapshot_complete=True, native_slot_policy=native_default_slot_policy(),
        initial_active_inventory_gid=None if chosen is None else chosen.inventory_gid,
        melee_actor_guid=None if melee is None else melee_actors[0].actor_guid)
    by_actor = {p['actor_guid']: p for p in plans}
    tails = parent.get('continuations', ())
    for stage in initialized.stages:
        if stage.actor_content is not None:
            if by_actor[stage.actor_guid]['content_blocks'] != (stage.actor_content,):
                raise ValueError('The actual admitted weapon identity or owner differs from its frozen snapshot')
        elif sum(group == stage.updates for group in tails) != 1:
            raise ValueError('The complete initial manager binding stage must appear exactly once')
    actors = tuple(m.actor_guid for m in manifests)
    recipes = build_recipes(ticket, gun_allocations=allocations, known_actor_guids=actors,
        actor_opens_acknowledged=True, identity_and_owner_acknowledged=True,
        initial_state_is_fresh=True, max_packet_bytes=1024)
    positions = project_equipment_positions(ticket, initialization=initialized,
        recipe_updates=recipes, known_actor_guids=actors)
    for recipe, position in zip(recipes, positions):
        groups = by_actor[recipe.actor_guid].get('continuations', ())
        if groups[:2] != ((recipe.actor_content,), (position.actor_content,)):
            raise ValueError('The exact weapon recipe and native equipment position must precede switch authority')
    switch = build_timeline(ticket, pawn_guid=pawn_guid, manager_component_guid=manager.guid,
        replicate_component_guid=replicate.guid, initialization=initialized,
        known_actor_guids=actors, recipe_updates=recipes,
        clock=LocalInitialSwitchClock(clock_policy['frame_no'], clock_policy['world_time']),
        actor_opens_acknowledged=True, all_initialization_stages_acknowledged=True,
        complete_recipes_acknowledged=True, initial_state_is_fresh=True, max_packet_bytes=1024)
    if sum(group == (switch.update,) for group in tails) != 1:
        raise ValueError('The exact initial owner timeline must appear once in the final admission plan')
    binding = OwnerSwitchRuntimeBinding(hashlib.sha256(ticket.cookie.encode()).hexdigest(), 0,
        pawn_guid, parent['channel_index'], manager.guid,
        tuple((b.unique_id, b.pair.weapon_slot) for b in initialized.bindings),
        source_generation_digest(), True, True)
    seed = seed_from_initial_timeline(binding, switch.timeline)

    def consume(state, bunch, receipt, elapsed):
        decision = receive_admitted(binding, state, bunch, receipt,
            server_frame_no=state.semantic.server_frame_no + 1,
            server_world_time=elapsed, max_packet_bytes=1024)
        return OwnerSwitchDecision(decision.state, decision.update, decision.disposition, decision.duplicate)

    current = SourceGuard(ROOT, dict(pins))

    return OwnerSwitchProfile(parent['channel_index'], pawn_guid, manager.guid, seed, consume, current)
