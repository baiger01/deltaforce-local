"""Collect a fixed read-only metadata cohort from an already owned trial."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


MAX_TRIAL_REPORT_BYTES = 8 * 1024 * 1024


def _owned_report_bytes(path, game_root, identity):
    from observe_owned_gameplay_metadata import owned_trial_identity
    if (type(identity) is not dict or type(identity.get('pid')) is not int or
            type(identity.get('created_at')) not in (int, float)):
        raise ValueError('One exact owned client identity is required')
    if not 0 < path.stat().st_size <= MAX_TRIAL_REPORT_BYTES:
        raise ValueError('The owned trial snapshot exceeds its fixed read bound')
    with path.open('rb') as stream:
        raw = stream.read(MAX_TRIAL_REPORT_BYTES + 1)
    if not 0 < len(raw) <= MAX_TRIAL_REPORT_BYTES:
        raise ValueError('The owned trial snapshot grew beyond its fixed read bound')
    if owned_trial_identity(json.loads(raw), game_root) != (identity['pid'], identity['created_at']):
        raise ValueError('The owned trial snapshot differs from the requested process identity')
    return raw


def cohort_status(results):
    expected = dict.fromkeys(('portable-hud-guids', 'portable-runtime-after-possession', 'economy-inventory-receive',
        'economy-inventory-gun-receive',
        'economy-inventory-spaces',
        'owned-vitals-metadata', 'owned-weapon-state', 'owned-map-marker-metadata',
        'owned-weapon-current-metadata', 'owned-fsm-metadata', 'owned-weapon-mesh-followup',
        'current-world-actor-membership',
        'current-world-box-guid-mappings', 'owned-pawn-fsm-rpc-layouts',
        'owned-skill-rpc-layouts',
        'owned-skill-entity-metadata', 'world-tag-replication-mode',
        'world-interaction-lifecycle', 'world-interaction-rpc-metadata',
        'economy-loaded-interactors', 'owned-gameplay-metadata'), 'observed')
    expected['portable-after-open-templates'] = 'metadata_export_complete'
    return ('observed' if set(results) == set(expected) and
            all(results[name].get('status') == status for name, status in expected.items()) else 'partial')


def extended_source_pins():
    from observe_owned_skill_entity_metadata import source_pins as entity_sources
    from observe_world_interaction_lifecycle_partial import source_pins as world_sources
    from observe_world_interaction_capacity_scope import source_pins as world_capacity_sources
    from observe_world_tag_replication_mode import source_pins as world_tag_sources
    from observe_world_interaction_rpc_metadata import sources as rpc_sources
    from observe_current_world_actor_membership import source_pins as membership_sources
    from observe_current_world_box_guid_mappings import source_pins as box_guid_sources
    from observe_owned_pawn_fsm_rpc_layouts import source_pins as pawn_fsm_rpc_sources
    from observe_owned_skill_rpc_layouts_v2 import source_pins as skill_rpc_sources
    from observe_portable_hud_guids import observer_source_pins as hud_sources
    from observe_weapon_initialization_followup import SOURCES as weapon_sources
    from observe_weapon_owner_current_metadata import (PAWN_CAPTURE, PAWN_CAPTURE_SHA,
        MANAGER_CAPTURE, MANAGER_CAPTURE_SHA, FOLLOWUP_SHA)
    from weapon_switch_timeline_codec import source_pins as timeline_sources
    from fsm_readonly_scope import source_pins as fsm_sources
    from observe_weapon_mesh_followup import PINS as mesh_sources
    from weapon_appearance_readonly_scope import PINS as appearance_sources
    root, pins = Path(__file__).resolve().parent.parent, {}
    groups = [qualify() for qualify in (entity_sources, world_sources, world_capacity_sources,
        world_tag_sources, rpc_sources, fsm_sources, membership_sources,
        box_guid_sources, pawn_fsm_rpc_sources, skill_rpc_sources)]
    groups.append(hud_sources())
    groups.append(dict(weapon_sources, **{'work/observe_weapon_initialization_followup.py':
        hashlib.sha256((root/'work/observe_weapon_initialization_followup.py').read_bytes()).hexdigest()}))
    groups.append(dict(mesh_sources, **{'work/observe_weapon_mesh_followup.py':
        hashlib.sha256((root/'work/observe_weapon_mesh_followup.py').read_bytes()).hexdigest()}))
    groups.append(dict(appearance_sources, **{'work/weapon_appearance_readonly_scope.py':
        hashlib.sha256((root/'work/weapon_appearance_readonly_scope.py').read_bytes()).hexdigest()}))
    groups.append(dict(timeline_sources(), **{PAWN_CAPTURE: PAWN_CAPTURE_SHA,
        MANAGER_CAPTURE: MANAGER_CAPTURE_SHA,
        'work/observe_weapon_initialization_followup.py': FOLLOWUP_SHA,
        'work/observe_weapon_owner_current_metadata.py': hashlib.sha256(
            (root/'work/observe_weapon_owner_current_metadata.py').read_bytes()).hexdigest()}))
    for group in groups:
        for relative, digest in group.items():
            path = (root / relative).resolve(strict=True)
            if (not path.is_relative_to(root) or
                    hashlib.sha256(path.read_bytes()).hexdigest() != digest or
                    relative in pins and pins[relative] != digest):
                raise ValueError('An extended observer source is changed or aliased: ' + relative)
            pins[relative] = digest
    return pins


class GameplayObservationProcess:
    """Own one disposable reader process, never the game or the UDP probe."""
    def __init__(self, root, game_root, trial_report, output_dir, profile_path, *,
                 source_pins=None, process_identity=None, timeout_seconds=900):
        if not 1 <= timeout_seconds <= 900:
            raise ValueError('Gameplay observer timeout is outside its bounded scope')
        self.root, self.game_root = Path(root).resolve(), Path(game_root).resolve()
        self.trial_report, self.folder = Path(trial_report).resolve(), Path(output_dir).resolve()
        self.profile = Path(profile_path).resolve()
        if not all(p.is_relative_to(self.root) for p in (self.trial_report, self.folder, self.profile)):
            raise ValueError('Observation output and configuration must stay inside the project')
        self.sources, self.timeout = source_pins, timeout_seconds
        self.identity = process_identity
        self.result_path = self.folder / 'portable-gameplay-observation-result.json'
        self.process, self.deadline = None, None
        self.state = dict(status='not_started', gameplay_verified=False, game_termination_requested=False)

    def start(self, snapshot):
        if self.process is not None or self.state['status'] != 'not_started':
            raise ValueError('One gameplay observation is allowed per trial')
        if type(snapshot) is not bytes or not 0 < len(snapshot) <= 1024*1024:
            raise ValueError('A bounded immutable admission snapshot is required')
        trial_raw = _owned_report_bytes(self.trial_report, self.game_root, self.identity)
        trial_snapshot = self.folder / 'active-trial-snapshot.json'
        with trial_snapshot.open('xb') as stream:
            stream.write(trial_raw)
        snapshot_path = self.folder / 'admitted-loadout-snapshot.json'
        with snapshot_path.open('xb') as stream:
            stream.write(snapshot)
        request = dict(kind='portable_gameplay_observation_request_v1', project_root=str(self.root),
            game_root=str(self.game_root), trial_report=str(trial_snapshot),
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            output_dir=str(self.folder), profile=str(self.profile), source_pins=self.sources,
            process_identity=self.identity,
            profile_sha256=hashlib.sha256(self.profile.read_bytes()).hexdigest(),
            snapshot_sha256=hashlib.sha256(snapshot).hexdigest())
        request_path = self.folder / 'portable-gameplay-observation-request.json'
        with request_path.open('x', encoding='utf8') as stream:
            json.dump(request, stream, indent=2)
        with (self.folder / 'portable-gameplay-observer.stdout.log').open('xb') as stdout, \
                (self.folder / 'portable-gameplay-observer.stderr.log').open('xb') as stderr:
            self.process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                '--request', str(request_path)], cwd=self.root, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        self.deadline = time.monotonic() + self.timeout
        self.state.update(status='running', observer_pid=self.process.pid)
        return dict(self.state)

    def _stop(self, status):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.state.update(status=status, game_termination_requested=False)
        return dict(self.state)

    def poll(self):
        if self.process is None or self.state['status'] != 'running':
            return dict(self.state)
        code = self.process.poll()
        if code is None:
            if time.monotonic() >= self.deadline:
                return self._stop('timed_out')
            return dict(self.state)
        try:
            if code != 0 or self.result_path.stat().st_size > 65536:
                raise ValueError('The independent reader failed or produced an oversized summary')
            result = json.loads(self.result_path.read_text(encoding='utf8'))
            if (type(result) is not dict or result.get('gameplay_verified') is not False or
                    result.get('status') not in ('observed', 'partial', 'refused')):
                raise ValueError('The independent reader returned an invalid summary')
            self.state.update(result, observer_exit_code=code, game_termination_requested=False)
        except (OSError, ValueError) as error:
            self.state.update(status='refused', observer_exit_code=code, reason=str(error))
        return dict(self.state)

    def close(self):
        state = self.poll()
        return self._stop('cancelled') if state['status'] == 'running' else state


def _worker(request_path):
    root = Path(__file__).resolve().parent.parent
    request_path = Path(request_path).resolve(strict=True)
    if not request_path.is_relative_to(root) or request_path.stat().st_size > 1024*1024:
        raise ValueError('Observer request is outside the project or oversized')
    request = json.loads(request_path.read_text(encoding='utf8'))
    if (request.get('kind') != 'portable_gameplay_observation_request_v1' or
            Path(request['project_root']).resolve() != root):
        raise ValueError('Observer request does not match this project')
    folder, profile, report = (Path(request[k]).resolve(strict=True)
                               for k in ('output_dir', 'profile', 'trial_report'))
    if not all(p.is_relative_to(root) for p in (folder, profile, report)):
        raise ValueError('Observer request paths escaped this project')
    if report != folder / 'active-trial-snapshot.json':
        raise ValueError('The cohort requires its exclusive owned trial snapshot')
    identity = request.get('process_identity')
    def verify_trial_snapshot():
        raw = _owned_report_bytes(report, request['game_root'], identity)
        if hashlib.sha256(raw).hexdigest() != request.get('trial_report_sha256'):
            raise ValueError('Exact owned trial snapshot changed')
    verify_trial_snapshot()
    snapshot = folder / 'admitted-loadout-snapshot.json'
    if snapshot.stat().st_size > 1024*1024 or hashlib.sha256(snapshot.read_bytes()).hexdigest() != request['snapshot_sha256']:
        raise ValueError('Exact admitted snapshot changed')
    sys.path.insert(0, str(root / 'outputs/df-local-server'))
    from portable_map_bootstrap import load_plan
    def verify_sources():
        verify_trial_snapshot()
        if (hashlib.sha256(profile.read_bytes()).hexdigest() != request['profile_sha256'] or
                load_plan(root, profile).sources != request['source_pins']):
            raise ValueError('Portable sources changed during independent observation')
    from observe_owned_gameplay_metadata import observe as gameplay
    from observe_weapon_initialization_followup import observe as weapons
    from observe_weapon_owner_current_metadata import observe as current_weapon
    from observe_portable_map_runtime import observe as runtime
    from observe_owned_vitals_metadata import observe as vitals
    from observe_owned_map_marker_metadata import observe as markers
    from observe_economy_loaded_interactors import observe as interactors
    from observe_economy_inventory_receive import observe as inventory
    from observe_economy_inventory_gun_receive import observe as gun_inventory
    from observe_economy_inventory_spaces import observe as inventory_spaces
    from observe_owned_skill_entity_metadata import observe as skill_entities
    from observe_world_interaction_capacity_scope import observe as world_lifecycle
    from observe_world_tag_replication_mode import observe as world_tag_mode
    from observe_world_interaction_rpc_metadata import observe as world_rpc
    from observe_owned_fsm_metadata import observe as fsm
    from observe_weapon_mesh_followup import observe as weapon_mesh
    from observe_current_world_actor_membership import observe as membership
    from observe_current_world_box_guid_mappings import observe as box_guids
    from observe_owned_pawn_fsm_rpc_layouts import observe as pawn_fsm_rpcs
    from observe_owned_skill_rpc_layouts_v2 import observe as skill_rpcs
    from observe_portable_hud_guids import observe as hud
    results = {}
    # The FSM metadata is needed before the longer template/export cohort can
    # outlast a short possession or connection. A refusal remains a refusal.
    try:
        verify_sources()
        fsm_result = fsm(request['game_root'], report)
        verify_sources()
    except Exception as error:
        fsm_result = dict(status='refused', reason=str(error), error_type=type(error).__name__,
            process_memory_written=False, native_methods_invoked=False, packets_sent=False)
    fsm_path = folder/'owned-fsm-metadata.json'
    with fsm_path.open('x', encoding='utf8') as stream:
        json.dump(fsm_result, stream, indent=2)
    results['owned-fsm-metadata'] = dict(status=fsm_result.get('status'),
        reason=fsm_result.get('reason'), path=str(fsm_path))
    # Persist admission consumers before the longer world and RPC layout scans.
    for name, observer in (('portable-hud-guids', hud),
                           ('portable-runtime-after-possession', runtime),
                           ('owned-vitals-metadata', vitals),
                           ('economy-inventory-receive', inventory),
                           ('economy-inventory-gun-receive', gun_inventory),
                           ('economy-inventory-spaces', inventory_spaces)):
        try:
            verify_sources()
            args = ((request['game_root'], report, snapshot)
                    if observer in (inventory, gun_inventory, inventory_spaces)
                    else (request['game_root'], report))
            result = observer(*args)
            verify_sources()
        except Exception as error:
            result = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False, packets_sent=False)
        path = folder / (name + '.json')
        with path.open('x', encoding='utf8') as stream:
            json.dump(result, stream, indent=2)
        results[name] = dict(status=result.get('status'), reason=result.get('reason'), path=str(path))
    try:
        verify_sources()
        membership_result = membership(request['game_root'], report)
        verify_sources()
    except Exception as error:
        membership_result = dict(status='refused', reason=str(error), error_type=type(error).__name__,
            process_memory_written=False, native_methods_invoked=False, packets_sent=False)
    membership_path = folder/'current-world-actor-membership.json'
    with membership_path.open('x', encoding='utf8') as stream:
        json.dump(membership_result, stream, indent=2)
    results['current-world-actor-membership'] = dict(status=membership_result.get('status'),
        reason=membership_result.get('reason'), path=str(membership_path))
    for name, observer in (('current-world-box-guid-mappings', box_guids),):
        try:
            verify_sources()
            options = dict(profile_path=profile) if observer is box_guids else {}
            result = observer(request['game_root'], report, **options)
            verify_sources()
        except Exception as error:
            result = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False, packets_sent=False)
        path = folder / (name + '.json')
        with path.open('x', encoding='utf8') as stream:
            json.dump(result, stream, indent=2)
        results[name] = dict(status=result.get('status'), reason=result.get('reason'), path=str(path))
    try:
        verify_sources()
        mesh_result = weapon_mesh(request['game_root'], report)
        verify_sources()
    except Exception as error:
        mesh_result = dict(status='refused', reason=str(error), error_type=type(error).__name__,
            process_memory_written=False, native_methods_invoked=False, packets_sent=False)
    mesh_path = folder/'owned-weapon-mesh-followup.json'
    with mesh_path.open('x', encoding='utf8') as stream:
        json.dump(mesh_result, stream, indent=2)
    results['owned-weapon-mesh-followup'] = dict(status=mesh_result.get('status'),
        reason=mesh_result.get('reason'), path=str(mesh_path))
    try:
        verify_sources()
        from export_native_replication_metadata import collect as templates
        template_folder = folder / 'portable-after-open-templates'
        template_folder.mkdir()
        exported = templates(request['game_root'], template_folder,
            pid=identity['pid'], created_at=identity['created_at'],
            bootstrap_templates_only=True, maximum_seconds=60)
        verify_sources()
        results['portable-after-open-templates'] = dict(status=exported.get('status'),
            directory=str(template_folder),
            classes=[r['name'] for r in exported.get('roots', {}).get('classes', [])])
    except Exception as error:
        results['portable-after-open-templates'] = dict(status='refused', reason=str(error))
    # Preserve current state before repeating expensive RPC layout discovery.
    for name, observer in (('world-tag-replication-mode', world_tag_mode),
                           ('owned-skill-entity-metadata', skill_entities),
                           ('owned-map-marker-metadata', markers),
                           ('owned-weapon-current-metadata', current_weapon),
                           ('owned-weapon-state', weapons),
                           ('world-interaction-lifecycle', world_lifecycle),
                           ('world-interaction-rpc-metadata', world_rpc),
                           ('economy-loaded-interactors', interactors), ('owned-gameplay-metadata', gameplay),
                           ('owned-pawn-fsm-rpc-layouts', pawn_fsm_rpcs),
                           ('owned-skill-rpc-layouts', skill_rpcs)):
        try:
            verify_sources()
            args = ((request['game_root'], report, snapshot) if observer in (inventory, gun_inventory, inventory_spaces)
                    else (request['game_root'], report))
            result = observer(*args)
            verify_sources()
        except Exception as error:
            result = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False, packets_sent=False)
        path = folder / (name + '.json')
        with path.open('x', encoding='utf8') as stream:
            json.dump(result, stream, indent=2)
        results[name] = dict(status=result.get('status'), reason=result.get('reason'), path=str(path))
    result = dict(status=cohort_status(results),
        results=results, snapshot_sha256=request['snapshot_sha256'],
        trial_report_sha256=request['trial_report_sha256'],
        snapshot_origin='exact_single_delivered_admission', gameplay_verified=False)
    with (folder / 'portable-gameplay-observation-result.json').open('x', encoding='utf8') as stream:
        json.dump(result, stream, indent=2)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', type=Path, required=True)
    _worker(parser.parse_args().request)
