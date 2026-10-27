"""Keep current minimum Actor diagnostics separate from old/full bootstraps."""
import hashlib

from snapshot_updated_client_code import qualify_launch as qualify_observation


def qualify_launch(args, game_root, shadow_root):
    requested = getattr(args, 'updated_minimum_actor_bootstrap', False)
    if type(requested) is not bool:
        raise ValueError('An explicit boolean minimum Actor mode is required')
    if requested and not (getattr(args, 'updated_client_transport_observation', False) is True and
            getattr(args, 'ds_control_probe', False) is True):
        raise ValueError('The minimum Actor mode requires the qualified current control transport')
    result = qualify_observation(args, game_root, shadow_root)
    if not requested:
        return result
    if result is None or result['mode'] != 'updated_control_capture':
        raise ValueError('The minimum Actor mode requires only its current control transport')
    from updated_map_bootstrap import load_plan, ROOT
    from updated_enabled_header_context import source_pins
    plan = load_plan()
    pins = {**result['source_pins'], **plan.sources, **source_pins()}
    for name in ('work/updated_minimum_launch.py', 'work/updated_map_receiver_guard.py',
                 'work/export_native_replication_metadata.py', 'work/portable_source_guard.py'):
        pins[name] = hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    return dict(result, mode='updated_source_minimum_actor_bootstrap', source_pins=pins,
        minimum_actor_profile=plan.summary(),
        live_receiver_check_required_before_install_and_admission=True,
        native_gameplay_acceptance=False)
