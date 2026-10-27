"""Read only the qualified ordinary UObject-reference receiver conditions.

The caller supplies the bounded, identity-rechecking connection-binding view.
No process is opened, native method called, or memory written here. GUIDCache
is an owned native struct, not a UObject; stable owning pointer/field reads
cannot prove its lifetime or produce an atomic snapshot.
"""
PACKAGE_MAP_SERIALIZE_SLOT = 0x260
GAME_PACKAGE_MAP_SERIALIZE_RVA = 0x49cd3b0


def observe_reference_conditions(view, connection):
    view.object(connection, 'NetConnection')
    mode = view.keep(connection + 0xb4, 1)[0]
    package_map = view.ptr(connection + 0x68)
    result = dict(connection_internal_ack_raw=mode, internal_ack_bit_set=bool(mode & 1),
                  ordinary_receive_properties_branch=(mode & 1) == 0,
                  package_map=hex(package_map), status='observed',
                  native_serializer_executed=False, native_guid_resolution_verified=False,
                  native_reference_assignment_verified=False, atomic_snapshot=False)
    if not package_map:
        result.update(status='unavailable', refusal_reason='connection_package_map_null')
        return result
    view.object(package_map, 'PackageMapClient')
    hook = view.method(package_map, PACKAGE_MAP_SERIALIZE_SLOT, GAME_PACKAGE_MAP_SERIALIZE_RVA)
    hook['matches_source_qualified_game_override'] = hook.pop('matches_saved_base_body')
    result['object_reference_serializer'] = hook
    if not hook['matches_source_qualified_game_override']:
        result.update(status='unsupported', refusal_reason='actual_package_map_serializer_not_qualified')
        return result
    back_connection = view.ptr(package_map + 0x130)
    result['package_map_back_connection_matches'] = back_connection == connection
    if back_connection != connection:
        result.update(status='unavailable', refusal_reason='package_map_connection_mismatch')
        return result
    cache = view.ptr(package_map + 0x310)
    result['guid_cache_pointer'] = hex(cache)
    result['game_object_reference_load_gate_has_guid_cache'] = bool(cache)
    if not cache:
        result.update(status='unavailable', refusal_reason='game_package_map_guid_cache_null')
        return result
    exporting = view.keep(cache + 0x152, 1)[0]
    result.update(guid_cache_exporting_raw=exporting, guid_cache_exporting_nonzero=bool(exporting),
                  recovered_ordinary_branch_conditions_observed=(mode & 1) == 0 and exporting == 0,
                  guid_cache_is_uobject=False, guid_cache_lifetime_proved=False)
    return result
