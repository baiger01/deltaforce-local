"""Qualify the cooked HUD reference and add its class to the PC export graph."""
from dataclasses import replace
import hashlib
import json

from dfserver.legacy_ds_actor_manifest import GuidPathBinding, preflight_actor_manifest
from dfserver.legacy_ds_guid_exports import GuidExportNode
from dfserver.legacy_ds_pc_hud_rpc import PCHUDProfile, CLASS_PATH, HUD_CLASS_PATH
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, SHIPPING_SHA256

SCHEMA_SHA256 = '767742c4ac03274433f43235af52f5e962b26dfd4557215659fd62dc35fb9049'
_REQUIRED_GUID_SOURCES = {
    'work/evidence/model-init-chain-20261018/native-hud-internal-write-object.json':
        'e3437748e2f402d30d5acd5d148f17c1667f92e1d8181c6c80cc06659472d2d3',
    'work/evidence/model-init-chain-20261018/native-hud-required-guid-channel-and-rpc-policy.json':
        '4965bf086aafb5ebef39cb1ad152609a553a7fb835ee6b28fd9a4ed42532ca3b',
    'work/evidence/model-init-chain-20261018/native-hud-required-guid-resolution-lifecycle.json':
        '4769117f95196e007b5a955f58fe14dd96194ccd80711bd40331021384ea33a4',
}


def required_guid_source_pins(root):
    """Verify the ordinary class-reference list, receive queue, and Outer resolver."""
    from portable_map_bootstrap import sealed_read
    for relative, digest in _REQUIRED_GUID_SOURCES.items():
        report = json.loads(sealed_read(root, dict(relative_path=relative, sha256=digest)))
        if (report.get('kind') != 'qualified_portable_offline_native_analysis' or
                report.get('client_sha256') != SHIPPING_SHA256 or
                report.get('cache_manifest_sha256') !=
                'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754' or
                report.get('process_access') is not False):
            raise ValueError('The HUD required GUID evidence qualification changed')
    return dict(_REQUIRED_GUID_SOURCES)


def hud_profile(raw, pc_record, archive_sha256):
    from portable_map_bootstrap import rpc_index
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The pinned cooked HUD and native RPC schema is required')
    schema = json.loads(raw)
    if (schema.get('kind') != 'client_derived_controller_hud_schema' or
            schema.get('client_sha256') != SHIPPING_SHA256 or
            schema.get('process_pointers_reused') is not False or
            schema.get('required_hud_class_path') != HUD_CLASS_PATH or
            schema.get('rpc_name') != 'ClientSetHUD' or
            schema.get('class_name') != pc_record.get('class_name') or
            schema.get('rep_index') != rpc_index(pc_record, 'ClientSetHUD') or
            schema.get('exclusive_index_maximum') != pc_record.get('exclusive_index_maximum')):
        raise ValueError('The HUD declaration differs from the owned controller schema')
    return PCHUDProfile(CLASS_PATH, schema['exclusive_index_maximum'], schema['rep_index'],
        int(schema['function_flags'], 16), HUD_CLASS_PATH, archive_sha256,
        NativeScalarBinding(SHIPPING_SHA256, 0x10e8ed20, None, 0x1ab61800))


def add_hud_class_export(actors, profile):
    profile.__post_init__()
    used = {m.actor_guid for m in (a.manifest for a in actors.values())}
    used.update(b.guid for a in actors.values() for b in a.manifest.path_bindings)
    # These are service-assigned NetGUIDs, never client item/configuration IDs.
    package_guid = next(g for g in range(3, 2*len(used)+9, 2) if g not in used)
    class_guid = next(g for g in range(3, 2*len(used)+11, 2) if g not in used and g != package_guid)
    package, leaf = profile.hud_class_path.rsplit('.', 1)
    pc = actors['PlayerController']
    manifest = replace(pc.manifest,
        exports=pc.manifest.exports + (GuidExportNode(class_guid, leaf, GuidExportNode(package_guid, package)),),
        path_bindings=pc.manifest.path_bindings + (GuidPathBinding(package_guid, package),
                                                 GuidPathBinding(class_guid, profile.hud_class_path, '.')))
    preflight = preflight_actor_manifest(manifest, channel_sequence=pc.channel_sequence,
                                         max_packet_bytes=pc.max_packet_bytes)
    return replace(pc, manifest=manifest, preflight=preflight), class_guid
