"""Qualify the pinned native controller rotation declaration for this plan."""
import hashlib
import json

from dfserver.legacy_ds_pc_rotation_rpc import PCRotationProfile, CLASS_PATH
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256

SCHEMA_SHA256 = '4db34bfa70e23c1f6d636dcefb659a75f2ed04e20e39a940bc7ca33660624b1b'


def rotation_profile(schema, record, archive_sha256):
    from portable_map_bootstrap import rpc_index
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256 or
            schema.get('kind') != 'client_derived_controller_rotation_schema' or
            schema.get('client_sha256') != SHIPPING_SHA256 or schema.get('process_pointers_reused') is not False or
            schema.get('class_name') != record.get('class_name') or
            schema.get('rpc_name') != 'ClientSetRotation' or
            schema.get('rep_index') != rpc_index(record, 'ClientSetRotation') or
            schema.get('exclusive_index_maximum') != record.get('exclusive_index_maximum')):
        raise ValueError('The qualified native ClientSetRotation schema is required')
    return PCRotationProfile(CLASS_PATH, schema['exclusive_index_maximum'], schema['rep_index'],
                             int(schema['function_flags'], 16), archive_sha256)
