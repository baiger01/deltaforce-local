"""Publish the qualified RPC declaration without private cache/instance data."""
import hashlib
import json

from seal_client_set_rotation_contract import derive as derive_contract, ROOT


def derive():
    contract = derive_contract()
    raw = (json.dumps(contract, indent=2, sort_keys=True)+'\n').encode()
    return dict(kind='client_derived_controller_rotation_schema',
        client_sha256=contract['client_sha256'],
        native_contract_sha256=hashlib.sha256(raw).hexdigest(),
        cache_manifest_sha256=contract['cache_manifest_sha256'],
        class_name=contract['class_name'], rpc_name=contract['rpc_name'],
        rep_index=contract['rep_index'], exclusive_index_maximum=contract['exclusive_index_maximum'],
        function_flags=contract['function_flags'], parameter_struct_bytes=contract['parameter_struct_bytes'],
        linked_parameter_order=contract['linked_parameter_order'], parameters=contract['parameters'],
        wire_rules=contract['wire_rules'], native_instruction_facts=contract['verified_instruction_facts'],
        process_pointers_reused=False, native_camera_axes_verified=False)


if __name__ == '__main__':
    schema = derive()
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    path = ROOT/'outputs/df-local-server/protocol/portable-map-spawn/rotation-schema.json'
    with path.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest())))
