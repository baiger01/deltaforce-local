"""Read the existing GP subworld-name cache; no getters, writes or credentials.

Native4d08ce0 prefers the eight-byte FName at GPClientSeamlessTravel+180.
StaticClass5fcc990 names that class in the SHA-pinned client. Its Outer is read
as UObject metadata, not assumed to be a World. The cached payload belongs only
to the verified GP class. This does not decide the global UI World or claim that
a cached name was selected by the loading caller.
"""
import hashlib
from pathlib import Path
import re
import struct

from native_replication_metadata_core import MetadataSession, span

CLASS_NAME = 'GPClientSeamlessTravel'
SOURCE_PINS = {
    'work/evidence/map-entry-next-20261007/map-context-full.5fcc990.asm.txt':
        'a217e464de25229ff4e6f98fb9b16fa6afe66e8525d88edf4ea2c8811c3b929a',
    'work/evidence/map-entry-next-20261007/map-context-full.5fcc990.code':
        'c1fb8aaaa3d6def2955401d75872a930b20cd886b66c92e12e469071c176c400',
    'work/evidence/map-entry-next-20261007/map-subworld-full.4d08ce0.asm.txt':
        '9a828050503708addbd6326b80a9f0b95cb5b9c17ab6eedce7eddbb05bf0f831',
}


def qualified_subworld_context_source_pins(root):
    root = Path(root).resolve(strict=True)
    pins = {}
    for relative, expected in SOURCE_PINS.items():
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not 0 < path.stat().st_size <= 1024 * 1024:
            raise ValueError('Invalid subworld cache source range')
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError('Subworld cache source identity changed')
        pins[relative] = actual
    relative = 'work/native_loading_subworld_context.py'
    actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if actual != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('Subworld cache reader was imported from another root')
    pins[relative] = actual
    return pins


def observe_subworld_contexts(session, candidates, *, object_identity, resolve_fname):
    if (not isinstance(session, MetadataSession) or type(candidates) is not list or
            len(candidates) > 16 or not callable(object_identity) or not callable(resolve_fname)):
        raise ValueError('Bounded typed subworld-cache inputs are required')
    addresses = [row.get('address') for row in candidates]
    if any(type(value) is not int for value in addresses) or len(set(addresses)) != len(addresses):
        raise ValueError('Subworld candidates require distinct observed objects')
    rows = []
    for address in addresses:
        span(address, 0x188)
        identity = object_identity(address, CLASS_NAME)
        outer_bytes = session.stable(address + 0x10, 8)
        outer = struct.unpack('<Q', outer_bytes)[0]
        span(outer, 1)
        outer_identity = object_identity(outer, 'Object')
        token = session.stable(address + 0x180, 8)
        name = resolve_fname(token)
        if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', name):
            raise ValueError('Subworld cache did not resolve to a bounded scene identifier')
        if (object_identity(address, CLASS_NAME) != identity or
                object_identity(outer, 'Object') != outer_identity or
                session.stable(address + 0x10, 8) != outer_bytes or
                session.stable(address + 0x180, 8) != token):
            raise ValueError('Subworld cache identity or fields changed during recheck')
        rows.append({'instance_name': identity['name'],
            'class_ancestry': identity['class_ancestry'],
            'outer_name': outer_identity['name'],
            'outer_class_ancestry': outer_identity['class_ancestry'],
            'owning_world_name': (outer_identity['name']
                                  if 'World' in outer_identity['class_ancestry'] else None),
            'cached_subworld_name': name, 'name_token_is_zero': token == bytes(8),
            'identity_and_fields_rechecked': True})
    return {'status': 'existing_subworld_contexts_observed' if rows else 'not_observed',
        'contexts': rows, 'source_receiver_rva': '0x4d08ce0',
        'selected_by_loading_context_verified': False,
        'native_getter_invoked': False, 'process_memory_written': False,
        'playable_map_verified': False}
