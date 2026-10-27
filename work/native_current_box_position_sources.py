"""Offline same-build generic root, plain location and zero-origin qualification."""
import hashlib
import json
import math
import mmap
from pathlib import Path

import observe_current_world_actor_membership as membership
import native_packed_object_reference as packed_reference
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache

ROOT = Path(__file__).resolve().parent.parent
SHIPPING_SHA256, IMAGE_SIZE = membership.SHIPPING_SHA256, membership.IMAGE_SIZE
SOURCE = 'work/evidence/current-box-position-research-20261020-v1/native-generic-actor-root-scene-world-origin.json'
SOURCE_SHA256 = 'a7f63db3678f20760efbba45139e28d3a2b6c9e2f18b74c3d149aba7324162de'
CATALOG = 'work/evidence/map-system-audit-20261018/native-economy-loaded-level1-container-door-catalog-v2.json'
CATALOG_SHA256 = 'd0b9dd3a71225f6cb5aab029658a6a852eb75378a89a99746ac0bfc5d4ed9bdc'
CACHE = 'work/native-code-cache/1792259162856698600'
MANIFEST_SHA256 = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'


def _document(relative, digest):
    path = (ROOT / relative).resolve(strict=True)
    if not path.is_relative_to(ROOT) or not 0 < path.stat().st_size <= 1024 * 1024:
        raise ValueError('The bounded current box position source is unavailable')
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('The current box position source changed')
    return json.loads(raw)


def qualified_native():
    doc = _document(SOURCE, SOURCE_SHA256)
    if (doc['kind'] != 'same_build_generic_actor_plain_root_world_position_sources'
            or doc['client_sha256'] != SHIPPING_SHA256 or doc['cache_manifest_sha256'] != MANIFEST_SHA256
            or doc['process_access'] is not False or doc['native_methods_invoked'] is not False
            or len(doc['functions']) != 8 or len(doc['immutable_records']) != 14):
        raise ValueError('The generic Actor position source provenance changed')
    getter, = [row for row in doc['functions'] if row['requested_rva'] == '0xe36ab0']
    if (SOURCE != packed_reference.ROOT_SOURCE_PATH or SOURCE_SHA256 != packed_reference.ROOT_SOURCE_SHA256
            or getter['linear_decode_covers_extent'] is not True
            or getter['decoded_bytes'] != 1247
            or getter['pdata']['begin'] != '0xe36ab0' or getter['pdata']['end_exclusive'] != '0xe36f8f'
            or getter['span_start'] != '0xe36ab0' or getter['span_bytes'] != 1247
            or getter['code_sha256'] != packed_reference.SOURCE_FILE_PINS[
                'work/evidence/map-entry-next-20261007/actor-get-root-component-full.e36ab0.code']):
        raise ValueError('The shared direct root decoder requires its identical bounded Actor getter')
    return doc


def authored_positions():
    doc = _document(CATALOG, CATALOG_SHA256)
    expected = {row['actor_path']: row['class_path'] for row in membership.sealed_scope.qualified_actor_paths()
                if row['class_path'].endswith('BP_Interactor_Container_SafeBox_C')}
    rows = {}
    for row in doc['actors']:
        path = row['cooked_object_path']
        if path not in expected:
            continue
        transform = row['transform']
        location = transform['relative_location']
        xyz = location['serialized_float32']
        if (row['class_import'] != expected[path] or path in rows
                or transform['attach_parent'] is not None or location['serialized_type'] != 'EncVector'
                or type(xyz) is not list or len(xyz) != 3
                or any(type(value) not in (int, float) or not math.isfinite(value) for value in xyz)):
            raise ValueError('The exact authored SafeBox root comparison source changed')
        rows[path] = tuple(xyz)
    if len(rows) != 3 or set(rows) != set(expected):
        raise ValueError('The three source-qualified authored SafeBox paths are required')
    return rows


def source_pins():
    qualified_native()
    authored_positions()
    pins = membership.source_pins()
    pins[packed_reference.MODULE_PATH] = hashlib.sha256(Path(packed_reference.__file__).read_bytes()).hexdigest()
    pins.update({SOURCE: SOURCE_SHA256, CATALOG: CATALOG_SHA256})
    for relative in ('work/native_current_box_position_sources.py',
                     'work/current_world_box_position_readonly_scope.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    if Path(__file__).resolve() != ROOT / 'work/native_current_box_position_sources.py':
        raise ValueError('The position source qualifier was imported from another checkout')
    return pins


def qualify_installed_sources(game_root):
    """Check existing disk/cache bytes only; no process, decoder or getter call."""
    pins, doc = source_pins(), qualified_native()
    cache = CodeCache(ROOT / CACHE, MANIFEST_SHA256, game_root)
    for function in doc['functions']:
        first, length = int(function['span_start'], 16), function['span_bytes']
        raw = cache.read(first, length)
        if hashlib.sha256(raw).hexdigest() != function['code_sha256']:
            raise ValueError('The generic Actor position cache function changed')
    executable = Path(game_root) / cache.manifest['plan']['client_relative_to_game_root']
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = ImmutableImage(raw)
        for record in doc['immutable_records']:
            data = image.read(int(record['rva'], 16), record['size'])
            if data.hex() != record['hex'] or hashlib.sha256(data).hexdigest() != record['sha256']:
                raise ValueError('The generic Actor position native type record changed')
    if source_pins() != pins:
        raise ValueError('The generic Actor position sources changed during qualification')
    return pins
