"""Read available code ranges from a freshly owned, disk-qualified snapshot.

The old private manifest/plan is not reconstructed. Each new cache is bound to
an explicit manifest hash and a plan regenerated from the current pinned PE.
"""
import hashlib
import json
from pathlib import Path

from snapshot_native_image_code import validate_plan, SOURCE_SHA

ROOT = Path(__file__).resolve().parent.parent


class CodeCache:
    def __init__(self, folder, manifest_sha256, game_root):
        self.folder = Path(folder).resolve(strict=True)
        if self.folder.parent != (ROOT/'work/native-code-cache').resolve():
            raise ValueError('A current project code-cache child is required')
        self.manifest_path = self.folder/'manifest.json'
        raw = self.manifest_path.read_bytes()
        if len(raw) > 32*1024*1024 or hashlib.sha256(raw).hexdigest() != manifest_sha256:
            raise ValueError('The explicit current cache manifest hash changed')
        self.manifest_sha256 = manifest_sha256
        self.manifest = json.loads(raw)
        plan = validate_plan(game_root)
        doc = self.manifest
        if (doc.get('kind') != 'private_file_backed_executable_code_cache' or
                doc.get('client_sha256') != SOURCE_SHA or doc.get('plan') != plan or
                doc.get('snapshot_is_atomic') is not False or
                doc.get('status') not in ('code_cache_complete', 'code_cache_partial') or
                any(doc.get(k) is not False for k in ('client_launched', 'elevation_requested',
                    'process_memory_written', 'live_data_object_read', 'original_game_modified',
                    'reconstructed_executable', 'native_complete_decode_claimed'))):
            raise ValueError('The current native snapshot provenance or disk plan changed')
        if len(doc['sections']) != len(plan['sections']):
            raise ValueError('The exact file-backed executable section set is required')
        self.blocks = []
        available = requested = rpm = 0
        for actual, expected in zip(doc['sections'], plan['sections']):
            at = int(expected['rva'],16)
            length = expected['file_backed_code_bytes']
            if (actual['index'], actual['rva'], actual['bytes']) != (expected['index'], expected['rva'], length):
                raise ValueError('Snapshot section extent changed')
            section_available = 0
            for block in actual['blocks']:
                size = block['bytes']
                if (block['rva'] != hex(at) or type(size) is not int or not 0 < size <= plan['maximum_RPM_bytes'] or
                        at+size > int(expected['rva'],16)+length or type(block['available']) is not bool):
                    raise ValueError('Snapshot block ordering or extent changed')
                if block['available']:
                    name = f'section_{actual["index"]:02d}_rva_{at:08x}.code'
                    if block.get('file') != name or not isinstance(block.get('code_sha256'), str):
                        raise ValueError('Snapshot block path or digest changed')
                    section_available += size
                    requested += size
                    rpm += 1
                else:
                    reason = block.get('unavailable_reason')
                    if reason not in ('query_unavailable', 'invalid_region_boundary', 'invalid_region_alignment',
                                      'page_not_committed_executable_image', 'read_failed_or_incomplete'):
                        raise ValueError('Unknown unavailable-page reason')
                    if reason == 'read_failed_or_incomplete':
                        requested += size
                        rpm += 1
                self.blocks.append((at, size, block))
                at += size
            if (at != int(expected['rva'],16)+length or actual['available_bytes'] != section_available or
                    actual['unavailable_bytes'] != length-section_available):
                raise ValueError('Snapshot section coverage accounting changed')
            available += section_available
        if (doc['saved_code_bytes'] != available or doc['unavailable_bytes'] != plan['maximum_code_bytes']-available or
                doc['actual_RPM_count'] != rpm or doc['RPM_requested_bytes'] != requested or
                doc['scope_coverage_complete'] is not (available == plan['maximum_code_bytes'])):
            raise ValueError('Snapshot total accounting changed')
        if doc.get('complete') is not (available == plan['maximum_code_bytes']):
            raise ValueError('Snapshot completion flag disagrees with its available code')
        anchors = doc['known_sender_comparisons']
        if len(anchors) != len(plan['known_sender_targets']):
            raise ValueError('Snapshot known-code witness set changed')
        for actual, expected in zip(anchors, plan['known_sender_targets']):
            if (actual['name'] != expected['name'] or actual['rva'] != expected['rva'] or
                    actual['bytes'] != expected['code_bytes'] or actual['extra_live_reads'] != 0 or
                    actual['expected_code_sha256'] != expected['expected_code_sha256'] or
                    actual['matches_saved_native_sample'] is not True):
                raise ValueError('Snapshot known-code comparison changed')
            if hashlib.sha256(self.read(int(expected['rva'],16), expected['code_bytes'])).hexdigest() != expected['expected_code_sha256']:
                raise ValueError('Snapshot known-code bytes disagree with the actual blocks')

    def read(self, rva, size):
        if type(rva) is not int or type(size) is not int or rva < 0 or not 0 < size <= 8192:
            raise ValueError('A bounded exact code query is required')
        result = bytearray()
        at, end = rva, rva+size
        for first, length, block in self.blocks:
            if first+length <= at or first >= end:
                continue
            if first > at or not block['available']:
                raise ValueError('The requested code interval is unavailable')
            path = self.folder/block['file']
            if path.resolve().parent != self.folder or path.stat().st_size != length:
                raise ValueError('The current code block path or size changed')
            with path.open('rb') as stream:
                raw = stream.read(length+1)
            if (len(raw) != length or
                    hashlib.sha256(raw).hexdigest() != block['code_sha256']):
                raise ValueError('The current code block identity changed')
            high = min(first+length, end)
            result.extend(raw[at-first:high-first])
            at = high
        if at != end or hashlib.sha256(self.manifest_path.read_bytes()).hexdigest() != self.manifest_sha256:
            raise ValueError('Code coverage is incomplete or the current manifest changed')
        return bytes(result)
