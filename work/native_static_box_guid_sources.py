"""Current-build offline qualification for existing PackageMap associations.

The missing 20261005 ledger is not used. These reports were regenerated from
the installed build's sealed code cache. They qualify only existing sparse-map
and initialized weak-reference reads, never native resolution or acceptance.
"""
import hashlib
import json
import mmap
from pathlib import Path
import struct

import native_guid_object_metadata as guid_reader
import native_metadata_objects as object_reader
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache


ROOT = Path(__file__).resolve().parent.parent
SHIPPING_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MANIFEST_SHA256 = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
CACHE = 'work/native-code-cache/1792259162856698600'
EVIDENCE = 'work/evidence/durable-world-runtime-research-20261020-v1/'
REPORTS = {
    'native-guid-lookup-and-existing-weak-spans.json': 'd025fc21f0a1d38aeceef2724710fc53b232658c93b16362696e3ef173d15af2',
    'native-guid-cache-actual-and-existing-weak.json': 'a941dad3bb898b0f4e48e2173a261c44cf349da742b1d1acbe755efdbeab26c5',
    'native-guid-cache-hash-lookup.json': 'f9f988ef8c59a4ffad7ba7097f7d94a9c5916846c71c6c47d5704a0649ee8f25',
    'native-guid-data-accessor-leaf.json': 'd6d4bdf31639a5dc952fd2e08022d79cacca4710c91828941ebbe5217ad62a98',
    'native-guid-connection-and-reference-gates.json': '7c1385cc129e279ae79bc25b9e8c8dbbed132725ad0edad223569f9494eb87de',
    'native-guid-export-mode-and-registry-selectors.json': '069630cf09f1f685a693080b765324018a6e43149cf17157025e2a255a28574e',
    'native-guid-classes-and-ordinary-rpc-gate.json': 'b369af2b92bbcb1468410b6d1936b29d83d5efdfb26837d783f8f1155528be59',
    'native-guid-connection-packagemap-init.json': '24e1d351e4238a747e524030865b043b229bdb53a5f1e6cd57041aecf03906d7',
    'native-guid-packagemap-backlink-init.json': 'bfbb023f07fa6161c1e2408149fb3446b683ead0530ba9354dccb9464cdbcae7',
}
READERS = {
    'work/native_guid_object_metadata.py': '79059c387c49d9e8c091abc560d83c6fb0a43ab93f5e29301d26c97be2d9d56e',
    'work/native_metadata_objects.py': '2e8236abeed2771ce95aabf74d97be9bbb6d35450afdae4b56bbcff2592fd80f',
}
SIGNATURES = {
    '0x12bb8320': '488b8910030000',
    '0x12bb8327': 'e974f0ffff',
    '0xd968d0': '488b01', '0xd968d3': 'c3',
    '0x12d4de08': '488b4b58', '0x12d4de15': '483b9998000000',
    '0x12b92919': '48895158', '0x12b929eb': 'e8d0ec7f00',
    '0x12b92a50': 'e85b0f0000', '0x12b92a5d': '48897b68',
    '0x12b939bf': '48899130010000',
    '0x49b0d7a': '8b4108', '0x49b0d86': '3b4134',
    '0x49b0d8e': '488d7938', '0x49b0d92': '488d4f08',
    '0x49b0d9c': '4c634e48', '0x49b0dc2': '486bf938',
    '0x49b0dd7': '8b5c0730',
    '0x12bbb4a1': '450fb68052010000',
    '0x12db94b4': 'f680b400000001',
}


def _documents(root):
    result, total = [], 0
    for name, digest in REPORTS.items():
        path = (root / EVIDENCE / name).resolve(strict=True)
        if not path.is_relative_to(root) or not 0 < path.stat().st_size <= 2 * 1024 * 1024:
            raise ValueError('The current GUID source report exceeds its scope')
        raw = path.read_bytes()
        total += len(raw)
        if total > 8 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('The current GUID source report changed')
        doc = json.loads(raw)
        if (doc.get('kind') != 'qualified_portable_offline_native_analysis'
                or doc.get('client_sha256') != SHIPPING_SHA256
                or doc.get('cache_manifest_sha256') != MANIFEST_SHA256
                or doc.get('process_access') is not False or doc.get('client_launched') is not False):
            raise ValueError('The current GUID source provenance changed')
        result.append(doc)
    return result


def source_pins(root=ROOT):
    root = Path(root).resolve(strict=True)
    documents = _documents(root)
    instructions = {row['rva']: row['bytes'] for doc in documents
                    for fn in doc['functions'] for row in fn['instructions']}
    for at, expected in SIGNATURES.items():
        if instructions.get(at) != expected:
            raise ValueError('The current GUID source instruction differs: ' + at)
    pins = {EVIDENCE + name: digest for name, digest in REPORTS.items()}
    for relative, expected in READERS.items():
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
            raise ValueError('The existing GUID reader implementation changed')
        pins[relative] = expected
    for module, relative in ((guid_reader, 'work/native_guid_object_metadata.py'),
                             (object_reader, 'work/native_metadata_objects.py')):
        if Path(module.__file__).resolve() != ROOT / relative:
            raise ValueError('The qualified GUID reader was imported from a different checkout')
    relative = 'work/native_static_box_guid_sources.py'
    pins[relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    return pins


def qualify_installed_sources(game_root):
    """Disk/cache only; no process handle or native method is used."""
    pins = source_pins()
    cache = CodeCache(ROOT / CACHE, MANIFEST_SHA256, game_root)
    for doc in _documents(ROOT):
        for fn in doc['functions']:
            first, amount = int(fn['span_start'], 16), fn['span_bytes']
            if type(amount) is not int or not 0 < amount <= 65536:
                raise ValueError('The current GUID source function exceeds its bound')
            raw = b''.join(cache.read(at, min(8192, first + amount - at))
                           for at in range(first, first + amount, 8192))
            if hashlib.sha256(raw).hexdigest() != fn['code_sha256']:
                raise ValueError('The current GUID source cache code changed')
    executable = Path(game_root) / cache.manifest['plan']['client_relative_to_game_root']
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = ImmutableImage(raw)
        if struct.unpack('<Q', image.read(0x1d59de58, 8))[0] != image.image_base + 0xd968d0:
            raise ValueError('The current GUID array accessor cell changed')
    if source_pins() != pins:
        raise ValueError('The current GUID source seal changed during qualification')
    return pins
