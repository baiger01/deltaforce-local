"""Pinned scope for an explicit updated-build loopback transport experiment.

The existing 8-byte outer-routing interpretation remains experimental. Control
exchange requires its separately qualified current profile. Actors, historical
class handles and process-memory readers remain outside this scope.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT_SHA256 = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
PROOFS = {
    'work/research_updated_stateless_handshake_79fb7b10.json':
        'eb77c89cd90717df7f49f18c0e47610460933d32b474cf7168c1742a9025330c',
    'work/research_updated_transport_79fb7b10.json':
        'd127c9b551192ba1a126f3b5f5e2c90f9a9a6a0e6d4ff806b6d037941fb73e92',
    'work/research_updated_transport_profile_79fb7b10.json':
        '2e55c4989ddb28f7ae75a6ddfd62e92f50d77bc523a99aebbf84ffd65ccd43c8',
}


def source_pins(*, control_profile=None, shadow=None):
    pins = {}
    for relative, expected in PROOFS.items():
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Updated transport proof changed')
        report = json.loads(raw)
        if report.get('client_sha256', report.get('shipping_sha256')) != CLIENT_SHA256:
            raise ValueError('Updated transport proof belongs to another build')
        pins[relative] = expected
    if control_profile is not None:
        from build_updated_control_profile import PROFILE, EVIDENCE, derive, serialized
        profile_path = Path(control_profile).resolve(strict=True)
        if profile_path != PROFILE.resolve(strict=True):
            raise ValueError('Updated control requires its separately qualified current profile')
        profile, evidence = derive(shadow)
        if (profile_path.read_bytes() != serialized(profile) or
                EVIDENCE.read_bytes() != serialized(evidence)):
            raise ValueError('Updated control profile or current source evidence changed')
        for item in evidence['source_pins'] + evidence['generator_and_parser_sources']:
            relative, expected = item['relative_path'], item['sha256']
            path = (ROOT/relative).resolve(strict=True)
            if not path.is_relative_to(ROOT):
                raise ValueError('Updated control qualification escaped the project')
            with path.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                    raise ValueError('Updated control source changed: '+relative)
            pins[relative] = expected
        files = (PROFILE, EVIDENCE, ROOT/'work/native_engine_ini_override.py')
        for path in files:
            pins[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    server = ROOT / 'outputs/df-local-server'
    files = [Path(__file__), *sorted((server/'dfserver').rglob('*.py')),
             *sorted((server/'protocol').glob('*.json')), server/'protocol/candidate_business.pb']
    if len(files) > 2048:
        raise ValueError('Updated transport source set exceeds its policy bound')
    for path in files:
        path = path.resolve(strict=True)
        if not path.is_relative_to(ROOT):
            raise ValueError('Updated transport source escapes the project')
        with path.open('rb') as stream:
            pins[path.relative_to(ROOT).as_posix()] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return pins
