"""Replay bounded weapon optional-data research against immutable client sources."""
import argparse
import ast
from contextlib import redirect_stdout
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
import research_weapon_wire_contract_20261020 as source


PINS = {
    0x2184790: (1059, '24229c3676477aa9177a69ecdda0bc8ae9bd200c96efc44a4cf37cd255043095'),
    0x2184ED0: (888, 'bb86cb97192229a472077ed026df55fef0df69ed6575c91b169eebdc92e307d1'),
    0x2184BC0: (770, 'c52093694bd619b49040794df3e3117e2826822c116de90abba391820c5ce576'),
    0x2181AC0: (768, '12fdb6e2b8e1f576f6d81a590956b92f8a14ed944c2ff209e113c9a8efa36aad'),
    0x21852C0: (759, 'b0da1cd305886e9670b0730a18c7887837501dcc1c9b9f9d02622adde9450b32'),
    0x52CEFD0: (681, '8346e935ec2313cfd8a09083f7eb6729d079799ba0197290d1a1b153d01ca114'),
    0x4D121A0: (308, '7a3023db2bd364e58ec96b25800672cd95c651604df2a54b8926b3111d1d4c3a'),
    0x1779FA0: (334, '37608c63f48e319796a99a25a2be7bf3f346a1aa6e55d92c3b7c6bd61bb184e3'),
    0x21821C0: (739, 'dcee58810c8732bed25f0a9f8e64b25ca5ce0b736a828a0655e52a1bbd81c853'),
    0x2A9ED0: (100, 'a6c62bbbcef791cc320413afe41f0f1f377e10278390de8802b9b42f4d32845c'),
    0x2A9F40: (100, 'dbdb2a41cfaa87f1e33aa9762d7602d480c09df7ab11ca5ec87a1d0520bde00b'),
}
GETTERS = [0x218F750, 0x218AAC0, 0x218AAF0, 0x5F57ED0, 0x5F54180]
DATA = [(0x1D7D9670, 72), (0x14EC8390, 4), (0x14F345B4, 4),
        (0x14F34590, 4), (0x14F8D21C, 4), (0x14F34644, 4),
        (0x14EC832C, 4), (0x158F829C, 4), (0x158F7CD0, 64),
        (0x158F7B88, 56), (0x1CAC9CA8, 4)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def extra_rigid_body_declaration():
    # This getter's declaration is outside the older helper's bounded range.
    cache = source.CodeCache(source.PEER/'work/native-code-cache/1792259162856698600',
                             source.MANIFEST_SHA, source.GAME)
    helper = source.PEER/'work/inspect_economy_uht_class_metadata.py'
    helper_raw = helper.read_bytes()
    executable = source.GAME/cache.manifest['plan']['client_relative_to_game_root']
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = source.ImmutableImage(mapped)
        md = source.Cs(source.CS_ARCH_X86, source.CS_MODE_64)
        md.detail = True
        env = dict(image=image, cache=cache, md=md, struct=struct, hashlib=hashlib)
        import capstone.x86_const as constants
        env.update(vars(constants))
        for node in ast.walk(ast.parse(helper_raw.decode('utf-8'))):
            if isinstance(node, ast.FunctionDef) and node.name in ('text', 'prop'):
                exec(compile(ast.Module(body=[node], type_ignores=[]), str(helper), 'exec'), env)
        raw = image.read(0x1D7D9670, 72)
        values = struct.unpack('<9Q', raw)
        name = env['text'](values[3])
        assert name == 'RigidBodyState' and values[4:6] == (64, 16)
        assert values[7] == (0x45 << 32) | 6
        pointers = struct.unpack('<6Q', image.read(values[6]-image.image_base, 48))
        fields = [env['prop'](pointer) for pointer in pointers]
        return dict(name=name, record_rva='0x1d7d9670', record_sha256=digest(raw),
                    native_size=64, alignment=16, fields=fields)


def collect():
    previous = sys.argv
    sys.argv = [str(source.__file__)]
    for getter in GETTERS:
        sys.argv += ['--struct-getter', hex(getter)]
    for rva in PINS:
        sys.argv += ['--native-function', hex(rva)]
    for rva, size in DATA:
        sys.argv += ['--data', f'{hex(rva)}:{size}']
    sys.argv += ['--code', '0x132ea360', '--size', '64']
    captured = io.StringIO()
    try:
        with redirect_stdout(captured):
            source.main()
    finally:
        sys.argv = previous
    result = json.loads(captured.getvalue())
    functions = result['native_analysis']['functions']
    assert len(functions) == len(PINS)
    for function in functions:
        expected = PINS[int(function['span_start'], 0)]
        assert (function['span_bytes'], function['code_sha256']) == expected
        assert function['linear_decode_covers_extent'] is True
    result['rigid_body_declaration'] = extra_rigid_body_declaration()
    data = {int(item['rva'], 0): bytes.fromhex(item['hex']) for item in result['data']}
    assert data[0x158F7CD0].decode('utf-16-le').split('\0')[0] == 'Weapon.Optimize.Net.EnableAimOp'
    assert data[0x158F7B88].decode('utf-16-le').split('\0')[0] == 'Weapon.Net.MaxBulletArrayNum'
    assert struct.unpack('<i', data[0x1CAC9CA8])[0] == 1000
    result['kind'] = 'weapon_optional_contract_source_replay'
    result['research_script_sha256'] = digest(Path(__file__).read_bytes())
    result['runtime_configuration_observed'] = False
    result['findings'] = dict(
        fire_multicast_order=['FireId:u64', 'BulletIndexZero:bit+[u8]',
            'InitSpeedFor3P:u16*100', 'NewAmmoCount:u16', 'AmmoIdZero:bit+[u64]',
            'ComboNumberZero:bit+[u8]', 'BothContinueCountsZero:bit+[u16,u16]',
            'OptionalData', 'BulletInfosCount:i32', 'BulletInfos[Count]'],
        optional_order=['DataOption:2bits', 'if >=1: MovementTimeStamp:raw32',
            'if >=1: CameraLocNonZero:bit+[PackedVector100_Max30]',
            'if >=1: CameraRot:AnglePair', 'if >=1: FireAimRot:AnglePair',
            'if >=2: CurrentSeed:raw32', 'if >=2: KickDeltaTime:raw32',
            'if >=2: Kick_TransRandIndex:4bits', 'if >=2: KickTargetRot:AnglePair'],
        angle_pair=dict(presence_bits=1, absent_loads_two_positive_zeroes=True,
            present_cvar_nonzero='two raw float32', present_cvar_zero='two uint16 scaled by 360/65536',
            cvar='Weapon.Optimize.Net.EnableAimOp', cvar_value_rva='0x1db7ff9c',
            current_cvar_value=None),
        bullet_array=dict(header='signed raw32', initializer_stride=280,
            cvar='Weapon.Net.MaxBulletArrayNum', cvar_value_rva='0x1cac9ca8',
            original_file_value=1000, current_value=None,
            loading_invalid_count='negative -> 0; above runtime maximum -> maximum; success flag false'),
        vehicle_order=['bIsUnderFPP:bool32', 'bIsAutonomousVehicle:bool32',
            'bHasVehicleLocation:bool32', 'SeatName:archive_FName', 'FrameId:raw32',
            'Position:PackedVector100_Max30', 'Quaternion:four_raw_float32',
            'LinVel:PackedVector100_Max30', 'AngVel:PackedVector100_Max30',
            'RigidBodyState.TimeStamp:float32', 'RigidBodyState.Flags:raw8',
            'CustomData:raw8', 'AutonomousFrameData.TimeStamp:float32'],
        qualification='normal no-byte-swap archive; conditional fields follow actual serializers, not memory layout',
        remaining=['current configuration and archive/PackageMap/FName context',
            'all nonempty BulletInfos element branches', 'FireMovePkg movement body',
            'LightFeature producer/compression qualification',
            'natural RPC parameter slices and authoritative execution'])
    return result


def stable_sources(document):
    return {key: document[key] for key in
            ('client_sha256', 'cache_manifest_sha256', 'structs', 'code', 'data',
             'rigid_body_declaration', 'findings')} | {
        'native_functions': document['native_analysis']['functions']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-evidence', type=Path)
    parser.add_argument('--compact', action='store_true')
    args = parser.parse_args()
    result = collect()
    if args.verify_evidence:
        expected_path = Path(__file__).resolve().parent/'evidence/gameplay-weapon-optional-research-20261021.json'
        if args.verify_evidence.resolve(strict=True) != expected_path:
            parser.error('Only the owned evidence snapshot is supported')
        saved = json.loads(expected_path.read_text(encoding='utf-8'))
        assert stable_sources(saved) == stable_sources(result), 'Saved source/contract changed'
    if args.compact:
        print(json.dumps(dict(status='verified', native_functions=len(PINS),
            struct_declarations=len(result['structs'])+1, constant_records=len(DATA),
            evidence_compared=bool(args.verify_evidence), process_access=False,
            client_launched=False, packets_sent=False, account_database_opened=False)))
    else:
        print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
