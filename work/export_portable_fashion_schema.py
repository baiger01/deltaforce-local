"""Derive portable Fashion schema from current declarations and pinned code."""
import hashlib
import json
import mmap
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache

ROOT = Path(__file__).resolve().parent.parent


def derive():
    shadow = Path('F:/deltaforce-local-shadow')
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600',
        'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754', shadow)
    source = ROOT/'work/native-client-tests/1792256241863805700/map-component-sources-final.json'
    raw = source.read_bytes()
    capture = json.loads(raw)
    assert capture['status'] == 'observed' and capture['identities_and_fields_rechecked'] is True
    assert capture['client_sha256'] == cache.manifest['client_sha256']
    assert capture['fashion']['owner_and_receiver_match_current_pawn'] is True
    prefix = []
    for klass in reversed(capture['fashion']['declarations']):
        fields = [r for r in klass['fields'] if int(r['property_flags'], 16) & 0x20]
        assert len({r['storage_offset'] for r in fields}) == len(fields)
        for row in sorted(fields, key=lambda r: r['storage_offset']):
            assert row['array_dimension'] == 1
            if row['name'] in ('currentCharacterHeroID', 'bIsFashionPrior'):
                numeric = row['name'] == 'currentCharacterHeroID'
                for slot, target in (('0x90', 0x10e5ce20 if numeric else 0x10e8ebe0),):
                    hook = row['hooks'][slot]
                    assert hook['target_rva'] == target
                    assert hook['target_module_sha256'] == cache.manifest['client_sha256']
                    assert hook['identity_rechecked'] is True and hook['inside_pinned_image'] is True
                if numeric:
                    leaf = row['hooks']['0x88']
                    assert leaf['target_rva'] == 0x286c000 and leaf['vtable_rva'] == 0x1ab60db0
                    assert leaf['identity_rechecked'] is True and leaf['inside_pinned_image'] is True
            prefix.append(dict(name=row['name'], handle=len(prefix)+1,
                offset=row['storage_offset'], storage_bytes=row['element_bytes'],
                declaring_class=klass['class_name'], property_flags=row['property_flags']))
            if row['name'] == 'currentUsingHeroFashionData':
                break
        if prefix and prefix[-1]['name'] == 'currentUsingHeroFashionData':
            break
    assert [(r['name'], r['offset']) for r in prefix] == [
        ('bReplicates', 200), ('bIsActive', 203), ('bIsFashionPrior', 1264),
        ('currentCharacterHeroID', 1288), ('characterTeamId', 1296), ('currentUsingHeroFashionData', 1400)]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    facts = ((0xb313685, 'lea', 'rdx, [rip + 0xc79e3ec]'),
        (0xb3136c6, 'mov', 'qword ptr [r14 + 0x26a8], rax'),
        (0x10e0561d, 'call', '0x10e055a0'),
        (0x10e058c1, 'call', '0x4a24e50'),
        (0x4a24f74, 'mov', 'eax, dword ptr [rsi + 0x54]'),
        (0x4a24f77, 'cmp', 'eax, dword ptr [rdx + 0x54]'),
        (0x10e058f7, 'mov', 'word ptr [rcx + 0x50], ax'),
        (0x12dbae86, 'movzx', 'eax, word ptr [rdx]'),
        (0x12dbb0a2, 'call', '0x12dbacf0'),
        (0xce576c5, 'jmp', '0xaffb570'))
    qualified = []
    for rva, mnemonic, operands in facts:
        code = cache.read(rva, 16)
        instruction = next(md.disasm(code, rva, count=1))
        assert (instruction.mnemonic, instruction.op_str) == (mnemonic, operands)
        qualified.append(dict(rva=hex(rva), mnemonic=mnemonic, operands=operands,
            bytes=instruction.bytes.hex(), sha256=hashlib.sha256(instruction.bytes).hexdigest()))
    with (shadow/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe').open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        text = image.read(0xb31368c+0xc79e3ec, 64).split(b'\0', 1)[0].decode('ascii')
        assert text == 'CharacterFashionComponent'
        array = image.read(0x18653060, 40)
        assert struct.unpack_from('<II', array, 32) == (1, 1400)
        params = image.read(0x1d1c2a80, 72)
        assert struct.unpack_from('<QQQ', params, 24) == (image.image_base+0x186517a8, 32, 8)
        assert struct.unpack_from('<Q', params, 48)[0] == image.image_base+0x18651778
        assert struct.unpack_from('<I', params, 56)[0] == 6
        children = []
        for pointer in struct.unpack('<6Q', image.read(0x18651778, 48)):
            record = image.read(pointer-image.image_base, 56)
            name = image.read(struct.unpack_from('<Q', record)[0]-image.image_base, 128).split(b'\0', 1)[0].decode('ascii')
            generation = struct.unpack_from('<I', record, 24)[0]
            offset = struct.unpack_from('<I', record, 36)[0]
            if generation == 0x4c:
                setter = struct.unpack_from('<Q', record, 48)[0]-image.image_base
                code = cache.read(setter, 5)
                assert code[:2] == b'\xc6\x41' and code[3:] == b'\x01\xc3'
                offset = code[2]
            else:
                assert generation == 7
            children.append(dict(name=name, offset=offset, kind='bool' if generation == 0x4c else 'uint64',
                property_record_rva=hex(pointer-image.image_base), record_sha256=hashlib.sha256(record).hexdigest()))
    children.sort(key=lambda row: row['offset'])
    assert [(r['name'], r['offset']) for r in children] == [('heroId', 0), ('fashionSuitId', 8),
        ('fashionTeammateVisible', 16), ('fashionEnemyVisible', 17), ('fashionSafehouseVisible', 18), ('watchItemId', 24)]
    for i, row in enumerate(children):
        row['handle'] = i+1
    return dict(kind='client_declaration_derived_default_fashion_schema',
        client_sha256=cache.manifest['client_sha256'], component_class='DFMCharacterFashionComponent',
        component_name=text, pawn_member_offset=0x26a8,
        declaration_capture_sha256=hashlib.sha256(raw).hexdigest(),
        native_cache_manifest_sha256=cache.manifest_sha256,
        existing_runtime_layout_observed=False, normal_receiver_rule_derived=True,
        scalar_prefix=prefix, fashion_array_children=children,
        array_property_record_rva='0x18653060', array_property_sha256=hashlib.sha256(array).hexdigest(),
        struct_params_rva='0x1d1c2a80', struct_params_sha256=hashlib.sha256(params).hexdigest(),
        verified_instruction_facts=qualified, native_model_verified=False)


if __name__ == '__main__':
    schema = derive()
    output = ROOT/'outputs/df-local-server/protocol/portable-map-spawn/fashion-schema.json'
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    with output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(output), sha256=hashlib.sha256(raw).hexdigest())))
